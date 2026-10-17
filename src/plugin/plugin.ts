import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
  sensitiveSessionMiddleware,
  sessionMiddleware,
} from 'better-auth/api';
import type { BetterAuthPlugin } from 'better-auth/types';
import { z } from 'zod';

import {
  compileResources,
  createRobrac,
  inheritanceDepth,
  withBeforeWrite,
} from '../core/engine.ts';
import type {
  PermissionRequestOf,
  ResourceRegistry,
  ResourceTypeOf,
  RobracEngine,
  RobracEngineOptions,
  RoleOf,
} from '../core/engine.ts';
import { RobracArgumentError, RobracError } from '../core/errors.ts';
import { checkPermissions } from '../core/roles.ts';
import type {
  AccessDecision,
  RobracContext,
  Scope,
  SubjectRef,
} from '../core/types.ts';
import { betterAuthGrantStore } from '../store/better-auth.ts';
import type { BetterAuthAdapterLike } from '../store/better-auth.ts';
import type { GrantStore } from '../store/types.ts';
import { ROBRAC_PLUGIN_ID } from './id.ts';
import type {
  AccessBatchBody,
  AccessibleIdsBody,
  CheckBody,
  GrantRoleBody,
  ListGrantsResult,
  ResourceScopedBody,
  RevokeRoleBody,
  SerializedDecision,
  SetRolesBody,
  SubjectDescriptor,
} from './infer.ts';
import { grantSchema } from './schema.ts';
import type { GrantSchemaOptions } from './schema.ts';
import {
  activeOrganizationScope,
  defaultSubjectResolver,
  MEMBER_SUBJECT,
  organizationSubjectValidator,
  USER_SUBJECT,
} from './subjects.ts';
import type {
  ScopeResolver,
  SubjectResolver,
  SubjectValidator,
} from './subjects.ts';

export { ROBRAC_PLUGIN_ID, type RobracPluginId } from './id.ts';

export type RobracPluginOptions<TRegistry extends ResourceRegistry> = {
  /** Resource types, keyed by their `type`. */
  resources: TRegistry;

  /**
   * Where grants live. Defaults to a store over Better Auth's internal
   * adapter. Pass your own {@link GrantStore}, or a factory that receives the
   * adapter, to point robrac at an existing table or hand-tuned SQL.
   */
  store?: GrantStore | ((adapter: BetterAuthAdapterLike) => GrantStore);

  /** See `RobracEngineOptions['scope']`. Defaults to `'required'`. */
  scope?: 'required' | 'optional' | 'disabled';

  /**
   * How the tenant for a request is determined. Defaults to the active
   * organization. Not called under `scope: 'disabled'`.
   */
  resolveScope?: ScopeResolver;

  /**
   * How the caller's identities are determined. Defaults to user + member,
   * refusing callers that are not a member of the active organization. A
   * custom resolver takes over that membership check.
   */
  resolveSubjects?: SubjectResolver;

  /** Table/column naming and the optional `scope` foreign key. */
  schema?: { grant?: GrantSchemaOptions };

  /** See `RobracEngineOptions['maxInheritanceDepth']`. */
  maxInheritanceDepth?: number;

  /** See `RobracEngineOptions['escalation']`. Defaults to `'deny'`. */
  escalation?: 'deny' | 'allow';

  /** Audit hook for every decision. */
  onDecision?: RobracEngineOptions<TRegistry>['onDecision'];

  /** Audit hook for every grant change. */
  onGrantChange?: RobracEngineOptions<TRegistry>['onGrantChange'];

  subjects?: {
    /**
     * Turn `(type, id)` pairs into something a share dialog can render.
     * Without it, `listGrants` returns raw subject references.
     */
    describe?: (args: {
      subjects: SubjectRef[];
      scope: Scope;
      context: RobracContext;
    }) => Promise<SubjectDescriptor[]> | SubjectDescriptor[];

    /**
     * Decide whether a grant target belongs to the caller's tenant before
     * `grants/grant` and `grants/set` write it. Defaults to an organization
     * membership check when the default subject resolver is in use; other
     * resolvers accept every target unless this is set.
     */
    validate?: SubjectValidator;
  };

  /**
   * Grant cleanup wired to the organization plugin's endpoints. Removing a
   * member deletes the member's and the user's grants in that organization;
   * deleting an organization deletes every grant in it.
   *
   * Enabled by default only with the default scope resolver, and never under
   * `scope: 'disabled'`.
   */
  cleanup?: {
    onMemberRemoved?: boolean;
    onOrganizationDeleted?: boolean;
  };

  /** Per-path rate limits. Set to `false` to inherit the global defaults. */
  rateLimit?:
    | false
    | {
        /** Read endpoints, including `/robrac/grants/list`. */
        read?: { window: number; max: number };
        /** Grant mutations: `/robrac/grants/grant`, `set` and `revoke`. */
        write?: { window: number; max: number };
      };
};

// 255 fits the `varchar(255)` columns Better Auth creates on MySQL.
const identifier = z
  .string()
  .min(1)
  .max(255)
  .refine((value) => !value.includes('\u0000'), 'Must not contain NUL.')
  // A lone surrogate is stored as U+FFFD and never reads back as written.
  .refine((value) => value.isWellFormed(), 'Must be well-formed Unicode.');

const subjectRefSchema = z.object({ type: identifier, id: identifier });

const actionsSchema = z.array(z.string().max(256)).max(64);

const permissionRequestSchema = z
  .record(
    z.string().max(256),
    z.union([
      actionsSchema,
      z.object({
        actions: actionsSchema,
        connector: z.enum(['AND', 'OR']).optional(),
      }),
    ])
  )
  .refine((request) => Object.keys(request).length <= 64, 'Too many facets.');

const connectorSchema = z.enum(['AND', 'OR']).optional();

const expiresAtSchema = z.coerce.date().nullish();

const WRITE_PATHS = new Set([
  '/robrac/grants/grant',
  '/robrac/grants/set',
  '/robrac/grants/revoke',
]);

// The inferred body types allow an ISO string; zod has already coerced it.
function toExpiry(value: string | Date | null | undefined): Date | null {
  if (value === null || value === undefined) {
    return null;
  }
  return value instanceof Date ? value : new Date(value);
}

type Logger = { error: (message: string, ...args: unknown[]) => void };

/** Map core errors onto HTTP status codes. */
function toApiError(error: unknown, logger: Logger): never {
  if (error instanceof RobracArgumentError) {
    throw new APIError('BAD_REQUEST', { message: error.message });
  }
  if (error instanceof RobracError) {
    switch (error.code) {
      case 'UNKNOWN_RESOURCE_TYPE':
      case 'UNKNOWN_ROLE':
        throw new APIError('BAD_REQUEST', { message: error.message });
      case 'RESOURCE_NOT_FOUND':
        throw new APIError('NOT_FOUND', { message: error.message });
      case 'SCOPE_REQUIRED':
      case 'FORBIDDEN':
        throw new APIError('FORBIDDEN', { message: error.message });
      case 'INVALID_CONFIGURATION':
        logger.error('robrac: invalid configuration', error);
        throw new APIError('INTERNAL_SERVER_ERROR', {
          message: 'robrac is misconfigured.',
        });
    }
  }
  throw error;
}

/**
 * A caller with no role and no permission on a resource learns nothing about
 * it, not even that it exists or is under a `'deny'` override.
 */
function isVisible(decision: AccessDecision): boolean {
  return (
    decision.found &&
    (decision.effectiveRoles.length > 0 ||
      Object.values(decision.permissions).some((row) =>
        Object.values(row).includes(true)
      ))
  );
}

function serializeDecision(decision: AccessDecision): SerializedDecision {
  if (!isVisible(decision)) {
    return {
      found: false,
      scope: decision.scope,
      resourceType: decision.resource.type,
      resourceId: decision.resource.id,
      roles: [],
      effectiveRoles: [],
      permissions: Object.fromEntries(
        Object.entries(decision.permissions).map(([facet, row]) => [
          facet,
          Object.fromEntries(Object.keys(row).map((action) => [action, false])),
        ])
      ),
      override: null,
    };
  }
  return {
    found: true,
    scope: decision.scope,
    resourceType: decision.resource.type,
    resourceId: decision.resource.id,
    roles: decision.roles,
    effectiveRoles: decision.effectiveRoles,
    permissions: decision.permissions,
    override: decision.override,
  };
}

function readMember(
  returned: unknown
): { id: string; organizationId: string; userId: string | null } | null {
  if (typeof returned !== 'object' || returned === null) {
    return null;
  }
  const candidate = 'member' in returned ? returned.member : returned;
  if (typeof candidate !== 'object' || candidate === null) {
    return null;
  }
  const { id, organizationId, userId } = candidate as Record<string, unknown>;
  return typeof id === 'string' && typeof organizationId === 'string'
    ? {
        id,
        organizationId,
        userId: typeof userId === 'string' ? userId : null,
      }
    : null;
}

function readOrganizationId(returned: unknown): string | null {
  if (typeof returned === 'string') {
    return returned;
  }
  if (typeof returned === 'object' && returned !== null && 'id' in returned) {
    const { id } = returned;
    return typeof id === 'string' ? id : null;
  }
  return null;
}

/**
 * robrac: Role Based Resource Access Control for Better Auth.
 *
 * The returned plugin also exposes `getEngine()`, the decision engine the
 * endpoints use, for server code that should not go through HTTP.
 *
 * @example
 * ```ts
 * export const robracPlugin = robrac({
 *   resources: { recording: recordingResource },
 * });
 *
 * export const auth = betterAuth({
 *   plugins: [organization(), robracPlugin],
 * });
 * ```
 */
export function robrac<const TRegistry extends ResourceRegistry>(
  options: RobracPluginOptions<TRegistry>
) {
  const scopeMode = options.scope ?? 'required';

  // Configuration bugs fail at boot, not at the first authorization check.
  compileResources(options.resources, scopeMode);
  inheritanceDepth(options.maxInheritanceDepth);

  const schemaOptions = options.schema?.grant ?? {};
  const resolveScope = options.resolveScope ?? activeOrganizationScope;
  const resolveSubjects = options.resolveSubjects ?? defaultSubjectResolver();
  const validateSubject =
    options.subjects?.validate ?? organizationSubjectValidator(resolveSubjects);

  // Cleanup reads organization ids as scopes, which only holds for the default
  // scope resolver. Under 'disabled' every grant has a null scope, and a
  // scope-wide revoke must never be widened to "every grant".
  const organizationScopes = resolveScope === activeOrganizationScope;
  const cleanupMemberRemoved =
    scopeMode !== 'disabled' &&
    (options.cleanup?.onMemberRemoved ?? organizationScopes);
  const cleanupOrgDeleted =
    scopeMode !== 'disabled' &&
    (options.cleanup?.onOrganizationDeleted ?? organizationScopes);

  // The Better Auth adapter only exists once the auth context is created. One
  // engine per adapter, so a plugin instance shared by two auth instances
  // never writes to the wrong database.
  const engines = new WeakMap<object, RobracEngine<TRegistry>>();
  let firstEngine: RobracEngine<TRegistry> | null = null;

  const createEngine = (adapter: BetterAuthAdapterLike) =>
    createRobrac({
      resources: options.resources,
      store:
        typeof options.store === 'function'
          ? options.store(adapter)
          : (options.store ??
            betterAuthGrantStore({ adapter, model: schemaOptions.modelName })),
      scope: options.scope,
      maxInheritanceDepth: options.maxInheritanceDepth,
      escalation: options.escalation,
      onDecision: options.onDecision,
      onGrantChange: options.onGrantChange,
    });

  const engineFor = (adapter: BetterAuthAdapterLike) => {
    let engine = engines.get(adapter);
    if (!engine) {
      engine = createEngine(adapter);
      engines.set(adapter, engine);
      firstEngine ??= engine;
    }
    return engine;
  };

  type Caller = {
    engine: RobracEngine<TRegistry>;
    adapter: BetterAuthAdapterLike;
    subjects: readonly SubjectRef[];
    scope: Scope;
    context: RobracContext;
    grantedBy: SubjectRef | undefined;
  };

  const resolveCaller = async (ctx: {
    context: Record<string, unknown>;
    headers?: Headers | undefined;
    request?: Request | undefined;
  }): Promise<Caller> => {
    const adapter = ctx.context.adapter as BetterAuthAdapterLike;
    const session = ctx.context.session as {
      user: { id: string } & Record<string, unknown>;
      session: Record<string, unknown>;
    };
    const context: RobracContext = {
      headers: ctx.headers,
      request: ctx.request,
      session: session.session,
      user: session.user,
      auth: ctx.context,
    };

    const scope =
      scopeMode === 'disabled'
        ? null
        : await resolveScope({
            user: session.user,
            session: session.session,
            context,
          });
    const subjects = await resolveSubjects({
      user: session.user,
      session: session.session,
      adapter,
      scope,
      context,
    });

    return {
      engine: engineFor(adapter),
      adapter,
      subjects,
      scope,
      context,
      grantedBy:
        subjects.find((subject) => subject.type === MEMBER_SUBJECT) ??
        subjects[0],
    };
  };

  // Runs once the caller is authorized, so a caller who may not manage the
  // resource gets the same answer whatever the subject and cannot probe who
  // belongs to the organization.
  const subjectCheck =
    (caller: Caller, subject: SubjectRef, logger: Logger) => async () => {
      if (!validateSubject) {
        return;
      }
      const valid = await Promise.resolve()
        .then(() =>
          validateSubject({
            subject,
            scope: caller.scope,
            adapter: caller.adapter,
            context: caller.context,
          })
        )
        .catch((error: unknown) => {
          logger.error('robrac: subject validation failed', error);
          return false;
        });
      if (!valid) {
        throw new APIError('BAD_REQUEST', {
          message: 'This subject does not belong to the current scope.',
        });
      }
    };

  // Bodies are validated as loose strings so the endpoints stay usable from
  // untyped callers; the registry-aware types come from `$Infer`.
  type AnyType = ResourceTypeOf<TRegistry>;
  const asType = (value: string) => value as AnyType;
  const asPermissions = (value: unknown) =>
    value as PermissionRequestOf<TRegistry, AnyType>;
  const asRole = (value: string) => value as RoleOf<TRegistry, AnyType>;

  const rateLimit =
    options.rateLimit === false
      ? []
      : [
          {
            pathMatcher: (path: string) => WRITE_PATHS.has(path),
            window: options.rateLimit?.write?.window ?? 60,
            max: options.rateLimit?.write?.max ?? 30,
          },
          {
            pathMatcher: (path: string) =>
              path.startsWith('/robrac/') && !WRITE_PATHS.has(path),
            window: options.rateLimit?.read?.window ?? 10,
            max: options.rateLimit?.read?.max ?? 120,
          },
        ];

  const memberCleanup = {
    matcher: (context: { path?: string }) =>
      context.path === '/organization/remove-member' ||
      context.path === '/organization/leave',
    handler: createAuthMiddleware(async (ctx) => {
      const member = readMember(ctx.context.returned);
      if (!member) {
        return;
      }
      // The removal itself has succeeded, so a failure here is only logged.
      // The default subject resolver refuses a removed member anyway.
      try {
        const grants = engineFor(ctx.context.adapter).grants;
        await grants.revokeSubject({
          scope: member.organizationId,
          subject: { type: MEMBER_SUBJECT, id: member.id },
        });
        if (member.userId) {
          await grants.revokeSubject({
            scope: member.organizationId,
            subject: { type: USER_SUBJECT, id: member.userId },
          });
        }
      } catch (error) {
        ctx.context.logger.error('robrac: member grant cleanup failed', error);
      }
    }),
  };

  const organizationCleanup = {
    matcher: (context: { path?: string }) =>
      context.path === '/organization/delete',
    handler: createAuthMiddleware(async (ctx) => {
      const organizationId = readOrganizationId(ctx.context.returned);
      if (!organizationId) {
        return;
      }
      try {
        await engineFor(ctx.context.adapter).grants.revokeScope({
          scope: organizationId,
        });
      } catch (error) {
        ctx.context.logger.error(
          'robrac: organization grant cleanup failed',
          error
        );
      }
    }),
  };

  const plugin = {
    id: ROBRAC_PLUGIN_ID,

    init(ctx: { adapter: unknown }) {
      engineFor(ctx.adapter as BetterAuthAdapterLike);
    },

    endpoints: {
      /** `POST /robrac/check`: may the caller do X to this resource? */
      checkResourceAccess: createAuthEndpoint(
        '/robrac/check',
        {
          method: 'POST',
          requireHeaders: true,
          use: [sessionMiddleware],
          body: z.object({
            resourceType: identifier,
            resourceId: identifier,
            permissions: permissionRequestSchema,
            connector: connectorSchema,
          }),
          metadata: { $Infer: { body: {} as CheckBody<TRegistry> } },
        },
        async (ctx) => {
          try {
            const caller = await resolveCaller(ctx);
            const success = await caller.engine.check({
              type: asType(ctx.body.resourceType),
              id: ctx.body.resourceId,
              permissions: asPermissions(ctx.body.permissions),
              connector: ctx.body.connector,
              subjects: caller.subjects,
              scope: caller.scope,
              context: caller.context,
            });
            return ctx.json({ success });
          } catch (error) {
            return toApiError(error, ctx.context.logger);
          }
        }
      ),

      /** `POST /robrac/access`: the full decision for one resource. */
      getResourceAccess: createAuthEndpoint(
        '/robrac/access',
        {
          method: 'POST',
          requireHeaders: true,
          use: [sessionMiddleware],
          body: z.object({ resourceType: identifier, resourceId: identifier }),
          metadata: { $Infer: { body: {} as ResourceScopedBody<TRegistry> } },
        },
        async (ctx) => {
          try {
            const caller = await resolveCaller(ctx);
            const decision = await caller.engine.evaluate({
              type: asType(ctx.body.resourceType),
              id: ctx.body.resourceId,
              subjects: caller.subjects,
              scope: caller.scope,
              context: caller.context,
            });
            if (!isVisible(decision)) {
              throw new RobracError(
                'RESOURCE_NOT_FOUND',
                'Resource not found.'
              );
            }
            return ctx.json(serializeDecision(decision));
          } catch (error) {
            return toApiError(error, ctx.context.logger);
          }
        }
      ),

      /**
       * `POST /robrac/access-batch`: decisions for a page of resources in one
       * round trip. Pass `permissions` to also get back just the allowed ids.
       */
      getResourceAccessBatch: createAuthEndpoint(
        '/robrac/access-batch',
        {
          method: 'POST',
          requireHeaders: true,
          use: [sessionMiddleware],
          body: z.object({
            resourceType: identifier,
            resourceIds: z.array(identifier).min(1).max(200),
            permissions: permissionRequestSchema.optional(),
            connector: connectorSchema,
          }),
          metadata: { $Infer: { body: {} as AccessBatchBody<TRegistry> } },
        },
        async (ctx) => {
          try {
            const caller = await resolveCaller(ctx);
            const decisions = await caller.engine.evaluateMany({
              type: asType(ctx.body.resourceType),
              ids: ctx.body.resourceIds,
              subjects: caller.subjects,
              scope: caller.scope,
              context: caller.context,
            });
            const request = ctx.body.permissions;
            const allowedIds = request
              ? [...decisions]
                  .filter(
                    ([, decision]) =>
                      decision.found &&
                      checkPermissions(
                        decision.permissions,
                        request,
                        ctx.body.connector
                      )
                  )
                  .map(([id]) => id)
              : undefined;
            return ctx.json({
              decisions: [...decisions.values()].map(serializeDecision),
              allowedIds,
            });
          } catch (error) {
            return toApiError(error, ctx.context.logger);
          }
        }
      ),

      /** `POST /robrac/grants/list`: who has access to this resource. */
      listResourceGrants: createAuthEndpoint(
        '/robrac/grants/list',
        {
          method: 'POST',
          requireHeaders: true,
          use: [sessionMiddleware],
          body: z.object({ resourceType: identifier, resourceId: identifier }),
          metadata: { $Infer: { body: {} as ResourceScopedBody<TRegistry> } },
        },
        async (ctx) => {
          try {
            const caller = await resolveCaller(ctx);
            const { grants, availableRoles, declaredRoles } =
              await caller.engine.authorized.listGrants({
                type: asType(ctx.body.resourceType),
                id: ctx.body.resourceId,
                actor: caller.subjects,
                scope: caller.scope,
                context: caller.context,
              });
            const describe = options.subjects?.describe;
            const result: ListGrantsResult = {
              resourceType: ctx.body.resourceType,
              resourceId: ctx.body.resourceId,
              scope: caller.scope,
              availableRoles,
              declaredRoles,
              grants,
              subjects: describe
                ? await describe({
                    subjects: grants.map((grant) => ({
                      type: grant.subjectType,
                      id: grant.subjectId,
                    })),
                    scope: caller.scope,
                    context: caller.context,
                  })
                : undefined,
            };
            return ctx.json(result);
          } catch (error) {
            return toApiError(error, ctx.context.logger);
          }
        }
      ),

      /** `POST /robrac/grants/grant`: add one role for one subject. */
      grantResourceRole: createAuthEndpoint(
        '/robrac/grants/grant',
        {
          method: 'POST',
          requireHeaders: true,
          use: [sensitiveSessionMiddleware],
          body: z.object({
            resourceType: identifier,
            resourceId: identifier,
            subject: subjectRefSchema,
            role: identifier,
            expiresAt: expiresAtSchema,
          }),
          metadata: { $Infer: { body: {} as GrantRoleBody<TRegistry> } },
        },
        async (ctx) => {
          try {
            const caller = await resolveCaller(ctx);
            const grant = await withBeforeWrite(caller.engine).grant(
              {
                type: asType(ctx.body.resourceType),
                id: ctx.body.resourceId,
                subject: ctx.body.subject,
                role: asRole(ctx.body.role),
                expiresAt: toExpiry(ctx.body.expiresAt),
                actor: caller.subjects,
                grantedBy: caller.grantedBy,
                scope: caller.scope,
                context: caller.context,
              },
              subjectCheck(caller, ctx.body.subject, ctx.context.logger)
            );
            return ctx.json({ grant });
          } catch (error) {
            return toApiError(error, ctx.context.logger);
          }
        }
      ),

      /** `POST /robrac/grants/set`: replace a subject's roles wholesale. */
      setResourceRoles: createAuthEndpoint(
        '/robrac/grants/set',
        {
          method: 'POST',
          requireHeaders: true,
          use: [sensitiveSessionMiddleware],
          body: z.object({
            resourceType: identifier,
            resourceId: identifier,
            subject: subjectRefSchema,
            roles: z.array(identifier).max(64),
            expiresAt: expiresAtSchema,
          }),
          metadata: { $Infer: { body: {} as SetRolesBody<TRegistry> } },
        },
        async (ctx) => {
          try {
            const caller = await resolveCaller(ctx);
            const check = subjectCheck(
              caller,
              ctx.body.subject,
              ctx.context.logger
            );
            const grants = await withBeforeWrite(caller.engine).setRoles(
              {
                type: asType(ctx.body.resourceType),
                id: ctx.body.resourceId,
                subject: ctx.body.subject,
                roles: ctx.body.roles.map(asRole),
                expiresAt: toExpiry(ctx.body.expiresAt),
                actor: caller.subjects,
                grantedBy: caller.grantedBy,
                scope: caller.scope,
                context: caller.context,
              },
              // Clearing a subject's roles needs no proof it belongs here.
              ctx.body.roles.length > 0 ? check : () => Promise.resolve()
            );
            return ctx.json({ grants });
          } catch (error) {
            return toApiError(error, ctx.context.logger);
          }
        }
      ),

      /** `POST /robrac/grants/revoke`: drop one role, or all of them. */
      revokeResourceRole: createAuthEndpoint(
        '/robrac/grants/revoke',
        {
          method: 'POST',
          requireHeaders: true,
          use: [sensitiveSessionMiddleware],
          body: z.object({
            resourceType: identifier,
            resourceId: identifier,
            subject: subjectRefSchema,
            role: identifier.optional(),
          }),
          metadata: { $Infer: { body: {} as RevokeRoleBody<TRegistry> } },
        },
        async (ctx) => {
          try {
            const caller = await resolveCaller(ctx);
            const revoked = await caller.engine.authorized.revoke({
              type: asType(ctx.body.resourceType),
              id: ctx.body.resourceId,
              subject: ctx.body.subject,
              role:
                ctx.body.role === undefined ? undefined : asRole(ctx.body.role),
              actor: caller.subjects,
              revokedBy: caller.grantedBy,
              scope: caller.scope,
              context: caller.context,
            });
            return ctx.json({ revoked });
          } catch (error) {
            return toApiError(error, ctx.context.logger);
          }
        }
      ),

      /**
       * `POST /robrac/accessible-ids`: the ids the caller holds a grant on.
       * Server-only: a query-planning primitive for your own `WHERE` clause.
       */
      listAccessibleResourceIds: createAuthEndpoint(
        '/robrac/accessible-ids',
        {
          method: 'POST',
          requireHeaders: true,
          use: [sessionMiddleware],
          body: z.object({
            resourceType: identifier,
            permissions: permissionRequestSchema.optional(),
            limit: z.number().int().positive().max(1000).optional(),
            offset: z.number().int().min(0).max(1_000_000).optional(),
          }),
          metadata: {
            SERVER_ONLY: true,
            $Infer: { body: {} as AccessibleIdsBody<TRegistry> },
          },
        },
        async (ctx) => {
          try {
            const caller = await resolveCaller(ctx);
            const resourceIds = await caller.engine.accessibleResourceIds({
              type: asType(ctx.body.resourceType),
              permissions: ctx.body.permissions
                ? asPermissions(ctx.body.permissions)
                : undefined,
              limit: ctx.body.limit,
              offset: ctx.body.offset,
              subjects: caller.subjects,
              scope: caller.scope,
            });
            return ctx.json({ resourceIds });
          } catch (error) {
            return toApiError(error, ctx.context.logger);
          }
        }
      ),
    },

    hooks: {
      after: [
        ...(cleanupMemberRemoved ? [memberCleanup] : []),
        ...(cleanupOrgDeleted ? [organizationCleanup] : []),
      ],
    },

    rateLimit,

    schema: grantSchema(schemaOptions),

    $Infer: {
      Decision: {} as SerializedDecision,
      Subject: {} as SubjectRef,
    },
  } satisfies BetterAuthPlugin;

  return Object.assign(plugin, {
    /**
     * The decision engine backing this plugin. Available once Better Auth has
     * initialized the plugin; with several auth instances, the first one's.
     */
    getEngine(): RobracEngine<TRegistry> {
      if (!firstEngine) {
        throw new RobracError(
          'INVALID_CONFIGURATION',
          'robrac has not been initialized yet. Pass the plugin to betterAuth() before calling getEngine().'
        );
      }
      return firstEngine;
    },
  });
}
