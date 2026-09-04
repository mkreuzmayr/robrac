import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
  sessionMiddleware,
} from 'better-auth/api';
import type { BetterAuthPlugin } from 'better-auth/types';
import { z } from 'zod';

import {
  compileResources,
  createRobrac,
  resolveMaxInheritanceDepth,
} from '../core/engine.ts';
import type {
  PermissionRequestOf,
  ResourceRegistry,
  ResourceTypeOf,
  RobracEngine,
  RobracEngineOptions,
  RoleOf,
} from '../core/engine.ts';
import { RobracError } from '../core/errors.ts';
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
} from './subjects.ts';
import type { ScopeResolver, SubjectResolver } from './subjects.ts';

export const ROBRAC_PLUGIN_ID = 'robrac';
export type RobracPluginId = typeof ROBRAC_PLUGIN_ID;

export type RobracPluginOptions<TRegistry extends ResourceRegistry> = {
  /** Resource types, keyed by their `type`. */
  resources: TRegistry;

  /**
   * Where grants live.
   *
   * Defaults to a store over Better Auth's internal adapter, which already
   * speaks whichever database you configured — Drizzle, Prisma, Kysely, Mongo
   * or a direct connection. Pass your own {@link GrantStore}, or a factory
   * that receives the adapter, to point robrac at an existing table or at
   * hand-tuned SQL.
   */
  store?: GrantStore | ((adapter: BetterAuthAdapterLike) => GrantStore);

  /** See `RobracEngineOptions['scope']`. Defaults to `'required'`. */
  scope?: 'required' | 'optional' | 'disabled';

  /** How the tenant for a request is determined. Defaults to the active organization. */
  resolveScope?: ScopeResolver;

  /** How the caller's identities are determined. Defaults to user + member. */
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
     * Without it, `listGrants` returns raw subject references and your UI
     * resolves names itself.
     */
    describe?: (args: {
      subjects: SubjectRef[];
      scope: Scope;
      context: RobracContext;
    }) => Promise<SubjectDescriptor[]> | SubjectDescriptor[];
  };

  /**
   * Best-effort grant cleanup wired to the organization plugin's endpoints.
   *
   * This is hygiene, not a security control: a removed member's grants are
   * already inert, because subject resolution can no longer produce that
   * member id. Both flags default to enabled.
   */
  cleanup?: {
    onMemberRemoved?: boolean;
    onOrganizationDeleted?: boolean;
  };

  /** Per-path rate limits. Set to `false` to inherit the global defaults. */
  rateLimit?:
    | false
    | {
        /** Read endpoints (`/robrac/check`, `/robrac/access`, ...). */
        read?: { window: number; max: number };
        /** Grant mutations (`/robrac/grants/*`). */
        write?: { window: number; max: number };
      };
};

const subjectRefSchema = z.object({
  type: z.string().min(1),
  id: z.string().min(1),
});

const permissionRequestSchema = z.record(
  z.string(),
  z.union([
    z.array(z.string()),
    z.object({
      actions: z.array(z.string()),
      connector: z.enum(['AND', 'OR']).optional(),
    }),
  ])
);

const connectorSchema = z.enum(['AND', 'OR']).optional();

/** Grant expiry crosses the wire as an ISO string but is stored as a `Date`. */
function toExpiry(value: string | Date | null | undefined): Date | null {
  if (value === null || value === undefined) {
    return null;
  }
  return value instanceof Date ? value : new Date(value);
}

/** Map core errors onto HTTP status codes. */
function toApiError(error: unknown): never {
  if (error instanceof RobracError) {
    switch (error.code) {
      case 'UNKNOWN_RESOURCE_TYPE':
      case 'UNKNOWN_ROLE':
      case 'INVALID_CONFIGURATION':
        throw new APIError('BAD_REQUEST', { message: error.message });
      case 'RESOURCE_NOT_FOUND':
        throw new APIError('NOT_FOUND', { message: error.message });
      case 'SCOPE_REQUIRED':
      case 'FORBIDDEN':
        throw new APIError('FORBIDDEN', { message: error.message });
    }
  }
  throw error;
}

function serializeDecision(decision: AccessDecision): SerializedDecision {
  return {
    found: decision.found,
    scope: decision.scope,
    resourceType: decision.resource.type,
    resourceId: decision.resource.id,
    roles: decision.roles,
    effectiveRoles: decision.effectiveRoles,
    permissions: decision.permissions,
    override: decision.override,
  };
}

/**
 * robrac — Role Based Resource Access Control for Better Auth.
 *
 * Adds per-resource authorization on top of Better Auth's organization-level
 * roles: who may read *this* recording, edit *that* document, share *this*
 * folder.
 *
 * The returned plugin also exposes `getEngine()`, which hands you the same
 * decision engine the endpoints use — call it from loaders, background jobs or
 * any server code that should not go through HTTP.
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
  resolveMaxInheritanceDepth(options.maxInheritanceDepth);

  // Fail at boot, not at the first authorization check: role cycles, roles
  // that reference undeclared actions, and resources missing a scope() under
  // multi-tenancy are all configuration bugs.
  compileResources(options.resources, scopeMode);

  const schemaOptions = options.schema?.grant ?? {};
  const resolveScope = options.resolveScope ?? activeOrganizationScope;
  const resolveSubjects = options.resolveSubjects ?? defaultSubjectResolver();
  // Both cleanup hooks interpret an organization id as a robrac scope, which
  // is only meaningful when scopes are in play. Under `scope: 'disabled'`
  // every grant is stored with a null scope, so a scope-wide revoke keyed on
  // an organization id would either match nothing or — far worse — be widened
  // to "every grant in the database". Leave them off.
  const scopesAreOrganizations = scopeMode !== 'disabled';
  const cleanupMemberRemoved =
    scopesAreOrganizations && options.cleanup?.onMemberRemoved !== false;
  const cleanupOrgDeleted =
    scopesAreOrganizations && options.cleanup?.onOrganizationDeleted !== false;

  // The engine needs the Better Auth adapter, which only exists once the auth
  // context has been created. `init` fills this in before any request runs.
  let engine: RobracEngine<TRegistry> | null = null;

  const buildEngine = (
    adapter: BetterAuthAdapterLike
  ): RobracEngine<TRegistry> => {
    const store =
      typeof options.store === 'function'
        ? options.store(adapter)
        : (options.store ??
          betterAuthGrantStore({
            adapter,
            model: schemaOptions.modelName,
          }));

    return createRobrac({
      resources: options.resources,
      store,
      scope: options.scope,
      maxInheritanceDepth: options.maxInheritanceDepth,
      escalation: options.escalation,
      onDecision: options.onDecision,
      onGrantChange: options.onGrantChange,
    });
  };

  const engineFor = (adapter: BetterAuthAdapterLike) =>
    (engine ??= buildEngine(adapter));

  /** Everything an endpoint needs, resolved once per request. */
  type Caller = {
    engine: RobracEngine<TRegistry>;
    subjects: readonly SubjectRef[];
    scope: Scope;
    context: RobracContext;
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

    const scope = await resolveScope({
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

    return { engine: engineFor(adapter), subjects, scope, context };
  };

  /**
   * The request bodies are validated as loose strings so that the endpoints
   * stay usable from untyped callers; the registry-aware types come from
   * `$Infer`. These aliases document where that gap is bridged.
   */
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
            pathMatcher: (path: string) => path.startsWith('/robrac/grants/'),
            window: options.rateLimit?.write?.window ?? 60,
            max: options.rateLimit?.write?.max ?? 30,
          },
          {
            pathMatcher: (path: string) =>
              path.startsWith('/robrac/') &&
              !path.startsWith('/robrac/grants/'),
            window: options.rateLimit?.read?.window ?? 10,
            max: options.rateLimit?.read?.max ?? 120,
          },
        ];

  const plugin = {
    id: ROBRAC_PLUGIN_ID,

    init(ctx: { adapter: unknown }) {
      engine ??= buildEngine(ctx.adapter as BetterAuthAdapterLike);
    },

    endpoints: {
      /** `POST /robrac/check` — may the caller do X to this resource? */
      checkResourceAccess: createAuthEndpoint(
        '/robrac/check',
        {
          method: 'POST',
          requireHeaders: true,
          use: [sessionMiddleware],
          body: z.object({
            resourceType: z.string(),
            resourceId: z.string(),
            permissions: permissionRequestSchema,
            connector: connectorSchema,
          }),
          metadata: { $Infer: { body: {} as CheckBody<TRegistry> } },
        },
        async (ctx) => {
          const caller = await resolveCaller(ctx);
          try {
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
            return toApiError(error);
          }
        }
      ),

      /** `POST /robrac/access` — the full decision for one resource. */
      getResourceAccess: createAuthEndpoint(
        '/robrac/access',
        {
          method: 'POST',
          requireHeaders: true,
          use: [sessionMiddleware],
          body: z.object({
            resourceType: z.string(),
            resourceId: z.string(),
          }),
          metadata: { $Infer: { body: {} as ResourceScopedBody<TRegistry> } },
        },
        async (ctx) => {
          const caller = await resolveCaller(ctx);
          try {
            const decision = await caller.engine.evaluate({
              type: asType(ctx.body.resourceType),
              id: ctx.body.resourceId,
              subjects: caller.subjects,
              scope: caller.scope,
              context: caller.context,
            });

            if (!decision.found) {
              throw new APIError('NOT_FOUND', {
                message: 'Resource not found.',
              });
            }

            return ctx.json(serializeDecision(decision));
          } catch (error) {
            return toApiError(error);
          }
        }
      ),

      /**
       * `POST /robrac/access-batch` — decisions for a page of resources in one
       * round trip. Pass `permissions` to also get back just the allowed ids.
       */
      getResourceAccessBatch: createAuthEndpoint(
        '/robrac/access-batch',
        {
          method: 'POST',
          requireHeaders: true,
          use: [sessionMiddleware],
          body: z.object({
            resourceType: z.string(),
            resourceIds: z.array(z.string()).min(1).max(200),
            permissions: permissionRequestSchema.optional(),
            connector: connectorSchema,
          }),
          metadata: { $Infer: { body: {} as AccessBatchBody<TRegistry> } },
        },
        async (ctx) => {
          const caller = await resolveCaller(ctx);
          try {
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
            return toApiError(error);
          }
        }
      ),

      /** `POST /robrac/grants/list` — who has access to this resource. */
      listResourceGrants: createAuthEndpoint(
        '/robrac/grants/list',
        {
          method: 'POST',
          requireHeaders: true,
          use: [sessionMiddleware],
          body: z.object({
            resourceType: z.string(),
            resourceId: z.string(),
          }),
          metadata: { $Infer: { body: {} as ResourceScopedBody<TRegistry> } },
        },
        async (ctx) => {
          const caller = await resolveCaller(ctx);
          try {
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
            return toApiError(error);
          }
        }
      ),

      /** `POST /robrac/grants/grant` — add one role for one subject. */
      grantResourceRole: createAuthEndpoint(
        '/robrac/grants/grant',
        {
          method: 'POST',
          requireHeaders: true,
          use: [sessionMiddleware],
          body: z.object({
            resourceType: z.string(),
            resourceId: z.string(),
            subject: subjectRefSchema,
            role: z.string(),
            expiresAt: z.coerce.date().nullish(),
          }),
          metadata: { $Infer: { body: {} as GrantRoleBody<TRegistry> } },
        },
        async (ctx) => {
          const caller = await resolveCaller(ctx);
          try {
            const grant = await caller.engine.authorized.grant({
              type: asType(ctx.body.resourceType),
              id: ctx.body.resourceId,
              subject: ctx.body.subject,
              role: asRole(ctx.body.role),
              expiresAt: toExpiry(ctx.body.expiresAt),
              actor: caller.subjects,
              grantedBy: caller.subjects.find(
                (subject) => subject.type === MEMBER_SUBJECT
              ),
              scope: caller.scope,
              context: caller.context,
            });
            return ctx.json({ grant });
          } catch (error) {
            return toApiError(error);
          }
        }
      ),

      /** `POST /robrac/grants/set` — replace a subject's roles wholesale. */
      setResourceRoles: createAuthEndpoint(
        '/robrac/grants/set',
        {
          method: 'POST',
          requireHeaders: true,
          use: [sessionMiddleware],
          body: z.object({
            resourceType: z.string(),
            resourceId: z.string(),
            subject: subjectRefSchema,
            roles: z.array(z.string()),
            expiresAt: z.coerce.date().nullish(),
          }),
          metadata: { $Infer: { body: {} as SetRolesBody<TRegistry> } },
        },
        async (ctx) => {
          const caller = await resolveCaller(ctx);
          try {
            const grants = await caller.engine.authorized.setRoles({
              type: asType(ctx.body.resourceType),
              id: ctx.body.resourceId,
              subject: ctx.body.subject,
              roles: ctx.body.roles.map(asRole),
              expiresAt: toExpiry(ctx.body.expiresAt),
              actor: caller.subjects,
              grantedBy: caller.subjects.find(
                (subject) => subject.type === MEMBER_SUBJECT
              ),
              scope: caller.scope,
              context: caller.context,
            });
            return ctx.json({ grants });
          } catch (error) {
            return toApiError(error);
          }
        }
      ),

      /** `POST /robrac/grants/revoke` — drop one role, or all of them. */
      revokeResourceRole: createAuthEndpoint(
        '/robrac/grants/revoke',
        {
          method: 'POST',
          requireHeaders: true,
          use: [sessionMiddleware],
          body: z.object({
            resourceType: z.string(),
            resourceId: z.string(),
            subject: subjectRefSchema,
            role: z.string().optional(),
          }),
          metadata: { $Infer: { body: {} as RevokeRoleBody<TRegistry> } },
        },
        async (ctx) => {
          const caller = await resolveCaller(ctx);
          try {
            const revoked = await caller.engine.authorized.revoke({
              type: asType(ctx.body.resourceType),
              id: ctx.body.resourceId,
              subject: ctx.body.subject,
              role: ctx.body.role ? asRole(ctx.body.role) : undefined,
              actor: caller.subjects,
              scope: caller.scope,
              context: caller.context,
            });
            return ctx.json({ revoked });
          } catch (error) {
            return toApiError(error);
          }
        }
      ),

      /**
       * `POST /robrac/accessible-ids` — the ids the caller holds a grant on.
       *
       * Server-only: this is a query-planning primitive meant to be folded
       * into your own `WHERE` clause, not something a browser should page
       * through.
       */
      listAccessibleResourceIds: createAuthEndpoint(
        '/robrac/accessible-ids',
        {
          method: 'POST',
          requireHeaders: true,
          use: [sessionMiddleware],
          body: z.object({
            resourceType: z.string(),
            permissions: permissionRequestSchema.optional(),
            limit: z.number().int().positive().max(1000).optional(),
            offset: z.number().int().min(0).optional(),
          }),
          metadata: {
            SERVER_ONLY: true,
            $Infer: { body: {} as AccessibleIdsBody<TRegistry> },
          },
        },
        async (ctx) => {
          const caller = await resolveCaller(ctx);
          try {
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
            return toApiError(error);
          }
        }
      ),
    },

    hooks: {
      after: [
        ...(cleanupMemberRemoved
          ? [
              {
                matcher: (context: { path?: string }) =>
                  context.path === '/organization/remove-member' ||
                  context.path === '/organization/leave',
                handler: createAuthMiddleware(async (ctx) => {
                  const member = readMember(ctx.context.returned);
                  if (!member) {
                    return;
                  }
                  await engineFor(ctx.context.adapter).grants.revokeSubject({
                    scope: member.organizationId,
                    subject: { type: MEMBER_SUBJECT, id: member.id },
                  });
                }),
              },
            ]
          : []),
        ...(cleanupOrgDeleted
          ? [
              {
                matcher: (context: { path?: string }) =>
                  context.path === '/organization/delete',
                handler: createAuthMiddleware(async (ctx) => {
                  const organizationId = readOrganizationId(
                    ctx.context.returned
                  );
                  if (!organizationId) {
                    return;
                  }
                  await engineFor(ctx.context.adapter).grants.revokeScope({
                    scope: organizationId,
                  });
                }),
              },
            ]
          : []),
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
     * The decision engine backing this plugin. Available after Better Auth has
     * initialized the plugin; use it from server code that should not pay for
     * an HTTP round trip.
     */
    getEngine(): RobracEngine<TRegistry> {
      if (!engine) {
        throw new RobracError(
          'INVALID_CONFIGURATION',
          'robrac has not been initialized yet. Pass the plugin to betterAuth() before calling getEngine().'
        );
      }
      return engine;
    },
  });
}

function readMember(
  returned: unknown
): { id: string; organizationId: string } | null {
  if (typeof returned !== 'object' || returned === null) {
    return null;
  }
  const candidate = 'member' in returned ? returned.member : returned;
  if (typeof candidate !== 'object' || candidate === null) {
    return null;
  }
  const { id, organizationId } = candidate as Record<string, unknown>;
  return typeof id === 'string' && typeof organizationId === 'string'
    ? { id, organizationId }
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
