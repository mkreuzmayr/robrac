import type { GrantStore } from '../store/types.ts';
import { RobracError } from './errors.ts';
import { assertResourceIsConsistent } from './resource.ts';
import type { ResourceDefinition } from './resource.ts';
import {
  buildPermissionMatrix,
  checkPermissions,
  constantMatrix,
  normalizeRoles,
} from './roles.ts';
import type {
  AccessDecision,
  AppliedRole,
  Grant,
  NormalizedRole,
  PermissionMatrix,
  PermissionRequest,
  ResourceRef,
  RobracContext,
  RoleInput,
  Scope,
  Statements,
  SubjectRef,
} from './types.ts';

/* -------------------------------------------------------------------------- */
/* Registry types                                                             */
/* -------------------------------------------------------------------------- */

/**
 * A heterogeneous map of resource definitions.
 *
 * `any` is load-bearing here rather than sloppy: each entry has a different
 * resource type, statement map and role map, and `unknown` would make the
 * definitions non-assignable and break inference in every callback. The
 * per-type helpers below (`DataOf`, `StatementsOf`, `RoleOf`) recover the
 * precise types wherever they matter, so nothing downstream sees `any`.
 */
export type ResourceRegistry = Record<
  string,
  // oxlint-disable-next-line typescript/no-explicit-any
  ResourceDefinition<any, any, any>
>;

export type ResourceTypeOf<TRegistry extends ResourceRegistry> =
  keyof TRegistry & string;

export type StatementsOf<
  TRegistry extends ResourceRegistry,
  TType extends ResourceTypeOf<TRegistry>,
> =
  TRegistry[TType] extends ResourceDefinition<
    infer _Resource,
    infer TStatements,
    infer _Roles
  >
    ? TStatements
    : never;

export type DataOf<
  TRegistry extends ResourceRegistry,
  TType extends ResourceTypeOf<TRegistry>,
> =
  TRegistry[TType] extends ResourceDefinition<
    infer TResource,
    infer _Statements,
    infer _Roles
  >
    ? TResource
    : never;

export type RoleOf<
  TRegistry extends ResourceRegistry,
  TType extends ResourceTypeOf<TRegistry>,
> =
  TRegistry[TType] extends ResourceDefinition<
    infer _Resource,
    infer _Statements,
    infer TRoles
  >
    ? keyof TRoles & string
    : never;

export type PermissionRequestOf<
  TRegistry extends ResourceRegistry,
  TType extends ResourceTypeOf<TRegistry>,
> = PermissionRequest<StatementsOf<TRegistry, TType>>;

/**
 * A decision for one registered resource type, with both the loaded data and
 * the permission matrix narrowed to what that type declares. This is what
 * makes `decision.permissions.recording.share` a checked `boolean` rather than
 * an index into a bag of strings.
 */
export type DecisionFor<
  TRegistry extends ResourceRegistry,
  TType extends ResourceTypeOf<TRegistry>,
> = AccessDecision<DataOf<TRegistry, TType>, StatementsOf<TRegistry, TType>>;

/* -------------------------------------------------------------------------- */
/* Options                                                                    */
/* -------------------------------------------------------------------------- */

export type DecisionEvent = {
  subjects: readonly SubjectRef[];
  scope: Scope;
  resource: ResourceRef;
  decision: AccessDecision;
  request?: PermissionRequest;
  allowed?: boolean;
};

export type GrantChangeEvent = {
  action: 'grant' | 'revoke';
  scope: Scope;
  resource: ResourceRef;
  subject: SubjectRef;
  roles: readonly string[];
  by: readonly SubjectRef[] | null;
};

export type RobracEngineOptions<TRegistry extends ResourceRegistry> = {
  /** Resource types, keyed by their `type`. */
  resources: TRegistry;

  /** Where grants live. See `store/types.ts` for the contract. */
  store: GrantStore;

  /**
   * Multi-tenancy mode.
   *
   * - `'required'` (default): every resource definition must implement
   *   `scope()`, and a resource whose scope differs from the requested one is
   *   reported as not found. This is the setting that makes cross-tenant
   *   access impossible by construction.
   * - `'optional'`: scope is matched when the definition provides it.
   * - `'disabled'`: single-tenant; scope is always `null`.
   */
  scope?: 'required' | 'optional' | 'disabled';

  /**
   * How far up a `parent()` chain grants cascade. Guards against cycles in
   * application data.
   *
   * @default 5
   */
  maxInheritanceDepth?: number;

  /**
   * Whether a subject may hand out a role that exceeds its own permissions.
   *
   * `'deny'` (default) means an actor can only grant roles whose permissions
   * are a subset of what the actor itself is allowed to do — a share-capable
   * editor cannot mint owners.
   *
   * @default 'deny'
   */
  escalation?: 'deny' | 'allow';

  /** Called for every evaluated decision. Use it to feed an audit log. */
  onDecision?: (event: DecisionEvent) => void;

  /** Called whenever grants change. Use it to feed an audit log. */
  onGrantChange?: (event: GrantChangeEvent) => void;

  /** Clock injection point, for tests and for deterministic replay. */
  now?: () => Date;
};

export type CompiledResource = {
  definition: ResourceDefinition<
    unknown,
    Statements,
    Record<string, RoleInput>
  >;
  roles: Record<string, NormalizedRole>;
};

/**
 * Compiled registries, keyed by the registry object and scope mode.
 *
 * The Better Auth plugin compiles eagerly so that a bad role map fails at boot,
 * then `createRobrac` compiles again when the adapter shows up. Both want the
 * same answer for the same registry, so the second call is a cache hit rather
 * than a second pass over every role.
 */
const compilationCache = new WeakMap<
  ResourceRegistry,
  Map<string, Map<string, CompiledResource>>
>();

/**
 * Validate a registry and pre-resolve its role inheritance.
 *
 * Called eagerly by both `createRobrac` and the Better Auth plugin so that a
 * typo in a role name fails at boot rather than at the first authorization
 * check in production.
 */
export function compileResources(
  resources: ResourceRegistry,
  scopeMode: 'required' | 'optional' | 'disabled'
): Map<string, CompiledResource> {
  const byScopeMode = compilationCache.get(resources);
  const cached = byScopeMode?.get(scopeMode);
  if (cached) {
    return cached;
  }

  const compiled = new Map<string, CompiledResource>();

  const entries = Object.entries(resources) as [
    string,
    CompiledResource['definition'],
  ][];

  for (const [key, definition] of entries) {
    if (definition.type !== key) {
      throw new RobracError(
        'INVALID_CONFIGURATION',
        `Resource registered under key "${key}" declares type "${definition.type}". They must match.`
      );
    }
    if (scopeMode === 'required' && !definition.scope) {
      throw new RobracError(
        'INVALID_CONFIGURATION',
        `Resource "${key}" must implement scope() when robrac runs with scope: 'required'.`
      );
    }

    const roles = normalizeRoles(definition.roles);
    assertResourceIsConsistent(
      definition as never,
      Object.fromEntries(
        Object.entries(roles).map(([name, role]) => [name, role.effective])
      )
    );
    compiled.set(key, {
      definition,
      roles,
    });
  }

  if (byScopeMode) {
    byScopeMode.set(scopeMode, compiled);
  } else {
    compilationCache.set(resources, new Map([[scopeMode, compiled]]));
  }

  return compiled;
}

/* -------------------------------------------------------------------------- */
/* Engine                                                                     */
/* -------------------------------------------------------------------------- */

type CollectedRoles = {
  data: unknown;
  resource: ResourceRef;
  applied: AppliedRole[];
};

export type RobracEngine<TRegistry extends ResourceRegistry> = ReturnType<
  typeof createRobrac<TRegistry>
>;

/** Validate the recursion bound before requests can traverse parent chains. */
export function resolveMaxInheritanceDepth(depth = 5): number {
  if (!Number.isSafeInteger(depth) || depth < 0) {
    throw new RobracError(
      'INVALID_CONFIGURATION',
      'maxInheritanceDepth must be a non-negative safe integer.'
    );
  }
  return depth;
}

/**
 * Build a framework-agnostic authorization engine.
 *
 * This is the whole of robrac's logic. The Better Auth plugin in
 * `plugin/plugin.ts` is a thin transport layer on top of it — background
 * workers, cron jobs, gRPC services or a second HTTP framework can import this
 * directly and get byte-identical decisions.
 */
export function createRobrac<const TRegistry extends ResourceRegistry>(
  options: RobracEngineOptions<TRegistry>
) {
  const scopeMode = options.scope ?? 'required';
  const maxDepth = resolveMaxInheritanceDepth(options.maxInheritanceDepth);
  const escalation = options.escalation ?? 'deny';
  const now = options.now ?? (() => new Date());

  const compiled = compileResources(options.resources, scopeMode);

  function resource(type: string): CompiledResource {
    const entry = compiled.get(type);
    if (!entry) {
      throw new RobracError(
        'UNKNOWN_RESOURCE_TYPE',
        `Unknown resource type: ${type}`
      );
    }
    return entry;
  }

  /**
   * Normalize the scope a caller supplied.
   *
   * Under `'disabled'` every grant lives in the null scope, so whatever the
   * caller passes is collapsed. Under `'required'` a missing scope is a caller
   * bug, not "no access": silently treating it as `null` makes every resource
   * report `found: false` with no diagnostic, which is indistinguishable from a
   * permission problem and takes hours to track down.
   */
  function resolveScope(scope: Scope | undefined): Scope {
    if (scopeMode === 'disabled') {
      return null;
    }
    const value = scope ?? null;
    if (scopeMode === 'required' && value === null) {
      throw new RobracError(
        'SCOPE_REQUIRED',
        "No scope was provided, but robrac is configured with scope: 'required'. " +
          'Check that a tenant is selected — with the Better Auth plugin this usually means the session has no activeOrganizationId.'
      );
    }
    return value;
  }

  /**
   * Scope for bulk deletions, which must never widen.
   *
   * Unlike {@link resolveScope} this never collapses a caller-supplied value to
   * `null`: under `'disabled'` that would silently turn "delete this tenant's
   * grants" into "delete every grant in the database", since all rows are
   * stored with a null scope.
   */
  function bulkScope(scope: Scope | undefined): Scope {
    const value = scope ?? null;
    if (scopeMode === 'required' && value === null) {
      throw new RobracError(
        'SCOPE_REQUIRED',
        "A bulk revoke needs an explicit scope when robrac is configured with scope: 'required'."
      );
    }
    return value;
  }

  async function loadResources(
    entry: CompiledResource,
    ids: readonly string[],
    scope: Scope,
    context: RobracContext
  ): Promise<Map<string, unknown>> {
    const unique = [...new Set(ids)];
    if (unique.length === 0) {
      return new Map();
    }

    const { definition } = entry;

    // `!= null` on purpose: `TResource` is inferred from the loader, so a
    // perfectly idiomatic `({ id }) => map.get(id)` returns `undefined` for a
    // miss. Treating that as "found" hands `undefined` to `scope()` and
    // crashes the request instead of answering `found: false`.
    if (definition.loadMany) {
      const loaded = await definition.loadMany({ ids: unique, scope, context });
      const present = new Map<string, unknown>();
      for (const [id, data] of loaded) {
        if (data != null) {
          present.set(id, data);
        }
      }
      return present;
    }

    const loaded = await Promise.all(
      unique.map(
        async (id) =>
          [id, await definition.load({ id, scope, context })] as const
      )
    );
    return new Map(
      loaded.filter((pair): pair is [string, unknown] => pair[1] != null)
    );
  }

  function inScope(
    entry: CompiledResource,
    data: unknown,
    scope: Scope
  ): boolean {
    if (scopeMode === 'disabled' || !entry.definition.scope) {
      return true;
    }
    return entry.definition.scope(data) === scope;
  }

  /**
   * Gather every role a set of subjects effectively holds on a batch of
   * resources of one type, expressed in that type's own role namespace.
   *
   * Runs one grant query and one resource load per level of the parent chain,
   * regardless of how many resources are being evaluated.
   */
  async function collectRoles(args: {
    type: string;
    ids: readonly string[];
    subjects: readonly SubjectRef[];
    scope: Scope;
    context: RobracContext;
    depth: number;
  }): Promise<Map<string, CollectedRoles>> {
    const entry = resource(args.type);
    const loaded = await loadResources(
      entry,
      args.ids,
      args.scope,
      args.context
    );

    const present = new Map<string, unknown>();
    for (const [id, data] of loaded) {
      if (inScope(entry, data, args.scope)) {
        present.set(id, data);
      }
    }
    if (present.size === 0) {
      return new Map();
    }

    const grants =
      args.subjects.length === 0
        ? []
        : await options.store.findGrants({
            scope: args.scope,
            resourceType: args.type,
            resourceIds: [...present.keys()],
            subjects: args.subjects,
            now: now(),
          });

    const grantsByResource = new Map<string, Grant[]>();
    for (const grant of grants) {
      const bucket = grantsByResource.get(grant.resourceId);
      if (bucket) {
        bucket.push(grant);
      } else {
        grantsByResource.set(grant.resourceId, [grant]);
      }
    }

    const result = new Map<string, CollectedRoles>();

    await Promise.all(
      [...present].map(async ([id, data]) => {
        const ref: ResourceRef = { type: args.type, id };
        const applied: AppliedRole[] = (grantsByResource.get(id) ?? []).map(
          (grant) => ({ role: grant.role, origin: 'explicit' as const })
        );

        // `computeRoles` can push into the typed accumulator, return an
        // array, or do both; the union of the two is what counts.
        const accumulated: string[] = [];
        const returned = await entry.definition.computeRoles?.({
          data,
          resource: ref,
          scope: args.scope,
          subjects: args.subjects,
          context: args.context,
          roles: accumulated,
        });
        for (const role of new Set([...accumulated, ...(returned ?? [])])) {
          applied.push({ role, origin: 'computed' });
        }

        result.set(id, { data, resource: ref, applied });
      })
    );

    if (entry.definition.parent && args.depth < maxDepth) {
      await applyInheritance({ entry, result, ...args });
    }

    return result;
  }

  /** Resolve one level of parents for a batch and fold their roles down. */
  async function applyInheritance(args: {
    entry: CompiledResource;
    result: Map<string, CollectedRoles>;
    subjects: readonly SubjectRef[];
    scope: Scope;
    context: RobracContext;
    depth: number;
  }): Promise<void> {
    const { entry, result } = args;
    const parentOf = new Map<string, ResourceRef>();

    await Promise.all(
      [...result].map(async ([id, collected]) => {
        const parent = await entry.definition.parent?.({
          data: collected.data,
          resource: collected.resource,
          scope: args.scope,
          context: args.context,
        });
        if (parent) {
          parentOf.set(id, parent);
        }
      })
    );

    if (parentOf.size === 0) {
      return;
    }

    const idsByType = new Map<string, Set<string>>();
    for (const parent of parentOf.values()) {
      const bucket = idsByType.get(parent.type);
      if (bucket) {
        bucket.add(parent.id);
      } else {
        idsByType.set(parent.type, new Set([parent.id]));
      }
    }

    const parentRoles = new Map<string, Map<string, CollectedRoles>>();
    await Promise.all(
      [...idsByType].map(async ([parentType, ids]) => {
        parentRoles.set(
          parentType,
          await collectRoles({
            type: parentType,
            ids: [...ids],
            subjects: args.subjects,
            scope: args.scope,
            context: args.context,
            depth: args.depth + 1,
          })
        );
      })
    );

    for (const [id, parent] of parentOf) {
      const collected = result.get(id);
      const inherited = parentRoles.get(parent.type)?.get(parent.id);
      if (!collected || !inherited) {
        continue;
      }

      const seen = new Set<string>();
      for (const applied of inherited.applied) {
        if (seen.has(applied.role)) {
          continue;
        }
        seen.add(applied.role);

        const mapped = entry.definition.inheritRole
          ? entry.definition.inheritRole({ parent, role: applied.role })
          : // Default: carry the role over when the child declares a role of
            // the same name. Anything else is dropped rather than guessed.
            entry.roles[applied.role]
            ? applied.role
            : null;

        if (mapped) {
          collected.applied.push({
            role: mapped,
            origin: 'inherited',
            via: parent,
          });
        }
      }
    }
  }

  function decide(
    entry: CompiledResource,
    scope: Scope,
    ref: ResourceRef,
    collected: CollectedRoles | undefined,
    override: 'allow' | 'deny' | null
  ): AccessDecision {
    if (!collected) {
      return {
        found: false,
        scope,
        resource: ref,
        data: null,
        roles: [],
        effectiveRoles: [],
        permissions: constantMatrix(entry.definition.statements, false),
        override: null,
      };
    }

    const effectiveRoles = [
      ...new Set(collected.applied.map((applied) => applied.role)),
    ];

    let permissions: PermissionMatrix;
    if (override === 'deny') {
      permissions = constantMatrix(entry.definition.statements, false);
    } else if (override === 'allow') {
      permissions = constantMatrix(entry.definition.statements, true);
    } else {
      permissions = buildPermissionMatrix(
        entry.definition.statements,
        entry.roles,
        effectiveRoles
      );
    }

    return {
      found: true,
      scope,
      resource: ref,
      data: collected.data,
      roles: collected.applied,
      effectiveRoles,
      permissions,
      override,
    };
  }

  /**
   * The single evaluation path.
   *
   * `emit` exists so that `check`, `require` and `filterAccessible` can report
   * one audit event carrying the actual verdict, instead of a bare decision
   * event from here followed by a second one with `allowed` filled in. An audit
   * consumer should see exactly one event per authorization question.
   */
  async function evaluateManyInternal<
    TType extends ResourceTypeOf<TRegistry>,
  >(args: {
    type: TType;
    ids: readonly string[];
    subjects: readonly SubjectRef[];
    scope?: Scope;
    context?: RobracContext;
    emit: boolean;
  }): Promise<Map<string, DecisionFor<TRegistry, TType>>> {
    const entry = resource(args.type);
    const scope = resolveScope(args.scope);
    const context = args.context ?? {};

    const collected = await collectRoles({
      type: args.type,
      ids: args.ids,
      subjects: args.subjects,
      scope,
      context,
      depth: 0,
    });

    const decisions = new Map<string, DecisionFor<TRegistry, TType>>();

    await Promise.all(
      [...new Set(args.ids)].map(async (id) => {
        const ref: ResourceRef = { type: args.type, id };
        const found = collected.get(id);

        const override = found
          ? ((await entry.definition.override?.({
              data: found.data,
              resource: ref,
              scope,
              subjects: args.subjects,
              context,
            })) ?? null)
          : null;

        const decision = decide(
          entry,
          scope,
          ref,
          found,
          override
        ) as DecisionFor<TRegistry, TType>;
        decisions.set(id, decision);
        if (args.emit) {
          options.onDecision?.({
            subjects: args.subjects,
            scope,
            resource: ref,
            decision,
          });
        }
      })
    );

    return decisions;
  }

  function evaluateMany<TType extends ResourceTypeOf<TRegistry>>(args: {
    type: TType;
    ids: readonly string[];
    subjects: readonly SubjectRef[];
    scope?: Scope;
    context?: RobracContext;
  }): Promise<Map<string, DecisionFor<TRegistry, TType>>> {
    return evaluateManyInternal({ ...args, emit: true });
  }

  async function evaluateInternal<
    TType extends ResourceTypeOf<TRegistry>,
  >(args: {
    type: TType;
    id: string;
    subjects: readonly SubjectRef[];
    scope?: Scope;
    context?: RobracContext;
    emit: boolean;
  }): Promise<DecisionFor<TRegistry, TType>> {
    const decisions = await evaluateManyInternal({
      type: args.type,
      ids: [args.id],
      subjects: args.subjects,
      scope: args.scope,
      context: args.context,
      emit: args.emit,
    });

    const decision = decisions.get(args.id);
    if (decision) {
      return decision;
    }

    // `evaluateManyInternal` always materializes a decision per requested id;
    // this is unreachable defensive code that keeps the return non-nullable.
    return decide(
      resource(args.type),
      resolveScope(args.scope),
      { type: args.type, id: args.id },
      undefined,
      null
    ) as DecisionFor<TRegistry, TType>;
  }

  function evaluate<TType extends ResourceTypeOf<TRegistry>>(args: {
    type: TType;
    id: string;
    subjects: readonly SubjectRef[];
    scope?: Scope;
    context?: RobracContext;
  }): Promise<DecisionFor<TRegistry, TType>> {
    return evaluateInternal({ ...args, emit: true });
  }

  /** Report one audit event carrying the verdict for a permission request. */
  function emitVerdict(
    subjects: readonly SubjectRef[],
    decision: AccessDecision,
    request: PermissionRequest | undefined,
    allowed: boolean
  ): void {
    options.onDecision?.({
      subjects,
      scope: decision.scope,
      resource: decision.resource,
      decision,
      request,
      allowed,
    });
  }

  async function check<TType extends ResourceTypeOf<TRegistry>>(args: {
    type: TType;
    id: string;
    permissions: PermissionRequestOf<TRegistry, TType>;
    subjects: readonly SubjectRef[];
    scope?: Scope;
    context?: RobracContext;
    /** How several facets in one request combine. Defaults to `AND`. */
    connector?: 'AND' | 'OR';
  }): Promise<boolean> {
    const decision = await evaluateInternal({ ...args, emit: false });
    const allowed =
      decision.found &&
      checkPermissions(decision.permissions, args.permissions, args.connector);

    emitVerdict(args.subjects, decision, args.permissions, allowed);
    return allowed;
  }

  /** `check`, but throws `RobracError('FORBIDDEN')` instead of returning false. */
  async function require<TType extends ResourceTypeOf<TRegistry>>(args: {
    type: TType;
    id: string;
    permissions: PermissionRequestOf<TRegistry, TType>;
    subjects: readonly SubjectRef[];
    scope?: Scope;
    context?: RobracContext;
    connector?: 'AND' | 'OR';
  }): Promise<DecisionFor<TRegistry, TType>> {
    const decision = await evaluateInternal({ ...args, emit: false });
    const allowed =
      decision.found &&
      checkPermissions(decision.permissions, args.permissions, args.connector);

    emitVerdict(args.subjects, decision, args.permissions, allowed);

    if (!allowed) {
      throw new RobracError(
        'FORBIDDEN',
        `Not allowed to perform this action on ${args.type}:${args.id}.`
      );
    }
    return decision;
  }

  /**
   * Keep only the ids the subjects may act on.
   *
   * Use this to post-filter a page you already loaded. To *pre*-filter at the
   * database level, combine `accessibleResourceIds` with whatever condition
   * expresses your computed roles — see the README's "Listing" section.
   */
  async function filterAccessible<
    TType extends ResourceTypeOf<TRegistry>,
  >(args: {
    type: TType;
    ids: readonly string[];
    permissions: PermissionRequestOf<TRegistry, TType>;
    subjects: readonly SubjectRef[];
    scope?: Scope;
    context?: RobracContext;
    connector?: 'AND' | 'OR';
  }): Promise<string[]> {
    const decisions = await evaluateManyInternal({ ...args, emit: false });
    return args.ids.filter((id) => {
      const decision = decisions.get(id);
      if (!decision) {
        return false;
      }
      const allowed =
        decision.found &&
        checkPermissions(
          decision.permissions,
          args.permissions,
          args.connector
        );
      emitVerdict(args.subjects, decision, args.permissions, allowed);
      return allowed;
    });
  }

  /**
   * Ids the subjects hold an explicit grant on.
   *
   * This is the building block for permission-aware SQL: `WHERE created_by = ?
   * OR visibility = 'organization' OR id IN (<these ids>)`. It deliberately
   * does *not* include computed roles — those live in your data model, so only
   * your query can express them efficiently.
   *
   * `limit`/`offset` page over *grant rows*, not over distinct resources: a
   * subject holding three roles on one resource consumes three of the limit.
   * They exist to bound a pathological result set, not to paginate a UI.
   */
  async function accessibleResourceIds<
    TType extends ResourceTypeOf<TRegistry>,
  >(args: {
    type: TType;
    subjects: readonly SubjectRef[];
    scope?: Scope;
    /** Keep only ids where the grant actually confers these permissions. */
    permissions?: PermissionRequestOf<TRegistry, TType>;
    limit?: number;
    offset?: number;
  }): Promise<string[]> {
    const entry = resource(args.type);
    const scope = resolveScope(args.scope);

    const grants = await options.store.listSubjectGrants({
      scope,
      subjects: args.subjects,
      resourceType: args.type,
      now: now(),
      limit: args.limit,
      offset: args.offset,
    });

    if (!args.permissions) {
      return [...new Set(grants.map((grant) => grant.resourceId))];
    }

    const rolesByResource = new Map<string, string[]>();
    for (const grant of grants) {
      const bucket = rolesByResource.get(grant.resourceId);
      if (bucket) {
        bucket.push(grant.role);
      } else {
        rolesByResource.set(grant.resourceId, [grant.role]);
      }
    }

    return [...rolesByResource]
      .filter(([, roles]) =>
        checkPermissions(
          buildPermissionMatrix(
            entry.definition.statements,
            entry.roles,
            roles
          ),
          args.permissions as PermissionRequest
        )
      )
      .map(([id]) => id);
  }

  /* ---------------------------------------------------------------------- */
  /* Grant management                                                        */
  /* ---------------------------------------------------------------------- */

  function assertKnownRole(entry: CompiledResource, role: string): void {
    if (!entry.roles[role]) {
      throw new RobracError(
        'UNKNOWN_ROLE',
        `Unknown role "${role}" for resource type "${entry.definition.type}".`
      );
    }
  }

  /**
   * Unchecked grant primitives.
   *
   * These perform no authorization of their own — they are the trusted
   * server-side path for seeds, migrations, admin tooling and back-office
   * jobs. Anything reachable from a user request should go through
   * {@link authorized} instead.
   */
  const grants = {
    list<TType extends ResourceTypeOf<TRegistry>>(args: {
      type: TType;
      id: string;
      scope?: Scope;
      includeExpired?: boolean;
    }): Promise<Grant[]> {
      return options.store.listResourceGrants({
        scope: resolveScope(args.scope),
        resource: { type: args.type, id: args.id },
        now: now(),
        includeExpired: args.includeExpired,
      });
    },

    async grant<TType extends ResourceTypeOf<TRegistry>>(args: {
      type: TType;
      id: string;
      subject: SubjectRef;
      role: RoleOf<TRegistry, TType>;
      scope?: Scope;
      grantedBy?: SubjectRef | null;
      expiresAt?: Date | null;
    }): Promise<Grant> {
      const entry = resource(args.type);
      assertKnownRole(entry, args.role);

      const scope = resolveScope(args.scope);
      const ref: ResourceRef = { type: args.type, id: args.id };
      const grant = await options.store.upsertGrant({
        scope,
        resource: ref,
        subject: args.subject,
        role: args.role,
        grantedBy: args.grantedBy ?? null,
        expiresAt: args.expiresAt ?? null,
      });

      options.onGrantChange?.({
        action: 'grant',
        scope,
        resource: ref,
        subject: args.subject,
        roles: [args.role],
        by: args.grantedBy ? [args.grantedBy] : null,
      });

      return grant;
    },

    async revoke<TType extends ResourceTypeOf<TRegistry>>(args: {
      type: TType;
      id: string;
      subject: SubjectRef;
      /** Omit to revoke every role the subject holds on this resource. */
      role?: RoleOf<TRegistry, TType>;
      scope?: Scope;
    }): Promise<number> {
      const scope = resolveScope(args.scope);
      const ref: ResourceRef = { type: args.type, id: args.id };

      if (args.role) {
        const deleted = await options.store.deleteGrant({
          scope,
          resource: ref,
          subject: args.subject,
          role: args.role,
        });
        if (deleted > 0) {
          options.onGrantChange?.({
            action: 'revoke',
            scope,
            resource: ref,
            subject: args.subject,
            roles: [args.role],
            by: null,
          });
        }
        return deleted;
      }

      // Read before deleting so the audit event can name the roles that were
      // removed. "Revoked something" is not a useful audit record.
      const held = (
        await options.store.listResourceGrants({
          scope,
          resource: ref,
          now: now(),
          includeExpired: true,
        })
      ).filter(
        (grant) =>
          grant.subjectType === args.subject.type &&
          grant.subjectId === args.subject.id
      );

      const deleted = await options.store.deleteSubjectGrantsOnResource({
        scope,
        resource: ref,
        subject: args.subject,
      });

      if (deleted > 0) {
        options.onGrantChange?.({
          action: 'revoke',
          scope,
          resource: ref,
          subject: args.subject,
          roles: held.map((grant) => grant.role),
          by: null,
        });
      }

      return deleted;
    },

    /** Replace the subject's roles on a resource with exactly `roles`. */
    async set<TType extends ResourceTypeOf<TRegistry>>(args: {
      type: TType;
      id: string;
      subject: SubjectRef;
      roles: readonly RoleOf<TRegistry, TType>[];
      scope?: Scope;
      grantedBy?: SubjectRef | null;
      expiresAt?: Date | null;
    }): Promise<Grant[]> {
      const entry = resource(args.type);
      for (const role of args.roles) {
        assertKnownRole(entry, role);
      }

      const scope = resolveScope(args.scope);
      const ref: ResourceRef = { type: args.type, id: args.id };
      const wanted = new Set<string>(args.roles);

      // `set` is a replace, so a failure between the deletes and the upserts
      // would leave the subject with no roles at all — a silent revocation from
      // an operation that promised a swap. Run it in a transaction where the
      // store offers one.
      const run = async (store: GrantStore) => {
        const existing = await store.listResourceGrants({
          scope,
          resource: ref,
          now: now(),
          includeExpired: true,
        });

        const removed = existing
          .filter(
            (grant) =>
              grant.subjectType === args.subject.type &&
              grant.subjectId === args.subject.id &&
              !wanted.has(grant.role)
          )
          .map((grant) => grant.role);

        await Promise.all(
          removed.map((role) =>
            store.deleteGrant({
              scope,
              resource: ref,
              subject: args.subject,
              role,
            })
          )
        );

        const added = await Promise.all(
          [...wanted].map((role) =>
            store.upsertGrant({
              scope,
              resource: ref,
              subject: args.subject,
              role,
              grantedBy: args.grantedBy ?? null,
              expiresAt: args.expiresAt ?? null,
            })
          )
        );

        return { removed, added };
      };

      const { removed, added } = options.store.transaction
        ? await options.store.transaction(run)
        : await run(options.store);

      // Two events, because a downgrade is a revocation. Reporting only the
      // resulting role set would hide "owner was taken away" from the audit log.
      if (removed.length > 0) {
        options.onGrantChange?.({
          action: 'revoke',
          scope,
          resource: ref,
          subject: args.subject,
          roles: removed,
          by: args.grantedBy ? [args.grantedBy] : null,
        });
      }
      if (args.roles.length > 0) {
        options.onGrantChange?.({
          action: 'grant',
          scope,
          resource: ref,
          subject: args.subject,
          roles: args.roles,
          by: args.grantedBy ? [args.grantedBy] : null,
        });
      }

      return added;
    },

    /** Drop every grant on a resource. Call this when the resource is deleted. */
    revokeResource<TType extends ResourceTypeOf<TRegistry>>(args: {
      type: TType;
      id: string;
      scope?: Scope;
    }): Promise<number> {
      return options.store.deleteResourceGrants({
        scope: resolveScope(args.scope),
        resource: { type: args.type, id: args.id },
      });
    },

    /**
     * Drop every grant a subject holds in a scope. Call this when a member
     * leaves an organization or a team is dissolved.
     *
     * Uses the scope exactly as given — see {@link bulkScope}.
     */
    revokeSubject(args: {
      subject: SubjectRef;
      scope?: Scope;
    }): Promise<number> {
      return options.store.deleteSubjectGrants({
        scope: bulkScope(args.scope),
        subject: args.subject,
      });
    },

    /**
     * Drop every grant in a scope. Call this when a tenant is deleted.
     *
     * Uses the scope exactly as given — see {@link bulkScope}.
     */
    revokeScope(args: { scope: Scope }): Promise<number> {
      return options.store.deleteScopeGrants({
        scope: bulkScope(args.scope),
      });
    },
  };

  /* ---------------------------------------------------------------------- */
  /* Authorized grant management                                             */
  /* ---------------------------------------------------------------------- */

  async function assertCanManage(args: {
    type: string;
    id: string;
    actor: readonly SubjectRef[];
    scope: Scope;
    context: RobracContext;
  }): Promise<AccessDecision> {
    const entry = resource(args.type);
    const decision = await evaluateInternal({
      type: args.type,
      id: args.id,
      subjects: args.actor,
      scope: args.scope,
      context: args.context,
      emit: false,
    });

    if (!decision.found) {
      throw new RobracError(
        'RESOURCE_NOT_FOUND',
        `Resource ${args.type}:${args.id} not found.`
      );
    }

    const manage = entry.definition.manage;
    const allowed =
      typeof manage === 'function'
        ? await manage({
            data: decision.data,
            resource: decision.resource,
            scope: decision.scope,
            subjects: args.actor,
            context: args.context,
            permissions: decision.permissions,
          })
        : checkPermissions(decision.permissions, manage);

    // A refused grant-management attempt is exactly the kind of event an audit
    // log is for, so it goes through the same reporting path as `check`.
    emitVerdict(
      args.actor,
      decision,
      typeof manage === 'function' ? undefined : manage,
      allowed
    );

    if (!allowed) {
      throw new RobracError(
        'FORBIDDEN',
        `Not allowed to manage access for ${args.type}:${args.id}.`
      );
    }

    return decision;
  }

  /**
   * The permission a role confers that its would-be granter lacks, or `null`
   * when the role is entirely within the actor's own rights.
   *
   * Without this an "editor who may share" could mint owners and escalate
   * laterally through any resource they can see.
   */
  function escalationGap(
    entry: CompiledResource,
    actorDecision: AccessDecision,
    roleName: string
  ): string | null {
    if (escalation === 'allow' || actorDecision.override === 'allow') {
      return null;
    }

    const role = entry.roles[roleName];
    if (!role) {
      return null;
    }

    const actorPermissions = actorDecision.permissions as Record<
      string,
      Record<string, boolean>
    >;

    for (const [facet, actions] of Object.entries(role.effective)) {
      for (const action of actions) {
        const declared = entry.definition.statements[facet] ?? [];
        const concrete = action === '*' ? declared : [action];
        for (const candidate of concrete) {
          if (actorPermissions[facet]?.[candidate] !== true) {
            return `${facet}.${candidate}`;
          }
        }
      }
    }

    return null;
  }

  function assertNoEscalation(
    entry: CompiledResource,
    actorDecision: AccessDecision,
    roles: readonly string[]
  ): void {
    for (const roleName of roles) {
      const gap = escalationGap(entry, actorDecision, roleName);
      if (gap) {
        throw new RobracError(
          'FORBIDDEN',
          `Cannot grant role "${roleName}": it includes "${gap}", which you are not allowed to do.`
        );
      }
    }
  }

  /**
   * Grant management on behalf of a caller.
   *
   * Every method here enforces the resource's `manage` permission and, unless
   * `escalation: 'allow'`, refuses to grant more than the caller holds.
   */
  const authorized = {
    async listGrants<TType extends ResourceTypeOf<TRegistry>>(args: {
      type: TType;
      id: string;
      actor: readonly SubjectRef[];
      scope?: Scope;
      context?: RobracContext;
    }): Promise<{
      grants: Grant[];
      /** Roles this actor may actually hand out. Render these as choices. */
      availableRoles: string[];
      /** Every role the resource type declares, grantable or not. */
      declaredRoles: string[];
    }> {
      const scope = resolveScope(args.scope);
      const decision = await assertCanManage({
        type: args.type,
        id: args.id,
        actor: args.actor,
        scope,
        context: args.context ?? {},
      });

      const entry = resource(args.type);
      const declaredRoles = Object.keys(entry.roles);

      return {
        grants: await grants.list({ type: args.type, id: args.id, scope }),
        // Filtered by the same anti-escalation rule `grant` enforces, so a
        // share dialog cannot offer a role that will be rejected on submit.
        availableRoles: declaredRoles.filter(
          (role) => escalationGap(entry, decision, role) === null
        ),
        declaredRoles,
      };
    },

    async grant<TType extends ResourceTypeOf<TRegistry>>(args: {
      type: TType;
      id: string;
      subject: SubjectRef;
      role: RoleOf<TRegistry, TType>;
      actor: readonly SubjectRef[];
      /** Subject recorded as the granter. Defaults to the first actor. */
      grantedBy?: SubjectRef;
      scope?: Scope;
      expiresAt?: Date | null;
      context?: RobracContext;
    }): Promise<Grant> {
      const entry = resource(args.type);
      assertKnownRole(entry, args.role);

      const scope = resolveScope(args.scope);
      const decision = await assertCanManage({
        type: args.type,
        id: args.id,
        actor: args.actor,
        scope,
        context: args.context ?? {},
      });
      assertNoEscalation(entry, decision, [args.role]);

      return await grants.grant({
        ...args,
        scope,
        grantedBy: args.grantedBy ?? args.actor[0] ?? null,
      });
    },

    async setRoles<TType extends ResourceTypeOf<TRegistry>>(args: {
      type: TType;
      id: string;
      subject: SubjectRef;
      roles: readonly RoleOf<TRegistry, TType>[];
      actor: readonly SubjectRef[];
      grantedBy?: SubjectRef;
      scope?: Scope;
      expiresAt?: Date | null;
      context?: RobracContext;
    }): Promise<Grant[]> {
      const entry = resource(args.type);
      for (const role of args.roles) {
        assertKnownRole(entry, role);
      }

      const scope = resolveScope(args.scope);
      const decision = await assertCanManage({
        type: args.type,
        id: args.id,
        actor: args.actor,
        scope,
        context: args.context ?? {},
      });
      assertNoEscalation(entry, decision, args.roles);

      return await grants.set({
        ...args,
        scope,
        grantedBy: args.grantedBy ?? args.actor[0] ?? null,
      });
    },

    async revoke<TType extends ResourceTypeOf<TRegistry>>(args: {
      type: TType;
      id: string;
      subject: SubjectRef;
      role?: RoleOf<TRegistry, TType>;
      actor: readonly SubjectRef[];
      scope?: Scope;
      context?: RobracContext;
    }): Promise<number> {
      const scope = resolveScope(args.scope);
      await assertCanManage({
        type: args.type,
        id: args.id,
        actor: args.actor,
        scope,
        context: args.context ?? {},
      });

      return await grants.revoke({ ...args, scope });
    },
  };

  return {
    evaluate,
    evaluateMany,
    check,
    require,
    filterAccessible,
    accessibleResourceIds,
    grants,
    authorized,
    /** Role names declared for a resource type. */
    rolesOf(type: ResourceTypeOf<TRegistry>): string[] {
      return Object.keys(resource(type).roles);
    },
    /** Statements declared for a resource type. */
    statementsOf(type: ResourceTypeOf<TRegistry>): Statements {
      return resource(type).definition.statements;
    },
    /** The registry this engine was built from. Useful for `$Infer` plumbing. */
    resources: options.resources,
  };
}
