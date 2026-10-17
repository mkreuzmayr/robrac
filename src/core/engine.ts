import type { GrantStore } from '../store/types.ts';
import { RobracArgumentError, RobracError } from './errors.ts';
import { assertResourceIsConsistent } from './resource.ts';
import type { ResourceDefinition } from './resource.ts';
import {
  ALL_ACTIONS,
  buildPermissionMatrix,
  checkPermissions,
  constantMatrix,
  grantedActions,
  normalizeRoles,
  own,
} from './roles.ts';
import type {
  AccessDecision,
  AppliedRole,
  Grant,
  NormalizedRole,
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
 * `any` is load-bearing: each entry has a different resource, statement and
 * role type, and `unknown` would make the definitions non-assignable. The
 * helpers below recover the precise types wherever they matter.
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

/** A decision with the loaded data and permission matrix narrowed to one type. */
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
   *   reported as not found.
   * - `'optional'`: scope is matched when the definition provides it.
   * - `'disabled'`: single-tenant; scope is always `null`.
   */
  scope?: 'required' | 'optional' | 'disabled';

  /**
   * How many `parent()` levels grants and `'deny'` overrides cascade through.
   * An integer from 0 to 64.
   *
   * @default 5
   */
  maxInheritanceDepth?: number;

  /**
   * `'deny'` (default) means an actor can only grant, revoke or extend roles
   * that stay within its own permissions, including what those roles cascade
   * to on descendants and how long the actor's own access lasts.
   *
   * @default 'deny'
   */
  escalation?: 'deny' | 'allow';

  /** Called for every evaluated decision. Use it to feed an audit log. */
  onDecision?: (event: DecisionEvent) => void;

  /**
   * Called whenever grants change, and awaited when it returns a promise.
   * Runs inside the store transaction when the store has one, so a throwing
   * hook rolls the change back. Keep it fast, and don't write through a
   * second connection that waits on that transaction: on a single-connection
   * database such as SQLite that deadlocks.
   */
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

const MAX_INHERITANCE_DEPTH = 64;

/** Validate `maxInheritanceDepth`, which bounds the loads per evaluation. */
export function inheritanceDepth(value: number | undefined): number {
  const depth = value ?? 5;
  if (
    !Number.isSafeInteger(depth) ||
    depth < 0 ||
    depth > MAX_INHERITANCE_DEPTH
  ) {
    throw new RobracError(
      'INVALID_CONFIGURATION',
      `maxInheritanceDepth must be an integer from 0 to ${MAX_INHERITANCE_DEPTH}.`
    );
  }
  return depth;
}

function assertDefinitionShape(key: string, definition: unknown): void {
  const fail = (reason: string) => {
    throw new RobracError(
      'INVALID_CONFIGURATION',
      `Resource "${key}" ${reason}.`
    );
  };
  if (typeof definition !== 'object' || definition === null) {
    fail('must be a resource definition');
  }
  const { type, statements, roles, load } = definition as Record<
    string,
    unknown
  >;
  if (type !== key) {
    fail(`declares type "${String(type)}"; it must match its registry key`);
  }
  if (typeof load !== 'function') {
    fail('must implement load()');
  }
  if (typeof roles !== 'object' || roles === null) {
    fail('must declare roles');
  }
  if (typeof statements !== 'object' || statements === null) {
    fail('must declare statements');
  }
  for (const [facet, actions] of Object.entries(statements as object)) {
    if (
      !Array.isArray(actions) ||
      actions.some(
        (action) => typeof action !== 'string' || action === ALL_ACTIONS
      )
    ) {
      fail(`declares facet "${facet}" with invalid actions`);
    }
  }
}

const compilationCache = new WeakMap<
  ResourceRegistry,
  Map<string, Map<string, CompiledResource>>
>();

/**
 * Validate a registry and pre-resolve its role inheritance, so a typo in a
 * role name fails at boot rather than at the first authorization check.
 */
export function compileResources(
  resources: ResourceRegistry,
  scopeMode: 'required' | 'optional' | 'disabled'
): Map<string, CompiledResource> {
  const byScopeMode =
    compilationCache.get(resources) ??
    new Map<string, Map<string, CompiledResource>>();
  const cached = byScopeMode.get(scopeMode);
  if (cached) {
    return cached;
  }

  const compiled = new Map<string, CompiledResource>();
  for (const [key, value] of Object.entries(resources)) {
    assertDefinitionShape(key, value);
    const definition = value as CompiledResource['definition'];
    if (scopeMode === 'required' && typeof definition.scope !== 'function') {
      throw new RobracError(
        'INVALID_CONFIGURATION',
        `Resource "${key}" must implement scope() when robrac runs with scope: 'required'.`
      );
    }
    const parentTypes: unknown = definition.parentTypes;
    if (parentTypes !== undefined && !Array.isArray(parentTypes)) {
      throw new RobracError(
        'INVALID_CONFIGURATION',
        `Resource "${key}" must list parentTypes as an array.`
      );
    }
    for (const parentType of definition.parentTypes ?? []) {
      if (!Object.hasOwn(resources, parentType)) {
        throw new RobracError(
          'INVALID_CONFIGURATION',
          `Resource "${key}" lists unknown parent type "${parentType}".`
        );
      }
    }
    const roles = normalizeRoles(definition.roles);
    assertResourceIsConsistent(
      definition as never,
      Object.fromEntries(
        Object.entries(roles).map(([name, role]) => [name, role.effective])
      )
    );
    compiled.set(key, { definition, roles });
  }

  byScopeMode.set(scopeMode, compiled);
  compilationCache.set(resources, byScopeMode);
  return compiled;
}

/* -------------------------------------------------------------------------- */
/* Engine                                                                     */
/* -------------------------------------------------------------------------- */

type Held = Map<string, Hold[]>;

/**
 * One source of a role: when it expires (epoch ms, `Infinity` = never) and how
 * many levels below this resource it still cascades.
 */
type Hold = { expiry: number; reach: number };

type Override = 'allow' | 'deny' | null;

type Node = {
  entry: CompiledResource;
  ref: ResourceRef;
  data: unknown;
  override: Override;
  applied: AppliedRole[];
  held: Held;
  parent: ResourceRef | null;
};

type Resolved = {
  node: Node;
  applied: AppliedRole[];
  held: Held;
  override: Override;
};

type Evaluation = {
  decision: AccessDecision;
  held: Held;
};

function refKey(ref: ResourceRef): string {
  return JSON.stringify([ref.type, ref.id]);
}

function readOverride(value: unknown): Override {
  return value === 'allow' || value === 'deny' ? value : null;
}

function readParent(value: unknown): ResourceRef | null {
  if (value === null || value === undefined) {
    return null;
  }
  const { type, id } = value as Partial<ResourceRef>;
  if (typeof type !== 'string' || typeof id !== 'string') {
    throw new RobracError(
      'INVALID_CONFIGURATION',
      'parent() must return { type, id } or null.'
    );
  }
  return { type, id };
}

// An invalid date fails closed: `NaN > now` is false.
function isLive(grant: Grant, at: Date): boolean {
  return grant.expiresAt === null || grant.expiresAt.getTime() > at.getTime();
}

function isSubject(grant: Grant, subject: SubjectRef): boolean {
  return grant.subjectType === subject.type && grant.subjectId === subject.id;
}

function hold(held: Held, role: string, source: Hold): void {
  const holds = held.get(role) ?? [];
  holds.push(source);
  held.set(role, holds);
}

/** Role -> furthest reach among its holds that are still live after `time`. */
function reachAfter(held: Held, time = -Infinity): Map<string, number> {
  const reaches = new Map<string, number>();
  for (const [role, holds] of held) {
    for (const { expiry, reach } of holds) {
      if (expiry > time) {
        reaches.set(role, Math.max(reaches.get(role) ?? -1, reach));
      }
    }
  }
  return reaches;
}

function unique<T>(values: Iterable<T>): T[] {
  return [...new Set(values)];
}

export type RobracEngine<TRegistry extends ResourceRegistry> = ReturnType<
  typeof createRobrac<TRegistry>
>;

type BeforeWrite = () => Promise<void>;

type AuthorizedWrite = {
  type: string;
  id: string;
  subject: SubjectRef;
  actor: readonly SubjectRef[];
  grantedBy?: SubjectRef;
  scope?: Scope;
  expiresAt?: Date | null;
  context?: RobracContext;
};

type CheckedWrites = {
  grant(
    args: AuthorizedWrite & { role: string },
    beforeWrite: BeforeWrite
  ): Promise<Grant>;
  setRoles(
    args: AuthorizedWrite & { roles: readonly string[] },
    beforeWrite: BeforeWrite
  ): Promise<Grant[]>;
};

const checkedWrites = new WeakMap<object, CheckedWrites>();

/**
 * `authorized.grant` and `setRoles` running `beforeWrite` once the caller is
 * authorized and before anything is written. For the plugin, which validates
 * the subject only for callers allowed to manage the resource.
 */
export function withBeforeWrite(engine: object): CheckedWrites {
  const writes = checkedWrites.get(engine);
  if (!writes) {
    throw new TypeError('Not a robrac engine.');
  }
  return writes;
}

/**
 * Build a framework-agnostic authorization engine.
 *
 * The Better Auth plugin is a thin transport on top of this. Background
 * workers, cron jobs or another HTTP framework can import it directly and get
 * identical decisions.
 */
export function createRobrac<const TRegistry extends ResourceRegistry>(
  options: RobracEngineOptions<TRegistry>
) {
  const scopeMode = options.scope ?? 'required';
  const maxDepth = inheritanceDepth(options.maxInheritanceDepth);
  const escalation = options.escalation ?? 'deny';
  const now = options.now ?? (() => new Date());
  const store = options.store;

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

  // A missing scope under 'required' is a caller bug. Collapsing it to `null`
  // would make every resource read as not found, which looks like a
  // permission problem and hides the real cause.
  function resolveScope(scope: Scope | undefined): Scope {
    if (scopeMode === 'disabled') {
      return null;
    }
    const value = scope ?? null;
    if (scopeMode === 'required' && value === null) {
      throw new RobracError(
        'SCOPE_REQUIRED',
        "No scope was provided, but robrac is configured with scope: 'required'. " +
          'With the Better Auth plugin this usually means the session has no activeOrganizationId.'
      );
    }
    return value;
  }

  // Bulk deletions never collapse a given scope to `null`: under 'disabled'
  // that would turn "delete this tenant's grants" into "delete every grant".
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

  function roleOf(entry: CompiledResource, role: string) {
    return own(entry.roles, role);
  }

  function inScope(entry: CompiledResource, data: unknown, scope: Scope) {
    if (scopeMode === 'disabled' || !entry.definition.scope) {
      return true;
    }
    return entry.definition.scope(data) === scope;
  }

  function mapInherited(
    entry: CompiledResource,
    parent: ResourceRef,
    role: string
  ): string | null {
    const mapped = entry.definition.inheritRole
      ? entry.definition.inheritRole({ parent, role })
      : role;
    return typeof mapped === 'string' && roleOf(entry, mapped) ? mapped : null;
  }

  /* ---------------------------------------------------------------------- */
  /* Evaluation                                                              */
  /* ---------------------------------------------------------------------- */

  async function loadData(
    entry: CompiledResource,
    ids: readonly string[],
    scope: Scope,
    context: RobracContext
  ): Promise<Map<string, unknown>> {
    const { definition } = entry;
    const present = new Map<string, unknown>();
    if (ids.length === 0) {
      return present;
    }

    // `!= null` on purpose: a loader like `({ id }) => map.get(id)` returns
    // `undefined` for a miss, which must read as "not found".
    if (definition.loadMany) {
      const loaded = await definition.loadMany({ ids, scope, context });
      for (const id of ids) {
        const data = loaded.get(id);
        if (data != null) {
          present.set(id, data);
        }
      }
      return present;
    }

    await Promise.all(
      ids.map(async (id) => {
        const data = await definition.load({ id, scope, context });
        if (data != null) {
          present.set(id, data);
        }
      })
    );
    return present;
  }

  async function buildNodes(args: {
    entry: CompiledResource;
    ids: readonly string[];
    subjects: readonly SubjectRef[];
    scope: Scope;
    context: RobracContext;
    at: Date;
    expand: boolean;
  }): Promise<Map<string, Node>> {
    const { entry, scope, context, subjects } = args;
    const type = entry.definition.type;
    const loaded = await loadData(entry, args.ids, scope, context);
    const present = [...loaded].filter(([, data]) =>
      inScope(entry, data, scope)
    );

    const grants =
      present.length === 0 || subjects.length === 0
        ? []
        : await store.findGrants({
            scope,
            resourceType: type,
            resourceIds: present.map(([id]) => id),
            subjects,
            now: args.at,
          });

    const grantsByResource = new Map<string, Grant[]>();
    for (const grant of grants) {
      // Re-checked here so a lax custom store cannot widen access.
      if (
        grant.scope !== scope ||
        grant.resourceType !== type ||
        !subjects.some((subject) => isSubject(grant, subject)) ||
        !isLive(grant, args.at)
      ) {
        continue;
      }
      const bucket = grantsByResource.get(grant.resourceId) ?? [];
      bucket.push(grant);
      grantsByResource.set(grant.resourceId, bucket);
    }

    const nodes = await Promise.all(
      present.map(async ([id, data]): Promise<Node> => {
        const ref: ResourceRef = { type, id };
        const callbackArgs = { data, resource: ref, scope, subjects, context };
        const override = readOverride(
          await entry.definition.override?.(callbackArgs)
        );

        const applied: AppliedRole[] = [];
        const held: Held = new Map();
        const explicit = new Set<string>();
        for (const grant of grantsByResource.get(id) ?? []) {
          if (!explicit.has(grant.role)) {
            explicit.add(grant.role);
            applied.push({ role: grant.role, origin: 'explicit' });
          }
          // A row naming an undeclared role is listed but confers nothing,
          // here or on descendants.
          if (roleOf(entry, grant.role)) {
            hold(held, grant.role, {
              expiry: grant.expiresAt?.getTime() ?? Infinity,
              reach: maxDepth,
            });
          }
        }

        const accumulated: string[] = [];
        const returned = await entry.definition.computeRoles?.({
          ...callbackArgs,
          roles: accumulated,
        });
        const computed = [
          ...accumulated,
          ...(Array.isArray(returned) ? (returned as unknown[]) : []),
        ];
        for (const role of unique(computed)) {
          if (typeof role === 'string' && roleOf(entry, role)) {
            applied.push({ role, origin: 'computed' });
            hold(held, role, { expiry: Infinity, reach: maxDepth });
          }
        }

        const parent =
          args.expand && override !== 'deny' && entry.definition.parent
            ? readParent(
                await entry.definition.parent({
                  data,
                  resource: ref,
                  scope,
                  context,
                })
              )
            : null;
        const { parentTypes } = entry.definition;
        if (parent && parentTypes && !parentTypes.includes(parent.type)) {
          throw new RobracError(
            'INVALID_CONFIGURATION',
            `parent() of "${type}" returned type "${parent.type}", which parentTypes does not list.`
          );
        }

        return { entry, ref, data, override, applied, held, parent };
      })
    );

    return new Map(nodes.map((node) => [node.ref.id, node]));
  }

  /**
   * Load the requested resources and every ancestor within `maxDepth`, one
   * load and one grant query per resource type and level, then fold roles and
   * `'deny'` overrides down each parent chain.
   */
  async function collect(args: {
    type: string;
    ids: readonly string[];
    subjects: readonly SubjectRef[];
    scope: Scope;
    context: RobracContext;
    at: Date;
  }): Promise<Map<string, Resolved>> {
    const graph = new Map<string, Map<string, Node | null>>();
    const known = (ref: ResourceRef) =>
      graph.get(ref.type)?.has(ref.id) === true;

    let frontier = new Map([[args.type, unique(args.ids)]]);
    for (let depth = 0; frontier.size > 0; depth++) {
      const levelNodes: Node[] = [];
      await Promise.all(
        [...frontier].map(async ([type, ids]) => {
          const entry = compiled.get(type);
          if (!entry) {
            throw new RobracError(
              'INVALID_CONFIGURATION',
              `parent() returned unknown resource type "${type}".`
            );
          }
          const nodes = await buildNodes({
            ...args,
            entry,
            ids,
            expand: depth < maxDepth,
          });
          const byId = graph.get(type) ?? new Map<string, Node | null>();
          graph.set(type, byId);
          for (const id of ids) {
            const node = nodes.get(id) ?? null;
            byId.set(id, node);
            if (node) {
              levelNodes.push(node);
            }
          }
        })
      );

      const next = new Map<string, string[]>();
      for (const node of levelNodes) {
        if (node.parent && !known(node.parent)) {
          const ids = next.get(node.parent.type) ?? [];
          if (!ids.includes(node.parent.id)) {
            ids.push(node.parent.id);
          }
          next.set(node.parent.type, ids);
        }
      }
      frontier = next;
    }

    const resolve = (
      ref: ResourceRef,
      remaining: number,
      chain: Set<string>
    ): Resolved | null => {
      const node = graph.get(ref.type)?.get(ref.id);
      if (!node) {
        return null;
      }
      const applied = [...node.applied];
      const held: Held = new Map(
        [...node.held].map(([role, holds]) => [role, [...holds]])
      );
      let override = node.override;

      const parentRef = node.parent;
      if (
        override !== 'deny' &&
        parentRef &&
        remaining > 0 &&
        !chain.has(refKey(parentRef))
      ) {
        const parent = resolve(
          parentRef,
          remaining - 1,
          new Set(chain).add(refKey(parentRef))
        );
        if (parent?.override === 'deny') {
          override = 'deny';
        } else if (parent) {
          const inherited = new Set<string>();
          for (const [role, holds] of parent.held) {
            const mapped = mapInherited(node.entry, parentRef, role);
            if (!mapped) {
              continue;
            }
            if (!inherited.has(mapped)) {
              inherited.add(mapped);
              applied.push({
                role: mapped,
                origin: 'inherited',
                via: parentRef,
              });
            }
            for (const { expiry, reach } of holds) {
              if (reach > 0) {
                hold(held, mapped, { expiry, reach: reach - 1 });
              }
            }
          }
        }
      }

      return { node, applied, held, override };
    };

    const result = new Map<string, Resolved>();
    for (const id of unique(args.ids)) {
      const ref = { type: args.type, id };
      const resolved = resolve(ref, maxDepth, new Set([refKey(ref)]));
      if (resolved) {
        result.set(id, resolved);
      }
    }
    return result;
  }

  function toDecision(
    entry: CompiledResource,
    scope: Scope,
    ref: ResourceRef,
    resolved: Resolved | undefined
  ): AccessDecision {
    const statements = entry.definition.statements;
    if (!resolved) {
      return {
        found: false,
        scope,
        resource: ref,
        data: null,
        roles: [],
        effectiveRoles: [],
        permissions: constantMatrix(statements, false),
        override: null,
      };
    }
    const { override } = resolved;
    return {
      found: true,
      scope,
      resource: ref,
      data: resolved.node.data,
      roles: resolved.applied,
      effectiveRoles: unique(resolved.applied.map((applied) => applied.role)),
      permissions:
        override === null
          ? buildPermissionMatrix(statements, entry.roles, [
              ...resolved.held.keys(),
            ])
          : constantMatrix(statements, override === 'allow'),
      override,
    };
  }

  async function evaluateBatch(args: {
    type: string;
    ids: readonly string[];
    subjects: readonly SubjectRef[];
    scope?: Scope;
    context?: RobracContext;
    emit: boolean;
  }): Promise<Map<string, Evaluation>> {
    const entry = resource(args.type);
    const scope = resolveScope(args.scope);
    const resolved = await collect({
      type: args.type,
      ids: args.ids,
      subjects: args.subjects,
      scope,
      context: args.context ?? {},
      at: now(),
    });

    const evaluations = new Map<string, Evaluation>();
    for (const id of unique(args.ids)) {
      const ref: ResourceRef = { type: args.type, id };
      const found = resolved.get(id);
      const decision = toDecision(entry, scope, ref, found);
      evaluations.set(id, { decision, held: found?.held ?? new Map() });
      if (args.emit) {
        options.onDecision?.({
          subjects: args.subjects,
          scope,
          resource: ref,
          decision,
        });
      }
    }
    return evaluations;
  }

  async function evaluateOne(args: {
    type: string;
    id: string;
    subjects: readonly SubjectRef[];
    scope?: Scope;
    context?: RobracContext;
    emit: boolean;
  }): Promise<Evaluation> {
    const evaluations = await evaluateBatch({ ...args, ids: [args.id] });
    return evaluations.get(args.id)!;
  }

  async function evaluateMany<TType extends ResourceTypeOf<TRegistry>>(args: {
    type: TType;
    ids: readonly string[];
    subjects: readonly SubjectRef[];
    scope?: Scope;
    context?: RobracContext;
  }): Promise<Map<string, DecisionFor<TRegistry, TType>>> {
    const evaluations = await evaluateBatch({ ...args, emit: true });
    return new Map(
      [...evaluations].map(([id, { decision }]) => [
        id,
        decision as DecisionFor<TRegistry, TType>,
      ])
    );
  }

  async function evaluate<TType extends ResourceTypeOf<TRegistry>>(args: {
    type: TType;
    id: string;
    subjects: readonly SubjectRef[];
    scope?: Scope;
    context?: RobracContext;
  }): Promise<DecisionFor<TRegistry, TType>> {
    const { decision } = await evaluateOne({ ...args, emit: true });
    return decision as DecisionFor<TRegistry, TType>;
  }

  // `check`, `require`, `filterAccessible` and grant management report one
  // event carrying the verdict instead of a bare decision event plus another.
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

  function allows(
    decision: AccessDecision,
    request: PermissionRequest,
    connector: 'AND' | 'OR' | undefined
  ): boolean {
    return (
      decision.found &&
      checkPermissions(decision.permissions, request, connector)
    );
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
    const { decision } = await evaluateOne({ ...args, emit: false });
    const allowed = allows(decision, args.permissions, args.connector);
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
    const { decision } = await evaluateOne({ ...args, emit: false });
    const allowed = allows(decision, args.permissions, args.connector);
    emitVerdict(args.subjects, decision, args.permissions, allowed);
    if (!allowed) {
      throw new RobracError(
        'FORBIDDEN',
        `Not allowed to perform this action on ${args.type}:${args.id}.`
      );
    }
    return decision as DecisionFor<TRegistry, TType>;
  }

  /** Keep only the ids the subjects may act on, in input order. */
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
    const evaluations = await evaluateBatch({ ...args, emit: false });
    return args.ids.filter((id) => {
      const evaluation = evaluations.get(id);
      if (!evaluation) {
        return false;
      }
      const allowed = allows(
        evaluation.decision,
        args.permissions,
        args.connector
      );
      emitVerdict(
        args.subjects,
        evaluation.decision,
        args.permissions,
        allowed
      );
      return allowed;
    });
  }

  function assertPage(limit?: number, offset?: number): void {
    for (const [name, value] of [
      ['limit', limit],
      ['offset', offset],
    ] as const) {
      if (value !== undefined && (!Number.isSafeInteger(value) || value < 0)) {
        throw new RobracArgumentError(
          `${name} must be a non-negative integer.`
        );
      }
    }
  }

  /**
   * Ids the subjects hold a live, explicit grant of a declared role on, for
   * permission-aware SQL:
   * `WHERE created_by = ? OR visibility = 'organization' OR id IN (<ids>)`.
   *
   * Built from grant rows alone: computed roles, inherited roles, overrides
   * and the resources' own scope are not applied. Express those in the same
   * query, e.g. `AND NOT legal_hold`.
   *
   * `limit`/`offset` page over grant rows ordered by grant id, not over
   * distinct resources. They bound a pathological result set; they are not
   * for paginating a UI.
   */
  async function accessibleResourceIds<
    TType extends ResourceTypeOf<TRegistry>,
  >(args: {
    type: TType;
    subjects: readonly SubjectRef[];
    scope?: Scope;
    /** Keep only ids where the grants confer these permissions. */
    permissions?: PermissionRequestOf<TRegistry, TType>;
    limit?: number;
    offset?: number;
  }): Promise<string[]> {
    const entry = resource(args.type);
    const scope = resolveScope(args.scope);
    assertPage(args.limit, args.offset);

    const at = now();
    const rolesOf = (grants: readonly Grant[]) => {
      const roles = new Map<string, string[]>();
      for (const grant of grants) {
        if (
          grant.scope === scope &&
          grant.resourceType === args.type &&
          roleOf(entry, grant.role) &&
          args.subjects.some((subject) => isSubject(grant, subject)) &&
          isLive(grant, at)
        ) {
          const bucket = roles.get(grant.resourceId) ?? [];
          bucket.push(grant.role);
          roles.set(grant.resourceId, bucket);
        }
      }
      return roles;
    };

    const page = rolesOf(
      await store.listSubjectGrants({
        scope,
        subjects: args.subjects,
        resourceType: args.type,
        now: at,
        limit: args.limit,
        offset: args.offset,
      })
    );
    const request = args.permissions;
    if (!request || page.size === 0) {
      return [...page.keys()];
    }

    // A page holds only some of a resource's rows; judge each on all of them.
    const complete =
      args.limit === undefined && !args.offset
        ? page
        : rolesOf(
            await store.findGrants({
              scope,
              resourceType: args.type,
              resourceIds: [...page.keys()],
              subjects: args.subjects,
              now: at,
            })
          );
    return [...page.keys()].filter((id) =>
      checkPermissions(
        buildPermissionMatrix(
          entry.definition.statements,
          entry.roles,
          complete.get(id) ?? []
        ),
        request
      )
    );
  }

  /* ---------------------------------------------------------------------- */
  /* Grant management                                                        */
  /* ---------------------------------------------------------------------- */

  function assertKnownRole(entry: CompiledResource, role: string): void {
    if (typeof role !== 'string' || !roleOf(entry, role)) {
      throw new RobracError(
        'UNKNOWN_ROLE',
        `Unknown role "${String(role)}" for resource type "${entry.definition.type}".`
      );
    }
  }

  // Only the authorized tier demands a future date; trusted code may import
  // historical rows.
  function readExpiry(
    value: Date | null | undefined,
    future?: Date
  ): Date | null {
    if (value === null || value === undefined) {
      return null;
    }
    if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
      throw new RobracArgumentError('expiresAt must be a valid date.');
    }
    if (future && value.getTime() <= future.getTime()) {
      throw new RobracArgumentError('expiresAt must be in the future.');
    }
    return value;
  }

  function atomically<R>(run: (store: GrantStore) => Promise<R>): Promise<R> {
    return store.transaction ? store.transaction(run) : run(store);
  }

  async function emitChange(event: GrantChangeEvent): Promise<void> {
    await Promise.resolve(options.onGrantChange?.(event));
  }

  function byOf(subject: SubjectRef | null | undefined) {
    return subject ? [subject] : null;
  }

  async function grantRole(args: {
    ref: ResourceRef;
    scope: Scope;
    subject: SubjectRef;
    role: string;
    grantedBy: SubjectRef | null;
    by?: readonly SubjectRef[];
    expiresAt: Date | null;
    at: Date;
  }): Promise<Grant> {
    return atomically(async (tx) => {
      const grant = await tx.upsertGrant({
        scope: args.scope,
        resource: args.ref,
        subject: args.subject,
        role: args.role,
        grantedBy: args.grantedBy,
        expiresAt: args.expiresAt,
        now: args.at,
      });
      await emitChange({
        action: 'grant',
        scope: args.scope,
        resource: args.ref,
        subject: args.subject,
        roles: [args.role],
        by: args.by ?? byOf(args.grantedBy),
      });
      return grant;
    });
  }

  /** The subject's stored roles on a resource, mapped to whether any row is live. */
  async function heldRoles(
    tx: GrantStore,
    scope: Scope,
    ref: ResourceRef,
    subject: SubjectRef,
    at: Date
  ): Promise<Map<string, boolean>> {
    const grants = await tx.listResourceGrants({
      scope,
      resource: ref,
      now: at,
      includeExpired: true,
      subject,
    });
    const roles = new Map<string, boolean>();
    for (const grant of grants) {
      if (
        grant.scope === scope &&
        grant.resourceType === ref.type &&
        grant.resourceId === ref.id &&
        isSubject(grant, subject)
      ) {
        roles.set(
          grant.role,
          roles.get(grant.role) === true || isLive(grant, at)
        );
      }
    }
    return roles;
  }

  /**
   * The roles the caller may delete, out of those it read. A refused live role
   * throws. A refused expired role is kept, so a concurrent renewal survives.
   */
  function removable(
    held: Map<string, boolean>,
    roles: readonly string[],
    guard: ((role: string) => string | null) | undefined
  ): string[] {
    const allowed: string[] = [];
    for (const role of roles) {
      const live = held.get(role);
      if (live === undefined) {
        continue;
      }
      const gap = guard?.(role) ?? null;
      if (gap === null) {
        allowed.push(role);
      } else if (live) {
        throw new RobracError(
          'FORBIDDEN',
          `Cannot revoke role "${role}": it includes "${gap}", which you are not allowed to do.`
        );
      }
    }
    return allowed;
  }

  async function revokeRoles(args: {
    scope: Scope;
    ref: ResourceRef;
    subject: SubjectRef;
    role: string | undefined;
    revokedBy: SubjectRef | null;
    by?: readonly SubjectRef[];
    at: Date;
    guard?: (role: string) => string | null;
  }): Promise<number> {
    const { scope, ref, subject } = args;
    return atomically(async (tx) => {
      let roles: string[];
      let deleted = 0;
      if (args.guard) {
        const held = await heldRoles(tx, scope, ref, subject, args.at);
        roles = removable(
          held,
          args.role === undefined ? [...held.keys()] : [args.role],
          args.guard
        );
        for (const role of roles) {
          deleted += await tx.deleteGrant({
            scope,
            resource: ref,
            subject,
            role,
          });
        }
      } else if (args.role !== undefined) {
        roles = [args.role];
        deleted = await tx.deleteGrant({
          scope,
          resource: ref,
          subject,
          role: args.role,
        });
      } else {
        roles = [...(await heldRoles(tx, scope, ref, subject, args.at)).keys()];
        deleted = await tx.deleteSubjectGrantsOnResource({
          scope,
          resource: ref,
          subject,
        });
      }
      if (deleted > 0) {
        await emitChange({
          action: 'revoke',
          scope,
          resource: ref,
          subject,
          roles,
          by: args.by ?? byOf(args.revokedBy),
        });
      }
      return deleted;
    });
  }

  async function replaceRoles(args: {
    scope: Scope;
    ref: ResourceRef;
    subject: SubjectRef;
    roles: readonly string[];
    grantedBy: SubjectRef | null;
    by?: readonly SubjectRef[];
    expiresAt: Date | null;
    at: Date;
    guardRemoval?: (role: string) => string | null;
  }): Promise<Grant[]> {
    const { scope, ref, subject } = args;
    const wanted = unique(args.roles);
    return atomically(async (tx) => {
      const held = await heldRoles(tx, scope, ref, subject, args.at);
      const removed = removable(
        held,
        [...held.keys()].filter((role) => !wanted.includes(role)),
        args.guardRemoval
      );
      for (const role of removed) {
        await tx.deleteGrant({ scope, resource: ref, subject, role });
      }
      const added: Grant[] = [];
      for (const role of wanted) {
        added.push(
          await tx.upsertGrant({
            scope,
            resource: ref,
            subject,
            role,
            grantedBy: args.grantedBy,
            expiresAt: args.expiresAt,
            now: args.at,
          })
        );
      }

      // Two events, because a downgrade is a revocation.
      const by = args.by ?? byOf(args.grantedBy);
      if (removed.length > 0) {
        await emitChange({
          action: 'revoke',
          scope,
          resource: ref,
          subject,
          roles: removed,
          by,
        });
      }
      if (wanted.length > 0) {
        await emitChange({
          action: 'grant',
          scope,
          resource: ref,
          subject,
          roles: wanted,
          by,
        });
      }
      return added;
    });
  }

  /**
   * Unchecked grant primitives for trusted server code: seeds, migrations,
   * admin tooling and back-office jobs. Anything reachable from a user request
   * should go through {@link authorized} instead.
   */
  const grants = {
    async list<TType extends ResourceTypeOf<TRegistry>>(args: {
      type: TType;
      id: string;
      scope?: Scope;
      includeExpired?: boolean;
    }): Promise<Grant[]> {
      return await store.listResourceGrants({
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
      const at = now();
      return await grantRole({
        ref: { type: args.type, id: args.id },
        scope: resolveScope(args.scope),
        subject: args.subject,
        role: args.role,
        grantedBy: args.grantedBy ?? null,
        expiresAt: readExpiry(args.expiresAt),
        at,
      });
    },

    async revoke<TType extends ResourceTypeOf<TRegistry>>(args: {
      type: TType;
      id: string;
      subject: SubjectRef;
      /** Omit to revoke every role the subject holds on this resource. */
      role?: RoleOf<TRegistry, TType>;
      scope?: Scope;
      /** Recorded as the actor in the audit event. */
      revokedBy?: SubjectRef | null;
    }): Promise<number> {
      return await revokeRoles({
        scope: resolveScope(args.scope),
        ref: { type: args.type, id: args.id },
        subject: args.subject,
        role: args.role,
        revokedBy: args.revokedBy ?? null,
        at: now(),
      });
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
      const at = now();
      return await replaceRoles({
        scope: resolveScope(args.scope),
        ref: { type: args.type, id: args.id },
        subject: args.subject,
        roles: args.roles,
        grantedBy: args.grantedBy ?? null,
        expiresAt: readExpiry(args.expiresAt),
        at,
      });
    },

    /** Drop every grant on a resource. Call this when the resource is deleted. */
    async revokeResource<TType extends ResourceTypeOf<TRegistry>>(args: {
      type: TType;
      id: string;
      scope?: Scope;
    }): Promise<number> {
      const scope = resolveScope(args.scope);
      const ref = { type: args.type, id: args.id };
      return await atomically(async (tx) => {
        const existing = options.onGrantChange
          ? await tx.listResourceGrants({
              scope,
              resource: ref,
              now: now(),
              includeExpired: true,
            })
          : [];
        const deleted = await tx.deleteResourceGrants({ scope, resource: ref });
        if (deleted > 0) {
          const bySubject = new Map<string, Grant[]>();
          for (const grant of existing) {
            const key = JSON.stringify([grant.subjectType, grant.subjectId]);
            bySubject.set(key, [...(bySubject.get(key) ?? []), grant]);
          }
          for (const held of bySubject.values()) {
            await emitChange({
              action: 'revoke',
              scope,
              resource: ref,
              subject: { type: held[0]!.subjectType, id: held[0]!.subjectId },
              roles: unique(held.map((grant) => grant.role)),
              by: null,
            });
          }
        }
        return deleted;
      });
    },

    /**
     * Drop every grant a subject holds in a scope. Call this when a member
     * leaves an organization or a team is dissolved. Uses the scope exactly as
     * given, even under `scope: 'disabled'`.
     */
    async revokeSubject(args: {
      subject: SubjectRef;
      scope?: Scope;
    }): Promise<number> {
      const scope = bulkScope(args.scope);
      const at = now();
      return await atomically(async (tx) => {
        const existing = options.onGrantChange
          ? (
              await Promise.all(
                [...compiled.keys()].map((resourceType) =>
                  tx.listSubjectGrants({
                    scope,
                    subjects: [args.subject],
                    resourceType,
                    now: at,
                    includeExpired: true,
                  })
                )
              )
            ).flat()
          : [];
        const deleted = await tx.deleteSubjectGrants({
          scope,
          subject: args.subject,
        });
        if (deleted > 0) {
          const byResource = new Map<string, Grant[]>();
          for (const grant of existing) {
            const key = JSON.stringify([grant.resourceType, grant.resourceId]);
            byResource.set(key, [...(byResource.get(key) ?? []), grant]);
          }
          for (const held of byResource.values()) {
            await emitChange({
              action: 'revoke',
              scope,
              resource: {
                type: held[0]!.resourceType,
                id: held[0]!.resourceId,
              },
              subject: args.subject,
              roles: unique(held.map((grant) => grant.role)),
              by: null,
            });
          }
        }
        return deleted;
      });
    },

    /**
     * Drop every grant in a scope. Call this when a tenant is deleted. Uses the
     * scope exactly as given and emits no per-grant events.
     */
    async revokeScope(args: { scope: Scope }): Promise<number> {
      return await store.deleteScopeGrants({ scope: bulkScope(args.scope) });
    },
  };

  /* ---------------------------------------------------------------------- */
  /* Authorized grant management                                             */
  /* ---------------------------------------------------------------------- */

  async function authorize(args: {
    type: string;
    id: string;
    actor: readonly SubjectRef[];
    scope: Scope;
    context: RobracContext;
  }): Promise<Evaluation & { entry: CompiledResource }> {
    const entry = resource(args.type);
    const evaluation = await evaluateOne({
      type: args.type,
      id: args.id,
      subjects: args.actor,
      scope: args.scope,
      context: args.context,
      emit: false,
    });
    const { decision } = evaluation;
    const manage = entry.definition.manage;
    const allowed =
      decision.found &&
      decision.override !== 'deny' &&
      (typeof manage === 'function'
        ? (await manage({
            data: decision.data,
            resource: decision.resource,
            scope: decision.scope,
            subjects: args.actor,
            context: args.context,
            permissions: decision.permissions,
          })) === true
        : checkPermissions(decision.permissions, manage));

    emitVerdict(
      args.actor,
      decision,
      typeof manage === 'function' ? undefined : manage,
      allowed
    );
    if (!decision.found) {
      throw new RobracError(
        'RESOURCE_NOT_FOUND',
        `Resource ${args.type}:${args.id} not found.`
      );
    }
    if (!allowed) {
      // Without any role or permission, the caller learns nothing, not even
      // that the resource exists.
      const visible =
        evaluation.held.size > 0 ||
        Object.values(decision.permissions).some((row) =>
          Object.values(row).includes(true)
        );
      throw visible
        ? new RobracError(
            'FORBIDDEN',
            `Not allowed to manage access for ${args.type}:${args.id}.`
          )
        : new RobracError(
            'RESOURCE_NOT_FOUND',
            `Resource ${args.type}:${args.id} not found.`
          );
    }
    return { ...evaluation, entry };
  }

  function unrestricted(evaluation: Evaluation): boolean {
    return escalation === 'allow' || evaluation.decision.override === 'allow';
  }

  /**
   * The first permission `role` confers that the actor's roles do not, or
   * `null`. `actor` maps each role to how many levels below the root resource
   * it still cascades.
   *
   * Compares the resource itself and, recursively, what both sides cascade to
   * on descendants: two roles with equal permissions here can still map to
   * very different roles below. Every type with `parent()` counts as a
   * possible child unless its `parentTypes` excludes this one. A role this
   * type does not declare confers nothing and cascades nowhere.
   */
  function escalationGap(
    entry: CompiledResource,
    ref: ResourceRef,
    actor: ReadonlyMap<string, number>,
    role: string,
    depth = 0,
    visited = new Map<string, number>()
  ): string | null {
    if (!roleOf(entry, role)) {
      return null;
    }
    const statements = entry.definition.statements;
    const wanted = grantedActions(statements, entry.roles, [role]);
    const held = grantedActions(statements, entry.roles, actor.keys());
    for (const [facet, actions] of wanted) {
      for (const action of actions) {
        if (held.get(facet)?.has(action) !== true) {
          return depth === 0
            ? `${facet}.${action}`
            : `${facet}.${action} on descendant ${entry.definition.type} resources`;
        }
      }
    }
    if (depth >= maxDepth) {
      return null;
    }

    for (const child of compiled.values()) {
      const { parent, parentTypes } = child.definition;
      if (
        !parent ||
        (parentTypes && !parentTypes.includes(entry.definition.type))
      ) {
        continue;
      }
      const mapped = mapInherited(child, ref, role);
      if (!mapped) {
        continue;
      }
      const childActor = new Map<string, number>();
      for (const [actorRole, reach] of actor) {
        const inherited = mapInherited(child, ref, actorRole);
        if (inherited && reach > depth) {
          childActor.set(
            inherited,
            Math.max(childActor.get(inherited) ?? -1, reach)
          );
        }
      }
      // Keyed on reach left below the child, so an earlier visit at the same or
      // a shallower depth explored everything this one would.
      const key = JSON.stringify([
        child.definition.type,
        mapped,
        [...childActor]
          .map(([name, reach]) => [name, reach - depth - 1])
          .sort(),
      ]);
      const seenAt = visited.get(key);
      if (seenAt !== undefined && seenAt <= depth) {
        continue;
      }
      visited.set(key, depth);
      const gap = escalationGap(
        child,
        { type: child.definition.type, id: '' },
        childActor,
        mapped,
        depth + 1,
        visited
      );
      if (gap) {
        return gap;
      }
    }
    return null;
  }

  /** Latest expiry a grant of `role` may have before it outlives the actor's own access. */
  function grantHorizon(
    entry: CompiledResource,
    ref: ResourceRef,
    held: Held,
    role: string
  ): number {
    const cutoffs = unique(
      [...held.values()]
        .flat()
        .map(({ expiry }) => expiry)
        .filter(Number.isFinite)
    ).sort((a, b) => a - b);
    for (const cutoff of cutoffs) {
      if (escalationGap(entry, ref, reachAfter(held, cutoff), role)) {
        return cutoff;
      }
    }
    return Infinity;
  }

  function assertCanGrant(
    evaluation: Evaluation & { entry: CompiledResource },
    role: string,
    expiresAt: Date | null
  ): void {
    if (unrestricted(evaluation)) {
      return;
    }
    const { entry, held, decision } = evaluation;
    const gap = escalationGap(entry, decision.resource, reachAfter(held), role);
    if (gap) {
      throw new RobracError(
        'FORBIDDEN',
        `Cannot grant role "${role}": it includes "${gap}", which you are not allowed to do.`
      );
    }
    const horizon = grantHorizon(entry, decision.resource, held, role);
    if ((expiresAt?.getTime() ?? Infinity) > horizon) {
      throw new RobracError(
        'FORBIDDEN',
        `Cannot grant role "${role}" beyond ${new Date(horizon).toISOString()}, when your own access to it expires.`
      );
    }
  }

  function removalGap(
    evaluation: Evaluation & { entry: CompiledResource },
    role: string
  ): string | null {
    if (unrestricted(evaluation)) {
      return null;
    }
    const { entry, held, decision } = evaluation;
    return escalationGap(entry, decision.resource, reachAfter(held), role);
  }

  async function authorizedGrant(
    args: AuthorizedWrite & { role: string },
    beforeWrite?: BeforeWrite
  ): Promise<Grant> {
    const entry = resource(args.type);
    assertKnownRole(entry, args.role);
    const scope = resolveScope(args.scope);
    const at = now();
    const expiresAt = readExpiry(args.expiresAt, at);
    const evaluation = await authorize({
      ...args,
      scope,
      context: args.context ?? {},
    });
    assertCanGrant(evaluation, args.role, expiresAt);
    await beforeWrite?.();
    return grantRole({
      ref: evaluation.decision.resource,
      scope,
      subject: args.subject,
      role: args.role,
      grantedBy: args.grantedBy ?? args.actor[0] ?? null,
      by: args.grantedBy ? [args.grantedBy] : args.actor,
      expiresAt,
      at,
    });
  }

  async function authorizedSetRoles(
    args: AuthorizedWrite & { roles: readonly string[] },
    beforeWrite?: BeforeWrite
  ): Promise<Grant[]> {
    const entry = resource(args.type);
    for (const role of args.roles) {
      assertKnownRole(entry, role);
    }
    const scope = resolveScope(args.scope);
    const at = now();
    const expiresAt = readExpiry(args.expiresAt, at);
    const evaluation = await authorize({
      ...args,
      scope,
      context: args.context ?? {},
    });
    for (const role of args.roles) {
      assertCanGrant(evaluation, role, expiresAt);
    }
    await beforeWrite?.();
    return replaceRoles({
      scope,
      ref: evaluation.decision.resource,
      subject: args.subject,
      roles: args.roles,
      grantedBy: args.grantedBy ?? args.actor[0] ?? null,
      by: args.grantedBy ? [args.grantedBy] : args.actor,
      expiresAt,
      at,
      guardRemoval: (role) => removalGap(evaluation, role),
    });
  }

  /**
   * Grant management on behalf of a caller. Every method enforces the
   * resource's `manage` permission and, unless `escalation: 'allow'`, refuses
   * to grant, extend or revoke more than the caller itself holds.
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
      /**
       * Roles this actor may hand out. A caller whose own access expires must
       * also pass an `expiresAt` no later than that.
       */
      availableRoles: string[];
      /** Every role the resource type declares, grantable or not. */
      declaredRoles: string[];
    }> {
      const scope = resolveScope(args.scope);
      const evaluation = await authorize({
        ...args,
        scope,
        context: args.context ?? {},
      });
      const { entry, held, decision } = evaluation;
      const declaredRoles = Object.keys(entry.roles);
      const { type, id } = decision.resource;
      const at = now();
      const grants = await store.listResourceGrants({
        scope,
        resource: decision.resource,
        now: at,
      });
      return {
        grants: grants.filter(
          (grant) =>
            grant.scope === scope &&
            grant.resourceType === type &&
            grant.resourceId === id &&
            isLive(grant, at)
        ),
        availableRoles: declaredRoles.filter(
          (role) =>
            unrestricted(evaluation) ||
            escalationGap(entry, decision.resource, reachAfter(held), role) ===
              null
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
      return await authorizedGrant(args);
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
      return await authorizedSetRoles(args);
    },

    async revoke<TType extends ResourceTypeOf<TRegistry>>(args: {
      type: TType;
      id: string;
      subject: SubjectRef;
      role?: RoleOf<TRegistry, TType>;
      actor: readonly SubjectRef[];
      /** Recorded as the actor in the audit event instead of `actor`. */
      revokedBy?: SubjectRef;
      scope?: Scope;
      context?: RobracContext;
    }): Promise<number> {
      const scope = resolveScope(args.scope);
      const evaluation = await authorize({
        ...args,
        scope,
        context: args.context ?? {},
      });
      return revokeRoles({
        scope,
        ref: evaluation.decision.resource,
        subject: args.subject,
        role: args.role,
        revokedBy: args.revokedBy ?? args.actor[0] ?? null,
        by: args.revokedBy ? [args.revokedBy] : args.actor,
        at: now(),
        guard: (role) => removalGap(evaluation, role),
      });
    },
  };

  const engine = {
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
  checkedWrites.set(engine, {
    grant: authorizedGrant,
    setRoles: authorizedSetRoles,
  });
  return engine;
}
