/**
 * Core vocabulary of robrac.
 *
 * robrac deliberately keeps three things abstract so that it can be dropped
 * into any product without dragging that product's data model along:
 *
 * - **Subject** — *who* is asking. Not necessarily a user: an organization
 *   member, a team, a service account or an API key are all subjects.
 * - **Scope** — the tenant boundary a decision is made in (usually an
 *   organization id). `null` means "single tenant / not scoped".
 * - **Resource** — *what* is being accessed, identified by a `(type, id)` pair
 *   that robrac never has to understand. The application teaches robrac how to
 *   load it via a {@link ResourceDefinition}.
 */

/** A `(type, id)` pair identifying who is asking for access. */
export type SubjectRef = {
  type: string;
  id: string;
};

/** A `(type, id)` pair identifying the thing being accessed. */
export type ResourceRef = {
  type: string;
  id: string;
};

/** Tenant boundary. `null` for single-tenant deployments. */
export type Scope = string | null;

/**
 * A stored role assignment: subject S holds role R on resource X within scope.
 *
 * Grants are additive. A subject may hold several roles on the same resource
 * and the effective permission set is their union.
 */
export type Grant = {
  id: string;
  scope: Scope;
  resourceType: string;
  resourceId: string;
  subjectType: string;
  subjectId: string;
  role: string;
  grantedBySubjectType: string | null;
  grantedBySubjectId: string | null;
  /** `null` means the grant never expires. */
  expiresAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

/**
 * Statement map: resource facet -> allowed actions.
 *
 * Structurally identical to Better Auth's access-control statements, so
 * `createAccessControl(...).statements` can be handed to robrac unchanged.
 *
 * @example
 * ```ts
 * { recording: ['read', 'update', 'share'], note: ['read'] }
 * ```
 */
export type Statements = Readonly<Record<string, readonly string[]>>;

/** A subset of {@link Statements}: what a role actually allows. */
export type PermissionMap<TStatements extends Statements = Statements> = {
  readonly [P in keyof TStatements]?: readonly TStatements[P][number][];
};

/**
 * What a caller asks for, e.g. `{ recording: ['read'] }`.
 *
 * Actions listed as an array must all be allowed. The object form opts a
 * single facet into `OR` semantics: `{ recording: { actions: ['update',
 * 'delete'], connector: 'OR' } }` asks for either.
 */
export type PermissionRequest<TStatements extends Statements = Statements> = {
  readonly [P in keyof TStatements]?:
    | readonly TStatements[P][number][]
    | {
        actions: readonly TStatements[P][number][];
        connector?: 'AND' | 'OR';
      };
};

/**
 * Fully expanded allow/deny table for every declared facet + action.
 *
 * When the statements are a concrete `as const` object, this resolves to an
 * exact shape — `decision.permissions.recording.share` is a `boolean`, and a
 * typo in either segment is a compile error.
 */
export type PermissionMatrix<TStatements extends Statements = Statements> = {
  [P in keyof TStatements]: Record<TStatements[P][number], boolean>;
};

/** Structural view of a {@link PermissionMatrix}, for code that stays generic. */
export type PermissionTable = Record<string, Record<string, boolean>>;

/**
 * A Better Auth `Role` object. robrac accepts these directly so existing
 * `createAccessControl(...).newRole(...)` definitions keep working.
 */
export type BetterAuthRoleLike = {
  statements: Statements;
};

/** Either a raw permission map or a Better Auth role object. */
export type RoleInput = PermissionMap | BetterAuthRoleLike;

/**
 * A normalized robrac role: a permission map plus the names of roles it
 * inherits from. Inheritance is resolved eagerly when the role set is built.
 */
export type NormalizedRole = {
  name: string;
  /** Permissions declared directly on this role. */
  own: Record<string, readonly string[]>;
  /** Permissions after resolving `extends`. */
  effective: Record<string, readonly string[]>;
  extends: readonly string[];
};

/** Where an effective role came from. Surfaced in decisions for debugging. */
export type RoleOrigin = 'explicit' | 'computed' | 'inherited';

/** A role that applied to a decision, with its provenance. */
export type AppliedRole = {
  role: string;
  origin: RoleOrigin;
  /** Set when `origin` is `'inherited'`: the ancestor the role came from. */
  via?: ResourceRef;
};

/**
 * The result of `evaluate`. This is the single object every other API is
 * derived from — `check` is just a predicate over `permissions`.
 */
export type AccessDecision<
  TResource = unknown,
  TStatements extends Statements = Statements,
> = {
  /** `false` when the resource does not exist (or is outside the scope). */
  found: boolean;
  scope: Scope;
  resource: ResourceRef;
  /** The loaded domain object, when found. */
  data: TResource | null;
  roles: AppliedRole[];
  /** Distinct role names, deduplicated. */
  effectiveRoles: string[];
  permissions: PermissionMatrix<TStatements>;
  /**
   * Set when a resource `override` short-circuited role evaluation:
   * `'allow'` grants everything, `'deny'` revokes everything.
   */
  override: 'allow' | 'deny' | null;
};

/** Arbitrary per-request data forwarded to resource callbacks. */
export type RobracContext = Record<string, unknown>;
