import type { Grant, ResourceRef, Scope, SubjectRef } from '../core/types.ts';

/**
 * Everything robrac needs from a database.
 *
 * This is the entire ORM boundary. `robrac` ships two
 * implementations — one over Better Auth's internal adapter (works with
 * Drizzle, Prisma, Kysely, Mongo, or a direct connection without any extra
 * code) and one in memory — but a team with an existing grants table or a
 * hot-path performance requirement can implement these eight methods against
 * raw SQL and lose nothing. `transaction` is optional.
 *
 * Implementation contract:
 * - Reads never return rows whose `expiresAt` is at or before the supplied
 *   `now`, unless the caller opts in with `includeExpired`. Every read takes
 *   `now` as a parameter rather than calling the clock itself, so a frozen
 *   clock in tests governs the whole engine.
 * - `scope` participates in every predicate. `null` is a real value, not a
 *   wildcard: `scope: null` matches only rows stored with no scope.
 * - `limit`/`offset` apply *after* expiry and subject filtering. A store that
 *   pushes them into SQL ahead of those filters silently drops rows the caller
 *   is entitled to; see `listSubjectGrants` in `store/better-auth.ts` for how
 *   to page correctly against a backend that cannot express the filters.
 */
export type GrantStore = {
  /**
   * The hot path. Fetch the live grants that any of `subjects` holds on any of
   * `resourceIds`, in one round trip.
   */
  findGrants(query: {
    scope: Scope;
    resourceType: string;
    resourceIds: readonly string[];
    subjects: readonly SubjectRef[];
    now: Date;
  }): Promise<Grant[]>;

  /** Every grant on one resource, regardless of subject. Powers share dialogs. */
  listResourceGrants(query: {
    scope: Scope;
    resource: ResourceRef;
    now: Date;
    includeExpired?: boolean;
  }): Promise<Grant[]>;

  /**
   * Every live grant a subject holds on a resource type. Used to build
   * permission-aware `WHERE resource_id IN (...)` filters in application
   * queries.
   *
   * `limit`/`offset` count *live, matching* rows — see the contract note above.
   */
  listSubjectGrants(query: {
    scope: Scope;
    subjects: readonly SubjectRef[];
    resourceType: string;
    now: Date;
    limit?: number;
    offset?: number;
  }): Promise<Grant[]>;

  /**
   * Insert the grant, or refresh `expiresAt` / `grantedBy` if it already
   * exists. Must be safe to call concurrently for the same tuple.
   */
  upsertGrant(input: {
    scope: Scope;
    resource: ResourceRef;
    subject: SubjectRef;
    role: string;
    grantedBy: SubjectRef | null;
    expiresAt: Date | null;
  }): Promise<Grant>;

  /** Remove one role from one subject on one resource. */
  deleteGrant(query: {
    scope: Scope;
    resource: ResourceRef;
    subject: SubjectRef;
    role: string;
  }): Promise<number>;

  /** Remove every role a subject holds on one resource. */
  deleteSubjectGrantsOnResource(query: {
    scope: Scope;
    resource: ResourceRef;
    subject: SubjectRef;
  }): Promise<number>;

  /** Remove every grant on a resource. Call this when the resource is deleted. */
  deleteResourceGrants(query: {
    scope: Scope;
    resource: ResourceRef;
  }): Promise<number>;

  /**
   * Remove every grant a subject holds anywhere in a scope. Call this when a
   * member leaves an organization or a team is dissolved.
   */
  deleteSubjectGrants(query: {
    scope: Scope;
    subject: SubjectRef;
  }): Promise<number>;

  /** Remove every grant in a scope. Call this when a tenant is deleted. */
  deleteScopeGrants(query: { scope: Scope }): Promise<number>;

  /**
   * Run several operations atomically.
   *
   * Optional: when absent, robrac composes the operations without a
   * transaction. Implement it if your backend supports one — `setRoles` is a
   * replace, and a failure between its deletes and its upserts would otherwise
   * leave a subject with no roles at all.
   */
  transaction?<R>(run: (store: GrantStore) => Promise<R>): Promise<R>;
};
