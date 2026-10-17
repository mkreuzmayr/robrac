import type { Grant, ResourceRef, Scope, SubjectRef } from '../core/types.ts';

/**
 * Everything robrac needs from a database: nine methods plus an optional
 * `transaction`.
 *
 * Implementation contract:
 * - Reads are complete. A store must never silently truncate a result; page
 *   internally if the backend caps result sizes.
 * - Reads never return rows whose `expiresAt` is at or before the supplied
 *   `now`, unless the caller opts in with `includeExpired`. Stores take `now`
 *   from the caller instead of reading the clock, so a frozen clock in tests
 *   governs the whole engine.
 * - `scope` participates in every predicate. `null` is a real value, not a
 *   wildcard: `scope: null` matches only rows stored with no scope.
 * - `limit`/`offset` apply *after* expiry and subject filtering.
 * - Returned grants are copies; mutating them must not change stored state.
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

  /**
   * Every grant on one resource, ordered by `createdAt`. Powers share dialogs.
   * When `subject` is given, only that subject's grants are needed; a store
   * may ignore the hint and return all of them.
   */
  listResourceGrants(query: {
    scope: Scope;
    resource: ResourceRef;
    now: Date;
    includeExpired?: boolean;
    subject?: SubjectRef;
  }): Promise<Grant[]>;

  /**
   * Every grant a subject holds on a resource type, ordered by grant id; only
   * live ones unless `includeExpired`. Used to build permission-aware
   * `WHERE resource_id IN (...)` filters.
   */
  listSubjectGrants(query: {
    scope: Scope;
    subjects: readonly SubjectRef[];
    resourceType: string;
    now: Date;
    includeExpired?: boolean;
    limit?: number;
    offset?: number;
  }): Promise<Grant[]>;

  /**
   * Insert the grant, or refresh `expiresAt` / `grantedBy` if it already
   * exists. Must be safe to call concurrently for the same tuple and must
   * leave exactly one row for it. `now` stamps `createdAt` / `updatedAt`.
   */
  upsertGrant(input: {
    scope: Scope;
    resource: ResourceRef;
    subject: SubjectRef;
    role: string;
    grantedBy: SubjectRef | null;
    expiresAt: Date | null;
    now?: Date;
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

  /** Remove every grant a subject holds anywhere in a scope. */
  deleteSubjectGrants(query: {
    scope: Scope;
    subject: SubjectRef;
  }): Promise<number>;

  /** Remove every grant in a scope. Call this when a tenant is deleted. */
  deleteScopeGrants(query: { scope: Scope }): Promise<number>;

  /**
   * Run several operations atomically. Only implement it when the backend
   * really provides atomicity; robrac composes the operations without one
   * when it is absent.
   */
  transaction?<R>(run: (store: GrantStore) => Promise<R>): Promise<R>;
};
