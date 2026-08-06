import type { Grant, ResourceRef, Scope, SubjectRef } from '../core/types.ts';
import type { GrantStore } from './types.ts';

function matchesSubject(grant: Grant, subject: SubjectRef): boolean {
  return grant.subjectType === subject.type && grant.subjectId === subject.id;
}

function matchesResource(grant: Grant, resource: ResourceRef): boolean {
  return (
    grant.resourceType === resource.type && grant.resourceId === resource.id
  );
}

function isLive(grant: Grant, now: Date): boolean {
  return grant.expiresAt === null || grant.expiresAt.getTime() > now.getTime();
}

/**
 * In-memory {@link GrantStore}.
 *
 * Intended for tests, local prototypes and edge deployments that keep
 * authorization state elsewhere. It is not durable and not shared across
 * processes.
 */
export function memoryGrantStore(
  options: { seed?: readonly Grant[]; generateId?: () => string } = {}
): GrantStore & { all(): Grant[]; clear(): void } {
  let counter = 0;
  const generateId =
    options.generateId ?? (() => `grant_${++counter}_${Date.now()}`);
  const grants = new Map<string, Grant>(
    (options.seed ?? []).map((grant) => [grant.id, grant])
  );

  const list = () => [...grants.values()];

  const remove = (predicate: (grant: Grant) => boolean) => {
    let deleted = 0;
    for (const [id, grant] of grants) {
      if (predicate(grant)) {
        grants.delete(id);
        deleted++;
      }
    }
    return deleted;
  };

  const store: GrantStore & { all(): Grant[]; clear(): void } = {
    all: list,
    clear: () => grants.clear(),

    // A single in-process map is already atomic with respect to `await`
    // boundaries, so the transaction is just a pass-through that keeps the
    // engine's `setRoles` on the same code path as a real database.
    transaction: (run) => run(store),

    findGrants({ scope, resourceType, resourceIds, subjects, now }) {
      const ids = new Set(resourceIds);
      return Promise.resolve(
        list().filter(
          (grant) =>
            grant.scope === scope &&
            grant.resourceType === resourceType &&
            ids.has(grant.resourceId) &&
            subjects.some((subject) => matchesSubject(grant, subject)) &&
            isLive(grant, now)
        )
      );
    },

    listResourceGrants({ scope, resource, now, includeExpired }) {
      return Promise.resolve(
        list().filter(
          (grant) =>
            grant.scope === scope &&
            matchesResource(grant, resource) &&
            (includeExpired === true || isLive(grant, now))
        )
      );
    },

    listSubjectGrants({
      scope,
      subjects,
      resourceType,
      now,
      limit,
      offset = 0,
    }) {
      const matched = list()
        .filter(
          (grant) =>
            grant.scope === scope &&
            grant.resourceType === resourceType &&
            subjects.some((subject) => matchesSubject(grant, subject)) &&
            isLive(grant, now)
        )
        .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());

      return Promise.resolve(
        limit === undefined
          ? matched.slice(offset)
          : matched.slice(offset, offset + limit)
      );
    },

    upsertGrant({ scope, resource, subject, role, grantedBy, expiresAt }) {
      const existing = list().find(
        (grant) =>
          grant.scope === scope &&
          matchesResource(grant, resource) &&
          matchesSubject(grant, subject) &&
          grant.role === role
      );

      const now = new Date();
      if (existing) {
        const updated: Grant = {
          ...existing,
          grantedBySubjectType: grantedBy?.type ?? null,
          grantedBySubjectId: grantedBy?.id ?? null,
          expiresAt,
          updatedAt: now,
        };
        grants.set(updated.id, updated);
        return Promise.resolve(updated);
      }

      const created: Grant = {
        id: generateId(),
        scope,
        resourceType: resource.type,
        resourceId: resource.id,
        subjectType: subject.type,
        subjectId: subject.id,
        role,
        grantedBySubjectType: grantedBy?.type ?? null,
        grantedBySubjectId: grantedBy?.id ?? null,
        expiresAt,
        createdAt: now,
        updatedAt: now,
      };
      grants.set(created.id, created);
      return Promise.resolve(created);
    },

    deleteGrant({ scope, resource, subject, role }) {
      return Promise.resolve(
        remove(
          (grant) =>
            grant.scope === scope &&
            matchesResource(grant, resource) &&
            matchesSubject(grant, subject) &&
            grant.role === role
        )
      );
    },

    deleteSubjectGrantsOnResource({ scope, resource, subject }) {
      return Promise.resolve(
        remove(
          (grant) =>
            grant.scope === scope &&
            matchesResource(grant, resource) &&
            matchesSubject(grant, subject)
        )
      );
    },

    deleteResourceGrants({ scope, resource }) {
      return Promise.resolve(
        remove(
          (grant) => grant.scope === scope && matchesResource(grant, resource)
        )
      );
    },

    deleteSubjectGrants({ scope, subject }) {
      return Promise.resolve(
        remove(
          (grant) => grant.scope === scope && matchesSubject(grant, subject)
        )
      );
    },

    deleteScopeGrants({ scope }: { scope: Scope }) {
      return Promise.resolve(remove((grant) => grant.scope === scope));
    },
  };

  return store;
}
