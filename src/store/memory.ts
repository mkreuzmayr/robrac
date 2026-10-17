import type { Grant, ResourceRef, Scope, SubjectRef } from '../core/types.ts';
import type { GrantStore } from './types.ts';

type MemoryGrantStore = GrantStore & { all(): Grant[]; clear(): void };

type UpsertInput = Parameters<GrantStore['upsertGrant']>[0];

function copy(grant: Grant): Grant {
  return {
    ...grant,
    expiresAt: grant.expiresAt ? new Date(grant.expiresAt) : null,
    createdAt: new Date(grant.createdAt),
    updatedAt: new Date(grant.updatedAt),
  };
}

function isLive(grant: Grant, now: Date): boolean {
  return grant.expiresAt === null || grant.expiresAt.getTime() > now.getTime();
}

function onResource(grant: Grant, scope: Scope, resource: ResourceRef) {
  return (
    grant.scope === scope &&
    grant.resourceType === resource.type &&
    grant.resourceId === resource.id
  );
}

function isSubject(grant: Grant, subject: SubjectRef) {
  return grant.subjectType === subject.type && grant.subjectId === subject.id;
}

function sameTuple(grant: Grant, input: Omit<UpsertInput, 'now'>) {
  return (
    onResource(grant, input.scope, input.resource) &&
    isSubject(grant, input.subject) &&
    grant.role === input.role
  );
}

function byId(a: Grant, b: Grant) {
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

function byCreation(a: Grant, b: Grant) {
  return a.createdAt.getTime() - b.createdAt.getTime() || byId(a, b);
}

/**
 * In-memory {@link GrantStore} for tests, prototypes and single-process
 * deployments. Not durable and not shared across processes.
 *
 * Transactions run against a private snapshot; their writes are replayed onto
 * the live store only when the callback resolves.
 */
export function memoryGrantStore(
  options: { seed?: readonly Grant[]; generateId?: () => string } = {}
): MemoryGrantStore {
  let counter = 0;
  const generateId =
    options.generateId ?? (() => `grant_${Date.now()}_${++counter}`);
  return createStore(
    new Map((options.seed ?? []).map((grant) => [grant.id, copy(grant)])),
    generateId
  );
}

function createStore(
  grants: Map<string, Grant>,
  generateId: () => string
): MemoryGrantStore {
  const rows = () => [...grants.values()];

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

  const freshId = () => {
    let id = generateId();
    while (grants.has(id)) {
      id = generateId();
    }
    return id;
  };

  const write = (input: UpsertInput, id?: string): Grant => {
    const now = new Date(input.now ?? Date.now());
    const matches = rows().filter((grant) => sameTuple(grant, input));
    const [existing, ...duplicates] = matches.sort(byId);
    for (const duplicate of duplicates) {
      grants.delete(duplicate.id);
    }
    const grant: Grant = {
      id: existing?.id ?? (id && !grants.has(id) ? id : freshId()),
      scope: input.scope,
      resourceType: input.resource.type,
      resourceId: input.resource.id,
      subjectType: input.subject.type,
      subjectId: input.subject.id,
      role: input.role,
      grantedBySubjectType: input.grantedBy?.type ?? null,
      grantedBySubjectId: input.grantedBy?.id ?? null,
      expiresAt: input.expiresAt ? new Date(input.expiresAt) : null,
      createdAt: existing?.createdAt ?? now,
      updatedAt: new Date(now),
    };
    grants.set(grant.id, grant);
    return grant;
  };

  const store: MemoryGrantStore = {
    all: () => rows().sort(byCreation).map(copy),
    clear: () => grants.clear(),

    async transaction(run) {
      const log: ((target: MemoryGrantStore) => unknown)[] = [];
      const staged = createStore(
        new Map(rows().map((grant) => [grant.id, copy(grant)])),
        generateId
      );
      const recorded: MemoryGrantStore = {
        ...staged,
        async upsertGrant(input) {
          const grant = await staged.upsertGrant(input);
          log.push(() => write({ ...input, now: grant.updatedAt }, grant.id));
          return grant;
        },
        deleteGrant(query) {
          log.push((target) => target.deleteGrant(query));
          return staged.deleteGrant(query);
        },
        deleteSubjectGrantsOnResource(query) {
          log.push((target) => target.deleteSubjectGrantsOnResource(query));
          return staged.deleteSubjectGrantsOnResource(query);
        },
        deleteResourceGrants(query) {
          log.push((target) => target.deleteResourceGrants(query));
          return staged.deleteResourceGrants(query);
        },
        deleteSubjectGrants(query) {
          log.push((target) => target.deleteSubjectGrants(query));
          return staged.deleteSubjectGrants(query);
        },
        deleteScopeGrants(query) {
          log.push((target) => target.deleteScopeGrants(query));
          return staged.deleteScopeGrants(query);
        },
        clear() {
          log.push((target) => target.clear());
          staged.clear();
        },
        transaction: (nested) => nested(recorded),
      };
      const result = await run(recorded);
      // Every replayed operation is synchronous, so the commit cannot
      // interleave with other writers.
      for (const apply of log) {
        void apply(store);
      }
      return result;
    },

    findGrants({ scope, resourceType, resourceIds, subjects, now }) {
      const ids = new Set(resourceIds);
      return Promise.resolve(
        rows()
          .filter(
            (grant) =>
              grant.scope === scope &&
              grant.resourceType === resourceType &&
              ids.has(grant.resourceId) &&
              subjects.some((subject) => isSubject(grant, subject)) &&
              isLive(grant, now)
          )
          .map(copy)
      );
    },

    listResourceGrants({ scope, resource, now, includeExpired, subject }) {
      return Promise.resolve(
        rows()
          .filter(
            (grant) =>
              onResource(grant, scope, resource) &&
              (!subject || isSubject(grant, subject)) &&
              (includeExpired === true || isLive(grant, now))
          )
          .sort(byCreation)
          .map(copy)
      );
    },

    listSubjectGrants({
      scope,
      subjects,
      resourceType,
      now,
      includeExpired,
      limit,
      offset = 0,
    }) {
      const matched = rows()
        .filter(
          (grant) =>
            grant.scope === scope &&
            grant.resourceType === resourceType &&
            subjects.some((subject) => isSubject(grant, subject)) &&
            (includeExpired === true || isLive(grant, now))
        )
        .sort(byId);
      return Promise.resolve(
        matched
          .slice(offset, limit === undefined ? undefined : offset + limit)
          .map(copy)
      );
    },

    upsertGrant(input) {
      return Promise.resolve(copy(write(input)));
    },

    deleteGrant({ scope, resource, subject, role }) {
      return Promise.resolve(
        remove(
          (grant) =>
            onResource(grant, scope, resource) &&
            isSubject(grant, subject) &&
            grant.role === role
        )
      );
    },

    deleteSubjectGrantsOnResource({ scope, resource, subject }) {
      return Promise.resolve(
        remove(
          (grant) =>
            onResource(grant, scope, resource) && isSubject(grant, subject)
        )
      );
    },

    deleteResourceGrants({ scope, resource }) {
      return Promise.resolve(
        remove((grant) => onResource(grant, scope, resource))
      );
    },

    deleteSubjectGrants({ scope, subject }) {
      return Promise.resolve(
        remove((grant) => grant.scope === scope && isSubject(grant, subject))
      );
    },

    deleteScopeGrants({ scope }) {
      return Promise.resolve(remove((grant) => grant.scope === scope));
    },
  };

  return store;
}
