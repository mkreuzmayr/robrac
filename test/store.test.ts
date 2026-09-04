import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';

import {
  betterAuthGrantStore,
  createRobrac,
  defineResource,
  memoryGrantStore,
  robrac,
} from '../src/index.ts';
import type { GrantStore } from '../src/index.ts';

const ORG = 'org_1';
const OTHER = 'org_2';
const DOC = { type: 'document', id: 'doc_1' } as const;
const BOB = { type: 'member', id: 'm_bob' } as const;

/** Fixed clock. Every read takes `now` so a store never consults the wall clock. */
const NOW = new Date('2026-01-01T00:00:00Z');

/**
 * Build a store backed by a real Better Auth instance so the adapter path is
 * exercised end to end — schema declaration, field mapping, date handling and
 * all. The memory adapter stands in for Postgres; the store never sees the
 * difference, which is the whole point.
 */
async function betterAuthStore(
  seed: Record<string, unknown>[] = []
): Promise<GrantStore> {
  // The memory adapter expects one array per model up front.
  const db = {
    user: [],
    session: [],
    account: [],
    verification: [],
    robracGrant: seed,
  };

  const auth = betterAuth({
    baseURL: 'http://localhost:3000',
    secret: 'robrac-test-secret-robrac-test-secret',
    database: memoryAdapter(db),
    advanced: { database: { defaultFindManyLimit: 2 } },
    plugins: [
      robrac({
        scope: 'disabled',
        resources: {
          document: defineResource({
            type: 'document',
            statements: { document: ['read'] },
            roles: { viewer: { document: ['read'] } },
            load: () => null,
            manage: { document: ['read'] },
          }),
        },
      }),
    ],
  });

  const context = await auth.$context;
  return betterAuthGrantStore({
    adapter: context.adapter,
  });
}

/**
 * One contract, two implementations. Everything robrac needs from a database
 * lives in these assertions — a team writing a raw-SQL store can copy this
 * suite verbatim to prove theirs is correct.
 */
function storeContract(name: string, create: () => Promise<GrantStore>) {
  describe(`GrantStore contract: ${name}`, () => {
    it('round-trips a grant', async () => {
      const store = await create();
      const created = await store.upsertGrant({
        scope: ORG,
        resource: DOC,
        subject: BOB,
        role: 'viewer',
        grantedBy: { type: 'member', id: 'm_alice' },
        expiresAt: null,
      });

      assert.equal(created.role, 'viewer');
      assert.equal(created.scope, ORG);
      assert.equal(created.grantedBySubjectId, 'm_alice');
      assert.ok(created.createdAt instanceof Date);

      const [found] = await store.listResourceGrants({
        scope: ORG,
        resource: DOC,
        now: NOW,
      });
      assert.equal(found?.id, created.id);
    });

    it('upserts rather than duplicating', async () => {
      const store = await create();
      const first = await store.upsertGrant({
        scope: ORG,
        resource: DOC,
        subject: BOB,
        role: 'viewer',
        grantedBy: null,
        expiresAt: null,
      });
      const second = await store.upsertGrant({
        scope: ORG,
        resource: DOC,
        subject: BOB,
        role: 'viewer',
        grantedBy: null,
        expiresAt: new Date('2030-01-01T00:00:00Z'),
      });

      assert.equal(first.id, second.id);
      assert.deepEqual(second.expiresAt, new Date('2030-01-01T00:00:00Z'));

      const all = await store.listResourceGrants({
        scope: ORG,
        resource: DOC,
        now: NOW,
      });
      assert.equal(all.length, 1);
    });

    it('treats scope as a value, not a wildcard', async () => {
      const store = await create();
      await store.upsertGrant({
        scope: OTHER,
        resource: DOC,
        subject: BOB,
        role: 'viewer',
        grantedBy: null,
        expiresAt: null,
      });

      const inOrg = await store.findGrants({
        scope: ORG,
        resourceType: DOC.type,
        resourceIds: [DOC.id],
        subjects: [BOB],
        now: new Date(),
      });
      assert.deepEqual(inOrg, []);

      const inOther = await store.findGrants({
        scope: OTHER,
        resourceType: DOC.type,
        resourceIds: [DOC.id],
        subjects: [BOB],
        now: new Date(),
      });
      assert.equal(inOther.length, 1);
    });

    it('matches subjects as exact (type, id) pairs', async () => {
      const store = await create();
      await store.upsertGrant({
        scope: ORG,
        resource: DOC,
        subject: { type: 'team', id: 'shared_id' },
        role: 'viewer',
        grantedBy: null,
        expiresAt: null,
      });

      // A subject list whose types and ids each appear in the row, but never
      // as the same pair. A naive `type IN (...) AND id IN (...)` query would
      // match; the contract says it must not.
      const decoy = await store.findGrants({
        scope: ORG,
        resourceType: DOC.type,
        resourceIds: [DOC.id],
        subjects: [
          { type: 'team', id: 'other_id' },
          { type: 'member', id: 'shared_id' },
        ],
        now: new Date(),
      });
      assert.deepEqual(decoy, []);

      const exact = await store.findGrants({
        scope: ORG,
        resourceType: DOC.type,
        resourceIds: [DOC.id],
        subjects: [{ type: 'team', id: 'shared_id' }],
        now: new Date(),
      });
      assert.equal(exact.length, 1);
    });

    it('hides expired grants from reads', async () => {
      const store = await create();
      await store.upsertGrant({
        scope: ORG,
        resource: DOC,
        subject: BOB,
        role: 'viewer',
        grantedBy: null,
        expiresAt: new Date('2020-01-01T00:00:00Z'),
      });

      const live = await store.findGrants({
        scope: ORG,
        resourceType: DOC.type,
        resourceIds: [DOC.id],
        subjects: [BOB],
        now: new Date('2026-01-01T00:00:00Z'),
      });
      assert.deepEqual(live, []);

      const withExpired = await store.listResourceGrants({
        scope: ORG,
        resource: DOC,
        now: NOW,
        includeExpired: true,
      });
      assert.equal(withExpired.length, 1);
    });

    it('batches several resource ids into one read', async () => {
      const store = await create();
      for (const id of ['doc_1', 'doc_2', 'doc_3']) {
        await store.upsertGrant({
          scope: ORG,
          resource: { type: 'document', id },
          subject: BOB,
          role: 'viewer',
          grantedBy: null,
          expiresAt: null,
        });
      }

      const found = await store.findGrants({
        scope: ORG,
        resourceType: 'document',
        resourceIds: ['doc_1', 'doc_3', 'doc_missing'],
        subjects: [BOB],
        now: new Date(),
      });

      assert.deepEqual(found.map((grant) => grant.resourceId).sort(), [
        'doc_1',
        'doc_3',
      ]);
    });

    it('lists a subject’s grants across a resource type', async () => {
      const store = await create();
      for (const id of ['doc_1', 'doc_2']) {
        await store.upsertGrant({
          scope: ORG,
          resource: { type: 'document', id },
          subject: BOB,
          role: 'viewer',
          grantedBy: null,
          expiresAt: null,
        });
      }
      await store.upsertGrant({
        scope: ORG,
        resource: { type: 'folder', id: 'fld_1' },
        subject: BOB,
        role: 'viewer',
        grantedBy: null,
        expiresAt: null,
      });

      const documents = await store.listSubjectGrants({
        scope: ORG,
        subjects: [BOB],
        resourceType: 'document',
        now: new Date(),
      });

      assert.deepEqual(documents.map((grant) => grant.resourceId).sort(), [
        'doc_1',
        'doc_2',
      ]);
    });

    it('counts limit/offset over live rows, not raw rows', async () => {
      // The trap: expired rows sort first. A store that hands `limit` to SQL
      // before filtering spends the whole budget on rows it then discards, and
      // returns nothing while the caller genuinely has access to two documents.
      const store = await create();

      for (const id of ['expired_1', 'expired_2', 'expired_3']) {
        await store.upsertGrant({
          scope: ORG,
          resource: { type: 'document', id },
          subject: BOB,
          role: 'viewer',
          grantedBy: null,
          expiresAt: new Date('2020-01-01T00:00:00Z'),
        });
      }
      for (const id of ['live_1', 'live_2']) {
        await store.upsertGrant({
          scope: ORG,
          resource: { type: 'document', id },
          subject: BOB,
          role: 'viewer',
          grantedBy: null,
          expiresAt: null,
        });
      }

      const page = await store.listSubjectGrants({
        scope: ORG,
        subjects: [BOB],
        resourceType: 'document',
        now: NOW,
        limit: 3,
      });

      assert.deepEqual(page.map((grant) => grant.resourceId).sort(), [
        'live_1',
        'live_2',
      ]);

      const offsetPage = await store.listSubjectGrants({
        scope: ORG,
        subjects: [BOB],
        resourceType: 'document',
        now: NOW,
        limit: 1,
        offset: 1,
      });

      assert.equal(offsetPage.length, 1);
      assert.equal(offsetPage[0]?.resourceId, 'live_2');
    });

    it('does not let superset subject rows consume the limit', async () => {
      // `(team, shared)` and `(member, other)` are decoys that a two-`IN`-clause
      // query matches but the exact-pair filter rejects.
      const store = await create();

      for (const subject of [
        { type: 'team', id: 'shared' },
        { type: 'member', id: 'other' },
      ]) {
        await store.upsertGrant({
          scope: ORG,
          resource: { type: 'document', id: `decoy_${subject.type}` },
          subject,
          role: 'viewer',
          grantedBy: null,
          expiresAt: null,
        });
      }
      await store.upsertGrant({
        scope: ORG,
        resource: { type: 'document', id: 'real' },
        subject: { type: 'member', id: 'shared' },
        role: 'viewer',
        grantedBy: null,
        expiresAt: null,
      });

      const page = await store.listSubjectGrants({
        scope: ORG,
        subjects: [{ type: 'member', id: 'shared' }],
        resourceType: 'document',
        now: NOW,
        limit: 2,
      });

      assert.deepEqual(
        page.map((grant) => grant.resourceId),
        ['real']
      );
    });

    it('honours the caller’s clock rather than the wall clock', async () => {
      const store = await create();
      await store.upsertGrant({
        scope: ORG,
        resource: DOC,
        subject: BOB,
        role: 'viewer',
        grantedBy: null,
        expiresAt: new Date('2026-06-01T00:00:00Z'),
      });

      assert.equal(
        (
          await store.listResourceGrants({
            scope: ORG,
            resource: DOC,
            now: new Date('2026-01-01T00:00:00Z'),
          })
        ).length,
        1
      );
      assert.equal(
        (
          await store.listResourceGrants({
            scope: ORG,
            resource: DOC,
            now: new Date('2026-12-01T00:00:00Z'),
          })
        ).length,
        0
      );
    });

    it('deletes at every granularity', async () => {
      const store = await create();
      const seed = async () => {
        for (const role of ['viewer', 'editor']) {
          await store.upsertGrant({
            scope: ORG,
            resource: DOC,
            subject: BOB,
            role,
            grantedBy: null,
            expiresAt: null,
          });
        }
        await store.upsertGrant({
          scope: ORG,
          resource: { type: 'document', id: 'doc_2' },
          subject: BOB,
          role: 'viewer',
          grantedBy: null,
          expiresAt: null,
        });
      };

      await seed();
      assert.equal(
        await store.deleteGrant({
          scope: ORG,
          resource: DOC,
          subject: BOB,
          role: 'editor',
        }),
        1
      );
      assert.equal(
        (
          await store.listResourceGrants({
            scope: ORG,
            resource: DOC,
            now: NOW,
          })
        ).length,
        1
      );

      assert.equal(
        await store.deleteSubjectGrantsOnResource({
          scope: ORG,
          resource: DOC,
          subject: BOB,
        }),
        1
      );

      await seed();
      assert.equal(
        await store.deleteResourceGrants({ scope: ORG, resource: DOC }),
        2
      );

      await seed();
      assert.equal(
        await store.deleteSubjectGrants({ scope: ORG, subject: BOB }),
        3
      );

      await seed();
      assert.equal(await store.deleteScopeGrants({ scope: ORG }), 3);
      assert.deepEqual(
        await store.listResourceGrants({ scope: ORG, resource: DOC, now: NOW }),
        []
      );
    });

    it('handles a null scope', async () => {
      const store = await create();
      await store.upsertGrant({
        scope: null,
        resource: DOC,
        subject: BOB,
        role: 'viewer',
        grantedBy: null,
        expiresAt: null,
      });

      const found = await store.findGrants({
        scope: null,
        resourceType: DOC.type,
        resourceIds: [DOC.id],
        subjects: [BOB],
        now: new Date(),
      });

      assert.equal(found.length, 1);
      assert.equal(found[0]?.scope, null);
    });

    it('returns nothing for empty inputs instead of everything', async () => {
      const store = await create();
      await store.upsertGrant({
        scope: ORG,
        resource: DOC,
        subject: BOB,
        role: 'viewer',
        grantedBy: null,
        expiresAt: null,
      });

      assert.deepEqual(
        await store.findGrants({
          scope: ORG,
          resourceType: DOC.type,
          resourceIds: [],
          subjects: [BOB],
          now: new Date(),
        }),
        []
      );
      assert.deepEqual(
        await store.findGrants({
          scope: ORG,
          resourceType: DOC.type,
          resourceIds: [DOC.id],
          subjects: [],
          now: new Date(),
        }),
        []
      );
    });
  });
}

storeContract('memory', () => Promise.resolve(memoryGrantStore()));
storeContract('better-auth adapter', betterAuthStore);

describe('Better Auth grant pagination', () => {
  it('reads every page for all grant queries, including offset without limit', async () => {
    const seed = Array.from({ length: 505 }, (_, index) => ({
      id: `grant_${index}`,
      scope: ORG,
      resourceType: DOC.type,
      resourceId: DOC.id,
      subjectType: BOB.type,
      subjectId: BOB.id,
      role: `role_${index}`,
      expiresAt: null,
      createdAt: new Date(NOW.getTime() + index),
      updatedAt: NOW,
    }));
    const store = await betterAuthStore(seed);
    assert.equal(
      (
        await store.findGrants({
          scope: ORG,
          resourceType: DOC.type,
          resourceIds: [DOC.id],
          subjects: [BOB],
          now: NOW,
        })
      ).length,
      505
    );
    assert.equal(
      (
        await store.listResourceGrants({
          scope: ORG,
          resource: DOC,
          now: NOW,
          includeExpired: true,
        })
      ).length,
      505
    );
    const query = {
      scope: ORG,
      resourceType: DOC.type,
      subjects: [BOB],
      now: NOW,
    };
    assert.equal((await store.listSubjectGrants(query)).length, 505);
    const remaining = await store.listSubjectGrants({ ...query, offset: 502 });
    assert.deepEqual(
      remaining.map((grant) => grant.role),
      ['role_502', 'role_503', 'role_504']
    );
    assert.deepEqual(
      (await store.listSubjectGrants({ ...query, offset: 502, limit: 2 })).map(
        (grant) => grant.role
      ),
      ['role_502', 'role_503']
    );
    assert.deepEqual(await store.listSubjectGrants({ ...query, limit: 0 }), []);

    const engine = createRobrac({
      store,
      resources: {
        document: defineResource({
          type: 'document',
          statements: { document: ['read'] },
          roles: Object.fromEntries(
            seed.map((grant) => [grant.role, { document: ['read'] }])
          ),
          load: ({ id }) => ({ id }),
          scope: () => ORG,
          manage: { document: ['read'] },
        }),
      },
    });
    await engine.grants.set({
      type: DOC.type,
      id: DOC.id,
      scope: ORG,
      subject: BOB,
      roles: ['role_504'],
    });
    const replaced = await store.listResourceGrants({
      scope: ORG,
      resource: DOC,
      now: NOW,
      includeExpired: true,
    });
    assert.deepEqual(
      replaced.map((grant) => grant.role),
      ['role_504']
    );
  });
});
