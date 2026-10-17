import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { memoryAdapter } from 'better-auth/adapters/memory';

import { betterAuthGrantStore, memoryGrantStore } from '../src/index.ts';
import type { BetterAuthAdapterLike, GrantStore } from '../src/index.ts';
import { at, member, ORG } from './fixtures.ts';

function betterAuthAdapter(): BetterAuthAdapterLike {
  const factory = memoryAdapter({ robracGrant: [] });
  return factory({
    plugins: [
      {
        id: 'robrac-test',
        schema: {
          robracGrant: {
            fields: {
              scope: { type: 'string', required: false },
              resourceType: { type: 'string' },
              resourceId: { type: 'string' },
              subjectType: { type: 'string' },
              subjectId: { type: 'string' },
              role: { type: 'string' },
              grantedBySubjectType: { type: 'string', required: false },
              grantedBySubjectId: { type: 'string', required: false },
              expiresAt: { type: 'date', required: false },
              createdAt: { type: 'date' },
              updatedAt: { type: 'date' },
            },
          },
        },
      },
    ],
  });
}

const NOW = at('2026-01-01');
const doc = (id: string) => ({ type: 'document', id });
const bob = member('m_bob')[0]!;

function upsert(
  store: GrantStore,
  overrides: Partial<Parameters<GrantStore['upsertGrant']>[0]> = {}
) {
  return store.upsertGrant({
    scope: ORG,
    resource: doc('d1'),
    subject: bob,
    role: 'viewer',
    grantedBy: null,
    expiresAt: null,
    now: NOW,
    ...overrides,
  });
}

const stores: [string, () => GrantStore][] = [
  ['memory', () => memoryGrantStore()],
  ['better-auth', () => betterAuthGrantStore({ adapter: betterAuthAdapter() })],
];

for (const [name, create] of stores) {
  describe(`GrantStore contract: ${name}`, () => {
    it('treats a null scope as a value, not a wildcard', async () => {
      const store = create();
      await upsert(store, { scope: null });
      await upsert(store, { scope: ORG, role: 'editor' });
      const rows = await store.listResourceGrants({
        scope: null,
        resource: doc('d1'),
        now: NOW,
      });
      assert.deepEqual(
        rows.map((row) => row.role),
        ['viewer']
      );
    });

    it('filters expired rows unless asked for them', async () => {
      const store = create();
      await upsert(store, { expiresAt: at('2026-01-02') });
      const query = { scope: ORG, resource: doc('d1'), now: at('2026-01-02') };
      assert.equal((await store.listResourceGrants(query)).length, 0);
      assert.equal(
        (await store.listResourceGrants({ ...query, includeExpired: true }))
          .length,
        1
      );
    });

    it('keeps one row per tuple and refreshes its expiry', async () => {
      const store = create();
      await Promise.all([upsert(store), upsert(store), upsert(store)]);
      await upsert(store, { expiresAt: at('2026-01-05') });
      const rows = await store.listResourceGrants({
        scope: ORG,
        resource: doc('d1'),
        now: NOW,
      });
      assert.equal(rows.length, 1);
      assert.deepEqual(rows[0]!.expiresAt, at('2026-01-05'));
    });

    it('applies limit and offset after expiry filtering', async () => {
      const store = create();
      for (let index = 0; index < 6; index++) {
        await upsert(store, {
          resource: doc(`d${index}`),
          expiresAt: index % 2 === 0 ? at('2026-01-02') : null,
        });
      }
      const page = await store.listSubjectGrants({
        scope: ORG,
        subjects: [bob],
        resourceType: 'document',
        now: at('2026-01-03'),
        limit: 2,
        offset: 1,
      });
      const all = await store.listSubjectGrants({
        scope: ORG,
        subjects: [bob],
        resourceType: 'document',
        now: at('2026-01-03'),
      });
      assert.equal(all.length, 3);
      assert.deepEqual(page, all.slice(1, 3));
    });

    it('pages through subject grants without gaps or repeats', async () => {
      const store = create();
      for (let index = 0; index < 650; index++) {
        await upsert(store, { resource: doc(`d${index}`) });
      }
      const seen: string[] = [];
      for (let offset = 0; offset < 650; offset += 100) {
        const page = await store.listSubjectGrants({
          scope: ORG,
          subjects: [bob],
          resourceType: 'document',
          now: NOW,
          limit: 100,
          offset,
        });
        seen.push(...page.map((grant) => grant.id));
      }
      assert.equal(new Set(seen).size, 650);
    });

    it('matches exact subject pairs', async () => {
      const store = create();
      await upsert(store, { subject: { type: 'member', id: 'x' } });
      await upsert(store, { subject: { type: 'team', id: 'y' } });
      const rows = await store.findGrants({
        scope: ORG,
        resourceType: 'document',
        resourceIds: ['d1'],
        subjects: [
          { type: 'member', id: 'y' },
          { type: 'team', id: 'x' },
        ],
        now: NOW,
      });
      assert.deepEqual(rows, []);
    });

    it('reads and deletes every row past the adapter page size', async () => {
      const store = create();
      for (let index = 0; index < 620; index++) {
        await upsert(store, { subject: { type: 'member', id: `m${index}` } });
      }
      await upsert(store, { resource: doc('d2') });
      const list = (id: string) =>
        store.listResourceGrants({ scope: ORG, resource: doc(id), now: NOW });
      assert.equal((await list('d1')).length, 620);

      assert.equal(
        await store.deleteResourceGrants({ scope: ORG, resource: doc('d1') }),
        620
      );
      assert.equal((await list('d1')).length, 0);
      assert.equal((await list('d2')).length, 1);
    });
  });
}

describe('betterAuthGrantStore', () => {
  it('stays exact under a case-insensitive database collation', async () => {
    const inner = betterAuthAdapter();
    const insensitive = <T extends { where?: object[] }>(query: T): T => ({
      ...query,
      where: query.where?.map((clause) => ({ ...clause, mode: 'insensitive' })),
    });
    const store = betterAuthGrantStore({
      adapter: {
        ...inner,
        findMany: (query) => inner.findMany(insensitive(query)),
        findOne: (query) => inner.findOne(insensitive(query)),
        deleteMany: (query) => inner.deleteMany(insensitive(query)),
      },
    });
    await upsert(store, { resource: doc('Doc') });
    await upsert(store, { resource: doc('doc'), expiresAt: at('2026-02-01') });
    const list = (id: string) =>
      store.listResourceGrants({ scope: ORG, resource: doc(id), now: NOW });

    assert.equal((await list('Doc')).length, 1);
    assert.equal((await list('Doc'))[0]!.expiresAt, null);
    await store.deleteResourceGrants({ scope: ORG, resource: doc('doc') });
    assert.equal((await list('Doc')).length, 1);
    assert.equal((await list('doc')).length, 0);
  });

  it('fails cleanly when the database alters a stored value', async () => {
    const inner = betterAuthAdapter();
    const store = betterAuthGrantStore({
      adapter: {
        ...inner,
        create: (query) =>
          inner.create({
            ...query,
            data: { ...query.data, subjectId: 'altered' },
          }),
      },
    });
    await assert.rejects(upsert(store), /does not read back/);
    assert.deepEqual(await inner.findMany({ model: 'robracGrant' }), []);
  });

  it('survives a revoke between creating and reading a grant', async () => {
    const inner = betterAuthAdapter();
    const store = betterAuthGrantStore({
      adapter: {
        ...inner,
        create: async <T extends Record<string, unknown>, R = T>(query: {
          model: string;
          data: Omit<T, 'id'>;
        }) => {
          const row = await inner.create<T, R>(query);
          await inner.deleteMany({ model: 'robracGrant', where: [] });
          return row;
        },
      },
    });
    assert.equal((await upsert(store)).role, 'viewer');
  });

  it('only advertises a transaction the adapter really provides', () => {
    const real = betterAuthGrantStore({ adapter: betterAuthAdapter() });
    assert.equal(typeof real.transaction, 'function');

    const passThrough = {
      ...betterAuthAdapter(),
      options: { adapterConfig: { transaction: false } },
    };
    assert.equal(
      typeof betterAuthGrantStore({ adapter: passThrough }).transaction,
      'undefined'
    );
  });
});

describe('memoryGrantStore', () => {
  it('hands out copies of its rows', async () => {
    const store = memoryGrantStore();
    const grant = await upsert(store);
    grant.role = 'owner';
    (
      await store.findGrants({
        scope: ORG,
        resourceType: 'document',
        resourceIds: ['d1'],
        subjects: [bob],
        now: NOW,
      })
    )[0]!.expiresAt = new Date(0);
    assert.deepEqual(
      store.all().map((row) => [row.role, row.expiresAt]),
      [['viewer', null]]
    );
  });

  it('discards a failed transaction and keeps concurrent writes', async () => {
    const store = memoryGrantStore();
    await assert.rejects(
      store.transaction!(async (tx) => {
        await upsert(tx, { role: 'owner' });
        await upsert(store, { role: 'editor' });
        throw new Error('boom');
      })
    );
    assert.deepEqual(
      store.all().map((row) => row.role),
      ['editor']
    );

    await store.transaction!(async (tx) => {
      await tx.deleteGrant({
        scope: ORG,
        resource: doc('d1'),
        subject: bob,
        role: 'editor',
      });
      await upsert(tx, { role: 'owner' });
    });
    assert.deepEqual(
      store.all().map((row) => row.role),
      ['owner']
    );
  });
});
