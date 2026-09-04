import assert from 'node:assert/strict';
import { it } from 'node:test';

import {
  createRobrac,
  defineResource,
  memoryGrantStore,
} from '../src/index.ts';

const grant = {
  scope: null,
  resource: { type: 'document', id: 'doc' },
  subject: { type: 'user', id: 'alice' },
  role: 'viewer',
  grantedBy: null,
  expiresAt: null,
};

it('rolls back a role replacement when an insert fails', async () => {
  let nextId = 0;
  const store = memoryGrantStore({
    generateId: () => {
      if (++nextId === 3) throw new Error('Insert failed');
      return `grant_${nextId}`;
    },
  });
  const original = await store.upsertGrant(grant);
  const engine = createRobrac({
    scope: 'disabled',
    store,
    resources: {
      document: defineResource({
        type: 'document',
        statements: { document: ['read'] },
        roles: {
          viewer: { document: ['read'] },
          editor: { document: ['read'] },
          owner: { document: ['read'] },
        },
        load: ({ id }) => ({ id }),
        manage: { document: ['read'] },
      }),
    },
  });
  await assert.rejects(
    engine.grants.set({
      type: 'document',
      id: 'doc',
      subject: grant.subject,
      roles: ['editor', 'owner'],
    }),
    /Insert failed/
  );
  assert.deepEqual(store.all(), [original]);
});

it('publishes writes together only after a transaction succeeds', async () => {
  const store = memoryGrantStore();
  const original = await store.upsertGrant(grant);
  const ready = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const transaction = store.transaction!(async (tx) => {
    await tx.deleteScopeGrants({ scope: null });
    ready.resolve();
    await release.promise;
    await tx.upsertGrant({ ...grant, role: 'editor' });
  });
  await ready.promise;
  const during = store.all();
  release.resolve();
  await transaction;
  assert.deepEqual(during, [original]);
  assert.deepEqual(
    store.all().map((row) => row.role),
    ['editor']
  );
});

it('rejects a conflicting commit without losing concurrent writes', async () => {
  const store = memoryGrantStore();
  const original = await store.upsertGrant(grant);
  const ready = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const transaction = store.transaction!(async (tx) => {
    await tx.deleteScopeGrants({ scope: null });
    ready.resolve();
    await release.promise;
  });
  await ready.promise;
  const concurrent = await store.upsertGrant({ ...grant, role: 'editor' });
  const rejected = assert.rejects(transaction, /conflict/i);
  release.resolve();
  await rejected;
  assert.deepEqual(store.all(), [original, concurrent]);
});

it('isolates returned rows and nested rollback from the parent store', async () => {
  const store = memoryGrantStore();
  const original = await store.upsertGrant(grant);
  await store.transaction!(async (tx) => {
    await assert.rejects(
      tx.transaction!(async (nested) => {
        const [row] = await nested.listResourceGrants({
          scope: null,
          resource: grant.resource,
          now: new Date(),
        });
        assert.ok(row);
        row.role = 'owner';
        row.createdAt.setFullYear(2000);
        await nested.deleteScopeGrants({ scope: null });
        throw new Error('Rollback nested');
      }),
      /Rollback nested/
    );
    assert.deepEqual(
      await tx.listResourceGrants({
        scope: null,
        resource: grant.resource,
        now: new Date(),
      }),
      [original]
    );
    await tx.upsertGrant({ ...grant, role: 'editor' });
  });
  assert.deepEqual(
    store.all().map((row) => row.role),
    ['viewer', 'editor']
  );
});
