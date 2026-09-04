import assert from 'node:assert/strict';
import { it } from 'node:test';

import {
  createRobrac,
  defineResource,
  memoryGrantStore,
  RobracError,
} from '../src/index.ts';

const actor = [{ type: 'user', id: 'alice' }];

for (const override of ['allow', 'deny'] as const) {
  it(`${override} short-circuits grant reads, computed roles and parents`, async () => {
    const unexpected = () => {
      throw new Error('Role evaluation must not run');
    };
    const engine = createRobrac({
      scope: 'disabled',
      store: { ...memoryGrantStore(), findGrants: unexpected },
      resources: {
        document: defineResource({
          type: 'document',
          statements: { document: ['read'] },
          roles: { viewer: { document: ['read'] } },
          load: ({ id }) => ({ id }),
          override: () => override,
          computeRoles: unexpected,
          parent: unexpected,
          manage: { document: ['read'] },
        }),
      },
    });
    assert.equal(
      await engine.check({
        type: 'document',
        id: 'doc',
        subjects: actor,
        permissions: { document: ['read'] },
      }),
      override === 'allow'
    );
  });
}

it('a deny override blocks custom grant-management predicates and audits the denial', async () => {
  let calls = 0;
  const verdicts: boolean[] = [];
  const store = memoryGrantStore();
  const engine = createRobrac({
    scope: 'disabled',
    store,
    onDecision: ({ allowed }) => {
      if (allowed !== undefined) verdicts.push(allowed);
    },
    resources: {
      document: defineResource({
        type: 'document',
        statements: { document: ['read'] },
        roles: { viewer: { document: ['read'] } },
        load: ({ id }) => ({ id }),
        override: () => 'deny',
        manage: () => {
          calls++;
          return true;
        },
      }),
    },
  });
  const args = { type: 'document' as const, id: 'doc', actor };
  for (const operation of [
    () => engine.authorized.listGrants(args),
    () =>
      engine.authorized.grant({ ...args, subject: actor[0]!, role: 'viewer' }),
    () =>
      engine.authorized.setRoles({ ...args, subject: actor[0]!, roles: [] }),
    () => engine.authorized.revoke({ ...args, subject: actor[0]! }),
  ]) {
    await assert.rejects(
      operation,
      (error: unknown) =>
        error instanceof RobracError && error.code === 'FORBIDDEN'
    );
  }
  assert.equal(calls, 0);
  assert.deepEqual(verdicts, [false, false, false, false]);
  assert.deepEqual(store.all(), []);
});

it('a denied ancestor contributes no roles but does not erase direct child grants', async () => {
  const engine = createRobrac({
    scope: 'disabled',
    store: memoryGrantStore(),
    resources: {
      folder: defineResource({
        type: 'folder',
        statements: { folder: ['read'] },
        roles: { viewer: { folder: ['read'] } },
        load: ({ id }) => ({ id }),
        override: () => 'deny',
        manage: { folder: ['read'] },
      }),
      document: defineResource({
        type: 'document',
        statements: { document: ['read'] },
        roles: { viewer: { document: ['read'] } },
        load: ({ id }) => ({ id }),
        parent: () => ({ type: 'folder', id: 'folder' }),
        manage: { document: ['read'] },
      }),
    },
  });
  await engine.grants.grant({
    type: 'folder',
    id: 'folder',
    subject: actor[0]!,
    role: 'viewer',
  });
  const query = {
    type: 'document' as const,
    id: 'doc',
    subjects: actor,
    permissions: { document: ['read'] as const },
  };
  assert.equal(await engine.check(query), false);
  await engine.grants.grant({
    type: 'document',
    id: 'doc',
    subject: actor[0]!,
    role: 'viewer',
  });
  assert.equal(await engine.check(query), true);
});
