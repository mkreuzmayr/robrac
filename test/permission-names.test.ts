import assert from 'node:assert/strict';
import { it } from 'node:test';

import {
  buildPermissionMatrix,
  checkPermissions,
  constantMatrix,
  createRobrac,
  defineResource,
  extendRole,
  memoryGrantStore,
  normalizeRoles,
  RobracError,
} from '../src/index.ts';

for (const name of ['constructor', 'toString', '__proto__']) {
  it(`supports ${name} as a role, facet and action`, () => {
    const statements = { [name]: [name, 'read'] };
    const roles = normalizeRoles({
      [name]: { [name]: [name] },
      editor: extendRole([name], { [name]: ['read'] }),
    });
    const matrix = buildPermissionMatrix(statements, roles, ['editor']);
    assert.equal(checkPermissions(matrix, { [name]: [name, 'read'] }), true);
    assert.equal(Object.hasOwn(matrix, name), true);
    assert.equal(Object.hasOwn(matrix[name]!, name), true);
    assert.deepEqual(JSON.parse(JSON.stringify(matrix)), {
      [name]: { [name]: true, read: true },
    });
    assert.equal(
      checkPermissions(constantMatrix(statements, false), { [name]: [name] }),
      false
    );
  });

  it(`rejects undeclared role ${name} and ignores stale grants`, async () => {
    assert.throws(
      () => normalizeRoles({ viewer: extendRole([name], {}) }),
      (error: unknown) =>
        error instanceof RobracError && error.code === 'INVALID_CONFIGURATION'
    );
    const statements = { document: ['read'] };
    const roles = { viewer: { document: ['read'] } };
    assert.equal(
      buildPermissionMatrix(statements, normalizeRoles(roles), [name]).document
        .read,
      false
    );
    const engine = createRobrac({
      scope: 'disabled',
      store: memoryGrantStore(),
      resources: {
        document: defineResource({
          type: 'document',
          statements,
          roles,
          load: ({ id }) => ({ id }),
          manage: { document: ['read'] },
        }),
      },
    });
    await assert.rejects(
      engine.grants.grant({
        type: 'document',
        id: 'doc_1',
        subject: { type: 'user', id: 'user_1' },
        role: name as 'viewer',
      }),
      (error: unknown) =>
        error instanceof RobracError && error.code === 'UNKNOWN_ROLE'
    );
  });
}

it('does not accept permissions inherited from a matrix prototype', () => {
  const matrix = Object.create({ document: { read: true } }) as Record<
    string,
    Record<string, boolean>
  >;
  assert.equal(checkPermissions(matrix, { document: ['read'] }), false);
  const row = Object.create({ read: true }) as Record<string, boolean>;
  assert.equal(
    checkPermissions({ document: row }, { document: ['read'] }),
    false
  );
});
