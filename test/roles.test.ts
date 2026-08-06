import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  buildPermissionMatrix,
  checkPermissions,
  constantMatrix,
  extendRole,
  normalizeRoles,
  RobracError,
} from '../src/index.ts';

const statements = {
  document: ['read', 'update', 'delete', 'share'],
  comment: ['read', 'write'],
} as const;

describe('normalizeRoles', () => {
  it('flattens a chain of extends', () => {
    const roles = normalizeRoles({
      viewer: { document: ['read'] },
      editor: extendRole(['viewer'], { document: ['update'] }),
      owner: extendRole(['editor'], { document: ['delete', 'share'] }),
    });

    assert.deepEqual(roles.owner?.effective.document, [
      'read',
      'update',
      'delete',
      'share',
    ]);
    assert.deepEqual(roles.viewer?.effective.document, ['read']);
  });

  it('merges several parents', () => {
    const roles = normalizeRoles({
      reader: { document: ['read'] },
      commenter: { comment: ['write'] },
      both: extendRole(['reader', 'commenter'], {}),
    });

    assert.deepEqual(roles.both?.effective, {
      document: ['read'],
      comment: ['write'],
    });
  });

  it('rejects inheritance cycles', () => {
    assert.throws(
      () =>
        normalizeRoles({
          a: extendRole(['b'], {}),
          b: extendRole(['a'], {}),
        }),
      (error: unknown) =>
        error instanceof RobracError &&
        error.code === 'INVALID_CONFIGURATION' &&
        /cycle/i.test(error.message)
    );
  });

  it('rejects extending an undeclared role', () => {
    assert.throws(
      () => normalizeRoles({ a: extendRole(['ghost'], {}) }),
      (error: unknown) =>
        error instanceof RobracError && error.code === 'INVALID_CONFIGURATION'
    );
  });

  it('accepts Better Auth role objects', () => {
    // `createAccessControl(...).newRole(...)` returns `{ statements, authorize }`.
    const betterAuthRole = {
      statements: { document: ['read', 'update'] },
      authorize: () => ({ success: true }) as const,
    };

    const roles = normalizeRoles({ editor: betterAuthRole });
    assert.deepEqual(roles.editor?.effective.document, ['read', 'update']);
  });
});

describe('buildPermissionMatrix', () => {
  const roles = normalizeRoles({
    viewer: { document: ['read'], comment: ['read'] },
    editor: extendRole(['viewer'], { document: ['update'] }),
    admin: { document: ['*'], comment: ['*'] },
  });

  it('unions the permissions of several roles', () => {
    const matrix = buildPermissionMatrix(statements, roles, [
      'viewer',
      'editor',
    ]);

    assert.equal(matrix.document.read, true);
    assert.equal(matrix.document.update, true);
    assert.equal(matrix.document.delete, false);
    assert.equal(matrix.comment.write, false);
  });

  it('expands the action wildcard to every declared action', () => {
    const matrix = buildPermissionMatrix(statements, roles, ['admin']);

    assert.deepEqual(matrix.document, {
      read: true,
      update: true,
      delete: true,
      share: true,
    });
  });

  it('ignores role names that no longer exist', () => {
    // A grant row can outlive the role that created it. A dangling role must
    // never widen access.
    const matrix = buildPermissionMatrix(statements, roles, ['deleted-role']);

    assert.equal(matrix.document.read, false);
  });

  it('materializes every declared action, including denied ones', () => {
    const matrix = buildPermissionMatrix(statements, roles, []);

    assert.deepEqual(Object.keys(matrix).sort(), ['comment', 'document']);
    assert.deepEqual(Object.keys(matrix.document).sort(), [
      'delete',
      'read',
      'share',
      'update',
    ]);
  });
});

describe('checkPermissions', () => {
  const allow = constantMatrix(statements, true);
  const deny = constantMatrix(statements, false);
  const readOnly = buildPermissionMatrix(
    statements,
    normalizeRoles({ viewer: { document: ['read'] } }),
    ['viewer']
  );

  it('requires every requested action by default', () => {
    assert.equal(checkPermissions(readOnly, { document: ['read'] }), true);
    assert.equal(
      checkPermissions(readOnly, { document: ['read', 'update'] }),
      false
    );
  });

  it('honours an OR connector between actions', () => {
    assert.equal(
      checkPermissions(readOnly, {
        document: { actions: ['read', 'update'], connector: 'OR' },
      }),
      true
    );
  });

  it('honours an OR connector between facets', () => {
    assert.equal(
      checkPermissions(readOnly, { document: ['read'], comment: ['write'] }),
      false
    );
    assert.equal(
      checkPermissions(
        readOnly,
        { document: ['read'], comment: ['write'] },
        'OR'
      ),
      true
    );
  });

  it('never satisfies an empty request', () => {
    // Asking for nothing must not read as "allowed" — an accidentally empty
    // permission object is a bug, not a green light.
    assert.equal(checkPermissions(allow, {}), false);
    assert.equal(checkPermissions(allow, { document: [] }), false);
  });

  it('denies unknown facets and actions', () => {
    // These are compile errors against a concrete statement map; the runtime
    // guard matters because requests also arrive as untyped JSON.
    // @ts-expect-error 'ghost' is not a declared facet
    assert.equal(checkPermissions(allow, { ghost: ['read'] }), false);
    // @ts-expect-error 'ghost' is not a declared action
    assert.equal(checkPermissions(allow, { document: ['ghost'] }), false);
    assert.equal(checkPermissions(deny, { document: ['read'] }), false);
  });
});
