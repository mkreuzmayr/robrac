import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { defineResource } from '../src/index.ts';
import { createTestRobrac } from '../src/testing.ts';
import {
  at,
  createData,
  member,
  ORG,
  OTHER_ORG,
  registry,
} from './fixtures.ts';

function setup(maxInheritanceDepth?: number) {
  const data = createData();
  const robrac = createTestRobrac({
    resources: registry(data),
    now: at('2026-01-01'),
    maxInheritanceDepth,
  });
  const grantFolder = (
    id: string,
    role: 'viewer' | 'owner',
    expiresAt?: Date
  ) =>
    robrac.grants.grant({
      type: 'folder',
      id,
      scope: ORG,
      subject: member('m_bob')[0]!,
      role,
      expiresAt,
    });
  const doc = (id: string) =>
    robrac.evaluate({
      type: 'document',
      id,
      scope: ORG,
      subjects: member('m_bob'),
    });
  return { data, robrac, grantFolder, doc };
}

describe('resource hierarchy', () => {
  it('cascades a folder grant to its documents', async () => {
    const { data, grantFolder, doc } = setup();
    data.folders.set('f1', { id: 'f1', organizationId: ORG });
    data.documents.set('d1', { id: 'd1', organizationId: ORG, folderId: 'f1' });
    await grantFolder('f1', 'owner');

    const decision = await doc('d1');
    assert.equal(decision.permissions.document.delete, true);
    assert.deepEqual(decision.roles, [
      { role: 'owner', origin: 'inherited', via: { type: 'folder', id: 'f1' } },
    ]);
  });

  it('propagates a deny override to every descendant', async () => {
    const { data, grantFolder, doc } = setup();
    data.folders.set('root', { id: 'root', organizationId: ORG, hold: true });
    data.folders.set('f1', { id: 'f1', organizationId: ORG, parentId: 'root' });
    data.documents.set('d1', {
      id: 'd1',
      organizationId: ORG,
      folderId: 'f1',
    });
    await grantFolder('f1', 'owner');

    const decision = await doc('d1');
    assert.equal(decision.override, 'deny');
    assert.equal(decision.permissions.document.read, false);
  });

  it('blocks grant management on descendants of a denied ancestor', async () => {
    const { data, robrac, grantFolder } = setup();
    data.folders.set('f1', { id: 'f1', organizationId: ORG, hold: true });
    data.documents.set('d1', { id: 'd1', organizationId: ORG, folderId: 'f1' });
    await grantFolder('f1', 'owner');
    await robrac.grants.grant({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subject: member('m_bob')[0]!,
      role: 'owner',
    });
    await assert.rejects(
      robrac.authorized.revoke({
        type: 'document',
        id: 'd1',
        scope: ORG,
        actor: member('m_bob'),
        subject: member('m_bob')[0]!,
      }),
      { code: 'FORBIDDEN' }
    );
  });

  it('drops role names a type does not declare', async () => {
    const space = defineResource({
      type: 'space',
      statements: { space: ['read'] },
      roles: { admin: { space: ['read'] } },
      load: ({ id }) => ({ id }),
      manage: { space: ['read'] },
    });
    const page = defineResource({
      type: 'page',
      statements: { page: ['read'] },
      roles: { reader: { page: ['read'] } },
      load: ({ id }) => ({ id }),
      computeRoles: ({ roles }) => {
        roles.push('ghost' as never);
      },
      parent: () => ({ type: 'space', id: 's1' }),
      inheritRole: ({ role }) => (role === 'admin' ? 'phantom' : role) as never,
      manage: { page: ['read'] },
    });
    const robrac = createTestRobrac({
      resources: { space, page },
      scope: 'disabled',
    });
    const subject = { type: 'user', id: 'u' };
    await robrac.grants.grant({
      type: 'space',
      id: 's1',
      subject,
      role: 'admin',
    });
    await robrac.store.upsertGrant({
      scope: null,
      resource: { type: 'space', id: 's1' },
      subject,
      role: 'reader',
      grantedBy: null,
      expiresAt: null,
    });

    const decision = await robrac.evaluate({
      type: 'page',
      id: 'p1',
      subjects: [subject],
    });
    assert.deepEqual(decision.roles, []);
    assert.equal(decision.permissions.page.read, false);
  });

  it('lets an inherited role expire with the ancestor grant', async () => {
    const { data, robrac, grantFolder, doc } = setup();
    data.folders.set('f1', { id: 'f1', organizationId: ORG });
    data.documents.set('d1', { id: 'd1', organizationId: ORG, folderId: 'f1' });
    await grantFolder('f1', 'viewer', at('2026-01-02'));

    assert.equal((await doc('d1')).permissions.document.read, true);
    robrac.clock.now = at('2026-01-03');
    assert.equal((await doc('d1')).permissions.document.read, false);
  });

  it('ignores an ancestor in another tenant', async () => {
    const { data, robrac, doc } = setup();
    data.folders.set('f_other', { id: 'f_other', organizationId: OTHER_ORG });
    data.documents.set('d1', {
      id: 'd1',
      organizationId: ORG,
      folderId: 'f_other',
    });
    await robrac.grants.grant({
      type: 'folder',
      id: 'f_other',
      scope: ORG,
      subject: member('m_bob')[0]!,
      role: 'owner',
    });
    assert.equal((await doc('d1')).permissions.document.read, false);
  });

  it('rejects a parent() type outside parentTypes or the registry', async () => {
    for (const [parentType, parentTypes] of [
      ['document', ['folder']],
      ['workspace', undefined],
    ] as const) {
      const data = createData();
      const resources = registry(data);
      const robrac = createTestRobrac({
        resources: {
          ...resources,
          document: {
            ...resources.document,
            parent: () => ({ type: parentType, id: 'd1' }),
            parentTypes,
          },
        },
      });
      data.documents.set('d1', { id: 'd1', organizationId: ORG });
      await assert.rejects(
        robrac.evaluate({
          type: 'document',
          id: 'd1',
          scope: ORG,
          subjects: [],
        }),
        { code: 'INVALID_CONFIGURATION' }
      );
    }
  });

  it('stops at maxInheritanceDepth', async () => {
    const { data, grantFolder, doc } = setup(1);
    data.folders.set('root', { id: 'root', organizationId: ORG });
    data.folders.set('f1', { id: 'f1', organizationId: ORG, parentId: 'root' });
    data.documents.set('d1', { id: 'd1', organizationId: ORG, folderId: 'f1' });
    await grantFolder('root', 'owner');
    assert.equal((await doc('d1')).permissions.document.read, false);
  });

  it('tolerates a parent cycle', async () => {
    const { data, grantFolder, doc } = setup(64);
    data.folders.set('a', { id: 'a', organizationId: ORG, parentId: 'b' });
    data.folders.set('b', { id: 'b', organizationId: ORG, parentId: 'a' });
    data.documents.set('d1', { id: 'd1', organizationId: ORG, folderId: 'a' });
    await grantFolder('b', 'viewer');
    assert.equal((await doc('d1')).permissions.document.read, true);
  });
});
