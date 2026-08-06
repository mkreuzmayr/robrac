import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { defineResource } from '../src/index.ts';
import { createTestRobrac, subjects } from '../src/testing.ts';
import { createFixture, registry } from './fixtures.ts';

const ORG = 'org_1';
const bob = subjects(['user', 'u_bob'], ['member', 'm_bob']);

function setup() {
  const fixture = createFixture();
  fixture.folders.set('fld_root', {
    id: 'fld_root',
    organizationId: ORG,
    name: 'Root',
  });
  fixture.documents.set('doc_in_folder', {
    id: 'doc_in_folder',
    organizationId: ORG,
    folderId: 'fld_root',
    createdBy: 'u_alice',
    visibility: 'private',
  });
  fixture.documents.set('doc_loose', {
    id: 'doc_loose',
    organizationId: ORG,
    folderId: null,
    createdBy: 'u_alice',
    visibility: 'private',
  });

  return {
    fixture,
    robrac: createTestRobrac({ resources: registry(fixture) }),
  };
}

describe('parent inheritance', () => {
  it('cascades a folder grant onto the documents inside it', async () => {
    const { robrac } = setup();

    await robrac.grants.grant({
      type: 'folder',
      id: 'fld_root',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'editor',
    });

    const decision = await robrac.evaluate({
      type: 'document',
      id: 'doc_in_folder',
      scope: ORG,
      subjects: bob,
    });

    assert.deepEqual(decision.effectiveRoles, ['editor']);
    assert.equal(decision.permissions.document.update, true);
    assert.equal(decision.permissions.document.delete, false);

    const inherited = decision.roles[0];
    assert.equal(inherited?.origin, 'inherited');
    assert.deepEqual(inherited?.via, { type: 'folder', id: 'fld_root' });
  });

  it('leaves documents outside the folder untouched', async () => {
    const { robrac } = setup();

    await robrac.grants.grant({
      type: 'folder',
      id: 'fld_root',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'owner',
    });

    const decision = await robrac.evaluate({
      type: 'document',
      id: 'doc_loose',
      scope: ORG,
      subjects: bob,
    });

    assert.deepEqual(decision.effectiveRoles, []);
  });

  it('drops ancestor roles the child does not declare', async () => {
    const fixture = createFixture();
    fixture.folders.set('fld_1', {
      id: 'fld_1',
      organizationId: ORG,
      name: 'F',
    });
    fixture.documents.set('doc_1', {
      id: 'doc_1',
      organizationId: ORG,
      folderId: 'fld_1',
      createdBy: 'u_alice',
      visibility: 'private',
    });

    const robrac = createTestRobrac({
      resources: {
        folder: defineResource({
          type: 'folder',
          statements: { folder: ['read', 'share'] },
          roles: { auditor: { folder: ['read'] } },
          load: ({ id }) => fixture.folders.get(id) ?? null,
          scope: (folder) => folder.organizationId,
          manage: { folder: ['share'] },
        }),
        document: defineResource({
          type: 'document',
          statements: { document: ['read'] },
          roles: { viewer: { document: ['read'] } },
          load: ({ id }) => fixture.documents.get(id) ?? null,
          scope: (document) => document.organizationId,
          parent: ({ data }) =>
            data.folderId ? { type: 'folder', id: data.folderId } : null,
          manage: { document: ['read'] },
        }),
      },
    });

    await robrac.grants.grant({
      type: 'folder',
      id: 'fld_1',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'auditor',
    });

    // No `inheritRole` and no matching role name on the child: the default is
    // to drop the role rather than guess at a mapping.
    const decision = await robrac.evaluate({
      type: 'document',
      id: 'doc_1',
      scope: ORG,
      subjects: bob,
    });

    assert.deepEqual(decision.effectiveRoles, []);
  });

  it('translates ancestor roles through inheritRole', async () => {
    const fixture = createFixture();
    fixture.folders.set('fld_1', {
      id: 'fld_1',
      organizationId: ORG,
      name: 'F',
    });
    fixture.documents.set('doc_1', {
      id: 'doc_1',
      organizationId: ORG,
      folderId: 'fld_1',
      createdBy: 'u_alice',
      visibility: 'private',
    });

    const robrac = createTestRobrac({
      resources: {
        folder: defineResource({
          type: 'folder',
          statements: { folder: ['read', 'share'] },
          roles: { curator: { folder: ['read', 'share'] } },
          load: ({ id }) => fixture.folders.get(id) ?? null,
          scope: (folder) => folder.organizationId,
          manage: { folder: ['share'] },
        }),
        document: defineResource({
          type: 'document',
          statements: { document: ['read', 'update'] },
          roles: {
            viewer: { document: ['read'] },
            editor: { document: ['read', 'update'] },
          },
          load: ({ id }) => fixture.documents.get(id) ?? null,
          scope: (document) => document.organizationId,
          parent: ({ data }) =>
            data.folderId ? { type: 'folder', id: data.folderId } : null,
          inheritRole: ({ role }) => (role === 'curator' ? 'editor' : null),
          manage: { document: ['update'] },
        }),
      },
    });

    await robrac.grants.grant({
      type: 'folder',
      id: 'fld_1',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'curator',
    });

    const decision = await robrac.evaluate({
      type: 'document',
      id: 'doc_1',
      scope: ORG,
      subjects: bob,
    });

    assert.deepEqual(decision.effectiveRoles, ['editor']);
    assert.equal(decision.permissions.document.update, true);
  });

  it('stops at maxInheritanceDepth instead of looping forever', async () => {
    // A folder that is its own parent: pathological data that must not hang.
    const fixture = createFixture();
    fixture.folders.set('fld_loop', {
      id: 'fld_loop',
      organizationId: ORG,
      name: 'Loop',
    });

    const robrac = createTestRobrac({
      maxInheritanceDepth: 3,
      resources: {
        folder: defineResource({
          type: 'folder',
          statements: { folder: ['read', 'share'] },
          roles: { viewer: { folder: ['read'] } },
          load: ({ id }) => fixture.folders.get(id) ?? null,
          scope: (folder) => folder.organizationId,
          parent: ({ resource }) => ({ type: 'folder', id: resource.id }),
          manage: { folder: ['share'] },
        }),
      },
    });

    await robrac.grants.grant({
      type: 'folder',
      id: 'fld_loop',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'viewer',
    });

    const decision = await robrac.evaluate({
      type: 'folder',
      id: 'fld_loop',
      scope: ORG,
      subjects: bob,
    });

    // The role is still resolved; it is just deduplicated into one entry.
    assert.deepEqual(decision.effectiveRoles, ['viewer']);
    assert.equal(decision.permissions.folder.read, true);
  });

  it('does not leak a grant across tenants through the parent chain', async () => {
    const { fixture, robrac } = setup();
    fixture.folders.set('fld_other', {
      id: 'fld_other',
      organizationId: 'org_2',
      name: 'Other tenant',
    });
    fixture.documents.set('doc_crossed', {
      id: 'doc_crossed',
      organizationId: ORG,
      folderId: 'fld_other',
      createdBy: 'u_alice',
      visibility: 'private',
    });

    await robrac.grants.grant({
      type: 'folder',
      id: 'fld_other',
      scope: 'org_2',
      subject: { type: 'member', id: 'm_bob' },
      role: 'owner',
    });

    const decision = await robrac.evaluate({
      type: 'document',
      id: 'doc_crossed',
      scope: ORG,
      subjects: bob,
    });

    // The parent belongs to another tenant, so it fails the scope check and
    // contributes nothing.
    assert.equal(decision.found, true);
    assert.deepEqual(decision.effectiveRoles, []);
  });
});
