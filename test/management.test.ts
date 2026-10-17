import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  defineResource,
  extendRole,
  RobracArgumentError,
} from '../src/index.ts';
import type { GrantChangeEvent } from '../src/index.ts';
import { createTestRobrac } from '../src/testing.ts';
import { at, createData, member, ORG, registry } from './fixtures.ts';

const OWNER = member('m_owner');
const SHARER = member('m_sharer');

async function setup(options: { escalation?: 'deny' | 'allow' } = {}) {
  const data = createData();
  data.documents.set('d1', { id: 'd1', organizationId: ORG });
  const events: GrantChangeEvent[] = [];
  const robrac = createTestRobrac({
    resources: registry(data),
    now: at('2026-01-01'),
    onGrantChange: (event) => {
      events.push(event);
    },
    ...options,
  });
  const grant = (
    subject: { type: string; id: string },
    role: 'viewer' | 'sharer' | 'editor' | 'owner',
    expiresAt?: Date
  ) =>
    robrac.grants.grant({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subject,
      role,
      expiresAt,
    });
  await grant(OWNER[0]!, 'owner');
  await grant(SHARER[0]!, 'sharer');
  const target = { type: 'member', id: 'm_target' };
  const roles = async (subject: { type: string; id: string }) =>
    (await robrac.grants.list({ type: 'document', id: 'd1', scope: ORG }))
      .filter((row) => row.subjectId === subject.id)
      .map((row) => row.role)
      .sort();
  return { data, robrac, events, grant, target, roles };
}

const forbidden = { code: 'FORBIDDEN' } as const;

describe('anti-escalation', () => {
  it('lets an actor grant only roles within its own permissions', async () => {
    const { robrac, target, roles } = await setup();
    const share = (role: 'viewer' | 'owner') =>
      robrac.authorized.grant({
        type: 'document',
        id: 'd1',
        scope: ORG,
        actor: SHARER,
        subject: target,
        role,
      });
    await assert.rejects(share('owner'), forbidden);
    await share('viewer');
    assert.deepEqual(await roles(target), ['viewer']);

    const listed = await robrac.authorized.listGrants({
      type: 'document',
      id: 'd1',
      scope: ORG,
      actor: SHARER,
    });
    assert.deepEqual(listed.availableRoles, ['viewer', 'sharer']);
  });

  it('refuses to revoke or demote a more powerful subject', async () => {
    const { robrac, roles } = await setup();
    for (const role of [undefined, 'owner'] as const) {
      await assert.rejects(
        robrac.authorized.revoke({
          type: 'document',
          id: 'd1',
          scope: ORG,
          actor: SHARER,
          subject: OWNER[0]!,
          role,
        }),
        forbidden
      );
    }
    await assert.rejects(
      robrac.authorized.setRoles({
        type: 'document',
        id: 'd1',
        scope: ORG,
        actor: SHARER,
        subject: OWNER[0]!,
        roles: ['viewer'],
      }),
      forbidden
    );
    assert.deepEqual(await roles(OWNER[0]!), ['owner']);

    const revoked = await robrac.authorized.revoke({
      type: 'document',
      id: 'd1',
      scope: ORG,
      actor: OWNER,
      subject: SHARER[0]!,
    });
    assert.equal(revoked, 1);
  });

  it('leaves a role granted while a revoke was in flight', async () => {
    const { robrac, target, roles } = await setup();
    const store = robrac.store;
    const transaction = store.transaction!.bind(store);
    store.transaction = (run) =>
      transaction((tx) =>
        run({
          ...tx,
          listResourceGrants: async (query) => {
            const rows = await tx.listResourceGrants(query);
            await robrac.grants.grant({
              type: 'document',
              id: 'd1',
              scope: ORG,
              subject: target,
              role: 'owner',
            });
            return rows;
          },
        })
      );
    const revoked = await robrac.authorized.revoke({
      type: 'document',
      id: 'd1',
      scope: ORG,
      actor: SHARER,
      subject: target,
      role: 'owner',
    });
    assert.equal(revoked, 0);
    assert.deepEqual(await roles(target), ['owner']);
  });

  it("caps new grants at the expiry of the actor's own access", async () => {
    const { robrac, grant, target, roles } = await setup();
    const temp = { type: 'member', id: 'm_temp' };
    await grant(temp, 'sharer', at('2026-01-10'));
    const share = (subject: typeof temp, expiresAt: Date | null) =>
      robrac.authorized.grant({
        type: 'document',
        id: 'd1',
        scope: ORG,
        actor: [temp],
        subject,
        role: 'sharer',
        expiresAt,
      });

    await assert.rejects(share(temp, null), /beyond 2026-01-10/);
    await assert.rejects(share(target, at('2026-02-01')), forbidden);
    await share(target, at('2026-01-10'));
    assert.deepEqual(await roles(target), ['sharer']);
  });

  it('follows inheritRole when comparing what roles cascade to', async () => {
    const folder = defineResource({
      type: 'folder',
      statements: { folder: ['read', 'share'] },
      roles: {
        contributor: { folder: ['read', 'share'] },
        curator: { folder: ['read', 'share'] },
      },
      load: ({ id }) => ({ id }),
      manage: { folder: ['share'] },
    });
    const document = defineResource({
      type: 'document',
      statements: { document: ['read', 'update'] },
      roles: {
        viewer: { document: ['read'] },
        editor: { document: ['read', 'update'] },
      },
      load: ({ id }) => ({ id, folderId: 'f1' }),
      parent: ({ data }) => ({ type: 'folder', id: data.folderId }),
      inheritRole: ({ parent, role }) =>
        parent.type !== 'folder'
          ? null
          : role === 'curator'
            ? 'editor'
            : role === 'contributor'
              ? 'viewer'
              : null,
      manage: { document: ['update'] },
    });
    const robrac = createTestRobrac({
      resources: { folder, document },
      scope: 'disabled',
    });
    const contributor = { type: 'member', id: 'm_c' };
    await robrac.grants.grant({
      type: 'folder',
      id: 'f1',
      subject: contributor,
      role: 'contributor',
    });
    await assert.rejects(
      robrac.authorized.grant({
        type: 'folder',
        id: 'f1',
        actor: [contributor],
        subject: contributor,
        role: 'curator',
      }),
      /document\.update on descendant document/
    );
  });

  it('compares what roles cascade to through the default mapping', async () => {
    const folder = defineResource({
      type: 'folder',
      statements: { folder: ['read', 'update', 'share'] },
      roles: {
        manager: { folder: ['read', 'update', 'share'] },
        editor: { folder: ['read', 'update'] },
      },
      load: ({ id }) => ({ id }),
      manage: { folder: ['share'] },
    });
    const document = defineResource({
      type: 'document',
      statements: { document: ['read', 'delete'] },
      roles: { editor: { document: ['read', 'delete'] } },
      load: ({ id }) => ({ id }),
      parent: () => ({ type: 'folder', id: 'f1' }),
      manage: { document: ['delete'] },
    });
    const robrac = createTestRobrac({
      resources: { folder, document },
      scope: 'disabled',
    });
    const manager = { type: 'member', id: 'm_m' };
    await robrac.grants.grant({
      type: 'folder',
      id: 'f1',
      subject: manager,
      role: 'manager',
    });
    await assert.rejects(
      robrac.authorized.grant({
        type: 'folder',
        id: 'f1',
        actor: [manager],
        subject: manager,
        role: 'editor',
      }),
      /on descendant document resources/
    );
  });

  it('credits the actor only with what its own roles cascade to', async () => {
    const workspace = defineResource({
      type: 'workspace',
      statements: { workspace: ['read', 'share'] },
      roles: {
        member: { workspace: ['read'] },
        admin: extendRole(['member'], { workspace: ['share'] }),
      },
      load: ({ id }) => ({ id }),
      manage: { workspace: ['share'] },
    });
    const project = defineResource({
      type: 'project',
      statements: { project: ['read', 'write'] },
      roles: { member: { project: ['read', 'write'] } },
      load: ({ id }) => ({ id }),
      parent: () => ({ type: 'workspace', id: 'w1' }),
      parentTypes: ['workspace'],
      manage: { project: ['write'] },
    });
    const robrac = createTestRobrac({
      resources: { workspace, project },
      scope: 'disabled',
    });
    const admin = { type: 'member', id: 'm_admin' };
    await robrac.grants.grant({
      type: 'workspace',
      id: 'w1',
      subject: admin,
      role: 'admin',
    });
    await assert.rejects(
      robrac.authorized.grant({
        type: 'workspace',
        id: 'w1',
        actor: [admin],
        subject: admin,
        role: 'member',
      }),
      /on descendant project resources/
    );
  });

  it('credits inherited roles only as far as they cascade', async () => {
    for (const depth of [1, 3, 5]) {
      const data = createData();
      for (let index = 0; index <= depth + 2; index++) {
        data.folders.set(`f${index}`, {
          id: `f${index}`,
          organizationId: ORG,
          parentId: index === 0 ? null : `f${index - 1}`,
        });
      }
      const robrac = createTestRobrac({
        resources: registry(data),
        maxInheritanceDepth: depth,
      });
      const mallory = member('m_mallory');
      await robrac.grants.grant({
        type: 'folder',
        id: 'f0',
        scope: ORG,
        subject: mallory[0]!,
        role: 'owner',
      });
      await assert.rejects(
        robrac.authorized.grant({
          type: 'folder',
          id: 'f1',
          scope: ORG,
          actor: mallory,
          subject: mallory[0]!,
          role: 'owner',
        }),
        /on descendant folder resources/,
        `maxInheritanceDepth ${depth}`
      );
    }
  });

  it('can be switched off', async () => {
    const { robrac, target, roles } = await setup({ escalation: 'allow' });
    await robrac.authorized.grant({
      type: 'document',
      id: 'd1',
      scope: ORG,
      actor: SHARER,
      subject: target,
      role: 'owner',
    });
    assert.deepEqual(await roles(target), ['owner']);
  });
});

describe('grant management', () => {
  it('requires the manage permission without revealing the resource', async () => {
    const { robrac, grant, target } = await setup();
    const viewer = { type: 'member', id: 'm_viewer' };
    await grant(viewer, 'viewer');
    const share = (actor: { type: string; id: string }) =>
      robrac.authorized.grant({
        type: 'document',
        id: 'd1',
        scope: ORG,
        actor: [actor],
        subject: target,
        role: 'viewer',
      });
    await assert.rejects(share(viewer), forbidden);
    await assert.rejects(share(member('m_stranger')[0]!), {
      code: 'RESOURCE_NOT_FOUND',
    });
  });

  it('is refused under a deny override', async () => {
    const { data, robrac, target } = await setup();
    data.documents.get('d1')!.hold = true;
    await assert.rejects(
      robrac.authorized.revoke({
        type: 'document',
        id: 'd1',
        scope: ORG,
        actor: OWNER,
        subject: target,
      }),
      forbidden
    );
  });

  it('rejects an expiry that is already past', async () => {
    const { robrac, target } = await setup();
    await assert.rejects(
      robrac.authorized.grant({
        type: 'document',
        id: 'd1',
        scope: ORG,
        actor: OWNER,
        subject: target,
        role: 'viewer',
        expiresAt: at('2025-12-31'),
      }),
      RobracArgumentError
    );
  });

  it('records the actor of every change', async () => {
    const { robrac, events, target } = await setup();
    events.length = 0;
    await robrac.authorized.setRoles({
      type: 'document',
      id: 'd1',
      scope: ORG,
      actor: OWNER,
      subject: target,
      roles: ['editor'],
    });
    await robrac.authorized.revoke({
      type: 'document',
      id: 'd1',
      scope: ORG,
      actor: OWNER,
      subject: target,
    });
    assert.deepEqual(
      events.map((event) => [event.action, event.roles, event.by]),
      [
        ['grant', ['editor'], OWNER],
        ['revoke', ['editor'], OWNER],
      ]
    );
  });

  it('rolls a change back when the audit hook throws', async () => {
    const data = createData();
    data.documents.set('d1', { id: 'd1', organizationId: ORG });
    const robrac = createTestRobrac({
      resources: registry(data),
      onGrantChange: () => {
        throw new Error('audit sink down');
      },
    });
    await assert.rejects(
      robrac.grants.grant({
        type: 'document',
        id: 'd1',
        scope: ORG,
        subject: OWNER[0]!,
        role: 'owner',
      }),
      /audit sink down/
    );
    assert.deepEqual(robrac.store.all(), []);
  });

  it('lets trusted code import an already expired grant', async () => {
    const { robrac, grant, target } = await setup();
    await grant(target, 'viewer', at('2025-06-01'));
    assert.equal(
      robrac.store.all().filter((row) => row.subjectId === target.id).length,
      1
    );
    assert.equal(
      await robrac.check({
        type: 'document',
        id: 'd1',
        scope: ORG,
        subjects: [target],
        permissions: { document: ['read'] },
      }),
      false
    );
  });
});
