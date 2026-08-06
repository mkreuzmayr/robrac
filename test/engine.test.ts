import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';

import { defineResource, RobracError } from '../src/index.ts';
import { createTestRobrac, subjects } from '../src/testing.ts';
import { createFixture, registry } from './fixtures.ts';
import type { Fixture } from './fixtures.ts';

const ORG = 'org_1';
const OTHER_ORG = 'org_2';

const alice = subjects(['user', 'u_alice'], ['member', 'm_alice']);
const bob = subjects(['user', 'u_bob'], ['member', 'm_bob']);

function setup() {
  const fixture = createFixture();
  fixture.documents.set('doc_private', {
    id: 'doc_private',
    organizationId: ORG,
    folderId: null,
    createdBy: 'u_alice',
    visibility: 'private',
  });
  fixture.documents.set('doc_shared', {
    id: 'doc_shared',
    organizationId: ORG,
    folderId: null,
    createdBy: 'u_alice',
    visibility: 'organization',
  });
  fixture.documents.set('doc_other_org', {
    id: 'doc_other_org',
    organizationId: OTHER_ORG,
    folderId: null,
    createdBy: 'u_alice',
    visibility: 'organization',
  });

  const robrac = createTestRobrac({ resources: registry(fixture) });
  return { fixture, robrac };
}

describe('computed roles', () => {
  it('gives the creator the owner role without any stored grant', async () => {
    const { robrac } = setup();

    const decision = await robrac.evaluate({
      type: 'document',
      id: 'doc_private',
      scope: ORG,
      subjects: alice,
    });

    assert.equal(decision.found, true);
    assert.deepEqual(decision.effectiveRoles, ['owner']);
    assert.equal(decision.roles[0]?.origin, 'computed');
    assert.equal(decision.permissions.document.delete, true);
  });

  it('denies a stranger on a private document', async () => {
    const { robrac } = setup();

    const allowed = await robrac.check({
      type: 'document',
      id: 'doc_private',
      scope: ORG,
      subjects: bob,
      permissions: { document: ['read'] },
    });

    assert.equal(allowed, false);
  });

  it('lets org-visible documents be read by anyone in the scope', async () => {
    const { robrac } = setup();

    const decision = await robrac.evaluate({
      type: 'document',
      id: 'doc_shared',
      scope: ORG,
      subjects: bob,
    });

    assert.deepEqual(decision.effectiveRoles, ['viewer']);
    assert.equal(decision.permissions.document.read, true);
    assert.equal(decision.permissions.document.update, false);
  });
});

describe('explicit grants', () => {
  it('unions grants with computed roles', async () => {
    const { robrac } = setup();

    await robrac.grants.grant({
      type: 'document',
      id: 'doc_shared',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'editor',
    });

    const decision = await robrac.evaluate({
      type: 'document',
      id: 'doc_shared',
      scope: ORG,
      subjects: bob,
    });

    assert.deepEqual(decision.effectiveRoles.sort(), ['editor', 'viewer']);
    assert.equal(decision.permissions.document.update, true);
    assert.equal(decision.permissions.document.delete, false);
    assert.equal(
      decision.roles.find((role) => role.role === 'editor')?.origin,
      'explicit'
    );
  });

  it('revokes a single role and leaves the others', async () => {
    const { robrac } = setup();
    const subject = { type: 'member', id: 'm_bob' } as const;

    await robrac.grants.set({
      type: 'document',
      id: 'doc_private',
      scope: ORG,
      subject,
      roles: ['viewer', 'commenter'],
    });
    await robrac.grants.revoke({
      type: 'document',
      id: 'doc_private',
      scope: ORG,
      subject,
      role: 'commenter',
    });

    const decision = await robrac.evaluate({
      type: 'document',
      id: 'doc_private',
      scope: ORG,
      subjects: bob,
    });

    assert.deepEqual(decision.effectiveRoles, ['viewer']);
  });

  it('replaces the whole role set with set()', async () => {
    const { robrac } = setup();
    const subject = { type: 'member', id: 'm_bob' } as const;

    await robrac.grants.set({
      type: 'document',
      id: 'doc_private',
      scope: ORG,
      subject,
      roles: ['owner'],
    });
    await robrac.grants.set({
      type: 'document',
      id: 'doc_private',
      scope: ORG,
      subject,
      roles: ['viewer'],
    });

    const stored = await robrac.grants.list({
      type: 'document',
      id: 'doc_private',
      scope: ORG,
    });

    assert.deepEqual(
      stored.map((grant) => grant.role),
      ['viewer']
    );
  });

  it('rejects an unknown role name', async () => {
    const { robrac } = setup();

    await assert.rejects(
      robrac.grants.grant({
        type: 'document',
        id: 'doc_private',
        scope: ORG,
        subject: { type: 'member', id: 'm_bob' },
        // @ts-expect-error the registry only declares four roles
        role: 'superuser',
      }),
      (error: unknown) =>
        error instanceof RobracError && error.code === 'UNKNOWN_ROLE'
    );
  });

  it('grants to any subject type, not just members', async () => {
    const { robrac } = setup();

    await robrac.grants.grant({
      type: 'document',
      id: 'doc_private',
      scope: ORG,
      subject: { type: 'team', id: 't_eng' },
      role: 'editor',
    });

    const allowed = await robrac.check({
      type: 'document',
      id: 'doc_private',
      scope: ORG,
      subjects: [...bob, { type: 'team', id: 't_eng' }],
      permissions: { document: ['update'] },
    });

    assert.equal(allowed, true);
  });
});

describe('expiry', () => {
  it('stops honouring a grant once it expires', async () => {
    const fixture = createFixture();
    fixture.documents.set('doc_1', {
      id: 'doc_1',
      organizationId: ORG,
      folderId: null,
      createdBy: 'u_alice',
      visibility: 'private',
    });

    const robrac = createTestRobrac({
      resources: registry(fixture),
      now: new Date('2026-01-01T00:00:00Z'),
    });

    await robrac.grants.grant({
      type: 'document',
      id: 'doc_1',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'viewer',
      expiresAt: new Date('2026-01-02T00:00:00Z'),
    });

    const request = {
      type: 'document',
      id: 'doc_1',
      scope: ORG,
      subjects: bob,
      permissions: { document: ['read'] },
    } as const;

    assert.equal(await robrac.check(request), true);

    robrac.clock.now = new Date('2026-01-03T00:00:00Z');
    assert.equal(await robrac.check(request), false);
  });
});

describe('tenant isolation', () => {
  let fixture: Fixture;
  let robrac: ReturnType<typeof createTestRobrac<ReturnType<typeof registry>>>;

  beforeEach(() => {
    const created = setup();
    fixture = created.fixture;
    robrac = created.robrac;
  });

  it('hides a resource evaluated under the wrong scope', async () => {
    const decision = await robrac.evaluate({
      type: 'document',
      id: 'doc_other_org',
      scope: ORG,
      subjects: alice,
    });

    // Alice created it, but it lives in another tenant: not found, not denied.
    assert.equal(decision.found, false);
    assert.deepEqual(decision.effectiveRoles, []);
  });

  it('ignores a grant stored under a different scope', async () => {
    await robrac.grants.grant({
      type: 'document',
      id: 'doc_private',
      scope: OTHER_ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'owner',
    });

    const allowed = await robrac.check({
      type: 'document',
      id: 'doc_private',
      scope: ORG,
      subjects: bob,
      permissions: { document: ['read'] },
    });

    assert.equal(allowed, false);
    assert.equal(fixture.documents.size, 3);
  });

  it('refuses to build without a scope() under multi-tenancy', () => {
    assert.throws(
      () =>
        createTestRobrac({
          resources: {
            thing: defineResource({
              type: 'thing',
              statements: { thing: ['read'] },
              roles: { viewer: { thing: ['read'] } },
              load: () => null,
              manage: { thing: ['read'] },
            }),
          },
        }),
      (error: unknown) =>
        error instanceof RobracError && error.code === 'INVALID_CONFIGURATION'
    );
  });
});

describe('override', () => {
  it('denies everything under a legal hold, even for the owner', async () => {
    const { fixture, robrac } = setup();
    const document = fixture.documents.get('doc_private');
    assert.ok(document);
    document.legalHold = true;

    const decision = await robrac.evaluate({
      type: 'document',
      id: 'doc_private',
      scope: ORG,
      subjects: alice,
    });

    assert.equal(decision.found, true);
    assert.equal(decision.override, 'deny');
    assert.deepEqual(decision.effectiveRoles, ['owner']);
    assert.equal(decision.permissions.document.read, false);
    assert.equal(decision.permissions.document.delete, false);
  });
});

describe('managed grants', () => {
  it('lets a subject with the manage permission share', async () => {
    const { robrac } = setup();

    const grant = await robrac.authorized.grant({
      type: 'document',
      id: 'doc_private',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'viewer',
      actor: alice,
    });

    assert.equal(grant.role, 'viewer');
    assert.equal(grant.grantedBySubjectId, 'u_alice');
  });

  it('refuses when the actor cannot manage the resource', async () => {
    const { robrac } = setup();

    await assert.rejects(
      robrac.authorized.grant({
        type: 'document',
        id: 'doc_shared',
        scope: ORG,
        subject: { type: 'member', id: 'm_carol' },
        role: 'viewer',
        actor: bob,
      }),
      (error: unknown) =>
        error instanceof RobracError && error.code === 'FORBIDDEN'
    );
  });

  it('reports a missing resource rather than a permission failure', async () => {
    const { robrac } = setup();

    await assert.rejects(
      robrac.authorized.listGrants({
        type: 'document',
        id: 'doc_missing',
        scope: ORG,
        actor: alice,
      }),
      (error: unknown) =>
        error instanceof RobracError && error.code === 'RESOURCE_NOT_FOUND'
    );
  });
});

describe('privilege escalation', () => {
  // A registry where "may share" and "may delete" come apart, so an actor can
  // legitimately manage access while still being less powerful than the role
  // they are trying to hand out.
  function escalationSetup(escalation: 'deny' | 'allow') {
    const fixture = createFixture();
    fixture.documents.set('doc_1', {
      id: 'doc_1',
      organizationId: ORG,
      folderId: null,
      createdBy: 'u_nobody',
      visibility: 'private',
    });

    const robrac = createTestRobrac({
      escalation,
      resources: {
        document: defineResource({
          type: 'document',
          statements: { document: ['read', 'update', 'delete', 'share'] },
          roles: {
            sharer: { document: ['read', 'share'] },
            owner: { document: ['read', 'update', 'delete', 'share'] },
          },
          load: ({ id }) => fixture.documents.get(id) ?? null,
          scope: (document) => document.organizationId,
          manage: { document: ['share'] },
        }),
      },
    });

    return robrac;
  }

  it('refuses to grant a role the actor could not exercise itself', async () => {
    const robrac = escalationSetup('deny');

    await robrac.grants.grant({
      type: 'document',
      id: 'doc_1',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'sharer',
    });

    // Bob may manage access — but `owner` includes document.delete, which he
    // cannot do. Letting him grant it would be lateral escalation.
    await assert.rejects(
      robrac.authorized.grant({
        type: 'document',
        id: 'doc_1',
        scope: ORG,
        subject: { type: 'member', id: 'm_carol' },
        role: 'owner',
        actor: bob,
      }),
      (error: unknown) =>
        error instanceof RobracError &&
        error.code === 'FORBIDDEN' &&
        /document\.(update|delete)/.test(error.message)
    );
  });

  it('still allows granting a role within the actor’s own rights', async () => {
    const robrac = escalationSetup('deny');

    await robrac.grants.grant({
      type: 'document',
      id: 'doc_1',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'sharer',
    });

    const grant = await robrac.authorized.grant({
      type: 'document',
      id: 'doc_1',
      scope: ORG,
      subject: { type: 'member', id: 'm_carol' },
      role: 'sharer',
      actor: bob,
    });

    assert.equal(grant.role, 'sharer');
  });

  it('permits escalation when explicitly configured', async () => {
    const robrac = escalationSetup('allow');

    await robrac.grants.grant({
      type: 'document',
      id: 'doc_1',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'sharer',
    });

    const grant = await robrac.authorized.grant({
      type: 'document',
      id: 'doc_1',
      scope: ORG,
      subject: { type: 'member', id: 'm_carol' },
      role: 'owner',
      actor: bob,
    });

    assert.equal(grant.role, 'owner');
  });

  it('applies the same rule to setRoles', async () => {
    const robrac = escalationSetup('deny');

    await robrac.grants.grant({
      type: 'document',
      id: 'doc_1',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'sharer',
    });

    await assert.rejects(
      robrac.authorized.setRoles({
        type: 'document',
        id: 'doc_1',
        scope: ORG,
        subject: { type: 'member', id: 'm_carol' },
        roles: ['owner'],
        actor: bob,
      }),
      (error: unknown) =>
        error instanceof RobracError && error.code === 'FORBIDDEN'
    );
  });
});

describe('batch evaluation', () => {
  it('loads a page of resources once, not once per id', async () => {
    const { fixture, robrac } = setup();
    fixture.loads.document = 0;

    const decisions = await robrac.evaluateMany({
      type: 'document',
      ids: ['doc_private', 'doc_shared', 'doc_missing'],
      scope: ORG,
      subjects: alice,
    });

    assert.equal(fixture.loads.document, 1);
    assert.equal(decisions.size, 3);
    assert.equal(decisions.get('doc_missing')?.found, false);
    assert.equal(decisions.get('doc_private')?.found, true);
  });

  it('filters a page down to the ids the caller may act on', async () => {
    const { robrac } = setup();

    const allowed = await robrac.filterAccessible({
      type: 'document',
      ids: ['doc_private', 'doc_shared', 'doc_other_org'],
      scope: ORG,
      subjects: bob,
      permissions: { document: ['read'] },
    });

    assert.deepEqual(allowed, ['doc_shared']);
  });
});

describe('accessibleResourceIds', () => {
  it('returns only ids backed by a grant that confers the permission', async () => {
    const { robrac } = setup();

    await robrac.grants.grant({
      type: 'document',
      id: 'doc_private',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'viewer',
    });
    await robrac.grants.grant({
      type: 'document',
      id: 'doc_shared',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'viewer',
    });

    assert.deepEqual(
      (
        await robrac.accessibleResourceIds({
          type: 'document',
          scope: ORG,
          subjects: bob,
        })
      ).sort(),
      ['doc_private', 'doc_shared']
    );

    assert.deepEqual(
      await robrac.accessibleResourceIds({
        type: 'document',
        scope: ORG,
        subjects: bob,
        permissions: { document: ['update'] },
      }),
      []
    );
  });
});

describe('audit hooks', () => {
  it('reports decisions and grant changes', async () => {
    const fixture = createFixture();
    fixture.documents.set('doc_1', {
      id: 'doc_1',
      organizationId: ORG,
      folderId: null,
      createdBy: 'u_alice',
      visibility: 'private',
    });

    const decisions: string[] = [];
    const changes: string[] = [];
    const robrac = createTestRobrac({
      resources: registry(fixture),
      onDecision: (event) => {
        if (event.allowed !== undefined) {
          decisions.push(`${event.resource.id}:${event.allowed}`);
        }
      },
      onGrantChange: (event) => {
        changes.push(`${event.action}:${event.roles.join(',')}`);
      },
    });

    await robrac.grants.grant({
      type: 'document',
      id: 'doc_1',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'viewer',
    });
    await robrac.check({
      type: 'document',
      id: 'doc_1',
      scope: ORG,
      subjects: bob,
      permissions: { document: ['read'] },
    });

    assert.deepEqual(changes, ['grant:viewer']);
    assert.deepEqual(decisions, ['doc_1:true']);
  });
});
