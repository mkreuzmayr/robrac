import assert from 'node:assert/strict';
import { before, describe, it } from 'node:test';

import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { organization } from 'better-auth/plugins/organization';

import {
  defaultSubjectResolver,
  defineResource,
  extendRole,
  hasSubject,
  robrac,
} from '../src/index.ts';
import type { BetterAuthAdapterLike } from '../src/index.ts';

type Doc = { id: string; organizationId: string | null; createdBy?: string };

function documentResource(documents: Map<string, Doc>) {
  return defineResource({
    type: 'document',
    statements: { document: ['read', 'update', 'share'] },
    roles: {
      viewer: { document: ['read'] },
      owner: extendRole(['viewer'], { document: ['update', 'share'] }),
    },
    load: ({ id }) => documents.get(id) ?? null,
    scope: (doc) => doc.organizationId,
    computeRoles: ({ data, subjects, roles }) => {
      if (hasSubject(subjects, 'user', data.createdBy)) roles.push('owner');
    },
    manage: { document: ['share'] },
  });
}

function database() {
  return memoryAdapter({
    user: [],
    session: [],
    account: [],
    verification: [],
    organization: [],
    member: [],
    invitation: [],
    team: [],
    teamMember: [],
    robracGrant: [],
  });
}

const settings = {
  baseURL: 'http://localhost:3000',
  secret: 'r0brac-test-secret-with-enough-entropy-1234',
  emailAndPassword: { enabled: true },
} as const;

async function status(call: Promise<unknown>): Promise<number> {
  try {
    await call;
    return 200;
  } catch (error) {
    const { statusCode, status } = error as {
      statusCode?: number;
      status?: unknown;
    };
    return statusCode ?? (typeof status === 'number' ? status : 500);
  }
}

describe('Better Auth plugin', () => {
  const documents = new Map<string, Doc>();
  const verdicts: (boolean | undefined)[] = [];
  const plugin = robrac({
    resources: { document: documentResource(documents) },
    onDecision: (event) => {
      verdicts.push(event.allowed);
    },
  });
  const auth = betterAuth({
    ...settings,
    database: database(),
    plugins: [organization({ teams: { enabled: true } }), plugin],
  });

  type Account = { userId: string; headers: Headers };
  const signUp = async (name: string): Promise<Account> => {
    const response = await auth.api.signUpEmail({
      body: {
        email: `${name}@example.com`,
        password: 'correct-horse-battery',
        name,
      },
      returnHeaders: true,
    });
    return {
      userId: response.response.user.id,
      headers: new Headers({
        cookie: response.headers.get('set-cookie') ?? '',
      }),
    };
  };
  const createOrg = async (owner: Account, slug: string) =>
    (
      await auth.api.createOrganization({
        headers: owner.headers,
        body: { name: slug, slug },
      })
    ).id;
  const join = async (account: Account, organizationId: string) => {
    const member = await auth.api.addMember({
      body: { userId: account.userId, organizationId, role: 'member' },
    });
    await auth.api.setActiveOrganization({
      headers: account.headers,
      body: { organizationId },
    });
    return member.id;
  };
  const check = (account: Account, id: string, action: 'read' | 'update') =>
    auth.api.checkResourceAccess({
      headers: account.headers,
      body: {
        resourceType: 'document',
        resourceId: id,
        permissions: { document: [action] },
      },
    });
  const grant = (
    account: Account,
    id: string,
    subject: { type: string; id: string },
    expiresAt?: Date
  ) =>
    auth.api.grantResourceRole({
      headers: account.headers,
      body: {
        resourceType: 'document',
        resourceId: id,
        subject,
        role: 'viewer',
        expiresAt,
      },
    });

  let alice: Account;
  let bob: Account;
  let carol: Account;
  let org: string;
  let otherOrg: string;
  let adapter: BetterAuthAdapterLike;

  before(async () => {
    adapter = (await auth.$context).adapter;
    alice = await signUp('alice');
    bob = await signUp('bob');
    carol = await signUp('carol');
    org = await createOrg(alice, 'acme');
    otherOrg = await createOrg(carol, 'other');
    documents.set('d_alice', {
      id: 'd_alice',
      organizationId: org,
      createdBy: alice.userId,
    });
  });

  it("cuts off a removed member's existing session and cleans up", async () => {
    const memberId = await join(bob, org);
    documents.set('d_bob', {
      id: 'd_bob',
      organizationId: org,
      createdBy: bob.userId,
    });
    await grant(alice, 'd_alice', { type: 'user', id: bob.userId });
    await grant(alice, 'd_alice', { type: 'member', id: memberId });
    assert.equal((await check(bob, 'd_bob', 'update')).success, true);
    assert.equal((await check(bob, 'd_alice', 'read')).success, true);

    await auth.api.removeMember({
      headers: alice.headers,
      body: { memberIdOrEmail: memberId, organizationId: org },
    });

    assert.equal(await status(check(bob, 'd_bob', 'update')), 403);
    assert.equal(
      await status(grant(bob, 'd_bob', { type: 'user', id: carol.userId })),
      403
    );
    const rows = await adapter.findMany<{ subjectId: string }>({
      model: 'robracGrant',
      limit: 1000,
    });
    assert.deepEqual(
      rows.filter((row) => [memberId, bob.userId].includes(row.subjectId)),
      []
    );
  });

  it('refuses grants to subjects outside the organization', async () => {
    const carolMember = await adapter.findOne<{ id: string }>({
      model: 'member',
      where: [{ field: 'organizationId', value: otherOrg }],
    });
    for (const subject of [
      { type: 'member', id: carolMember!.id },
      { type: 'user', id: carol.userId },
      { type: 'service', id: 'svc_1' },
    ]) {
      assert.equal(await status(grant(alice, 'd_alice', subject)), 400);
      assert.equal(
        await status(
          auth.api.setResourceRoles({
            headers: alice.headers,
            body: {
              resourceType: 'document',
              resourceId: 'd_alice',
              subject,
              roles: ['viewer'],
            },
          })
        ),
        400
      );
    }
  });

  it('reveals nothing about a resource the caller cannot access', async () => {
    const dave = await signUp('dave');
    const memberId = await join(dave, org);
    const access = () =>
      auth.api.getResourceAccess({
        headers: dave.headers,
        body: { resourceType: 'document', resourceId: 'd_alice' },
      });
    assert.equal(await status(access()), 404);

    const batch = await auth.api.getResourceAccessBatch({
      headers: dave.headers,
      body: { resourceType: 'document', resourceIds: ['d_alice'] },
    });
    assert.equal(batch.decisions[0]!.found, false);

    await grant(alice, 'd_alice', { type: 'member', id: memberId });
    assert.deepEqual((await access()).effectiveRoles, ['viewer']);
  });

  it('reports one verdict per grant request', async () => {
    const ivan = await signUp('ivan');
    const memberId = await join(ivan, org);
    const subject = { type: 'member', id: memberId };
    verdicts.length = 0;
    assert.equal(await status(grant(ivan, 'd_alice', subject)), 404);
    await grant(alice, 'd_alice', subject);
    assert.deepEqual(verdicts, [false, true]);
  });

  it('does not reveal who belongs to the organization', async () => {
    const gina = await signUp('gina');
    const memberId = await join(gina, org);
    const outsider = { type: 'user', id: carol.userId };
    const insider = { type: 'user', id: alice.userId };
    const attempt = (subject: { type: string; id: string }, role = 'viewer') =>
      status(
        auth.api.grantResourceRole({
          headers: gina.headers,
          body: {
            resourceType: 'document',
            resourceId: 'd_alice',
            subject,
            role: role as 'viewer',
          },
        })
      );
    assert.equal(await attempt(outsider), 404);
    assert.equal(await attempt(insider), 404);
    assert.equal(await attempt(outsider, 'nope'), 400);
    assert.equal(await attempt(insider, 'nope'), 400);

    await grant(alice, 'd_alice', { type: 'member', id: memberId });
    assert.equal(await attempt(outsider), 403);
    assert.equal(await attempt(insider), 403);
  });

  it('validates grant and revoke bodies', async () => {
    const past = new Date(Date.now() - 60_000);
    assert.equal(
      await status(
        grant(alice, 'd_alice', { type: 'user', id: alice.userId }, past)
      ),
      400
    );
    assert.equal(
      await status(
        auth.api.revokeResourceRole({
          headers: alice.headers,
          body: {
            resourceType: 'document',
            resourceId: 'd_alice',
            subject: { type: 'user', id: alice.userId },
            role: '' as 'viewer',
          },
        })
      ),
      400
    );
  });

  it('resolves only the teams of the active organization', async () => {
    const erin = await signUp('erin');
    await join(erin, otherOrg);
    await join(erin, org);
    const team = async (organizationId: string, owner: Account) => {
      const created = await auth.api.createTeam({
        headers: owner.headers,
        body: { name: `team-${organizationId}`, organizationId },
      });
      await auth.api.addTeamMember({
        headers: owner.headers,
        body: { teamId: created.id, userId: erin.userId },
      });
      return created.id;
    };
    await auth.api.setActiveOrganization({
      headers: carol.headers,
      body: { organizationId: otherOrg },
    });
    const ownTeam = await team(org, alice);
    await team(otherOrg, carol);

    const subjects = await defaultSubjectResolver({ includeTeams: true })({
      user: { id: erin.userId },
      session: {},
      adapter,
      scope: org,
      context: {},
    });
    assert.deepEqual(
      subjects.filter((subject) => subject.type === 'team'),
      [{ type: 'team', id: ownTeam }]
    );
  });

  it("deletes a member's grants when they leave", async () => {
    const hank = await signUp('hank');
    const memberId = await join(hank, org);
    await grant(alice, 'd_alice', { type: 'member', id: memberId });
    await grant(alice, 'd_alice', { type: 'user', id: hank.userId });
    await auth.api.leaveOrganization({
      headers: hank.headers,
      body: { organizationId: org },
    });
    const rows = await adapter.findMany<{ subjectId: string }>({
      model: 'robracGrant',
      where: [{ field: 'scope', value: org }],
      limit: 1000,
    });
    assert.deepEqual(
      rows.filter((row) => [memberId, hank.userId].includes(row.subjectId)),
      []
    );
  });

  it('deletes every grant of a deleted organization', async () => {
    const frank = await signUp('frank');
    const doomed = await createOrg(frank, 'doomed');
    documents.set('d_doomed', {
      id: 'd_doomed',
      organizationId: doomed,
      createdBy: frank.userId,
    });
    await grant(frank, 'd_doomed', { type: 'user', id: frank.userId });
    await auth.api.deleteOrganization({
      headers: frank.headers,
      body: { organizationId: doomed },
    });
    const rows = await adapter.findMany<{ scope: string }>({
      model: 'robracGrant',
      where: [{ field: 'scope', value: doomed }],
    });
    assert.deepEqual(rows, []);
  });

  it('leaves cleanup off for a custom scope resolver', () => {
    const custom = robrac({
      resources: { document: documentResource(documents) },
      resolveScope: () => 'workspace_1',
    });
    assert.deepEqual(custom.hooks.after, []);
  });

  it('rate-limits grant listing as a read', () => {
    const rule = plugin.rateLimit.find((candidate) =>
      candidate.pathMatcher('/robrac/grants/list')
    );
    assert.equal(rule?.max, 120);
  });
});

describe('Better Auth plugin in single-tenant mode', () => {
  it('never consults the scope resolver', async () => {
    const documents = new Map<string, Doc>();
    const auth = betterAuth({
      ...settings,
      database: database(),
      plugins: [
        robrac({
          resources: { document: documentResource(documents) },
          scope: 'disabled',
          resolveScope: () => {
            throw new Error('resolveScope must not run');
          },
          subjects: {
            validate: ({ subject }) => {
              if (subject.type === 'broken') {
                throw new Error('lookup failed');
              }
              return subject.type === 'user';
            },
          },
        }),
      ],
    });
    const response = await auth.api.signUpEmail({
      body: {
        email: 'solo@example.com',
        password: 'correct-horse-battery',
        name: 'solo',
      },
      returnHeaders: true,
    });
    documents.set('d1', {
      id: 'd1',
      organizationId: null,
      createdBy: response.response.user.id,
    });
    const headers = new Headers({
      cookie: response.headers.get('set-cookie') ?? '',
    });
    const { success } = await auth.api.checkResourceAccess({
      headers,
      body: {
        resourceType: 'document',
        resourceId: 'd1',
        permissions: { document: ['update'] },
      },
    });
    assert.equal(success, true);

    const target = (type: string) =>
      status(
        auth.api.grantResourceRole({
          headers,
          body: {
            resourceType: 'document',
            resourceId: 'd1',
            subject: { type, id: 'x' },
            role: 'viewer',
          },
        })
      );
    assert.equal(await target('team'), 400);
    assert.equal(await target('broken'), 400);
    assert.equal(await target('user'), 200);
  });
});
