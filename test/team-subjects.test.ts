import assert from 'node:assert/strict';
import { it } from 'node:test';

import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { organization } from 'better-auth/plugins/organization';

import { defaultSubjectResolver } from '../src/index.ts';

async function setup(count: number) {
  const createdAt = new Date('2026-01-01');
  const teams = Array.from({ length: count }, (_, i) => ({
    id: `team_${i}`,
    name: `Team ${i}`,
    organizationId: 'org_a',
    createdAt,
  }));
  const auth = betterAuth({
    baseURL: 'http://localhost:3000',
    secret: 'r0brac-test-secret-with-enough-entropy-1234',
    advanced: { database: { defaultFindManyLimit: 2 } },
    database: memoryAdapter({
      user: [],
      session: [],
      account: [],
      verification: [],
      invitation: [],
      organization: [],
      member: [
        {
          id: 'member_a',
          userId: 'alice',
          organizationId: 'org_a',
          role: 'member',
          createdAt,
        },
      ],
      team: [
        ...teams,
        {
          id: 'team_b',
          name: 'Other tenant',
          organizationId: 'org_b',
          createdAt,
        },
      ],
      teamMember: [
        { id: 'membership_0000', userId: 'alice', teamId: 'team_b', createdAt },
        ...teams.map((team, i) => ({
          id: `membership_${String(i + 1).padStart(4, '0')}`,
          userId: 'alice',
          teamId: team.id,
          createdAt,
        })),
        {
          id: 'membership_orphan',
          userId: 'alice',
          teamId: 'missing',
          createdAt,
        },
        {
          id: 'membership_duplicate',
          userId: 'alice',
          teamId: 'team_0',
          createdAt,
        },
      ],
    }),
    plugins: [organization({ teams: { enabled: true } })],
  });
  return (await auth.$context).adapter;
}

it('resolves only teams in the requested scope and drops orphan memberships', async () => {
  const adapter = await setup(1);
  const subjects = await defaultSubjectResolver({ includeTeams: true })({
    user: { id: 'alice' },
    session: {},
    adapter,
    scope: 'org_a',
    context: {},
  });
  assert.deepEqual(subjects, [
    { type: 'user', id: 'alice' },
    { type: 'member', id: 'member_a' },
    { type: 'team', id: 'team_0' },
  ]);
});

it('resolves all teams past the adapter default and page boundaries', async () => {
  const adapter = await setup(505);
  const resolve = defaultSubjectResolver({ includeTeams: true });
  const args = {
    user: { id: 'alice' },
    session: {},
    adapter,
    scope: 'org_a',
    context: {},
  };
  const teams = (await resolve(args)).filter(
    (subject) => subject.type === 'team'
  );
  assert.equal(teams.length, 505);
  assert.equal(new Set(teams.map((team) => team.id)).size, 505);
  assert.ok(teams.some((team) => team.id === 'team_504'));
  assert.deepEqual(await resolve({ ...args, scope: 'not_a_member' }), [
    { type: 'user', id: 'alice' },
  ]);
  assert.deepEqual(await resolve({ ...args, scope: null }), [
    { type: 'user', id: 'alice' },
  ]);
});
