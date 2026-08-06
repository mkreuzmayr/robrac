/**
 * Regression tests for bugs found in review.
 *
 * Each case fails against the implementation as it was before the
 * corresponding fix, so they pin the behaviour rather than just describing it.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  compileResources,
  createRobrac,
  defineResource,
  normalizeRoles,
  RobracError,
} from '../src/index.ts';
import type { GrantChangeEvent, GrantStore } from '../src/index.ts';
import {
  createTestRobrac,
  memoryGrantStore,
  subjects,
} from '../src/testing.ts';

const ORG = 'org_1';
const bob = subjects(['user', 'u_bob'], ['member', 'm_bob']);

type Doc = { id: string; org: string };

function docResource(docs: Map<string, Doc>, scoped = true) {
  return defineResource({
    type: 'document',
    statements: { document: ['read', 'update', 'delete', 'share'] },
    roles: {
      sharer: { document: ['read', 'share'] },
      owner: { document: ['read', 'update', 'delete', 'share'] },
    },
    load: ({ id }) => docs.get(id) ?? null,
    ...(scoped ? { scope: (doc: Doc) => doc.org } : {}),
    manage: { document: ['share'] },
  });
}

describe('revokeScope under scope: disabled', () => {
  it('does not wipe every grant in the store', async () => {
    const docs = new Map<string, Doc>([
      ['d1', { id: 'd1', org: ORG }],
      ['d2', { id: 'd2', org: ORG }],
    ]);

    const robrac = createTestRobrac({
      scope: 'disabled',
      resources: { document: docResource(docs, false) },
    });

    for (const id of ['d1', 'd2']) {
      await robrac.grants.grant({
        type: 'document',
        id,
        subject: { type: 'member', id: 'm_bob' },
        role: 'owner',
      });
    }

    // A tenant id in a deployment that has no tenants must not be collapsed to
    // the null scope every grant actually lives in.
    const deleted = await robrac.grants.revokeScope({ scope: 'org_unknown' });

    assert.equal(deleted, 0);
    assert.equal(robrac.store.all().length, 2);
  });

  it('does not wipe a subject’s grants across the store', async () => {
    const docs = new Map<string, Doc>([['d1', { id: 'd1', org: ORG }]]);
    const robrac = createTestRobrac({
      scope: 'disabled',
      resources: { document: docResource(docs, false) },
    });

    await robrac.grants.grant({
      type: 'document',
      id: 'd1',
      subject: { type: 'member', id: 'm_bob' },
      role: 'owner',
    });

    assert.equal(
      await robrac.grants.revokeSubject({
        subject: { type: 'member', id: 'm_bob' },
        scope: 'org_unknown',
      }),
      0
    );
    assert.equal(robrac.store.all().length, 1);
  });
});

describe('missing scope under scope: required', () => {
  it('reports SCOPE_REQUIRED instead of silently denying', async () => {
    const docs = new Map<string, Doc>([['d1', { id: 'd1', org: ORG }]]);
    const robrac = createTestRobrac({
      resources: { document: docResource(docs) },
    });

    await assert.rejects(
      robrac.evaluate({ type: 'document', id: 'd1', subjects: bob }),
      (error: unknown) =>
        error instanceof RobracError && error.code === 'SCOPE_REQUIRED'
    );

    await assert.rejects(
      robrac.check({
        type: 'document',
        id: 'd1',
        subjects: bob,
        scope: null,
        permissions: { document: ['read'] },
      }),
      (error: unknown) =>
        error instanceof RobracError && error.code === 'SCOPE_REQUIRED'
    );
  });

  it('still allows a null scope when scoping is optional', async () => {
    const docs = new Map<string, Doc>([['d1', { id: 'd1', org: ORG }]]);
    const robrac = createTestRobrac({
      scope: 'optional',
      resources: { document: docResource(docs, false) },
    });

    const decision = await robrac.evaluate({
      type: 'document',
      id: 'd1',
      subjects: bob,
    });
    assert.equal(decision.found, true);
  });
});

describe('loaders that return undefined', () => {
  it('treats undefined as not found rather than crashing scope()', async () => {
    const docs = new Map<string, Doc>();

    const robrac = createTestRobrac({
      resources: {
        document: defineResource({
          type: 'document',
          statements: { document: ['read'] },
          roles: { viewer: { document: ['read'] } },
          // The idiomatic one-liner: `Map.get` returns undefined on a miss.
          // The cast reproduces the production hazard — the declared resource
          // type says `Doc`, so `scope()` below is written as if it always
          // gets one, and the runtime hands it `undefined`.
          load: ({ id }) => docs.get(id)!,
          scope: (doc) => doc.org,
          manage: { document: ['read'] },
        }),
      },
    });

    const decision = await robrac.evaluate({
      type: 'document',
      id: 'missing',
      scope: ORG,
      subjects: bob,
    });
    assert.equal(decision.found, false);
  });

  it('applies the same rule to loadMany', async () => {
    const robrac = createTestRobrac({
      resources: {
        document: defineResource({
          type: 'document',
          statements: { document: ['read'] },
          roles: { viewer: { document: ['read'] } },
          load: () => null,
          loadMany: ({ ids }) =>
            new Map(ids.map((id) => [id, undefined as unknown as Doc])),
          scope: (doc) => doc.org,
          manage: { document: ['read'] },
        }),
      },
    });

    const decisions = await robrac.evaluateMany({
      type: 'document',
      ids: ['a', 'b'],
      scope: ORG,
      subjects: bob,
    });

    assert.equal(decisions.get('a')?.found, false);
    assert.equal(decisions.get('b')?.found, false);
  });
});

describe('grant-change auditing', () => {
  function auditSetup() {
    const docs = new Map<string, Doc>([['d1', { id: 'd1', org: ORG }]]);
    const events: GrantChangeEvent[] = [];
    const robrac = createTestRobrac({
      resources: { document: docResource(docs) },
      onGrantChange: (event) => events.push(event),
    });
    return { robrac, events };
  }

  it('reports a downgrade through set() as a revoke', async () => {
    const { robrac, events } = auditSetup();
    const subject = { type: 'member', id: 'm_bob' } as const;

    await robrac.grants.set({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subject,
      roles: ['owner'],
    });
    events.length = 0;

    await robrac.grants.set({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subject,
      roles: ['sharer'],
    });

    assert.deepEqual(
      events.map((event) => `${event.action}:${event.roles.join(',')}`),
      ['revoke:owner', 'grant:sharer']
    );
  });

  it('names the roles removed by a role-less revoke', async () => {
    const { robrac, events } = auditSetup();
    const subject = { type: 'member', id: 'm_bob' } as const;

    await robrac.grants.set({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subject,
      roles: ['sharer', 'owner'],
    });
    events.length = 0;

    await robrac.grants.revoke({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subject,
    });

    assert.equal(events.length, 1);
    assert.equal(events[0]?.action, 'revoke');
    assert.deepEqual([...(events[0]?.roles ?? [])].sort(), ['owner', 'sharer']);
  });

  it('runs set() inside a transaction when the store offers one', async () => {
    const docs = new Map<string, Doc>([['d1', { id: 'd1', org: ORG }]]);
    const inner = memoryGrantStore();
    let transactions = 0;

    const store: GrantStore = {
      ...inner,
      transaction: (run) => {
        transactions++;
        return run(inner);
      },
    };

    // `createTestRobrac` owns its store, so build the engine directly to
    // observe the transaction.
    const engine = createRobrac({
      resources: { document: docResource(docs) },
      store,
    });

    await engine.grants.set({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      roles: ['sharer'],
    });

    assert.equal(transactions, 1);
  });
});

describe('decision auditing', () => {
  it('emits exactly one event per check', async () => {
    const docs = new Map<string, Doc>([['d1', { id: 'd1', org: ORG }]]);
    const events: (boolean | undefined)[] = [];

    const robrac = createTestRobrac({
      resources: { document: docResource(docs) },
      onDecision: (event) => events.push(event.allowed),
    });

    await robrac.check({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subjects: bob,
      permissions: { document: ['read'] },
    });

    assert.deepEqual(events, [false]);
  });

  it('records a denial raised by require()', async () => {
    const docs = new Map<string, Doc>([['d1', { id: 'd1', org: ORG }]]);
    const events: (boolean | undefined)[] = [];

    const robrac = createTestRobrac({
      resources: { document: docResource(docs) },
      onDecision: (event) => events.push(event.allowed),
    });

    await assert.rejects(
      robrac.require({
        type: 'document',
        id: 'd1',
        scope: ORG,
        subjects: bob,
        permissions: { document: ['read'] },
      })
    );

    assert.deepEqual(events, [false]);
  });

  it('records a refused grant-management attempt', async () => {
    const docs = new Map<string, Doc>([['d1', { id: 'd1', org: ORG }]]);
    const events: (boolean | undefined)[] = [];

    const robrac = createTestRobrac({
      resources: { document: docResource(docs) },
      onDecision: (event) => events.push(event.allowed),
    });

    await assert.rejects(
      robrac.authorized.listGrants({
        type: 'document',
        id: 'd1',
        scope: ORG,
        actor: bob,
      })
    );

    assert.deepEqual(events, [false]);
  });
});

describe('availableRoles', () => {
  it('offers only the roles the actor can actually grant', async () => {
    const docs = new Map<string, Doc>([['d1', { id: 'd1', org: ORG }]]);
    const robrac = createTestRobrac({
      resources: { document: docResource(docs) },
    });

    await robrac.grants.grant({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'sharer',
    });

    const listed = await robrac.authorized.listGrants({
      type: 'document',
      id: 'd1',
      scope: ORG,
      actor: bob,
    });

    // `owner` includes document.delete, which a sharer cannot do — offering it
    // would render a choice that `grant` rejects on submit.
    assert.deepEqual(listed.availableRoles, ['sharer']);
    assert.deepEqual(listed.declaredRoles.sort(), ['owner', 'sharer']);
  });

  it('offers every role when escalation is allowed', async () => {
    const docs = new Map<string, Doc>([['d1', { id: 'd1', org: ORG }]]);
    const robrac = createTestRobrac({
      escalation: 'allow',
      resources: { document: docResource(docs) },
    });

    await robrac.grants.grant({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subject: { type: 'member', id: 'm_bob' },
      role: 'sharer',
    });

    const listed = await robrac.authorized.listGrants({
      type: 'document',
      id: 'd1',
      scope: ORG,
      actor: bob,
    });

    assert.deepEqual(listed.availableRoles.sort(), ['owner', 'sharer']);
  });
});

describe('registry compilation', () => {
  it('compiles a registry once, however often it is requested', () => {
    const docs = new Map<string, Doc>();
    const resources = { document: docResource(docs) };

    // The plugin compiles eagerly to fail fast at boot, then `createRobrac`
    // compiles again once the adapter exists. Identical output means the
    // second pass is a cache hit rather than a re-run over every role.
    const first = compileResources(resources, 'required');
    const second = compileResources(resources, 'required');

    assert.equal(first, second);

    // A different scope mode is a different question, so it is compiled again.
    assert.notEqual(compileResources(resources, 'optional'), first);
  });
});

describe('computeRoles typing', () => {
  const typedDocs = new Map<string, Doc>([['d1', { id: 'd1', org: ORG }]]);

  // A tiny declaration reused by the compile-time cases below. Each case gets
  // its own `defineResource` call so exactly one deliberate error is present —
  // stacked errors would collapse inference and mask each other.
  const base = {
    type: 'document',
    statements: { document: ['read', 'share'] },
    roles: {
      viewer: { document: ['read'] },
      owner: { document: ['read', 'share'] },
    },
    load: ({ id }: { id: string }) => typedDocs.get(id) ?? null,
    scope: (doc: Doc) => doc.org,
    manage: { document: ['share'] },
  } as const;

  it('rejects pushing an undeclared role at compile time', async () => {
    const robrac = createTestRobrac({
      resources: {
        document: defineResource({
          ...base,
          computeRoles: ({ roles }) => {
            // The accumulator only admits 'viewer' | 'owner'.
            roles.push('viewer');
            // @ts-expect-error 'admin' is not a declared role
            roles.push('admin');
          },
        }),
      },
    });

    // Runtime stays safe even where the compile guard is suppressed: an
    // undeclared name flows through as a role that confers nothing.
    const decision = await robrac.evaluate({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subjects: bob,
    });
    assert.deepEqual(decision.effectiveRoles.sort(), ['admin', 'viewer']);
    assert.equal(decision.permissions.document.read, true);
    assert.equal(decision.permissions.document.share, false);
  });

  it('rejects returning an undeclared role at compile time', () => {
    defineResource({
      ...base,
      // @ts-expect-error 'ghost' is not a declared role
      computeRoles: () => ['ghost'],
    });
    defineResource({
      ...base,
      // @ts-expect-error inheritRole may only return declared roles
      inheritRole: () => 'phantom',
    });
    assert.ok(true);
  });

  it('merges pushed and returned roles without duplicates', async () => {
    const robrac = createTestRobrac({
      resources: {
        document: defineResource({
          ...base,
          computeRoles: ({ roles }) => {
            roles.push('viewer');
            return ['viewer', 'owner'] as const;
          },
        }),
      },
    });

    const decision = await robrac.evaluate({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subjects: bob,
    });

    assert.deepEqual(decision.effectiveRoles.sort(), ['owner', 'viewer']);
    assert.equal(
      decision.roles.filter((role) => role.role === 'viewer').length,
      1
    );
  });
});

describe('a facet named "statements"', () => {
  it('is treated as a facet, not as a wrapped role object', () => {
    const roles = normalizeRoles({ viewer: { statements: ['read'] } });

    assert.deepEqual(roles.viewer?.effective, { statements: ['read'] });
  });

  it('still recognises a Better Auth role by its authorize function', () => {
    const betterAuthRole = {
      statements: { document: ['read', 'update'] },
      authorize: () => ({ success: true }) as const,
    };

    const roles = normalizeRoles({ editor: betterAuthRole });

    assert.deepEqual(roles.editor?.effective, {
      document: ['read', 'update'],
    });
  });

  it('rejects a malformed action list with the role name attached', () => {
    assert.throws(
      // @ts-expect-error deliberately malformed
      () => normalizeRoles({ viewer: { document: 'read' } }),
      (error: unknown) =>
        error instanceof RobracError &&
        error.code === 'INVALID_CONFIGURATION' &&
        error.message.includes('"viewer"') &&
        error.message.includes('"document"')
    );
  });
});
