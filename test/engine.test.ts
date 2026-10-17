import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';

import { createAccessControl } from 'better-auth/plugins/access';

import {
  createRobrac,
  defineResource,
  extendRole,
  memoryGrantStore,
  RobracError,
} from '../src/index.ts';
import type { GrantChangeEvent, GrantStore, SubjectRef } from '../src/index.ts';
import { createTestRobrac } from '../src/testing.ts';
import {
  at,
  createData,
  member,
  ORG,
  OTHER_ORG,
  registry,
  user,
} from './fixtures.ts';
import type { Data } from './fixtures.ts';

function setup() {
  const data = createData();
  data.documents.set('d1', {
    id: 'd1',
    organizationId: ORG,
    createdBy: 'u_alice',
  });
  data.documents.set('d2', {
    id: 'd2',
    organizationId: ORG,
    visibility: 'organization',
  });
  data.documents.set('d_other', { id: 'd_other', organizationId: OTHER_ORG });
  const robrac = createTestRobrac({
    resources: registry(data),
    now: at('2026-01-01'),
  });
  return { data, robrac };
}

describe('decisions', () => {
  let data: Data;
  let robrac: ReturnType<typeof setup>['robrac'];
  beforeEach(() => ({ data, robrac } = setup()));

  it('applies explicit grants through role inheritance', async () => {
    await robrac.grants.grant({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subject: member('m_bob')[0]!,
      role: 'editor',
    });
    const decision = await robrac.evaluate({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subjects: member('m_bob'),
    });
    assert.equal(decision.permissions.document.read, true);
    assert.equal(decision.permissions.document.update, true);
    assert.equal(decision.permissions.document.delete, false);
    assert.deepEqual(decision.roles, [{ role: 'editor', origin: 'explicit' }]);
  });

  it('derives computed roles from the resource', async () => {
    const creator = await robrac.evaluate({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subjects: user('u_alice'),
    });
    assert.equal(creator.permissions.document.delete, true);

    const anyone = await robrac.evaluate({
      type: 'document',
      id: 'd2',
      scope: ORG,
      subjects: user('u_carol'),
    });
    assert.deepEqual(anyone.effectiveRoles, ['viewer']);
  });

  it('reports a resource of another tenant as not found', async () => {
    await robrac.grants.grant({
      type: 'document',
      id: 'd_other',
      scope: ORG,
      subject: member('m_bob')[0]!,
      role: 'owner',
    });
    const decision = await robrac.evaluate({
      type: 'document',
      id: 'd_other',
      scope: ORG,
      subjects: member('m_bob'),
    });
    assert.equal(decision.found, false);
    assert.equal(decision.permissions.document.read, false);
  });

  it('ignores a grant stored under a different scope', async () => {
    await robrac.grants.grant({
      type: 'document',
      id: 'd1',
      scope: OTHER_ORG,
      subject: member('m_bob')[0]!,
      role: 'owner',
    });
    assert.equal(
      await robrac.check({
        type: 'document',
        id: 'd1',
        scope: ORG,
        subjects: member('m_bob'),
        permissions: { document: ['read'] },
      }),
      false
    );
  });

  it('stops honouring a grant at its expiry', async () => {
    await robrac.grants.grant({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subject: member('m_bob')[0]!,
      role: 'viewer',
      expiresAt: at('2026-01-02'),
    });
    const read = () =>
      robrac.check({
        type: 'document',
        id: 'd1',
        scope: ORG,
        subjects: member('m_bob'),
        permissions: { document: ['read'] },
      });
    assert.equal(await read(), true);
    robrac.clock.now = at('2026-01-02');
    assert.equal(await read(), false);
  });

  it('denies everything under a deny override, even for the creator', async () => {
    data.documents.get('d1')!.hold = true;
    const decision = await robrac.evaluate({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subjects: user('u_alice'),
    });
    assert.equal(decision.override, 'deny');
    assert.equal(decision.permissions.document.read, false);
  });

  it('never satisfies an empty request or an unknown action on its own', async () => {
    const ask = (permissions: Record<string, unknown>) =>
      robrac.check({
        type: 'document',
        id: 'd1',
        scope: ORG,
        subjects: user('u_alice'),
        permissions,
      });
    assert.equal(await ask({}), false);
    assert.equal(await ask({ document: [] }), false);
    assert.equal(await ask({ constructor: ['name'] }), false);
    assert.equal(await ask({ document: ['toString'] }), false);
    assert.equal(
      await ask({ document: { actions: ['read', 'nope'], connector: 'OR' } }),
      true
    );
  });

  it('demands an explicit scope in required mode', async () => {
    await assert.rejects(
      robrac.evaluate({ type: 'document', id: 'd1', subjects: [] }),
      { code: 'SCOPE_REQUIRED' }
    );
  });

  it('evaluates a batch with one grant query per type', async () => {
    const store = memoryGrantStore();
    let queries = 0;
    const counting: GrantStore = {
      ...store,
      findGrants: (query) => {
        queries++;
        return store.findGrants(query);
      },
    };
    for (let index = 0; index < 20; index++) {
      data.documents.set(`p${index}`, { id: `p${index}`, organizationId: ORG });
    }
    const engine = createRobrac({ resources: registry(data), store: counting });
    const decisions = await engine.evaluateMany({
      type: 'document',
      ids: [...data.documents.keys()],
      scope: ORG,
      subjects: member('m_bob'),
    });
    assert.equal(decisions.size, data.documents.size);
    assert.equal(queries, 1);
  });
});

describe('filterAccessible', () => {
  it('keeps allowed ids in input order and drops the rest', async () => {
    const { robrac } = setup();
    const allowed = await robrac.filterAccessible({
      type: 'document',
      ids: ['d2', 'd_other', 'missing', 'd1', 'd2'],
      scope: ORG,
      subjects: user('u_alice'),
      permissions: { document: ['read'] },
    });
    assert.deepEqual(allowed, ['d2', 'd1', 'd2']);
  });
});

describe('bulk revokes', () => {
  it('never widen a given scope to every grant', async () => {
    const note = defineResource({
      type: 'note',
      statements: { note: ['read'] },
      roles: { viewer: { note: ['read'] } },
      load: ({ id }) => ({ id }),
      manage: { note: ['read'] },
    });
    const store = memoryGrantStore();
    const engine = createRobrac({
      resources: { note },
      store,
      scope: 'disabled',
    });
    const subject = { type: 'member', id: 'm_bob' };
    await engine.grants.grant({
      type: 'note',
      id: 'n1',
      subject,
      role: 'viewer',
    });

    assert.equal(await engine.grants.revokeScope({ scope: ORG }), 0);
    assert.equal(await engine.grants.revokeSubject({ subject, scope: ORG }), 0);
    assert.equal(store.all().length, 1);
  });

  it('report one event per affected subject or resource', async () => {
    const events: GrantChangeEvent[] = [];
    const robrac = createTestRobrac({
      resources: registry(createData()),
      onGrantChange: (event) => {
        events.push(event);
      },
    });
    const grant = (
      id: string,
      subject: SubjectRef,
      role: 'viewer' | 'editor'
    ) =>
      robrac.grants.grant({ type: 'document', id, scope: ORG, subject, role });
    const bob = member('m_bob')[0]!;
    const alice = member('m_alice')[0]!;
    await grant('d1', bob, 'viewer');
    await grant('d1', alice, 'viewer');
    await grant('d2', bob, 'editor');
    events.length = 0;

    await robrac.grants.revokeResource({
      type: 'document',
      id: 'd1',
      scope: ORG,
    });
    await robrac.grants.revokeSubject({ subject: bob, scope: ORG });
    assert.deepEqual(
      events.map((event) => [
        event.resource.id,
        event.subject.id,
        event.roles,
        event.by,
      ]),
      [
        ['d1', 'm_bob', ['viewer'], null],
        ['d1', 'm_alice', ['viewer'], null],
        ['d2', 'm_bob', ['editor'], null],
      ]
    );
  });

  it('demand a scope in required mode', async () => {
    const { robrac } = setup();
    await assert.rejects(robrac.grants.revokeScope({ scope: null }), {
      code: 'SCOPE_REQUIRED',
    });
  });
});

describe('accessibleResourceIds', () => {
  it('lists live grant-backed ids that confer the permission', async () => {
    const { robrac } = setup();
    const bob = member('m_bob')[0]!;
    const grant = (id: string, role: 'viewer' | 'editor', expiresAt?: Date) =>
      robrac.grants.grant({
        type: 'document',
        id,
        scope: ORG,
        subject: bob,
        role,
        expiresAt,
      });
    await grant('a', 'viewer');
    await grant('b', 'editor');
    await grant('c', 'editor', at('2026-01-02'));
    robrac.clock.now = at('2026-01-03');

    const ids = (permissions?: { document: ['update'] }) =>
      robrac.accessibleResourceIds({
        type: 'document',
        scope: ORG,
        subjects: [bob],
        permissions,
      });
    assert.deepEqual((await ids()).sort(), ['a', 'b']);
    assert.deepEqual(await ids({ document: ['update'] }), ['b']);
  });

  it('judges a paged resource on all of its grants', async () => {
    const note = defineResource({
      type: 'note',
      statements: { note: ['read', 'update'] },
      roles: { reader: { note: ['read'] }, updater: { note: ['update'] } },
      load: ({ id }) => ({ id }),
      manage: { note: ['update'] },
    });
    const robrac = createTestRobrac({
      resources: { note },
      scope: 'disabled',
    });
    const subjects = [...user('u'), { type: 'team', id: 't' }];
    await robrac.grants.grant({
      type: 'note',
      id: 'x',
      subject: subjects[0]!,
      role: 'reader',
    });
    await robrac.grants.grant({
      type: 'note',
      id: 'x',
      subject: subjects[1]!,
      role: 'updater',
    });
    const page = (offset: number) =>
      robrac.accessibleResourceIds({
        type: 'note',
        subjects,
        permissions: { note: ['read', 'update'] },
        limit: 1,
        offset,
      });
    assert.deepEqual([...(await page(0)), ...(await page(1))], ['x', 'x']);
  });
});

describe('store rows', () => {
  it('ignores rows a lax store returns for another scope or subject', async () => {
    const { robrac } = setup();
    const row = {
      id: 'g1',
      scope: OTHER_ORG,
      resourceType: 'document',
      resourceId: 'd1',
      subjectType: 'member',
      subjectId: 'm_bob',
      role: 'owner',
      grantedBySubjectType: null,
      grantedBySubjectId: null,
      expiresAt: null,
      createdAt: new Date(0),
      updatedAt: new Date(0),
    };
    const lax = memoryGrantStore();
    const engine = createRobrac({
      resources: robrac.resources,
      store: {
        ...lax,
        findGrants: () =>
          Promise.resolve([row, { ...row, scope: ORG, subjectId: 'm_eve' }]),
        listSubjectGrants: () => Promise.resolve([row]),
      },
    });
    const query = { scope: ORG, subjects: member('m_bob') };
    const decision = await engine.evaluate({
      ...query,
      type: 'document',
      id: 'd1',
    });
    assert.deepEqual(decision.effectiveRoles, []);
    assert.deepEqual(
      await engine.accessibleResourceIds({ ...query, type: 'document' }),
      []
    );
  });
});

describe('role names', () => {
  it('treats Object.prototype names as unknown roles', async () => {
    const { robrac } = setup();
    for (const role of [
      'constructor',
      'toString',
      '__proto__',
      'hasOwnProperty',
    ]) {
      await assert.rejects(
        robrac.grants.grant({
          type: 'document',
          id: 'd1',
          scope: ORG,
          subject: member('m_bob')[0]!,
          role: role as never,
        }),
        { code: 'UNKNOWN_ROLE' }
      );
    }
  });

  it('confers nothing for a stored row naming an Object.prototype key', async () => {
    const { robrac } = setup();
    const store = memoryGrantStore({
      seed: [
        {
          id: 'g1',
          scope: ORG,
          resourceType: 'document',
          resourceId: 'd1',
          subjectType: 'member',
          subjectId: 'm_bob',
          role: 'constructor',
          grantedBySubjectType: null,
          grantedBySubjectId: null,
          expiresAt: null,
          createdAt: new Date(0),
          updatedAt: new Date(0),
        },
      ],
    });
    const engine = createRobrac({
      resources: robrac.resources,
      store,
    });
    const decision = await engine.evaluate({
      type: 'document',
      id: 'd1',
      scope: ORG,
      subjects: member('m_bob'),
    });
    assert.equal(decision.permissions.document.read, false);
  });

  it('accepts roles built with Better Auth access control', async () => {
    const statements = { note: ['read', 'update'] } as const;
    const ac = createAccessControl(statements);
    const note = defineResource({
      type: 'note',
      statements,
      roles: {
        reader: ac.newRole({ note: ['read'] }),
        writer: extendRole(['reader'], { note: ['update'] }),
      },
      load: ({ id }) => ({ id }),
      manage: { note: ['update'] },
    });
    const robrac = createTestRobrac({
      resources: { note },
      scope: 'disabled',
    });
    await robrac.grants.grant({
      type: 'note',
      id: 'n1',
      subject: user('u')[0]!,
      role: 'writer',
    });
    const decision = await robrac.evaluate({
      type: 'note',
      id: 'n1',
      subjects: user('u'),
    });
    assert.deepEqual(decision.permissions.note, { read: true, update: true });
  });

  it('supports a declared role that shadows a prototype name', async () => {
    const resource = defineResource({
      type: 'note',
      statements: { note: ['read'] },
      roles: { constructor: { note: ['read'] } },
      load: ({ id }) => ({ id }),
      manage: { note: ['read'] },
    });
    const robrac = createTestRobrac({
      resources: { note: resource },
      scope: 'disabled',
    });
    await robrac.grants.grant({
      type: 'note',
      id: 'n1',
      subject: user('u')[0]!,
      role: 'constructor',
    });
    assert.equal(
      await robrac.check({
        type: 'note',
        id: 'n1',
        subjects: user('u'),
        permissions: { note: ['read'] },
      }),
      true
    );
  });
});

describe('configuration', () => {
  const base = {
    type: 'note',
    statements: { note: ['read', 'update'] },
    load: () => null,
  } as const;

  const build =
    (definition: object, options: object = {}) =>
    () =>
      createRobrac({
        resources: { note: definition as never },
        store: memoryGrantStore(),
        scope: 'disabled',
        ...options,
      });

  it('rejects roles and manage requests naming undeclared actions', () => {
    assert.throws(
      build({
        ...base,
        roles: { viewer: { note: ['publish'] } },
        manage: { note: ['read'] },
      }),
      RobracError
    );
    assert.throws(
      build({
        ...base,
        roles: { viewer: { note: ['read'] } },
        manage: { note: ['share'] },
      }),
      RobracError
    );
  });

  it('rejects role inheritance cycles and unknown parents', () => {
    assert.throws(
      build({
        ...base,
        roles: {
          a: extendRole(['b'], { note: ['read'] }),
          b: extendRole(['a'], { note: ['read'] }),
        },
        manage: { note: ['read'] },
      }),
      /cycle/
    );
    assert.throws(
      build({
        ...base,
        roles: { a: extendRole(['toString'], { note: ['read'] }) },
        manage: { note: ['read'] },
      }),
      /unknown role/
    );
  });

  it('rejects an unbounded inheritance depth', () => {
    const valid = {
      ...base,
      roles: { viewer: { note: ['read'] } },
      manage: { note: ['read'] },
    };
    for (const depth of [Infinity, Number.NaN, -1, 1.5, 65]) {
      assert.throws(
        build(valid, { maxInheritanceDepth: depth }),
        /maxInheritanceDepth/
      );
    }
  });
});
