import assert from 'node:assert/strict';
import { before, describe, it } from 'node:test';

import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';

import { defineResource, extendRole, robrac } from '../src/index.ts';

type Document = {
  id: string;
  tenantId: string;
  createdBy: string;
  visibility: 'private' | 'tenant';
};

const TENANT = 'tenant_1';

const documents = new Map<string, Document>();

const documentResource = defineResource({
  type: 'document',
  statements: { document: ['read', 'update', 'delete', 'share'] },
  roles: {
    viewer: { document: ['read'] },
    editor: extendRole(['viewer'], { document: ['update'] }),
    owner: extendRole(['editor'], { document: ['delete', 'share'] }),
  },
  load: ({ id }) => documents.get(id) ?? null,
  scope: (document) => document.tenantId,
  computeRoles: ({ data, subjects, roles }) => {
    if (subjects.some((s) => s.type === 'user' && s.id === data.createdBy)) {
      roles.push('owner');
    }
    if (data.visibility === 'tenant') {
      roles.push('viewer');
    }
  },
  manage: { document: ['share'] },
});

const robracPlugin = robrac({
  resources: { document: documentResource },
  // This test runs without the organization plugin, so scope and subjects are
  // resolved from the app's own notion of a tenant.
  resolveScope: () => TENANT,
  resolveSubjects: ({ user }) => [{ type: 'user', id: user.id }],
});

const auth = betterAuth({
  baseURL: 'http://localhost:3000',
  secret: 'r0brac-test-secret-with-enough-entropy-1234',
  database: memoryAdapter({
    user: [],
    session: [],
    account: [],
    verification: [],
    robracGrant: [],
  }),
  emailAndPassword: { enabled: true },
  plugins: [robracPlugin],
});

async function signUp(email: string) {
  const response = await auth.api.signUpEmail({
    body: { email, password: 'correct-horse-battery-staple', name: email },
    returnHeaders: true,
  });

  const cookie = response.headers.get('set-cookie');
  assert.ok(cookie, `expected a session cookie for ${email}`);

  return {
    userId: response.response.user.id,
    headers: new Headers({ cookie }),
  };
}

describe('robrac better-auth plugin', () => {
  let alice: Awaited<ReturnType<typeof signUp>>;
  let bob: Awaited<ReturnType<typeof signUp>>;

  before(async () => {
    alice = await signUp('alice@example.com');
    bob = await signUp('bob@example.com');

    documents.set('doc_private', {
      id: 'doc_private',
      tenantId: TENANT,
      createdBy: alice.userId,
      visibility: 'private',
    });
    documents.set('doc_open', {
      id: 'doc_open',
      tenantId: TENANT,
      createdBy: alice.userId,
      visibility: 'tenant',
    });
  });

  it('declares the grant table in the plugin schema', () => {
    assert.ok(robracPlugin.schema.robracGrant);
    assert.deepEqual(
      Object.keys(robracPlugin.schema.robracGrant.fields).sort(),
      [
        'createdAt',
        'expiresAt',
        'grantedBySubjectId',
        'grantedBySubjectType',
        'resourceId',
        'resourceType',
        'role',
        'scope',
        'subjectId',
        'subjectType',
        'updatedAt',
      ]
    );
  });

  it('answers a permission check for the owner', async () => {
    const result = await auth.api.checkResourceAccess({
      headers: alice.headers,
      body: {
        resourceType: 'document',
        resourceId: 'doc_private',
        permissions: { document: ['delete'] },
      },
    });

    assert.deepEqual(result, { success: true });
  });

  it('denies a stranger', async () => {
    const result = await auth.api.checkResourceAccess({
      headers: bob.headers,
      body: {
        resourceType: 'document',
        resourceId: 'doc_private',
        permissions: { document: ['read'] },
      },
    });

    assert.deepEqual(result, { success: false });
  });

  it('returns a decision without leaking the resource itself', async () => {
    const decision = await auth.api.getResourceAccess({
      headers: bob.headers,
      body: { resourceType: 'document', resourceId: 'doc_open' },
    });

    assert.equal(decision.found, true);
    assert.equal(decision.resourceId, 'doc_open');
    assert.deepEqual(decision.effectiveRoles, ['viewer']);
    assert.equal(decision.permissions.document?.read, true);
    assert.equal(decision.permissions.document?.update, false);
    // The loaded document must never cross the wire.
    assert.equal('data' in decision, false);
  });

  it('404s on a resource that does not exist', async () => {
    await assert.rejects(
      auth.api.getResourceAccess({
        headers: alice.headers,
        body: { resourceType: 'document', resourceId: 'doc_missing' },
      }),
      (error: unknown) => (error as { status?: string }).status === 'NOT_FOUND'
    );
  });

  it('400s on an unknown resource type', async () => {
    await assert.rejects(
      auth.api.checkResourceAccess({
        headers: alice.headers,
        body: {
          // @ts-expect-error only 'document' is registered
          resourceType: 'ghost',
          resourceId: 'x',
          permissions: { document: ['read'] },
        },
      }),
      (error: unknown) =>
        (error as { status?: string }).status === 'BAD_REQUEST'
    );
  });

  it('grants, lists and revokes through the endpoints', async () => {
    const subject = { type: 'user', id: bob.userId };

    const granted = await auth.api.grantResourceRole({
      headers: alice.headers,
      body: {
        resourceType: 'document',
        resourceId: 'doc_private',
        subject,
        role: 'editor',
      },
    });
    assert.equal(granted.grant.role, 'editor');
    assert.equal(granted.grant.scope, TENANT);

    const listed = await auth.api.listResourceGrants({
      headers: alice.headers,
      body: { resourceType: 'document', resourceId: 'doc_private' },
    });
    // Alice owns the document, so every declared role is within her rights and
    // the escalation filter removes nothing.
    assert.deepEqual(listed.availableRoles.sort(), [
      'editor',
      'owner',
      'viewer',
    ]);
    assert.deepEqual(listed.declaredRoles.sort(), [
      'editor',
      'owner',
      'viewer',
    ]);
    assert.equal(listed.grants.length, 1);

    assert.deepEqual(
      await auth.api.checkResourceAccess({
        headers: bob.headers,
        body: {
          resourceType: 'document',
          resourceId: 'doc_private',
          permissions: { document: ['update'] },
        },
      }),
      { success: true }
    );

    const revoked = await auth.api.revokeResourceRole({
      headers: alice.headers,
      body: {
        resourceType: 'document',
        resourceId: 'doc_private',
        subject,
      },
    });
    assert.equal(revoked.revoked, 1);

    assert.deepEqual(
      await auth.api.checkResourceAccess({
        headers: bob.headers,
        body: {
          resourceType: 'document',
          resourceId: 'doc_private',
          permissions: { document: ['read'] },
        },
      }),
      { success: false }
    );
  });

  it('refuses a grant from someone who cannot share', async () => {
    await assert.rejects(
      auth.api.grantResourceRole({
        headers: bob.headers,
        body: {
          resourceType: 'document',
          resourceId: 'doc_open',
          subject: { type: 'user', id: bob.userId },
          role: 'owner',
        },
      }),
      (error: unknown) => (error as { status?: string }).status === 'FORBIDDEN'
    );
  });

  it('evaluates a page of resources in one request', async () => {
    const result = await auth.api.getResourceAccessBatch({
      headers: bob.headers,
      body: {
        resourceType: 'document',
        resourceIds: ['doc_private', 'doc_open', 'doc_missing'],
        permissions: { document: ['read'] },
      },
    });

    assert.equal(result.decisions.length, 3);
    assert.deepEqual(result.allowedIds, ['doc_open']);
  });

  it('honours grant expiry end to end', async () => {
    await auth.api.grantResourceRole({
      headers: alice.headers,
      body: {
        resourceType: 'document',
        resourceId: 'doc_private',
        subject: { type: 'user', id: bob.userId },
        role: 'viewer',
        expiresAt: new Date(Date.now() - 1000).toISOString(),
      },
    });

    assert.deepEqual(
      await auth.api.checkResourceAccess({
        headers: bob.headers,
        body: {
          resourceType: 'document',
          resourceId: 'doc_private',
          permissions: { document: ['read'] },
        },
      }),
      { success: false }
    );
  });

  it('exposes the engine for server-side callers', async () => {
    const engine = robracPlugin.getEngine();

    const allowed = await engine.check({
      type: 'document',
      id: 'doc_private',
      scope: TENANT,
      subjects: [{ type: 'user', id: alice.userId }],
      permissions: { document: ['share'] },
    });

    assert.equal(allowed, true);
  });

  it('keeps accessible-ids off the client surface', () => {
    // `SERVER_ONLY` metadata hides it from the generated client while leaving
    // it callable through `auth.api`.
    assert.equal(
      robracPlugin.endpoints.listAccessibleResourceIds.options.metadata
        ?.SERVER_ONLY,
      true
    );
    assert.equal(typeof auth.api.listAccessibleResourceIds, 'function');
  });

  it('rate-limits reads and writes on different budgets', () => {
    const write = robracPlugin.rateLimit.find((rule) =>
      rule.pathMatcher('/robrac/grants/grant')
    );
    const read = robracPlugin.rateLimit.find((rule) =>
      rule.pathMatcher('/robrac/check')
    );

    assert.equal(write?.max, 30);
    assert.equal(read?.max, 120);
  });
});
