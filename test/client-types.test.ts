import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { createAuthClient } from 'better-auth/client';

import { robracClient } from '../src/client.ts';
import { defineResource, robrac } from '../src/index.ts';

/**
 * A type-level regression test.
 *
 * `InferServerPlugin` matches the server plugin by its literal `id`. If that
 * literal ever widens to `string` — one stray annotation is enough — the client
 * silently resolves to `never` and every call below stops compiling, with no
 * runtime symptom to notice. Typecheck is the assertion; the runtime checks
 * just keep the file honest.
 */
const document = defineResource({
  type: 'document',
  statements: { document: ['read', 'update', 'share'] },
  roles: {
    viewer: { document: ['read'] },
    owner: { document: ['read', 'update', 'share'] },
  },
  load: () => null,
  scope: () => null,
  manage: { document: ['share'] },
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
  plugins: [robrac({ resources: { document }, scope: 'optional' })],
});

const client = createAuthClient({
  baseURL: 'http://localhost:3000',
  plugins: [robracClient<typeof auth>()],
});

describe('client plugin inference', () => {
  it('exposes the read surface', () => {
    assert.equal(typeof client.robrac.check, 'function');
    assert.equal(typeof client.robrac.access, 'function');
    assert.equal(typeof client.robrac.accessBatch, 'function');
  });

  it('exposes the grant surface', () => {
    assert.equal(typeof client.robrac.grants.list, 'function');
    assert.equal(typeof client.robrac.grants.grant, 'function');
    assert.equal(typeof client.robrac.grants.set, 'function');
    assert.equal(typeof client.robrac.grants.revoke, 'function');
  });

  it('keeps the server-only endpoint off the client', () => {
    assert.equal(
      'accessibleIds' in (client.robrac as Record<string, unknown>),
      false
    );
  });

  it('narrows permissions and roles by resource type', () => {
    // These calls are never awaited: their existence and their argument types
    // are the point.
    const typedCheck = () =>
      client.robrac.check({
        resourceType: 'document',
        resourceId: 'doc_1',
        permissions: { document: ['update'] },
      });

    const typedGrant = () =>
      client.robrac.grants.grant({
        resourceType: 'document',
        resourceId: 'doc_1',
        subject: { type: 'member', id: 'm_1' },
        role: 'owner',
      });

    const rejectsUnknownAction = () =>
      client.robrac.check({
        resourceType: 'document',
        resourceId: 'doc_1',
        // @ts-expect-error 'publish' is not a declared action on 'document'
        permissions: { document: ['publish'] },
      });

    const rejectsUnknownRole = () =>
      client.robrac.grants.grant({
        resourceType: 'document',
        resourceId: 'doc_1',
        subject: { type: 'member', id: 'm_1' },
        // @ts-expect-error 'admin' is not a declared role on 'document'
        role: 'admin',
      });

    for (const call of [
      typedCheck,
      typedGrant,
      rejectsUnknownAction,
      rejectsUnknownRole,
    ]) {
      assert.equal(typeof call, 'function');
    }
  });
});
