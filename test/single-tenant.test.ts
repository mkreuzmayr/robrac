import assert from 'node:assert/strict';
import { it } from 'node:test';

import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';

import { defineResource, robrac } from '../src/index.ts';
import type { Scope, SubjectRef } from '../src/index.ts';

for (const customSubjects of [false, true]) {
  it(`normalizes disabled scope before resolving subjects, custom=${customSubjects}`, async () => {
    let resolvedScope: Scope | undefined;
    let seenSubjects: readonly SubjectRef[] = [];
    const plugin = robrac({
      scope: 'disabled',
      resolveScope: () => 'stale_organization',
      ...(customSubjects
        ? {
            resolveSubjects: ({ user, scope }) => {
              resolvedScope = scope;
              return [{ type: 'user', id: user.id }];
            },
          }
        : {}),
      resources: {
        document: defineResource({
          type: 'document',
          statements: { document: ['read'] },
          roles: { viewer: { document: ['read'] } },
          load: ({ id }) => ({ id }),
          computeRoles: ({ subjects, roles }) => {
            seenSubjects = subjects;
            roles.push('viewer');
          },
          manage: { document: ['read'] },
        }),
      },
    });
    // No organization tables: this is a single-tenant application.
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
      plugins: [plugin],
    });
    const signup = await auth.api.signUpEmail({
      body: {
        email: 'single@example.com',
        name: 'Single',
        password: 'correct-horse-battery-staple',
      },
      returnHeaders: true,
    });
    const cookie = signup.headers.get('set-cookie');
    assert.ok(cookie);
    const decision = await auth.api.getResourceAccess({
      headers: new Headers({ cookie }),
      body: { resourceType: 'document', resourceId: 'doc_1' },
    });
    assert.equal(decision.scope, null);
    assert.equal(decision.permissions.document?.read, true);
    assert.deepEqual(seenSubjects, [
      { type: 'user', id: signup.response.user.id },
    ]);
    if (customSubjects) assert.equal(resolvedScope, null);
  });
}
