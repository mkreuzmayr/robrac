import assert from 'node:assert/strict';
import { it } from 'node:test';

import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { organization } from 'better-auth/plugins/organization';

import { defineResource, memoryGrantStore, robrac } from '../src/index.ts';

for (const customScope of [false, true]) {
  for (const optIn of [false, true]) {
    it(`organization deletion respects scope ownership, custom=${customScope}, optIn=${optIn}`, async () => {
      const store = memoryGrantStore();
      const plugin = robrac({
        resources: {
          document: defineResource({
            type: 'document',
            statements: { document: ['read'] },
            roles: { viewer: { document: ['read'] } },
            load: ({ id }) => ({ id }),
            scope: () => 'workspace',
            manage: { document: ['read'] },
          }),
        },
        store,
        ...(customScope ? { resolveScope: () => 'workspace' } : {}),
        ...(optIn
          ? { cleanup: { onOrganizationDeleted: true, onMemberRemoved: true } }
          : {}),
      });
      const auth = betterAuth({
        baseURL: 'http://localhost:3000',
        secret: 'r0brac-test-secret-with-enough-entropy-1234',
        database: memoryAdapter({
          user: [],
          session: [],
          account: [],
          verification: [],
          organization: [],
          member: [],
          invitation: [],
          robracGrant: [],
        }),
        emailAndPassword: { enabled: true },
        plugins: [organization(), plugin],
      });
      const signup = await auth.api.signUpEmail({
        body: {
          email: 'owner@example.com',
          name: 'Owner',
          password: 'correct-horse-battery-staple',
        },
        returnHeaders: true,
      });
      const cookie = signup.headers.get('set-cookie');
      assert.ok(cookie);
      const headers = new Headers({ cookie });
      const org = await auth.api.createOrganization({
        headers,
        body: { name: 'Organization', slug: 'organization' },
      });
      assert.ok(org);
      // Custom workspace IDs and organization IDs can overlap. An organization
      // deletion has no authority to delete grants in a separate namespace.
      await store.upsertGrant({
        scope: org.id,
        resource: { type: 'document', id: 'doc' },
        subject: { type: 'user', id: signup.response.user.id },
        role: 'viewer',
        grantedBy: null,
        expiresAt: null,
      });
      await auth.api.deleteOrganization({
        headers,
        body: { organizationId: org.id },
      });
      const shouldClean = !customScope || optIn;
      assert.equal(store.all().length, shouldClean ? 0 : 1);
      assert.equal(
        plugin.hooks.after.some((hook) =>
          hook.matcher({ path: '/organization/remove-member' })
        ),
        shouldClean
      );
    });
  }
}
