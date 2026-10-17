import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { createAuthClient } from 'better-auth/client';

import { robracClient } from '../src/client.ts';
import {
  defaultSubjectResolver,
  defineResource,
  organizationSubjectValidator,
  robrac,
} from '../src/index.ts';

// Type-level only: `tsc` is the assertion. `InferServerPlugin` matches the
// server plugin by its literal `id`; if that ever widens to `string`, the
// client silently resolves to `never` and these lines stop compiling.
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
  database: memoryAdapter({}),
  plugins: [robrac({ resources: { document }, scope: 'optional' })],
});

const client = createAuthClient({
  baseURL: 'http://localhost:3000',
  plugins: [robracClient<typeof auth>()],
});

const inner = defaultSubjectResolver();
robrac({
  resources: { document },
  resolveSubjects: async (args) => [
    ...(await inner(args)),
    { type: 'service', id: 'svc' },
  ],
  subjects: { validate: organizationSubjectValidator(inner) },
});

export const typeChecks = [
  () =>
    client.robrac.check({
      resourceType: 'document',
      resourceId: 'doc_1',
      permissions: { document: ['update'] },
    }),
  () => client.robrac.access({ resourceType: 'document', resourceId: 'd' }),
  () =>
    client.robrac.accessBatch({
      resourceType: 'document',
      resourceIds: ['d'],
    }),
  () =>
    client.robrac.grants.list({ resourceType: 'document', resourceId: 'd' }),
  () =>
    client.robrac.grants.grant({
      resourceType: 'document',
      resourceId: 'doc_1',
      subject: { type: 'member', id: 'm_1' },
      role: 'owner',
    }),
  () =>
    client.robrac.grants.set({
      resourceType: 'document',
      resourceId: 'doc_1',
      subject: { type: 'member', id: 'm_1' },
      roles: ['viewer'],
    }),
  () =>
    client.robrac.grants.revoke({
      resourceType: 'document',
      resourceId: 'doc_1',
      subject: { type: 'member', id: 'm_1' },
    }),
  () =>
    client.robrac.check({
      resourceType: 'document',
      resourceId: 'doc_1',
      // @ts-expect-error 'publish' is not a declared action on 'document'
      permissions: { document: ['publish'] },
    }),
  () =>
    client.robrac.grants.grant({
      resourceType: 'document',
      resourceId: 'doc_1',
      subject: { type: 'member', id: 'm_1' },
      // @ts-expect-error 'admin' is not a declared role on 'document'
      role: 'admin',
    }),
];

// The server-only endpoint must not reach the client.
export const noAccessibleIds: typeof client.robrac extends {
  accessibleIds: unknown;
}
  ? never
  : true = true;
