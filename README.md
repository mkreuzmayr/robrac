# robrac

robrac adds resource-level role-based access control to Better Auth.

Better Auth's `organization` plugin can tell you whether a member may edit recordings.
robrac can tell you whether they may edit a specific recording.

```ts
await robrac.check({
  type: 'recording',
  id: recordingId,
  scope: organizationId,
  subjects: [{ type: 'member', id: memberId }],
  permissions: { recording: ['update'] },
});
```

---

## Why another authorization package

Authorization for individual resources often gets tied to an app's ORM, `member`
table and resource types. robrac keeps three parts configurable:

| Concept      | What it means                            | Why it is configurable                                                             |
| ------------ | ---------------------------------------- | ---------------------------------------------------------------------------------- |
| **Subject**  | who is asking, identified by type and ID | Grants can target users, organization members, teams, service accounts or API keys |
| **Scope**    | the tenant for an access decision        | Use a required tenant ID, an optional tenant ID or `null` for a single-tenant app  |
| **Resource** | what the subject wants to access         | Each resource definition provides its own type, loader, roles and permissions      |

Persistence goes through a single [`GrantStore`](src/store/types.ts) interface. The
default implementation uses Better Auth's adapter. It works with Drizzle, Prisma,
Kysely, MongoDB or a raw connection without ORM-specific code in robrac.

### What it gives you beyond a `resource_roles` table

- Roles can inherit from other roles. robrac resolves `editor extends viewer` at boot.
- Computed roles cover rules such as "the creator is the owner" without storing a grant.
- Grants on parent resources can apply to their children through an explicit role mapping.
- Grants can expire without a cleanup job.
- Anti-escalation stops an editor with sharing rights from granting an owner role,
  revoking an owner or handing out access that outlives their own. It is on by default.
- Overrides handle cases such as legal holds, suspended tenants and break-glass access.
  A deny on a folder also denies everything inside it.
- Hooks report access decisions and grant changes.
- Batch evaluation uses one grant query for a page of resources instead of one per row.
- Startup validation rejects roles that refer to undeclared actions.

---

## Install

```bash
pnpm add robrac
```

`better-auth` `^1.6` is a peer dependency. `zod` `^4` is a regular dependency and
can be deduplicated with Better Auth's copy.

robrac ships as ESM with generated types and imports no `node:` built-ins. It runs on
Node, Bun, Deno and edge runtimes. The package declares Node 20 or newer in
`engines.node`.

---

## Quick start

### 1. Define a resource

```ts
import { defineResource, extendRole, hasSubject } from 'robrac';

export const recording = defineResource({
  type: 'recording',

  // Every facet + action this resource type knows about.
  statements: {
    recording: ['read', 'update', 'delete', 'share', 'transcribe'],
    note: ['read', 'update'],
  },

  roles: {
    viewer: { recording: ['read'], note: ['read'] },
    editor: extendRole(['viewer'], { recording: ['update', 'transcribe'] }),
    owner: extendRole(['editor'], {
      recording: ['delete', 'share'],
      note: ['update'],
    }),
  },

  // How robrac loads one. Return null when it does not exist.
  load: async ({ id }) =>
    (await db.query.recording.findFirst({ where: eq(t.id, id) })) ?? null,

  // Implement this to load a page of 50 resources in one call instead of 50.
  loadMany: async ({ ids }) => {
    const rows = await db.select().from(t).where(inArray(t.id, ids));
    return new Map(rows.map((row) => [row.id, row]));
  },

  // The tenant this row belongs to. A mismatch makes it invisible.
  scope: (row) => row.organizationId,

  // Derive roles from the resource instead of a stored grant. TypeScript checks
  // values pushed to `roles` against the role names declared above.
  computeRoles: ({ data, subjects, roles }) => {
    if (hasSubject(subjects, 'user', data.createdBy)) roles.push('owner');
    if (data.visibility === 'organization') roles.push('viewer');
  },

  // A caller needs this permission to manage grants.
  manage: { recording: ['share'] },
});
```

### 2. Register the plugin

```ts
import { betterAuth } from 'better-auth';
import { organization } from 'better-auth/plugins/organization';
import { robrac } from 'robrac';

export const robracPlugin = robrac({
  resources: { recording },
});

export const auth = betterAuth({
  database: drizzleAdapter(db, { provider: 'pg', schema }),
  plugins: [organization(), robracPlugin],
});

export type Auth = typeof auth;
```

By default, robrac reads the scope from `session.activeOrganizationId`. It resolves
the following subjects for the current session:

- `{ type: 'user', id }`
- `{ type: 'member', id }`

A session whose user is not a member of the active organization gets HTTP 403. Better
Auth leaves `activeOrganizationId` on a removed member's other sessions, so this check
runs on every request. You can replace both resolvers. See
[Subjects and scopes](#subjects-and-scopes).

> A session with no active organization has no scope. With the default
> `scope: 'required'`, robrac returns `SCOPE_REQUIRED` with HTTP status 403. Call
> `setActive` first or provide your own `resolveScope`.

### 3. Migrate the database

```bash
npx @better-auth/cli generate   # Drizzle / Prisma
npx @better-auth/cli migrate    # built-in adapter
```

Then add the composite index described in [Indexes](#indexes). Better Auth's schema
DSL cannot create it. Production deployments need this index.

### 4. Use it

Server side, without an HTTP round trip:

```ts
const robrac = robracPlugin.getEngine();

const decision = await robrac.evaluate({
  type: 'recording',
  id,
  scope: organizationId,
  subjects: [
    { type: 'user', id: userId },
    { type: 'member', id: memberId },
  ],
});

decision.found; // false when it does not exist in this tenant
decision.effectiveRoles; // ['owner']
decision.permissions.recording.share; // true; a typo is a compile error
decision.roles; // explicit, computed and inherited roles with their sources
```

Through the API, from a route handler:

```ts
const { success } = await auth.api.checkResourceAccess({
  headers: request.headers,
  body: {
    resourceType: 'recording',
    resourceId: id,
    permissions: { recording: ['update'] },
  },
});
```

From the browser:

```ts
import { createAuthClient } from 'better-auth/react';
import { robracClient } from 'robrac/client';
import type { Auth } from '~/server/auth';

export const authClient = createAuthClient({
  plugins: [robracClient<Auth>()],
});

await authClient.robrac.check({
  resourceType: 'recording',
  resourceId: id,
  permissions: { recording: ['update'] },
});
```

---

## Core concepts

### Decisions

`evaluate()` returns an `AccessDecision`:

```ts
type AccessDecision = {
  found: boolean; // false = does not exist, or not in this scope
  scope: string | null;
  resource: { type: string; id: string };
  data: TResource | null; // the loaded row (server-side only, never sent over the wire)
  roles: AppliedRole[]; // { role, origin: 'explicit' | 'computed' | 'inherited', via? }
  effectiveRoles: string[];
  permissions: PermissionMatrix; // fully expanded allow/deny table
  override: 'allow' | 'deny' | null;
};
```

`check()` tests the permission matrix. `require()` runs the same check and throws when
access is denied.

### Roles

A role is a permission map. `extendRole` adds inheritance. robrac also accepts objects
created by Better Auth's `createAccessControl(...).newRole(...)`, so you can reuse an
existing access-control setup:

```ts
roles: {
  viewer: { recording: ['read'] },
  editor: extendRole(['viewer'], { recording: ['update'] }),
  admin:  { recording: ['*'] },     // every declared action on that facet
}
```

robrac resolves inheritance when it starts. Cycles and references to undeclared roles
cause startup errors.

### Permission requests

Actions and facets are `AND`ed by default:

```ts
{ recording: ['read', 'update'] }               // both
{ recording: { actions: ['update', 'delete'], connector: 'OR' } }  // either
```

An empty request is never satisfied. An accidentally empty permission object is a bug,
and treating it as allowed would hide that bug.

### Computed roles

`computeRoles` derives roles from the resource without storing grants:

```ts
computeRoles: ({ data, subjects, roles }) => {
  if (hasSubject(subjects, 'user', data.createdBy)) roles.push('owner');
},
```

TypeScript checks the `roles` accumulator and any returned array against the names in
the resource's `roles` map. For example, `roles.push('onwer')` fails to compile. You
can push roles, return an array or do both. The engine combines the results.
`inheritRole` checks its return value against the same role names.

### Overrides

`override` returns a decision before robrac evaluates roles. Use it for states such as
a legal hold:

```ts
override: ({ data }) => (data.legalHold ? 'deny' : null),
```

`'deny'` clears every action and blocks grant management on the resource. It also
applies to every descendant reached through `parent`, and it beats a descendant's own
`'allow'`. `'allow'` grants every declared action and skips every anti-escalation
check, including what roles cascade to on descendants and when they expire, which
lets a break-glass administrator grant any role. An `'allow'` does not cascade.

`decision.roles` still lists the roles the caller holds under an override. Read
`permissions` for the answer.

### Resource hierarchy

A resource can name an ancestor whose grants cascade downward:

```ts
parent: ({ data }) => (data.folderId ? { type: 'folder', id: data.folderId } : null),
parentTypes: ['folder'],
inheritRole: ({ parent, role }) =>
  parent.type === 'folder' && role === 'curator' ? 'editor' : null,
```

Without `inheritRole`, an ancestor role carries over only when the child declares a
role with the same name. robrac drops any other role, and an ancestor's grant row for
a role the ancestor no longer declares confers nothing. `inheritRole` should return
`null` for parent types the resource never has: anti-escalation calls it for
descendants it cannot load, so its answer should depend only on `parent.type` and
`role`.

`parentTypes` lists the types `parent()` may return. robrac rejects any other type at
runtime. Declare it: without it, anti-escalation has to assume every type might be
this resource's parent.

`maxInheritanceDepth` defaults to 5 and accepts 0 to 64. A parent cycle in your data
stops at the first repeated ancestor. Each level adds one batched load and one grant
query per resource type, regardless of the number of resources in the batch.

robrac also checks the scope of each ancestor. A parent in another tenant contributes
nothing.

---

## Subjects and scopes

```ts
robrac({
  resources,

  // Which tenant is this request in?
  resolveScope: ({ session }) =>
    typeof session.activeWorkspaceId === 'string'
      ? session.activeWorkspaceId
      : null,

  // Which identities does the caller act under? Refuse callers outside the
  // tenant, because the session's tenant can be stale.
  resolveSubjects: async ({ user, scope }) => {
    if (scope && !(await isWorkspaceMember(user.id, scope))) {
      throw new RobracError('FORBIDDEN', 'Not a member of this workspace.');
    }
    return [
      { type: 'user', id: user.id },
      ...(await teamsFor(user.id, scope)).map((id) => ({ type: 'team', id })),
    ];
  },

  // Which grant targets belong to the tenant?
  subjects: {
    validate: ({ subject, scope }) => belongsToWorkspace(subject, scope),
  },
});
```

The default resolver returns the user and their membership in the active organization,
and refuses the request with `FORBIDDEN` when there is no membership. It treats every
non-null scope as an organization ID, so pair a custom `resolveScope` that returns
something else with a custom `resolveSubjects`. A custom `resolveSubjects` takes over
the membership check, so make it refuse non-members too. Pass
`defaultSubjectResolver({ includeTeams: true })` to include the caller's teams in the
active organization.

robrac combines roles from every subject identity. A caller receives both their
personal grants and their team grants.

### Multi-tenancy modes

| `scope`      | Behaviour                                                                       |
| ------------ | ------------------------------------------------------------------------------- |
| `'required'` | Default. Every resource must implement `scope()`; a mismatch reads as not found |
| `'optional'` | Scope is matched when the definition provides it                                |
| `'disabled'` | Single-tenant; scope is always `null`                                           |

With `'required'`, robrac checks the scope before it applies roles or permissions. A
resource in another scope reads as not found. With `'disabled'`, the plugin never calls
`resolveScope` and passes `null` to `resolveSubjects`.

---

## Listing resources

Listing needs different handling from a single-resource check.

Do not fetch a page and filter it afterwards. That produces short pages, wrong totals
and one permission check per row. robrac does not provide that API.

Apply access rules in the query instead. `accessibleResourceIds` returns the IDs
backed by live stored grants of declared roles. It does not apply computed roles,
inherited roles or overrides, so add those to the query using the columns they
inspect:

```ts
const grantedIds = await robrac.accessibleResourceIds({
  type: 'recording',
  scope: organizationId,
  subjects,
  permissions: { recording: ['read'] },
});

const rows = await db
  .select()
  .from(recording)
  .where(
    and(
      eq(recording.organizationId, organizationId),
      eq(recording.legalHold, false), // the 'deny' override
      or(
        eq(recording.createdBy, userId), // the 'owner' computed role
        eq(recording.visibility, 'organization'), // the 'viewer' computed role
        grantedIds.length ? inArray(recording.id, grantedIds) : sql`false`
      )
    )
  )
  .orderBy(desc(recording.createdAt))
  .limit(20);
```

This produces one indexed query with correct pagination and totals.

If you already have a page, such as search results or an ID list from another service,
use `filterAccessible` or `evaluateMany`. Both evaluate the batch with one grant
query:

```ts
const allowed = await robrac.filterAccessible({
  type: 'recording',
  ids: searchHits,
  scope: organizationId,
  subjects,
  permissions: { recording: ['read'] },
});
```

---

## Managing grants

robrac has separate grant APIs for trusted code and requests made on behalf of a user.

Use `robrac.grants.*` only in trusted server-side code such as seeds, migrations,
administration tools and background jobs. These methods do not perform authorization
checks:

```ts
await robrac.grants.grant({
  type: 'recording',
  id,
  scope: organizationId,
  subject: { type: 'member', id: memberId },
  role: 'editor',
  expiresAt: new Date(Date.now() + 7 * 24 * 3600_000),
});

await robrac.grants.set({ ..., roles: ['viewer'] });   // replace the whole set
await robrac.grants.revoke({ ..., role: 'editor' });   // or omit role for all
await robrac.grants.revokeResource({ type, id, scope });  // resource deleted
await robrac.grants.revokeSubject({ subject, scope });    // member left
await robrac.grants.revokeScope({ scope });               // tenant deleted
```

Use `robrac.authorized.*` when acting on behalf of a caller. These methods enforce the
resource's `manage` permission. Unless you set `escalation: 'allow'`, they also refuse
to:

- grant a role with a permission the caller lacks, on the resource or on what the role
  cascades to on descendants;
- revoke or replace a role with a permission the caller lacks;
- grant a role that outlives the caller's own access to it. A sharer whose grant
  expires on Friday can hand out access until Friday.

```ts
await robrac.authorized.grant({
  type: 'recording',
  id,
  subject: { type: 'member', id: targetMemberId },
  role: 'editor',
  actor: subjects,
});
```

The HTTP endpoints use the `authorized` tier exclusively. The `authorized` tier rejects
an `expiresAt` that is not in the future with a `RobracArgumentError`, which the
plugin maps to HTTP 400. A caller with no role and no permission on the resource gets
`RESOURCE_NOT_FOUND` rather than `FORBIDDEN`, so management calls don't reveal that it
exists.

A revoke or `setRoles` only deletes roles it read. A role granted while it runs
survives, and an expired role the caller could not revoke is left in place. The
caller's own access is checked before the store transaction starts, so a change racing
the removal of that access can still land.

The plugin's grant mutation endpoints (`grants/grant`, `grants/set` and
`grants/revoke`) use Better Auth's `sensitiveSessionMiddleware`, which
skips the cookie cache and reads the session from the server-side store.

Anti-escalation compares what roles cascade to on every type whose `parent()` could
return this one: all types with `parent`, narrowed by `parentTypes` where declared.
The caller is credited only with what its own roles cascade to. If a folder `owner`
should be able to hand out folder `viewer`, make sure `owner` cascades to at least
what `viewer` cascades to, for example by mapping both in `inheritRole`.

### Cleanup

Grants have no foreign key on `subjectId` because one subject column can represent
records from several tables.

- Set `schema.grant.scopeReferences` to make `scope` a foreign key and cascade tenant
  deletions in the database.
- After `/organization/remove-member` and `/organization/leave`, the plugin deletes the
  member's grants and the user's grants in that organization. After
  `/organization/delete`, it deletes every grant in the organization. A rejoining user
  starts with no grants.
- Cleanup is on by default only with the default `resolveScope`, because it treats
  organization IDs as scopes. It never runs under `scope: 'disabled'`. A failed
  cleanup is logged and does not fail the organization request; the membership check
  in the default subject resolver already denies access.

Call `grants.revokeResource` when you delete a resource.

---

## HTTP API

| Endpoint                      | `auth.api` method           | Client                 |
| ----------------------------- | --------------------------- | ---------------------- |
| `POST /robrac/check`          | `checkResourceAccess`       | `robrac.check`         |
| `POST /robrac/access`         | `getResourceAccess`         | `robrac.access`        |
| `POST /robrac/access-batch`   | `getResourceAccessBatch`    | `robrac.accessBatch`   |
| `POST /robrac/grants/list`    | `listResourceGrants`        | `robrac.grants.list`   |
| `POST /robrac/grants/grant`   | `grantResourceRole`         | `robrac.grants.grant`  |
| `POST /robrac/grants/set`     | `setResourceRoles`          | `robrac.grants.set`    |
| `POST /robrac/grants/revoke`  | `revokeResourceRole`        | `robrac.grants.revoke` |
| `POST /robrac/accessible-ids` | `listAccessibleResourceIds` | server only            |

`resourceType` is a discriminant. Selecting `'recording'` narrows `permissions` and
`role` to the values declared by that resource on both the client and server.

`/robrac/access` answers 404 when the caller holds no role and no permission on the
resource, and `/robrac/access-batch` reports such resources as `found: false`. A
caller cannot learn that a resource exists, or that it is under a legal hold, without
access to it.

Responses never include the loaded resource. robrac reports what the caller may do.
Your application remains responsible for returning the record and redacting fields.

The default rate limits are 120 reads per 10 seconds and 30 grant mutations per 60
seconds. Better Auth counts them per client IP and per path, so each endpoint has its
own budget. `/robrac/grants/list` uses the read budget. Configure or disable them with
`rateLimit`.

### Grant targets

`grants/grant` and `grants/set` check that the subject belongs to the caller's
organization before writing. With the default subject resolver, a `user` or `member`
must be a member of the organization and a `team` must be one of its teams (only with
`includeTeams`). Other subject types are rejected. A caller who may not manage the
resource gets the same 403 or 404 either way. A resolver that wraps the default one
can reuse its check with `validate: organizationSubjectValidator(inner)`. Any other
custom resolver needs its own `subjects.validate`:

```ts
robrac({
  resources,
  resolveSubjects,
  subjects: {
    validate: async ({ subject, scope }) =>
      subject.type === 'apiKey' && (await apiKeyBelongsTo(subject.id, scope)),
  },
});
```

### Share dialogs

`grants/list` filters `availableRoles` using the same anti-escalation rule as
`grants/grant`, so a dialog built from this list only offers roles the caller holds
the permissions for. If the caller's own access expires, the server also needs an
`expiresAt` no later than that. `declaredRoles` contains every role if you need to
show unavailable ones in a disabled state.

It returns raw `(subjectType, subjectId)` pairs for the grants themselves. To render
names, supply a describer:

```ts
robrac({
  resources,
  subjects: {
    describe: async ({ subjects, scope }) => {
      const memberIds = subjects
        .filter((s) => s.type === 'member')
        .map((s) => s.id);
      const rows = await db
        .select(/* join member -> user */)
        .where(
          and(inArray(member.id, memberIds), eq(member.organizationId, scope))
        );
      return rows.map((row) => ({
        type: 'member',
        id: row.memberId,
        label: row.name,
        image: row.image,
      }));
    },
  },
});
```

---

## Storage

### The contract

The store contract has nine required methods and an optional `transaction` method.
See [`src/store/types.ts`](src/store/types.ts). The repository's
[store tests](https://github.com/mkreuzmayr/robrac/blob/main/test/store.test.ts) run
the same contract against both bundled implementations; copy them to check a custom
store. The rules that matter most:

- Reads return every matching row. A store that silently stops at a page size can
  leave a role in place that `grants.set` was asked to remove.
- Every read accepts `now`. Stores must use that value instead of reading the wall
  clock so tests can control expiry.
- `limit` and `offset` count rows after expiry and subject filters run. Applying them
  earlier in SQL can omit resources the caller can access. A resource with several
  grant rows can appear on more than one page.
- `upsertGrant` leaves exactly one row per grant, even under concurrent calls.
- Only implement `transaction` when it is atomic. robrac runs every grant change
  except `revokeScope`, and the `onGrantChange` hook, inside it.

### The default implementation

`betterAuthGrantStore` uses `ctx.context.adapter`, so it works with the database
configured in Better Auth. Its queries follow two rules for adapter compatibility:

1. Queries do not use `OR` connectors because adapters combine `AND` and `OR` groups
   differently. The store applies `expiresAt IS NULL OR expiresAt > now` in memory
   after SQL has narrowed the result set.
2. Queries do not use composite subject predicates. The store narrows type and ID with
   two independent `IN` clauses, then matches each pair in memory. This SQL query may
   return extra rows, but subject counts per request are usually small.

Better Auth caps a `findMany` without a limit at 100 rows, so the store pages through
every read in chunks of 500, in the database's ID order. It re-checks every row
against the query in memory, because MySQL's default collation compares strings
case-insensitively. Concurrent upserts of the same grant can each insert a row when
the unique index below is missing; the store then keeps the first row and deletes the
others. With the index on PostgreSQL, the losing insert inside a transaction aborts
that transaction and the request fails; retry it. The store exposes `transaction`
only when the Better Auth adapter was configured with real transactions.

`memoryGrantStore` runs a transaction against a private copy and replays its writes
onto the live store when the callback resolves. A failed transaction changes nothing.

### Bringing your own

```ts
robrac({
  resources,
  store: myPostgresGrantStore, // or (adapter) => myStore
});
```

Custom stores can use an existing table, database-specific SQL or a cache.

### Schema

| Column                 | Type | Notes                              |
| ---------------------- | ---- | ---------------------------------- |
| `id`                   | text | primary key                        |
| `scope`                | text | nullable, indexed, optionally a FK |
| `resourceType`         | text |                                    |
| `resourceId`           | text | indexed                            |
| `subjectType`          | text |                                    |
| `subjectId`            | text | indexed                            |
| `role`                 | text |                                    |
| `grantedBySubjectType` | text | nullable                           |
| `grantedBySubjectId`   | text | nullable                           |
| `expiresAt`            | date | nullable; `null` never expires     |
| `createdAt`            | date |                                    |
| `updatedAt`            | date |                                    |

Rename anything:

```ts
robrac({
  resources,
  schema: {
    grant: {
      modelName: 'resource_grant',
      fields: { resourceType: 'resource_kind' },
      scopeReferences: { model: 'organization', onDelete: 'cascade' },
    },
  },
});
```

### Indexes

Better Auth's schema DSL only knows single-column `unique`, so add the composite
index yourself. The SQL below uses the default model and column names. Adjust it if
you renamed them, or if your adapter maps names to snake_case.

```sql
-- PostgreSQL 15+
CREATE UNIQUE INDEX robrac_grant_unique_idx
  ON "robracGrant" ("scope", "resourceType", "resourceId", "subjectType", "subjectId", "role")
  NULLS NOT DISTINCT;

CREATE INDEX robrac_grant_lookup_idx
  ON "robracGrant" ("scope", "resourceType", "subjectType", "subjectId");
```

The unique index needs `NULLS NOT DISTINCT` because `scope` is nullable. By default,
SQL treats two `NULL` values as distinct. Without this clause, the index does not
prevent duplicate grants in a single-tenant deployment because every row has
`scope = NULL`.

On PostgreSQL 14 and below, index a coalesced expression instead:

```sql
CREATE UNIQUE INDEX robrac_grant_unique_idx
  ON "robracGrant" (
    (coalesce("scope", '')), "resourceType", "resourceId",
    "subjectType", "subjectId", "role"
  );
```

On MySQL 8.0.13+, functional key parts need their own parentheses, and Better Auth
creates `resourceType`, `subjectType` and `role` as `text`, which needs a prefix
length. Change all six columns to `varchar(255) COLLATE utf8mb4_bin` in your
migration, so the index compares IDs the way robrac does (the default collation
ignores case), then:

```sql
CREATE UNIQUE INDEX robrac_grant_unique_idx
  ON robracGrant (
    (coalesce(scope, '')), resourceType, resourceId,
    subjectType, subjectId, role
  );
```

The unique index prevents concurrent upserts from creating duplicate grants. The
second index supports grant lookups during access checks.

---

## Auditing

```ts
robrac({
  resources,
  onDecision: (event) => {
    if (event.allowed === false) {
      logger.warn('robrac.denied', {
        subjects: event.subjects,
        resource: event.resource,
        request: event.request,
        roles: event.decision.effectiveRoles,
      });
    }
  },
  onGrantChange: (event) => {
    logger.info('robrac.grant', event);
  },
});
```

For `authorized.*` calls, `onDecision` reports the `manage` check. A grant then refused
by anti-escalation or subject validation throws `FORBIDDEN` or a 400 error and reports
no second event; log those from the error.

`decision.roles` records whether each role was explicit, computed or inherited. For
inherited roles, it also records the source. This information helps explain why an
access decision was made.

`onGrantChange` may return a promise, and robrac awaits it. It runs inside the store
transaction when the store has one, so a throwing hook rolls the change back. Keep it
fast, and on a single-connection database such as SQLite don't write through a second
connection, which would wait on that transaction forever.

`authorized.*` calls report every actor subject in `by`, or only `grantedBy` /
`revokedBy` when given. Trusted `grants.*` calls report `grantedBy` or `revokedBy`
when given and `null` otherwise. `revokeResource` and
`revokeSubject` report one event per affected subject or resource, with `by: null`.
`revokeSubject` only sees resource types in the registry. `revokeScope` deletes a whole
tenant and reports nothing.

---

## Testing

`robrac/testing` creates an engine with an in-memory store and a controllable clock.
Use it to test authorization rules without a database:

```ts
import { createTestRobrac, subjects } from 'robrac/testing';

const robrac = createTestRobrac({
  resources: { document },
  now: new Date('2026-01-01T00:00:00Z'),
});

await robrac.grants.grant({
  type: 'document',
  id: 'doc_1',
  scope: 'org_1',
  subject: { type: 'member', id: 'm_bob' },
  role: 'viewer',
  expiresAt: new Date('2026-01-02T00:00:00Z'),
});

robrac.clock.now = new Date('2026-01-03T00:00:00Z');

assert.equal(
  await robrac.check({
    type: 'document',
    id: 'doc_1',
    scope: 'org_1',
    subjects: subjects(['member', 'm_bob']),
    permissions: { document: ['read'] },
  }),
  false
);
```

```bash
pnpm test
```

---

## Using it without Better Auth

The engine has no HTTP or Better Auth dependency. Background workers, scheduled jobs
and services on other frameworks can import it directly and use the same decision
logic:

```ts
import { createRobrac } from 'robrac';

const robrac = createRobrac({ resources, store });
```

---

## Design notes

**Why not store a combined `subject` key?** A single `type:id` column would allow one
`IN` clause instead of two. It would make rows harder to read in a database console
and prevent indexes for a specific subject type. robrac instead queries a superset and
matches exact subject pairs in memory. Requests usually have only a few subjects.

**Why is `data` absent from HTTP responses?** Returning resource data would create
another read path with separate redaction rules. robrac answers access questions.
Your API returns the data.

**Why is anti-escalation on by default?** "May share" and "may delete" are different
permissions. Without the check, an editor with sharing rights could grant themselves a
more powerful role, strip the owner, or turn a one-week grant into a permanent one.
Set `escalation: 'allow'` if your roles are flat.

Two parent roles can grant the same permissions on the parent and still cascade to
different roles on children, so anti-escalation also compares the cascade. If it
refuses grants on a type that is never anyone's child, declare `parentTypes` on the
types that have a `parent()`.

**Why does an empty permission request fail?** `permissions: {}` usually means the
caller built the request incorrectly. Treating it as allowed would hide the mistake.

---

## Development

```bash
mise install     # node + pnpm
pnpm install
pnpm verify      # lint, typecheck, test, build
```

The test suite uses `node --test` and runs against `src/` directly. It needs no build
step or test framework.

See [CONTRIBUTING.md](CONTRIBUTING.md) for changeset and release conventions. While
robrac is pre-1.0, a breaking change requires a `minor` version bump.

## Changelog

Every released version is recorded in [CHANGELOG.md](CHANGELOG.md).

---

## License

MIT © Michael Kreuzmayr
