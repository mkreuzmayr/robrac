# robrac

**Ro**le **B**ased **R**esource **A**ccess **C**ontrol — a Better Auth plugin for the
authorization question that organization-level RBAC cannot answer.

Better Auth's `organization` plugin tells you whether a member may edit _recordings_.
robrac tells you whether they may edit **this** recording.

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

Most per-resource authorization code in a Better Auth app ends up hardcoded against
that app's ORM, its `member` table and its one resource type. robrac keeps three
things abstract so it stays a library rather than a fork of your data model:

| Concept      | What it is                              | Why abstract                                                                                 |
| ------------ | --------------------------------------- | -------------------------------------------------------------------------------------------- |
| **Subject**  | who is asking — `{ type, id }`          | Grants go to users, org members, teams, service accounts or API keys without a schema change |
| **Scope**    | the tenant a decision is made in        | Multi-tenant by default, `null` for single-tenant, and cross-tenant reads are impossible     |
| **Resource** | what is being accessed — `{ type, id }` | robrac never needs to know your tables; you teach it how to load one                         |

Persistence goes through a single [`GrantStore`](src/store/types.ts) interface. The
default implementation rides on Better Auth's own adapter, so robrac runs on Drizzle,
Prisma, Kysely, MongoDB or a raw connection with **zero ORM-specific code**.

### What it gives you beyond a `resource_roles` table

- **Role inheritance** — `editor extends viewer`, resolved once at boot.
- **Computed roles** — "the creator is the owner", "org-visible documents are readable
  by every member" — no rows written for the common case.
- **Resource hierarchy** — a grant on a folder cascades onto its documents, with an
  explicit role translation between the two namespaces.
- **Grant expiry** — time-boxed access without a cleanup job.
- **Anti-escalation** — a share-capable editor cannot mint owners. On by default.
- **Overrides** — legal hold, suspended tenant, break-glass admin.
- **Audit hooks** — every decision and every grant change.
- **Batch evaluation** — one query per page of resources, not one per row.
- **Boot-time validation** — a role that references an action you never declared is a
  startup error, not a silent denial six months later.

---

## Install

```bash
pnpm add robrac
```

`better-auth` `^1.6` is a peer dependency; `zod` `^4` comes along as a regular
dependency (better-auth depends on it too, so it dedupes).

robrac ships as ESM with generated types and imports **no `node:` builtins**, so it
runs on Node, Bun, Deno and edge runtimes alike. `engines.node` declares `>=20` as an
honest floor, not a hard gate.

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
    await db.query.recording.findFirst({ where: eq(t.id, id) }),

  // Strongly recommended: without it, a page of 50 issues 50 loads.
  loadMany: async ({ ids }) => {
    const rows = await db.select().from(t).where(inArray(t.id, ids));
    return new Map(rows.map((row) => [row.id, row]));
  },

  // The tenant this row belongs to. A mismatch makes it invisible.
  scope: (row) => row.organizationId,

  // Roles that follow from the data rather than from a stored grant. The
  // `roles` accumulator is typed to the role names declared above, so a typo
  // is a compile error.
  computeRoles: ({ data, subjects, roles }) => {
    if (hasSubject(subjects, 'user', data.createdBy)) roles.push('owner');
    if (data.visibility === 'organization') roles.push('viewer');
  },

  // What a caller must be allowed to do in order to hand out grants.
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

By default robrac resolves:

- **scope** from `session.activeOrganizationId`
- **subjects** as `[{ type: 'user', id }, { type: 'member', id }]`

Both are single options away from anything else — see [Subjects and scopes](#subjects-and-scopes).

> **A session with no active organization has no scope.** Under the default
> `scope: 'required'` that is an error (`SCOPE_REQUIRED`, HTTP 403 with a message
> saying so) rather than a blanket denial — a silent "you may do nothing" is
> indistinguishable from a permission bug and takes hours to diagnose. Make sure
> `setActive` has run, or supply your own `resolveScope`.

### 3. Migrate the database

```bash
npx @better-auth/cli generate   # Drizzle / Prisma
npx @better-auth/cli migrate    # built-in adapter
```

Then add the composite index Better Auth's schema DSL cannot express — see
[Indexes](#indexes). It is not optional in production.

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
decision.permissions.recording.share; // true — typed, a typo is a compile error
decision.roles; // provenance: explicit / computed / inherited
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

Everything is derived from one object:

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

`check()` is nothing more than a predicate over `permissions`. `require()` is
`check()` that throws.

### Roles

A role is a permission map. `extendRole` adds inheritance, and Better Auth's
`createAccessControl(...).newRole(...)` objects are accepted unchanged, so an existing
access-control setup can be handed over as-is:

```ts
roles: {
  viewer: { recording: ['read'] },
  editor: extendRole(['viewer'], { recording: ['update'] }),
  admin:  { recording: ['*'] },     // every declared action on that facet
}
```

Inheritance is flattened at construction. Cycles and references to undeclared roles
throw at boot.

### Permission requests

Actions and facets are `AND`ed by default:

```ts
{ recording: ['read', 'update'] }               // both
{ recording: { actions: ['update', 'delete'], connector: 'OR' } }  // either
```

An **empty request is never satisfied**. An accidentally empty permission object is a
bug, and treating it as "allowed" is the kind of bug that ships.

### Computed roles

The cheapest grant is the one you never store. `computeRoles` derives roles from the
resource itself:

```ts
computeRoles: ({ data, subjects, roles }) => {
  if (hasSubject(subjects, 'user', data.createdBy)) roles.push('owner');
},
```

The `roles` accumulator — and the return value, if you prefer returning an array —
is typed to the names declared in the resource's `roles` map, so `roles.push('onwer')`
fails to compile instead of becoming a role that silently confers nothing. Push,
return, or both; the engine takes the union. `inheritRole`'s return value is
constrained the same way.

### Overrides

`override` short-circuits the whole decision — useful for states that are not about
roles at all:

```ts
override: ({ data }) => (data.legalHold ? 'deny' : null),
```

`'deny'` blanks every action, `'allow'` grants every declared one. Overrides also
suppress the anti-escalation check when they return `'allow'`, which is what makes a
break-glass admin role practical.

### Resource hierarchy

A resource can name an ancestor whose grants cascade downward:

```ts
parent: ({ data }) => (data.folderId ? { type: 'folder', id: data.folderId } : null),
inheritRole: ({ role }) => (role === 'curator' ? 'editor' : null),
```

Without `inheritRole`, an ancestor role carries over only when the child declares a
role of the same name; anything else is dropped rather than guessed at. The walk is
bounded by `maxInheritanceDepth` (default 5), so a cycle in your data cannot hang a
request, and each level costs one batched query regardless of how many resources are
being evaluated.

Ancestors are scope-checked like anything else: a parent in another tenant contributes
nothing.

---

## Subjects and scopes

```ts
robrac({
  resources,

  // Which tenant is this request in?
  resolveScope: ({ session }) => session.activeWorkspaceId ?? null,

  // Which identities does the caller act under?
  resolveSubjects: async ({ user, adapter, scope }) => [
    { type: 'user', id: user.id },
    ...(await teamsFor(user.id, scope)).map((id) => ({ type: 'team', id })),
  ],
});
```

The bundled default resolves the user plus their membership in the active
organization. Pass `defaultSubjectResolver({ includeTeams: true })` to also pick up
the organization plugin's teams.

Subjects are **additive**: a caller's effective roles are the union across every
identity they hold, so a team grant and a personal grant compose without special
cases.

### Multi-tenancy modes

| `scope`      | Behaviour                                                                       |
| ------------ | ------------------------------------------------------------------------------- |
| `'required'` | Default. Every resource must implement `scope()`; a mismatch reads as not found |
| `'optional'` | Scope is matched when the definition provides it                                |
| `'disabled'` | Single-tenant; scope is always `null`                                           |

`'required'` is what makes cross-tenant access structurally impossible rather than a
thing you remembered to check.

---

## Listing resources

This is the part most per-resource authorization gets wrong, so it is worth being
explicit.

**Do not** fetch a page and filter it afterwards. You get short pages, wrong totals
and a permission check per row. robrac deliberately does not offer that API.

Instead, push access into the query. `accessibleResourceIds` gives you the ids backed
by a stored grant; your computed roles are already expressible in SQL because they
live in your own columns:

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

One indexed query, correct pagination, correct totals.

When you already hold a page — a search result, an id list from another service —
`filterAccessible` and `evaluateMany` evaluate the whole batch with one grant query:

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

Two tiers, and the distinction is deliberate.

`robrac.grants.*` are **unchecked primitives** for trusted server-side paths — seeds,
migrations, admin tooling, back-office jobs:

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

`robrac.authorized.*` is the same surface **on behalf of a caller**. It enforces the
resource's `manage` permission and, unless `escalation: 'allow'`, refuses to grant
more than the caller holds:

```ts
await robrac.authorized.grant({
  type: 'recording',
  id,
  subject: { type: 'member', id: targetMemberId },
  role: 'editor',
  actor: subjects,
});
```

The HTTP endpoints use the `authorized` tier exclusively.

### Cleanup

Grants have no foreign key on `subjectId` — subjects are heterogeneous by design, and
one column cannot reference several tables. In exchange:

- `scope` _can_ be a real foreign key: set `schema.grant.scopeReferences` and you get
  database-level cascade on tenant deletion.
- The plugin wires best-effort cleanup to `/organization/remove-member`,
  `/organization/leave` and `/organization/delete`.
- Removing a member is already safe without any of this: subject resolution can no
  longer produce that member id, so the rows are inert. Cleanup is hygiene.

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
| `POST /robrac/accessible-ids` | `listAccessibleResourceIds` | — (server only)        |

`resourceType` is a discriminant: picking `'recording'` narrows `permissions` and
`role` to what that resource declares, on both sides of the wire.

Responses never include the loaded resource. robrac answers "what may this caller do";
serving the record stays your application's job, which keeps field-level redaction
where it belongs.

Rate limits default to 120 reads / 10s and 30 grant mutations / 60s per path group,
and are configurable or disableable via `rateLimit`.

### Share dialogs

`grants/list` returns `availableRoles` already filtered by the anti-escalation rule
that `grants/grant` enforces, so a dialog rendered from it cannot offer a role that
will be rejected on submit. `declaredRoles` carries the full list when you need to
show the ungrantable ones greyed out.

It returns raw `(subjectType, subjectId)` pairs for the grants themselves. To render
names, supply a describer:

```ts
robrac({
  resources,
  subjects: {
    describe: async ({ subjects }) => {
      const memberIds = subjects
        .filter((s) => s.type === 'member')
        .map((s) => s.id);
      const rows = await db
        .select(/* join member -> user */)
        .where(inArray(member.id, memberIds));
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

Nine required methods plus an optional `transaction`, documented in
[`src/store/types.ts`](src/store/types.ts). The [store test suite](test/store.test.ts)
is written as a shared contract and runs against both bundled implementations — copy
it verbatim to validate a custom store.

Two rules are easy to get wrong and are pinned by the suite:

- **Every read takes `now`**; a store must never consult the wall clock, or a frozen
  clock in tests stops governing expiry.
- **`limit`/`offset` count rows that survive filtering.** Pushing them into SQL ahead
  of the expiry and subject filters silently drops resources the caller can reach.

### The default implementation

`betterAuthGrantStore` talks to `ctx.context.adapter`, so it inherits whichever
database Better Auth is configured with. Two constraints keep it portable across every
adapter:

1. **No `OR` connectors.** Adapters differ in how they combine `AND` and `OR` groups.
   Every predicate is a pure conjunction; the one genuinely disjunctive filter
   (`expiresAt IS NULL OR expiresAt > now`) is applied in memory over an already
   narrow result set.
2. **No composite subject predicate.** `(type, id)` pairs are narrowed in SQL with two
   independent `IN` clauses — a superset — and matched exactly in memory. Subject
   counts per request are single digits.

Because both filters run after the query, `listSubjectGrants` cannot simply hand
`limit` to SQL — it walks the result in chunks until it has enough live rows.

### Bringing your own

```ts
robrac({
  resources,
  store: myPostgresGrantStore, // or (adapter) => myStore
});
```

Point robrac at an existing table, hand-tuned SQL, or a cache in front of either.

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
| `expiresAt`            | date | nullable — `null` never expires    |
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
index yourself:

```sql
-- PostgreSQL 15+
CREATE UNIQUE INDEX robrac_grant_unique_idx
  ON robrac_grant (scope, resource_type, resource_id, subject_type, subject_id, role)
  NULLS NOT DISTINCT;

CREATE INDEX robrac_grant_lookup_idx
  ON robrac_grant (scope, resource_type, subject_type, subject_id);
```

`NULLS NOT DISTINCT` is not optional. `scope` is nullable, and by default SQL treats
two NULLs as distinct — so without it the unique index silently stops constraining
anything in single-tenant deployments, where _every_ row has `scope = NULL`.

On PostgreSQL 14 and below, or on MySQL, index a coalesced expression instead:

```sql
CREATE UNIQUE INDEX robrac_grant_unique_idx
  ON robrac_grant (
    coalesce(scope, ''), resource_type, resource_id,
    subject_type, subject_id, role
  );
```

The unique index closes the upsert race that the store's transaction only narrows.
The second index is the one the hot path actually uses.

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

`decision.roles` carries provenance — which roles were explicit, which were computed,
which were inherited and from where — which is usually the difference between an
audit log and an audit log you can act on.

---

## Testing

`robrac/testing` gives you an engine with an in-memory store and a frozen
clock, so authorization rules can be unit tested without a database:

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

The engine has no HTTP or Better Auth dependency. Background workers, cron jobs and
services on other frameworks can import it directly and get byte-identical decisions:

```ts
import { createRobrac } from 'robrac';

const robrac = createRobrac({ resources, store });
```

---

## Design notes

**Why not store a denormalized `subject` key?** A single `type:id` column would allow
one `IN` clause instead of two. It would also make the table unreadable in a database
console and impossible to index per subject type. The superset-then-filter approach
costs nothing at real subject counts.

**Why is `data` absent from HTTP responses?** Because the moment an authorization
endpoint starts returning rows, it becomes a second, unreviewed read path with its own
redaction rules. robrac answers questions about access; your API serves data.

**Why is anti-escalation on by default?** Because "may share" and "may delete" are
different permissions, and every system that conflates them eventually lets an editor
promote themselves. Opt out with `escalation: 'allow'` if your roles are flat.

**Why does an empty permission request fail?** Because `permissions: {}` is almost
always a bug in the caller, and the failure mode of the alternative is silent.

---

## Development

```bash
mise install     # node + pnpm
pnpm install
pnpm verify      # lint, typecheck, test, build
```

The test suite runs on `node --test` against `src/` directly — no build step, no test
framework.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the changeset and release conventions —
notably that while robrac is pre-1.0, a breaking change takes a **`minor`** bump.

## Changelog

Every released version is recorded in [CHANGELOG.md](CHANGELOG.md).

---

## License

MIT © Michael Kreuzmayr
