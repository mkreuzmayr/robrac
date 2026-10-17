---
'robrac': minor
---

**Breaking:** Security hardening. The API only gains additions, but several behaviours tighten.

- The default subject resolver refuses callers that are not a member of the active organization with `FORBIDDEN`. A removed member's other sessions no longer keep `user` grants or computed roles.
- Removing a member deletes their `member` and `user` grants in that organization. Cleanup now defaults on only with the default scope resolver.
- `grants/grant` and `grants/set` reject subjects outside the caller's organization when the default subject resolver is in use. `subjects.validate` adds the same check for custom resolvers.
- Anti-escalation now also covers revoking and replacing roles, refuses grants that outlive the actor's own access, and compares what roles cascade to on descendant types. The new optional `parentTypes` on a resource narrows which types count as its parents.
- `authorized.*` answers `RESOURCE_NOT_FOUND` instead of `FORBIDDEN` to callers with no role and no permission on the resource.
- A `'deny'` override cascades to descendants and blocks grant management.
- `betterAuthGrantStore` reads past Better Auth's 100-row default limit, converges duplicate rows, and only exposes `transaction` when the adapter has real transactions.
- `memoryGrantStore` transactions roll back on failure, and the store returns copies of its rows.
- Role lookups ignore `Object.prototype` names such as `constructor`.
- `/robrac/access` answers 404, and `/robrac/access-batch` reports `found: false`, for resources the caller cannot access at all.
- The `authorized` tier requires `expiresAt` to be in the future and throws the newly exported `RobracArgumentError` otherwise. `maxInheritanceDepth` must be an integer from 0 to 64. `manage` requests are validated at startup.
- Resource definitions and roles are validated more strictly at startup: `load`, `roles` and `statements` are required, actions must be strings, and `'*'` can no longer be declared as an action.
- `organizationSubjectValidator` is exported for resolvers that wrap the default one, and `defaultSubjectResolver` accepts a `teamModel`.
- The plugin answers `INVALID_CONFIGURATION` with HTTP 500 instead of 400 and logs the cause. A `parent()` returning an unknown type, or one outside `parentTypes`, is now `INVALID_CONFIGURATION` instead of `UNKNOWN_RESOURCE_TYPE`.
- The trusted tier rejects an invalid `Date` as `expiresAt`.
- `onGrantChange` is awaited and runs inside the store transaction when the store has one. Revokes record their actor, and `authorized.*` events list every actor subject in `by` unless `grantedBy` or `revokedBy` is given.
- Every `authorized.*` call reports one `onDecision` verdict, including for a resource that is not found.
- `revokeResource` and `revokeSubject` report one `onGrantChange` event per affected subject or resource. With a hook set, they read the affected grants first, and a throwing hook rolls the revoke back when the store has a transaction.
- A failed grant cleanup after a member removal or organization deletion is logged and no longer fails the organization request.
- Under `scope: 'disabled'`, the plugin no longer calls `resolveScope`.
- A guarded revoke or `setRoles` only deletes roles it read, and leaves an expired role the caller could not revoke in place instead of deleting it.
- `accessibleResourceIds` with `permissions` and `limit`/`offset` judges each resource on all of its grants, not only the rows on the current page.
- `grants/grant`, `grants/set` and `grants/revoke` use `sensitiveSessionMiddleware`, so a revoked session cannot keep writing through the cookie cache. A session injected by a before-hook instead of the session cookie is no longer accepted on these endpoints. Request ids must be well-formed Unicode.
- `/robrac/grants/list` uses the read rate limit. Request strings are length-limited.
- Computed and inherited role names that the resource does not declare are dropped, and grant rows for undeclared roles no longer cascade to children.
- `GrantStore` gains optional inputs: `subject` on `listResourceGrants`, `includeExpired` on `listSubjectGrants` and `now` on `upsertGrant`.
- `robrac/client` no longer imports server code.
