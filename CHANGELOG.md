# robrac

## 0.1.1

### Patch Changes

- Verify the release pipeline: no functional change.

## 0.1.0

### Minor Changes

- Initial release. Resource-level authorization for Better Auth: abstract subjects,
  scopes and resources, role inheritance and computed roles, resource hierarchy, grant
  expiry, anti-escalation, overrides, audit hooks and batch evaluation, over a
  pluggable `GrantStore` with a Better Auth adapter implementation. Ships ESM with
  generated types across `robrac`, `robrac/client` and `robrac/testing`.
