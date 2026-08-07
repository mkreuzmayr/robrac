# Changesets

This folder holds [changesets](https://github.com/changesets/changesets) — one Markdown
file per unreleased change, describing the bump it deserves and the changelog line it
earns. `pnpm changeset` writes one; `pnpm changeset:version` consumes every pending one,
rewrites `package.json` and `CHANGELOG.md`, and deletes them.

Changesets runs here in **version-only** mode: it never publishes. Publishing is the
release workflow's job, triggered by pushing a `v*` tag. See
[CONTRIBUTING.md](../CONTRIBUTING.md).

## While robrac is pre-1.0, never author a `major` changeset

Changesets has **no pre-1.0 guard**: a `major` changeset at `0.1.0` resolves to `1.0.0`,
not `0.2.0`. Until robrac reaches 1.0 deliberately:

- **breaking change → `minor`**, with the entry leading `**Breaking:** …`
- everything else → `patch`
