# Contributing to robrac

## Development

```bash
mise install     # node + pnpm
pnpm install
pnpm verify      # lint, typecheck, test, build
```

The test suite runs on `node --test` against `src/` directly, with no build step and no
test framework. `pnpm verify` and `pnpm format:check` are what CI runs on Node 22 and 26.

## Pull requests

Every PR runs `verify` on Node 22 and 26. The toolchain needs Node 22.18+, so Node 20
is covered by installing the packed tarball into a throwaway project and importing all
three entrypoints, which keeps `engines.node: ">=20"` honest.

If a PR changes anything a consumer can observe, add a changeset:

```bash
pnpm changeset
```

That writes a Markdown file under `.changeset/`. Commit it with the change.

### While robrac is pre-1.0, never author a `major` changeset

Changesets has **no pre-1.0 guard**. A `major` changeset at `0.1.0` resolves to
`1.0.0`, not `0.2.0`, and would ship a stability promise nobody made. Until 1.0 is
declared deliberately:

| Change                       | Bump    | Entry                      |
| ---------------------------- | ------- | -------------------------- |
| Breaking API change          | `minor` | leads with `**Breaking:**` |
| New feature, back-compatible | `minor` | plain                      |
| Fix, docs, internals         | `patch` | plain                      |

The `0.x` range is where breaking changes are expected; the version number just cannot
say so in semver's own vocabulary yet.

## Releasing

Releases are cut from `main` by a maintainer. Changesets runs in **version-only** mode:
it never publishes; pushing the tag does.

```bash
pnpm changeset:version        # consumes .changeset/*.md → package.json + CHANGELOG.md
git commit -am "chore: release 0.1.1"
git push
git tag v0.1.1                # must match package.json exactly
git push origin v0.1.1
```

The tag push triggers `.github/workflows/release.yml`, which:

1. hard-fails if the tagged commit is not on `main`, if the tag does not match
   `package.json`'s version, or if `CHANGELOG.md` has no section for it;
2. re-runs the full `verify` and packs the tarball in a job with read-only permissions;
3. publishes that exact tarball to npm under **trusted publishing (OIDC)** from a
   separate job that holds only `id-token: write` and runs in the `npm` environment.
   There is no npm token anywhere in this repo, and provenance is attached automatically;
4. cuts a GitHub Release with the body sliced from that version's `CHANGELOG.md` section.

Give the `npm` environment required reviewers in the repository settings, and protect
`v*` tags with a ruleset, so a single compromised account cannot publish alone.

Everything ships to the `latest` dist-tag. There is no prerelease channel.

### Why there is no `NODE_AUTH_TOKEN`

npm trusted publishing authenticates the workflow itself via OIDC, so no long-lived
credential exists to leak. It requires the repository to stay **public**, because provenance
will not generate from a private repo. It also requires the trusted-publisher configuration on
npmjs.com to name this repo, `release.yml` by filename and the `npm` environment.
Renaming either breaks publishing until the npm configuration is updated to match.
