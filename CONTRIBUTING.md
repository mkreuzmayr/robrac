# Contributing to robrac

## Development

```bash
mise install     # node + pnpm
pnpm install
pnpm verify      # lint, typecheck, test, build
```

The test suite runs on `node --test` against `src/` directly — no build step, no test
framework. `pnpm verify` is exactly what CI runs; if it is green locally it is green on
CI, on Node 20, 22 and 26.

## Pull requests

Every PR runs `verify` on a **Node 20 / 22 / 26** matrix, which is what keeps
`engines.node: ">=20"` an honest claim rather than an aspiration.

If a PR changes anything a consumer can observe, add a changeset:

```bash
pnpm changeset
```

That writes a Markdown file under `.changeset/`. Commit it with the change.

### While robrac is pre-1.0, never author a `major` changeset

Changesets has **no pre-1.0 guard**. A `major` changeset at `0.1.0` resolves to
`1.0.0`, not `0.2.0` — it would ship a stability promise nobody made. Until 1.0 is
declared deliberately:

| Change                       | Bump    | Entry                      |
| ---------------------------- | ------- | -------------------------- |
| Breaking API change          | `minor` | leads with `**Breaking:**` |
| New feature, back-compatible | `minor` | plain                      |
| Fix, docs, internals         | `patch` | plain                      |

The `0.x` range is where breaking changes are expected; the version number just cannot
say so in semver's own vocabulary yet.

## Releasing

Releases are cut from `main` by a maintainer. Changesets runs in **version-only** mode
— it never publishes; pushing the tag does.

```bash
pnpm changeset:version        # consumes .changeset/*.md → package.json + CHANGELOG.md
git commit -am "chore: release 0.1.1"
git push
git tag v0.1.1                # must match package.json exactly
git push origin v0.1.1
```

The tag push triggers `.github/workflows/release.yml`, which:

1. re-runs the full `verify` — an earlier green tick on the same commit is not trusted;
2. hard-fails if the tag does not match `package.json`'s version;
3. `pnpm publish`es to npm under **trusted publishing (OIDC)** — there is no npm token
   anywhere in this repo, and provenance is attached automatically;
4. cuts a GitHub Release with the body sliced from that version's `CHANGELOG.md` section.

Everything ships to the `latest` dist-tag. There is no prerelease channel.

### Why there is no `NODE_AUTH_TOKEN`

npm trusted publishing authenticates the workflow itself via OIDC, so no long-lived
credential exists to leak. It requires the repository to stay **public** — provenance
will not generate from a private repo — and the trusted-publisher configuration on
npmjs.com to name this repo and `release.yml` by filename. Renaming that workflow file
breaks publishing until the npm configuration is updated to match.
