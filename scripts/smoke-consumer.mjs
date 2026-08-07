// Installs a packed robrac tarball into a throwaway project and exercises all three
// entrypoints from *outside* the repo — the only way to catch a broken `exports` map,
// a missing file in `files`, or a runtime that the published ESM does not actually run
// on. Run as: node scripts/smoke-consumer.mjs <path-to-tarball>
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const tarball = process.argv[2];
if (!tarball) {
  console.error('usage: node scripts/smoke-consumer.mjs <path-to-tarball>');
  process.exit(1);
}

const dir = mkdtempSync(join(tmpdir(), 'robrac-smoke-'));
console.log(`node ${process.version} — consumer at ${dir}`);

writeFileSync(
  join(dir, 'package.json'),
  JSON.stringify(
    { name: 'robrac-smoke', private: true, type: 'module' },
    null,
    2
  )
);

/**
 * @param {string} cmd
 * @param {readonly string[]} args
 */
const run = (cmd, args) =>
  execFileSync(cmd, args, {
    cwd: dir,
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });

// npm, not pnpm: a consumer of a published package is the thing under test, and npm is
// the lowest common denominator every supported Node ships with.
run('npm', [
  'install',
  '--no-audit',
  '--no-fund',
  resolve(tarball),
  'better-auth@^1.6.0',
]);

writeFileSync(
  join(dir, 'smoke.mjs'),
  `
import assert from 'node:assert/strict';
import { createTestRobrac, subjects } from 'robrac/testing';
import { createRobrac, defineResource, extendRole } from 'robrac';
import { robracClient } from 'robrac/client';

assert.equal(typeof createRobrac, 'function', 'robrac root entrypoint');
assert.equal(typeof robracClient, 'function', 'robrac/client entrypoint');

const document = defineResource({
  type: 'document',
  statements: { document: ['read', 'update'] },
  roles: {
    viewer: { document: ['read'] },
    editor: extendRole(['viewer'], { document: ['update'] }),
  },
  load: async ({ id }) => ({ id, organizationId: 'org_1' }),
  scope: (row) => row.organizationId,
});

const robrac = createTestRobrac({ resources: { document } });

await robrac.grants.grant({
  type: 'document',
  id: 'doc_1',
  scope: 'org_1',
  subject: { type: 'member', id: 'm_bob' },
  role: 'editor',
});

const allowed = await robrac.check({
  type: 'document',
  id: 'doc_1',
  scope: 'org_1',
  subjects: subjects(['member', 'm_bob']),
  permissions: { document: ['update'] },
});
assert.equal(allowed, true, 'granted editor may update');

const denied = await robrac.check({
  type: 'document',
  id: 'doc_1',
  scope: 'org_other',
  subjects: subjects(['member', 'm_bob']),
  permissions: { document: ['read'] },
});
assert.equal(denied, false, 'a grant does not cross tenants');

console.log('smoke ok');
`
);

run('node', ['smoke.mjs']);
assert.ok(true);
