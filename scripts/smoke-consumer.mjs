// Installs a packed robrac tarball into a throwaway project and exercises all public
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
  'typescript@7.0.2',
]);

writeFileSync(
  join(dir, 'core.mjs'),
  `
import assert from 'node:assert/strict';
import { createRobrac, defineResource, memoryGrantStore } from 'robrac/core';
import { createTestRobrac } from 'robrac/testing';
assert.throws(() => import.meta.resolve('better-auth'), { code: 'ERR_MODULE_NOT_FOUND' });
const resources = { document: defineResource({
  type: 'document', statements: { document: ['read'] },
  roles: { viewer: { document: ['read'] } },
  load: ({ id }) => ({ id }), manage: { document: ['read'] },
}) };
const engine = createRobrac({ resources, store: memoryGrantStore(), scope: 'disabled' });
const subject = { type: 'user', id: 'alice' };
await engine.grants.grant({ type: 'document', id: 'doc', subject, role: 'viewer' });
assert.equal(await engine.check({ type: 'document', id: 'doc', subjects: [subject], permissions: { document: ['read'] } }), true);
assert.equal(await createTestRobrac({ resources, scope: 'disabled' }).check({ type: 'document', id: 'doc', subjects: [subject], permissions: { document: ['read'] } }), false);
console.log('standalone core ok');
`
);
run('node', ['core.mjs']);

writeFileSync(
  join(dir, 'core-types.mts'),
  `
import { createRobrac, defineResource, memoryGrantStore } from 'robrac/core';
import { createTestRobrac } from 'robrac/testing';
const resources = { document: defineResource({
  type: 'document', statements: { document: ['read'] },
  roles: { viewer: { document: ['read'] } },
  load: ({ id }) => ({ id }), manage: { document: ['read'] },
}) };
const engine = createRobrac({ resources, store: memoryGrantStore(), scope: 'disabled' });
const decision = await engine.evaluate({ type: 'document', id: 'doc', subjects: [] });
const readable: boolean = decision.permissions.document.read;
// @ts-expect-error undeclared action
const bad = decision.permissions.document.delete;
createTestRobrac({ resources, scope: 'disabled' });
`
);
run('node', [
  'node_modules/typescript/bin/tsc',
  '--noEmit',
  '--strict',
  '--skipLibCheck',
  'false',
  '--module',
  'NodeNext',
  '--target',
  'ES2022',
  'core-types.mts',
]);

run('npm', ['install', '--no-audit', '--no-fund', 'better-auth@^1.6.0']);

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
