import assert from 'node:assert/strict';
import { it } from 'node:test';

import { defineResource, robrac } from '../src/index.ts';

const resources = {
  document: defineResource({
    type: 'document',
    statements: { document: ['read'] },
    roles: { viewer: { document: ['read'] } },
    load: () => null,
    manage: { document: ['read'] },
  }),
};
for (const rateLimit of [
  undefined,
  { read: { window: 13, max: 17 }, write: { window: 19, max: 23 } },
]) {
  it(`uses read limits for grant listing, custom=${rateLimit !== undefined}`, () => {
    const plugin = robrac({ resources, scope: 'disabled', rateLimit });
    for (const path of [
      '/robrac/check',
      '/robrac/access',
      '/robrac/access-batch',
      '/robrac/grants/list',
      '/robrac/accessible-ids',
    ]) {
      const matches = plugin.rateLimit.filter((rule) => rule.pathMatcher(path));
      assert.equal(matches.length, 1, path);
      assert.equal(matches[0]?.max, rateLimit?.read.max ?? 120, path);
      assert.equal(matches[0]?.window, rateLimit?.read.window ?? 10, path);
    }
    for (const path of [
      '/robrac/grants/grant',
      '/robrac/grants/set',
      '/robrac/grants/revoke',
    ]) {
      const matches = plugin.rateLimit.filter((rule) => rule.pathMatcher(path));
      assert.equal(matches.length, 1, path);
      assert.equal(matches[0]?.max, rateLimit?.write.max ?? 30, path);
      assert.equal(matches[0]?.window, rateLimit?.write.window ?? 60, path);
    }
    assert.equal(
      plugin.rateLimit.some((rule) => rule.pathMatcher('/other')),
      false
    );
  });
}
it('allows disabling plugin rate limits', () => {
  assert.deepEqual(
    robrac({ resources, scope: 'disabled', rateLimit: false }).rateLimit,
    []
  );
});
