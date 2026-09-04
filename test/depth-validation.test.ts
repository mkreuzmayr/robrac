import assert from 'node:assert/strict';
import { it } from 'node:test';

import {
  createRobrac,
  defineResource,
  memoryGrantStore,
  robrac,
  RobracError,
} from '../src/index.ts';

const resources = {
  document: defineResource({
    type: 'document',
    statements: { document: ['read'] },
    roles: { viewer: { document: ['read'] } },
    load: () => null,
    manage: { document: ['read'] },
  }),
};
for (const maxInheritanceDepth of [
  -1,
  1.5,
  NaN,
  Infinity,
  -Infinity,
  Number.MAX_SAFE_INTEGER + 1,
]) {
  it(`rejects invalid inheritance depth ${maxInheritanceDepth} at construction`, () => {
    const options = {
      resources,
      scope: 'disabled' as const,
      maxInheritanceDepth,
    };
    const invalid = (error: unknown) =>
      error instanceof RobracError && error.code === 'INVALID_CONFIGURATION';
    assert.throws(
      () => createRobrac({ ...options, store: memoryGrantStore() }),
      invalid
    );
    assert.throws(() => robrac(options), invalid);
  });
}
it('accepts zero, positive integer and default inheritance depths', () => {
  for (const maxInheritanceDepth of [0, 1, 5, undefined]) {
    assert.doesNotThrow(() =>
      createRobrac({
        resources,
        scope: 'disabled',
        maxInheritanceDepth,
        store: memoryGrantStore(),
      })
    );
    assert.doesNotThrow(() =>
      robrac({ resources, scope: 'disabled', maxInheritanceDepth })
    );
  }
});
