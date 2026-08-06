/**
 * Test helpers.
 *
 * Authorization rules are exactly the kind of logic that deserves fast unit
 * tests, so robrac ships the pieces needed to exercise a resource definition
 * without a database, an HTTP server or a Better Auth instance.
 */
import { createRobrac } from './core/engine.ts';
import type { ResourceRegistry } from './core/engine.ts';
import type { Grant, SubjectRef } from './core/types.ts';
import { memoryGrantStore } from './store/memory.ts';

export { memoryGrantStore } from './store/memory.ts';

/**
 * A robrac engine backed by an in-memory store, with a fixed clock.
 *
 * @example
 * ```ts
 * const robrac = createTestRobrac({
 *   resources: { document: documentResource },
 *   now: new Date('2026-01-01T00:00:00Z'),
 * });
 *
 * await robrac.grants.grant({
 *   type: 'document',
 *   id: 'doc_1',
 *   subject: { type: 'user', id: 'u_1' },
 *   role: 'viewer',
 *   scope: 'org_1',
 * });
 *
 * assert.ok(
 *   await robrac.check({
 *     type: 'document',
 *     id: 'doc_1',
 *     scope: 'org_1',
 *     subjects: [{ type: 'user', id: 'u_1' }],
 *     permissions: { document: ['read'] },
 *   })
 * );
 * ```
 */
export function createTestRobrac<const TRegistry extends ResourceRegistry>(
  options: {
    resources: TRegistry;
    seed?: readonly Grant[];
    /** Frozen clock. Advance it by mutating the returned `clock`. */
    now?: Date;
  } & Omit<
    Partial<Parameters<typeof createRobrac<TRegistry>>[0]>,
    'resources' | 'store' | 'now'
  >
) {
  const clock = { now: options.now ?? new Date() };
  const store = memoryGrantStore({ seed: options.seed });

  const engine = createRobrac({
    ...options,
    resources: options.resources,
    store,
    now: () => clock.now,
  });

  return Object.assign(engine, {
    /** The backing store, for assertions on persisted rows. */
    store,
    /** Mutable clock: `clock.now = new Date(...)` to test expiry. */
    clock,
  });
}

/** Shorthand for building subject lists in tests. */
export function subjects(
  ...refs: (readonly [type: string, id: string])[]
): SubjectRef[] {
  return refs.map(([type, id]) => ({ type, id }));
}
