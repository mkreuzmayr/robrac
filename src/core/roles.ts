import { RobracError } from './errors.ts';
import type {
  NormalizedRole,
  PermissionMatrix,
  PermissionRequest,
  PermissionTable,
  RoleInput,
  Statements,
} from './types.ts';

// A symbol, so that a facet can legitimately be called `extends`.
const ROLE_EXTENDS = Symbol.for('robrac.role.extends');

/** Action wildcard: grants every action declared for that facet. */
export const ALL_ACTIONS = '*';

type ExtendedRole = {
  statements: Statements;
  [ROLE_EXTENDS]: readonly string[];
};

/**
 * Declare a role that inherits every permission of `parents` and adds
 * `permissions` on top.
 *
 * @example
 * ```ts
 * const roles = {
 *   viewer: { recording: ['read'] },
 *   editor: extendRole(['viewer'], { recording: ['update'] }),
 *   owner: extendRole(['editor'], { recording: ['delete', 'share'] }),
 * };
 * ```
 */
export function extendRole<const TStatements extends Statements>(
  parents: readonly string[],
  permissions: TStatements
): ExtendedRole {
  return { statements: permissions, [ROLE_EXTENDS]: parents };
}

/** Own-property lookup, so names like `constructor` never resolve to `Object.prototype`. */
export function own<T>(
  record: Readonly<Record<string, T>>,
  key: string
): T | undefined {
  return Object.hasOwn(record, key) ? record[key] : undefined;
}

// A plain permission map may contain a facet called `statements`, so a wrapper
// is only recognised by the `extendRole` marker or Better Auth's `authorize`.
function isRoleWrapper(value: RoleInput): value is { statements: Statements } {
  const candidate = value as {
    statements?: unknown;
    authorize?: unknown;
    [ROLE_EXTENDS]?: unknown;
  };
  if (
    typeof candidate.statements !== 'object' ||
    candidate.statements === null ||
    Array.isArray(candidate.statements)
  ) {
    return false;
  }
  return ROLE_EXTENDS in candidate || typeof candidate.authorize === 'function';
}

function readParents(name: string, role: RoleInput): string[] {
  const value: unknown = (role as Partial<ExtendedRole>)[ROLE_EXTENDS];
  if (value === undefined) {
    return [];
  }
  if (
    !Array.isArray(value) ||
    value.some((entry) => typeof entry !== 'string')
  ) {
    throw new RobracError(
      'INVALID_CONFIGURATION',
      `Role "${name}" must extend an array of role names.`
    );
  }
  return value as string[];
}

function readStatements(
  name: string,
  role: RoleInput
): Map<string, Set<string>> {
  if (typeof role !== 'object' || role === null || Array.isArray(role)) {
    throw new RobracError(
      'INVALID_CONFIGURATION',
      `Role "${name}" must be a permission map.`
    );
  }
  const statements = isRoleWrapper(role) ? role.statements : role;
  const result = new Map<string, Set<string>>();
  for (const [facet, actions] of Object.entries(statements)) {
    if (actions === undefined) {
      continue;
    }
    if (
      !Array.isArray(actions) ||
      actions.some((action) => typeof action !== 'string')
    ) {
      throw new RobracError(
        'INVALID_CONFIGURATION',
        `Role "${name}" declares facet "${facet}" as ${typeof actions}; it must be an array of actions.`
      );
    }
    result.set(facet, new Set(actions as readonly string[]));
  }
  return result;
}

function toRecord(
  statements: Map<string, Set<string>>
): Record<string, string[]> {
  return Object.fromEntries(
    [...statements].map(([facet, actions]) => [facet, [...actions]])
  );
}

/**
 * Resolve a role map into {@link NormalizedRole}s with `extends` flattened.
 *
 * Cycles and references to undeclared roles throw at construction time rather
 * than silently denying access at runtime.
 */
export function normalizeRoles(
  roles: Record<string, RoleInput>
): Record<string, NormalizedRole> {
  const declared = new Map<
    string,
    { own: Map<string, Set<string>>; parents: string[] }
  >();
  for (const [name, role] of Object.entries(roles)) {
    declared.set(name, {
      own: readStatements(name, role),
      parents: readParents(name, role),
    });
  }

  const resolved = new Map<string, NormalizedRole>();
  const resolving = new Set<string>();

  const resolve = (name: string, from?: string): NormalizedRole => {
    const cached = resolved.get(name);
    if (cached) {
      return cached;
    }
    const role = declared.get(name);
    if (!role) {
      throw new RobracError(
        'INVALID_CONFIGURATION',
        `Role "${from ?? name}" extends unknown role "${name}".`
      );
    }
    if (resolving.has(name)) {
      throw new RobracError(
        'INVALID_CONFIGURATION',
        `Role inheritance cycle detected at role "${name}".`
      );
    }

    resolving.add(name);
    const effective = new Map<string, Set<string>>();
    const merge = (source: Map<string, Set<string>>) => {
      for (const [facet, actions] of source) {
        const bucket = effective.get(facet) ?? new Set<string>();
        for (const action of actions) {
          bucket.add(action);
        }
        effective.set(facet, bucket);
      }
    };
    for (const parent of role.parents) {
      merge(
        new Map(
          Object.entries(resolve(parent, name).effective).map(
            ([facet, actions]) => [facet, new Set(actions)]
          )
        )
      );
    }
    merge(role.own);
    resolving.delete(name);

    const normalized: NormalizedRole = {
      name,
      own: toRecord(role.own),
      effective: toRecord(effective),
      extends: [...role.parents],
    };
    resolved.set(name, normalized);
    return normalized;
  };

  for (const name of declared.keys()) {
    resolve(name);
  }
  return Object.fromEntries(resolved);
}

/**
 * Every concrete `(facet, action)` pair the named roles confer, restricted to
 * what `statements` declares. Unknown role names confer nothing: a grant row
 * can outlive the role that created it, and a dangling role must never widen
 * access.
 */
export function grantedActions(
  statements: Statements,
  roles: Readonly<Record<string, NormalizedRole>>,
  roleNames: Iterable<string>
): Map<string, Set<string>> {
  const granted = new Map<string, Set<string>>();
  for (const name of roleNames) {
    const role = own(roles, name);
    if (!role) {
      continue;
    }
    for (const [facet, actions] of Object.entries(role.effective)) {
      const declared = own(statements, facet);
      if (!declared) {
        continue;
      }
      const bucket = granted.get(facet) ?? new Set<string>();
      for (const action of actions) {
        if (action === ALL_ACTIONS) {
          for (const declaredAction of declared) {
            bucket.add(declaredAction);
          }
        } else if (declared.includes(action)) {
          bucket.add(action);
        }
      }
      granted.set(facet, bucket);
    }
  }
  return granted;
}

function materialize<TStatements extends Statements>(
  statements: TStatements,
  allows: (facet: string, action: string) => boolean
): PermissionMatrix<TStatements> {
  return Object.fromEntries(
    Object.entries(statements).map(([facet, actions]) => [
      facet,
      Object.fromEntries(
        actions.map((action) => [action, allows(facet, action)])
      ),
    ])
  ) as PermissionMatrix<TStatements>;
}

/** The full allow/deny table for `statements`, given the roles a subject holds. */
export function buildPermissionMatrix<TStatements extends Statements>(
  statements: TStatements,
  roles: Record<string, NormalizedRole>,
  effectiveRoleNames: readonly string[]
): PermissionMatrix<TStatements> {
  const granted = grantedActions(statements, roles, effectiveRoleNames);
  return materialize(
    statements,
    (facet, action) => granted.get(facet)?.has(action) === true
  );
}

/** A matrix where every declared action resolves to `value`. */
export function constantMatrix<TStatements extends Statements>(
  statements: TStatements,
  value: boolean
): PermissionMatrix<TStatements> {
  return materialize(statements, () => value);
}

type ActionRequest =
  | readonly string[]
  | { actions: readonly string[]; connector?: 'AND' | 'OR' };

function readActionRequest(
  request: unknown
): { actions: readonly string[]; connector: 'AND' | 'OR' } | null {
  if (Array.isArray(request)) {
    return { actions: request as readonly string[], connector: 'AND' };
  }
  if (typeof request !== 'object' || request === null) {
    return null;
  }
  const { actions, connector } = request as Partial<
    Exclude<ActionRequest, readonly string[]>
  >;
  return Array.isArray(actions)
    ? { actions, connector: connector === 'OR' ? 'OR' : 'AND' }
    : null;
}

/**
 * Test a permission request against a matrix.
 *
 * Mirrors Better Auth's access-control semantics: actions within a facet and
 * facets within a request are `AND`ed unless a connector says otherwise. An
 * empty request, or a facet with no actions, is never satisfied.
 */
export function checkPermissions<TStatements extends Statements>(
  matrix: PermissionMatrix<TStatements>,
  request: PermissionRequest<TStatements>,
  connector: 'AND' | 'OR' = 'AND'
): boolean {
  const table = matrix as PermissionTable;
  const entries = Object.entries(request as Record<string, unknown>).filter(
    ([, actions]) => actions !== undefined
  );
  if (entries.length === 0) {
    return false;
  }

  const allows = (facet: string, action: string) => {
    const row = own(table, facet);
    return row !== undefined && own(row, action) === true;
  };

  const results = entries.map(([facet, raw]) => {
    const parsed = readActionRequest(raw);
    if (!parsed || parsed.actions.length === 0) {
      return false;
    }
    return parsed.connector === 'OR'
      ? parsed.actions.some((action) => allows(facet, action))
      : parsed.actions.every((action) => allows(facet, action));
  });

  return connector === 'OR' ? results.some(Boolean) : results.every(Boolean);
}
