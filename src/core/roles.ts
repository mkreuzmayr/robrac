import { RobracError } from './errors.ts';
import type {
  NormalizedRole,
  PermissionMatrix,
  PermissionRequest,
  PermissionTable,
  RoleInput,
  Statements,
} from './types.ts';

/**
 * Marks a role as inheriting from other roles. A symbol is used so that a
 * facet can legitimately be called `extends` without colliding.
 */
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
  return {
    statements: permissions,
    [ROLE_EXTENDS]: parents,
  };
}

/**
 * Distinguish a wrapped role from a plain permission map.
 *
 * Sniffing for a `statements` key alone is not enough: `{ statements: ['read']
 * }` is a legitimate permission map for a facet that happens to be named
 * `statements`, and treating it as a wrapper turns the action array into the
 * statement map and iterates the string `'read'` character by character. So a
 * wrapper is recognised only by the marker `extendRole` sets, or by the
 * `authorize` function every Better Auth role carries.
 */
function isRoleLike(value: RoleInput): value is { statements: Statements } {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

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

function readStatements(role: RoleInput): Statements {
  return isRoleLike(role) ? role.statements : (role as Statements);
}

function readExtends(role: RoleInput): readonly string[] {
  const value: unknown = (role as Partial<ExtendedRole>)[ROLE_EXTENDS];
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === 'string')
    : [];
}

function mergeInto(
  target: Record<string, string[]>,
  source: Statements
): Record<string, string[]> {
  for (const [facet, actions] of Object.entries(source)) {
    if (!actions) {
      continue;
    }
    const existing = target[facet];
    if (existing) {
      for (const action of actions) {
        if (!existing.includes(action)) {
          existing.push(action);
        }
      }
    } else {
      target[facet] = [...new Set(actions)];
    }
  }
  return target;
}

/**
 * Resolve a role map into {@link NormalizedRole}s with `extends` flattened.
 *
 * Cycles and references to undeclared roles are configuration bugs, so they
 * throw at construction time rather than silently denying access at runtime.
 */
export function normalizeRoles(
  roles: Record<string, RoleInput>
): Record<string, NormalizedRole> {
  const own: Record<string, Record<string, string[]>> = {};
  const parents: Record<string, readonly string[]> = {};

  for (const [name, role] of Object.entries(roles)) {
    const statements = readStatements(role);

    // Reject a malformed action list here, where the role name is still in
    // hand. Letting it through produces a nonsense permission map and an error
    // much later that points nowhere near the actual mistake.
    for (const [facet, actions] of Object.entries(statements)) {
      if (actions !== undefined && !Array.isArray(actions)) {
        throw new RobracError(
          'INVALID_CONFIGURATION',
          `Role "${name}" declares facet "${facet}" as ${typeof actions}; it must be an array of actions.`
        );
      }
    }

    own[name] = mergeInto({}, statements);
    parents[name] = readExtends(role);
  }

  const resolved: Record<string, NormalizedRole> = {};
  const resolving = new Set<string>();

  const resolve = (name: string): NormalizedRole => {
    const cached = resolved[name];
    if (cached) {
      return cached;
    }
    if (resolving.has(name)) {
      throw new RobracError(
        'INVALID_CONFIGURATION',
        `Role inheritance cycle detected at role "${name}".`
      );
    }

    const ownStatements = own[name];
    if (!ownStatements) {
      throw new RobracError(
        'INVALID_CONFIGURATION',
        `Role "${name}" extends an unknown role.`
      );
    }

    resolving.add(name);
    const effective: Record<string, string[]> = {};
    for (const parent of parents[name] ?? []) {
      mergeInto(effective, resolve(parent).effective);
    }
    mergeInto(effective, ownStatements);
    resolving.delete(name);

    const role: NormalizedRole = {
      name,
      own: ownStatements,
      effective,
      extends: parents[name] ?? [],
    };
    resolved[name] = role;
    return role;
  };

  for (const name of Object.keys(own)) {
    resolve(name);
  }

  return resolved;
}

/**
 * Build the full allow/deny table for `statements` given the roles a subject
 * effectively holds. Unknown role names are ignored: a grant row can outlive
 * the role that created it, and a dangling role must never widen access.
 */
export function buildPermissionMatrix<TStatements extends Statements>(
  statements: TStatements,
  roles: Record<string, NormalizedRole>,
  effectiveRoleNames: readonly string[]
): PermissionMatrix<TStatements> {
  const granted: Record<string, Set<string>> = {};

  for (const name of effectiveRoleNames) {
    const role = roles[name];
    if (!role) {
      continue;
    }
    for (const [facet, actions] of Object.entries(role.effective)) {
      const declared = statements[facet];
      if (!declared) {
        continue;
      }
      const bucket = (granted[facet] ??= new Set());
      for (const action of actions) {
        if (action === ALL_ACTIONS) {
          for (const declaredAction of declared) {
            bucket.add(declaredAction);
          }
        } else if (declared.includes(action)) {
          bucket.add(action);
        }
      }
    }
  }

  return materialize(statements, (facet, action) =>
    Boolean(granted[facet]?.has(action))
  );
}

/** A matrix where every declared action resolves to `value`. */
export function constantMatrix<TStatements extends Statements>(
  statements: TStatements,
  value: boolean
): PermissionMatrix<TStatements> {
  return materialize(statements, () => value);
}

function materialize<TStatements extends Statements>(
  statements: TStatements,
  allows: (facet: string, action: string) => boolean
): PermissionMatrix<TStatements> {
  const matrix: PermissionTable = {};
  for (const [facet, actions] of Object.entries(statements)) {
    const row: Record<string, boolean> = {};
    for (const action of actions) {
      row[action] = allows(facet, action);
    }
    matrix[facet] = row;
  }
  return matrix as PermissionMatrix<TStatements>;
}

type ActionRequest =
  | readonly string[]
  | { actions: readonly string[]; connector?: 'AND' | 'OR' };

function normalizeActionRequest(request: ActionRequest): {
  actions: readonly string[];
  connector: 'AND' | 'OR';
} {
  if (Array.isArray(request)) {
    return { actions: request, connector: 'AND' };
  }
  const object = request as {
    actions?: readonly string[];
    connector?: 'AND' | 'OR';
  };
  return {
    actions: object.actions ?? [],
    connector: object.connector === 'OR' ? 'OR' : 'AND',
  };
}

/**
 * Test a permission request against a matrix.
 *
 * Mirrors Better Auth's access-control semantics: actions within a facet and
 * facets within a request are `AND`ed unless a connector says otherwise. An
 * empty request is *not* satisfiable — asking for nothing must never be
 * mistaken for "allowed".
 */
export function checkPermissions<TStatements extends Statements>(
  matrix: PermissionMatrix<TStatements>,
  request: PermissionRequest<TStatements>,
  connector: 'AND' | 'OR' = 'AND'
): boolean {
  const entries = Object.entries(request as Record<string, ActionRequest>);
  if (entries.length === 0) {
    return false;
  }

  const table = matrix as PermissionTable;
  let satisfiedAny = false;

  for (const [facet, rawActions] of entries) {
    if (rawActions === undefined) {
      continue;
    }
    const { actions, connector: actionConnector } =
      normalizeActionRequest(rawActions);
    const row = table[facet];

    const satisfied =
      actions.length > 0 &&
      (actionConnector === 'OR'
        ? actions.some((action) => row?.[action] === true)
        : actions.every((action) => row?.[action] === true));

    if (satisfied) {
      if (connector === 'OR') {
        return true;
      }
      satisfiedAny = true;
    } else if (connector === 'AND') {
      return false;
    }
  }

  return satisfiedAny;
}
