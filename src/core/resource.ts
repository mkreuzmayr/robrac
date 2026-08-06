import { RobracError } from './errors.ts';
import { ALL_ACTIONS } from './roles.ts';
import type {
  PermissionRequest,
  ResourceRef,
  RobracContext,
  RoleInput,
  Scope,
  Statements,
  SubjectRef,
} from './types.ts';

type Awaitable<T> = T | Promise<T>;

/** The role names a resource definition declares, as a literal union. */
export type RoleNameOf<TRoles> = keyof TRoles & string;

/** Arguments handed to every resource callback that sees a loaded resource. */
export type ResourceCallbackArgs<TResource> = {
  /** The loaded domain object. */
  data: TResource;
  /** `(type, id)` of the resource being evaluated. */
  resource: ResourceRef;
  scope: Scope;
  /** Every identity the caller acts under (user, member, teams, ...). */
  subjects: readonly SubjectRef[];
  context: RobracContext;
};

export type ResourceDefinition<
  TResource = unknown,
  TStatements extends Statements = Statements,
  TRoles extends Record<string, RoleInput> = Record<string, RoleInput>,
> = {
  /** Stable identifier, stored on every grant row. Never rename casually. */
  type: string;

  /** Every facet + action this resource type knows about. */
  statements: TStatements;

  /**
   * Named roles. Accepts plain permission maps, `extendRole(...)` results, or
   * Better Auth `createAccessControl(...).newRole(...)` objects.
   */
  roles: TRoles;

  /** Load a single resource. Return `null` when it does not exist. */
  load: (args: {
    id: string;
    scope: Scope;
    context: RobracContext;
  }) => Awaitable<TResource | null>;

  /**
   * Batch loader. Strongly recommended: without it, evaluating a page of 50
   * resources issues 50 `load` calls.
   */
  loadMany?: (args: {
    ids: readonly string[];
    scope: Scope;
    context: RobracContext;
  }) => Awaitable<Map<string, TResource>>;

  /**
   * The tenant this resource belongs to. Required when the engine runs with
   * `scope: 'required'`; a mismatch against the requested scope makes the
   * resource invisible, which is what keeps tenants isolated.
   */
  scope?: (data: TResource) => Scope;

  /**
   * Roles derived from the resource itself rather than from a stored grant —
   * "the creator is an owner", "org-visible recordings are readable by every
   * member".
   *
   * `roles` is a typed accumulator: only names declared in the `roles` map
   * above can be pushed, so a typo is a compile error rather than a role that
   * silently confers nothing. Push into it, return an array, or both — the
   * engine merges the two.
   *
   * @example
   * ```ts
   * computeRoles({ data, subjects, roles }) {
   *   if (hasSubject(subjects, 'user', data.createdBy)) roles.push('owner');
   *   if (data.visibility === 'organization') roles.push('viewer');
   * },
   * ```
   *
   * Declared in method syntax on purpose: the accumulator's element type
   * narrows per resource, and methods are exempt from `strictFunctionTypes`'
   * contravariant parameter check — which is what keeps a definition with a
   * narrowed accumulator assignable to the registry's erased
   * `ResourceDefinition` constraint. Safe here because only the engine ever
   * calls this, always with the definition's own role names.
   */
  computeRoles?(
    args: ResourceCallbackArgs<TResource> & {
      /** Typed accumulator for the computed roles. */
      roles: RoleNameOf<TRoles>[];
    }
  ): Awaitable<readonly RoleNameOf<TRoles>[] | null | undefined | void>;

  /**
   * Short-circuit the whole decision. `'allow'` grants every declared action,
   * `'deny'` revokes every one of them (legal hold, suspended tenant, ...).
   * `deny` wins over `allow`.
   */
  override?: (
    args: ResourceCallbackArgs<TResource>
  ) => Awaitable<'allow' | 'deny' | null | undefined>;

  /**
   * The resource whose grants cascade onto this one — a folder, a project, a
   * workspace. Roles held on the ancestor are translated by `inheritRole`.
   */
  parent?: (args: {
    data: TResource;
    resource: ResourceRef;
    scope: Scope;
    context: RobracContext;
  }) => Awaitable<ResourceRef | null | undefined>;

  /**
   * Translate a role held on the ancestor into a role on this resource.
   * Return `null` to drop it. Defaults to identity when the ancestor's role
   * name also exists on this resource.
   *
   * The incoming `role` is a plain string — it lives in the ancestor's
   * namespace, which this definition knows nothing about. The return value is
   * constrained to this resource's own declared roles.
   */
  inheritRole?: (args: {
    parent: ResourceRef;
    role: string;
  }) => RoleNameOf<TRoles> | null | undefined;

  /**
   * What a subject must be allowed to do in order to hand out or revoke
   * grants on this resource. Either a permission request or a predicate.
   */
  manage:
    | PermissionRequest<TStatements>
    | ((
        args: ResourceCallbackArgs<TResource> & {
          permissions: Record<string, Record<string, boolean>>;
        }
      ) => Awaitable<boolean>);
};

/**
 * Declare a resource type. Purely an identity function that pins the generics
 * so `statements`, `roles` and the loaded resource type all infer.
 *
 * @example
 * ```ts
 * const recording = defineResource({
 *   type: 'recording',
 *   statements: { recording: ['read', 'update', 'delete', 'share'] },
 *   roles: {
 *     viewer: { recording: ['read'] },
 *     owner: { recording: ['read', 'update', 'delete', 'share'] },
 *   },
 *   load: ({ id }) => db.recording.findById(id),
 *   scope: (r) => r.organizationId,
 *   computeRoles: ({ data, subjects, roles }) => {
 *     // `roles` only accepts 'viewer' | 'owner' — a typo fails to compile.
 *     if (hasSubject(subjects, 'user', data.createdBy)) roles.push('owner');
 *   },
 *   manage: { recording: ['share'] },
 * });
 * ```
 */
export function defineResource<
  TResource,
  const TStatements extends Statements,
  const TRoles extends Record<string, RoleInput>,
>(
  definition: ResourceDefinition<TResource, TStatements, TRoles>
): ResourceDefinition<TResource, TStatements, TRoles> {
  return definition;
}

/** Convenience predicate for `computeRoles` / `override`. */
export function hasSubject(
  subjects: readonly SubjectRef[],
  type: string,
  id: string | null | undefined
): boolean {
  if (!id) {
    return false;
  }
  return subjects.some((subject) => subject.type === type && subject.id === id);
}

/** The id of the first subject of `type`, if the caller has one. */
export function subjectId(
  subjects: readonly SubjectRef[],
  type: string
): string | null {
  return subjects.find((subject) => subject.type === type)?.id ?? null;
}

/**
 * Reject typos at construction time. A role pointing at a facet or action that
 * was never declared is dead configuration, and dead configuration in an authz
 * system reads as "permission silently missing" months later.
 */
export function assertResourceIsConsistent(
  definition: ResourceDefinition<never, Statements, Record<string, RoleInput>>,
  roleStatements: Record<string, Record<string, readonly string[]>>
): void {
  for (const [roleName, facets] of Object.entries(roleStatements)) {
    for (const [facet, actions] of Object.entries(facets)) {
      const declared = definition.statements[facet];
      if (!declared) {
        throw new RobracError(
          'INVALID_CONFIGURATION',
          `Resource "${definition.type}" role "${roleName}" references undeclared facet "${facet}".`
        );
      }
      for (const action of actions) {
        if (action !== ALL_ACTIONS && !declared.includes(action)) {
          throw new RobracError(
            'INVALID_CONFIGURATION',
            `Resource "${definition.type}" role "${roleName}" references undeclared action "${facet}.${action}".`
          );
        }
      }
    }
  }
}
