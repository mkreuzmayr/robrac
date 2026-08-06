/**
 * robrac — **Ro**le **B**ased **R**esource **A**ccess **C**ontrol.
 *
 * A Better Auth plugin for the authorization question organization-level RBAC
 * cannot answer: not "may this member edit recordings", but "may this member
 * edit *this* recording".
 *
 * Three things are kept abstract so the package stays free of any host app's
 * data model: subjects (who), scopes (which tenant) and resources (what).
 * Persistence goes through a single {@link GrantStore} interface, whose default
 * implementation rides on Better Auth's own adapter — so robrac works on
 * Drizzle, Prisma, Kysely, MongoDB or a raw connection without a line of
 * ORM-specific code.
 *
 * See the README for the full guide.
 */

/* Core engine ------------------------------------------------------------- */
export {
  compileResources,
  createRobrac,
  type CompiledResource,
  type DataOf,
  type DecisionEvent,
  type GrantChangeEvent,
  type PermissionRequestOf,
  type ResourceRegistry,
  type ResourceTypeOf,
  type RobracEngine,
  type RobracEngineOptions,
  type RoleOf,
  type StatementsOf,
} from './core/engine.ts';

export {
  ROBRAC_ERROR_CODES,
  RobracError,
  type RobracErrorCode,
} from './core/errors.ts';

export {
  defineResource,
  hasSubject,
  subjectId,
  type ResourceCallbackArgs,
  type RoleNameOf,
  type ResourceDefinition,
} from './core/resource.ts';

export {
  ALL_ACTIONS,
  buildPermissionMatrix,
  checkPermissions,
  constantMatrix,
  extendRole,
  normalizeRoles,
} from './core/roles.ts';

export type {
  AccessDecision,
  AppliedRole,
  BetterAuthRoleLike,
  Grant,
  NormalizedRole,
  PermissionMap,
  PermissionMatrix,
  PermissionRequest,
  ResourceRef,
  RobracContext,
  RoleInput,
  RoleOrigin,
  Scope,
  Statements,
  SubjectRef,
} from './core/types.ts';

/* Storage ----------------------------------------------------------------- */
export {
  betterAuthGrantStore,
  type BetterAuthAdapterLike,
} from './store/better-auth.ts';
export { memoryGrantStore } from './store/memory.ts';
export type { GrantStore } from './store/types.ts';

/* Better Auth plugin ------------------------------------------------------ */
export {
  robrac,
  ROBRAC_PLUGIN_ID,
  type RobracPluginId,
  type RobracPluginOptions,
} from './plugin/plugin.ts';

export {
  GRANT_MODEL,
  grantSchema,
  type GrantField,
  type GrantSchemaOptions,
} from './plugin/schema.ts';

export {
  activeOrganizationScope,
  defaultSubjectResolver,
  MEMBER_SUBJECT,
  TEAM_SUBJECT,
  USER_SUBJECT,
  type ScopeResolver,
  type ScopeResolverArgs,
  type SubjectResolver,
  type SubjectResolverArgs,
} from './plugin/subjects.ts';

export type {
  AccessBatchBody,
  AccessibleIdsBody,
  CheckBody,
  GrantRoleBody,
  ListGrantsResult,
  ResourceScopedBody,
  RevokeRoleBody,
  SerializedDecision,
  SetRolesBody,
  SubjectDescriptor,
} from './plugin/infer.ts';
