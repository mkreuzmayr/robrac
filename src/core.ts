/** Authorization engine and stores without framework dependencies. */
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
