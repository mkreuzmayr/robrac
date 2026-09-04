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

export * from './core.ts';

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
