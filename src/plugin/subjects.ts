import { RobracError } from '../core/errors.ts';
import type { RobracContext, Scope, SubjectRef } from '../core/types.ts';
import type { BetterAuthAdapterLike } from '../store/better-auth.ts';

/** Subject type used for the authenticated user itself. */
export const USER_SUBJECT = 'user';
/** Subject type used for an organization membership. */
export const MEMBER_SUBJECT = 'member';
/** Subject type used for an organization team. */
export const TEAM_SUBJECT = 'team';

/** What the plugin knows about the caller before subjects are resolved. */
export type SubjectResolverArgs = {
  user: { id: string } & Record<string, unknown>;
  session: Record<string, unknown>;
  adapter: BetterAuthAdapterLike;
  scope: Scope;
  context: RobracContext;
};

export type SubjectResolver = (
  args: SubjectResolverArgs
) => Promise<readonly SubjectRef[]> | readonly SubjectRef[];

export type ScopeResolverArgs = {
  user: { id: string } & Record<string, unknown>;
  session: Record<string, unknown>;
  context: RobracContext;
};

export type ScopeResolver = (args: ScopeResolverArgs) => Promise<Scope> | Scope;

/**
 * Default scope: the session's active organization, or `null` when none is
 * active. The default subject resolver verifies the membership on every
 * request, because Better Auth keeps `activeOrganizationId` on a removed
 * member's other sessions.
 */
export const activeOrganizationScope: ScopeResolver = ({ session }) => {
  const value = session.activeOrganizationId;
  return typeof value === 'string' ? value : null;
};

type OrganizationModels = {
  includeTeams: boolean;
  memberModel: string;
  teamMemberModel: string;
  teamModel: string;
  userModel: string;
};

const ORGANIZATION_MODELS = Symbol('robrac.organizationModels');

type TaggedResolver = SubjectResolver & {
  [ORGANIZATION_MODELS]?: OrganizationModels;
};

const PAGE_SIZE = 500;

async function teamsInScope(
  adapter: BetterAuthAdapterLike,
  models: OrganizationModels,
  userId: string,
  scope: string
): Promise<string[]> {
  const teams = new Set<string>();
  const seen = new Set<string>();
  for (let offset = 0; ; offset += PAGE_SIZE) {
    const memberships = await adapter.findMany<{ id: string; teamId: string }>({
      model: models.teamMemberModel,
      where: [{ field: 'userId', value: userId }],
      limit: PAGE_SIZE,
      offset,
      sortBy: { field: 'id', direction: 'asc' },
    });
    const fresh = memberships.filter((row) => !seen.has(row.id));
    fresh.forEach((row) => seen.add(row.id));
    const teamIds = [...new Set(fresh.map((row) => row.teamId))];
    if (teamIds.length > 0) {
      // Team memberships carry no organization; the team row does.
      const rows = await adapter.findMany<{ id: string }>({
        model: models.teamModel,
        where: [
          { field: 'id', value: teamIds, operator: 'in' },
          { field: 'organizationId', value: scope },
        ],
        limit: teamIds.length,
      });
      for (const row of rows) {
        teams.add(row.id);
      }
    }
    if (memberships.length !== PAGE_SIZE) {
      return [...teams];
    }
    if (fresh.length === 0) {
      throw new Error('robrac: the database adapter ignores findMany offset.');
    }
  }
}

/**
 * Default subjects: the user, plus their membership (and optionally teams) in
 * the active organization.
 *
 * A caller with an active organization but no membership in it is refused
 * with `FORBIDDEN`, so a removed member's leftover sessions grant nothing.
 * This treats every non-null scope as an organization id.
 */
export function defaultSubjectResolver(
  options: {
    /**
     * Also resolve the caller's teams in the active organization, so a grant
     * can be handed to a whole team. Requires the organization plugin's
     * `teams` feature.
     *
     * @default false
     */
    includeTeams?: boolean;
    /** Schema key of the organization plugin's member model. */
    memberModel?: string;
    /** Schema key of the organization plugin's team-member model. */
    teamMemberModel?: string;
    /** Schema key of the organization plugin's team model. */
    teamModel?: string;
  } = {}
): SubjectResolver {
  const models: OrganizationModels = {
    includeTeams: options.includeTeams === true,
    memberModel: options.memberModel ?? 'member',
    teamMemberModel: options.teamMemberModel ?? 'teamMember',
    teamModel: options.teamModel ?? 'team',
    userModel: 'user',
  };

  const resolver: TaggedResolver = async ({ user, adapter, scope }) => {
    const subjects: SubjectRef[] = [{ type: USER_SUBJECT, id: user.id }];
    if (scope === null) {
      return subjects;
    }

    const member = await adapter.findOne<{ id: string }>({
      model: models.memberModel,
      where: [
        { field: 'organizationId', value: scope },
        { field: 'userId', value: user.id },
      ],
    });
    if (!member) {
      throw new RobracError(
        'FORBIDDEN',
        'You are not a member of the active organization.'
      );
    }
    subjects.push({ type: MEMBER_SUBJECT, id: member.id });

    if (models.includeTeams) {
      for (const teamId of await teamsInScope(
        adapter,
        models,
        user.id,
        scope
      )) {
        subjects.push({ type: TEAM_SUBJECT, id: teamId });
      }
    }
    return subjects;
  };
  resolver[ORGANIZATION_MODELS] = models;
  return resolver;
}

/** Arguments for checking that a grant target belongs to the caller's tenant. */
export type SubjectValidatorArgs = {
  subject: SubjectRef;
  scope: Scope;
  adapter: BetterAuthAdapterLike;
  context: RobracContext;
};

export type SubjectValidator = (
  args: SubjectValidatorArgs
) => Promise<boolean> | boolean;

/**
 * The grant-target check matching a {@link defaultSubjectResolver}: only
 * identities that resolver can produce in this scope are accepted. Returns
 * `undefined` for any other resolver, so a resolver that wraps the default one
 * should pass the inner one here and use the result as `subjects.validate`.
 */
export function organizationSubjectValidator(
  resolver: SubjectResolver
): SubjectValidator | undefined {
  const models = (resolver as TaggedResolver)[ORGANIZATION_MODELS];
  if (!models) {
    return undefined;
  }
  return async ({ subject, scope, adapter }) => {
    const exists = async (model: string, where: [string, string][]) =>
      (await adapter.findOne({
        model,
        where: where.map(([field, value]) => ({ field, value })),
      })) !== null;

    if (scope === null) {
      return (
        subject.type === USER_SUBJECT &&
        (await exists(models.userModel, [['id', subject.id]]))
      );
    }
    switch (subject.type) {
      case USER_SUBJECT:
        return exists(models.memberModel, [
          ['organizationId', scope],
          ['userId', subject.id],
        ]);
      case MEMBER_SUBJECT:
        return exists(models.memberModel, [
          ['organizationId', scope],
          ['id', subject.id],
        ]);
      case TEAM_SUBJECT:
        return (
          models.includeTeams &&
          exists(models.teamModel, [
            ['organizationId', scope],
            ['id', subject.id],
          ])
        );
      default:
        return false;
    }
  };
}
