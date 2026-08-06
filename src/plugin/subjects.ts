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
 * Default scope: the session's active organization.
 *
 * Returns `null` for apps that don't use the organization plugin, which puts
 * robrac into single-tenant mode for that request.
 */
export const activeOrganizationScope: ScopeResolver = ({ session }) => {
  const value = session.activeOrganizationId;
  return typeof value === 'string' ? value : null;
};

/**
 * Default subjects: the user, plus their membership in the active
 * organization.
 *
 * The membership matters because grants are usually handed out in a share
 * dialog that lists *members*, and because a membership disappearing must
 * revoke access even if the user account survives.
 */
export function defaultSubjectResolver(
  options: {
    /**
     * Also resolve the caller's teams, so a grant can be handed to a whole team.
     * Requires the organization plugin's `teams` feature.
     *
     * @default false
     */
    includeTeams?: boolean;
    /** Schema key of the organization plugin's member model. */
    memberModel?: string;
    /** Schema key of the organization plugin's team-member model. */
    teamMemberModel?: string;
  } = {}
): SubjectResolver {
  const memberModel = options.memberModel ?? 'member';
  const teamMemberModel = options.teamMemberModel ?? 'teamMember';

  return async ({ user, adapter, scope }) => {
    const subjects: SubjectRef[] = [{ type: USER_SUBJECT, id: user.id }];

    if (scope === null) {
      return subjects;
    }

    const member = await adapter.findOne<{ id: string }>({
      model: memberModel,
      where: [
        { field: 'organizationId', value: scope },
        { field: 'userId', value: user.id },
      ],
    });

    // No membership means no access to anything in this tenant. Returning just
    // the user subject is correct: grants are stored per member, so nothing
    // will match, and computed roles still see the empty membership.
    if (!member) {
      return subjects;
    }

    subjects.push({ type: MEMBER_SUBJECT, id: member.id });

    if (options.includeTeams === true) {
      const teamMemberships = await adapter.findMany<{ teamId: string }>({
        model: teamMemberModel,
        where: [{ field: 'userId', value: user.id }],
      });
      for (const membership of teamMemberships) {
        subjects.push({ type: TEAM_SUBJECT, id: membership.teamId });
      }
    }

    return subjects;
  };
}
