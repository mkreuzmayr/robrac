import type { BetterAuthOptions } from 'better-auth';
import { InferServerPlugin } from 'better-auth/client/plugins';

import type { RobracPluginId } from './plugin/id.ts';

export type { SerializedDecision, SubjectDescriptor } from './plugin/infer.ts';
export { ROBRAC_PLUGIN_ID, type RobracPluginId } from './plugin/id.ts';

/**
 * Client counterpart of the robrac server plugin.
 *
 * Pass your `Auth` type so that `resourceType` narrows `permissions` and
 * `role` on the client exactly as it does on the server.
 *
 * @example
 * ```ts
 * import { robracClient } from 'robrac/client';
 * import type { Auth } from '~/server/auth';
 *
 * export const authClient = createAuthClient({
 *   plugins: [robracClient<Auth>()],
 * });
 *
 * const { data } = await authClient.robrac.check({
 *   resourceType: 'recording',
 *   resourceId: id,
 *   permissions: { recording: ['update'] },
 * });
 * ```
 *
 * Available calls, derived from the server paths:
 * - `authClient.robrac.check(...)`
 * - `authClient.robrac.access(...)`
 * - `authClient.robrac.accessBatch(...)`
 * - `authClient.robrac.grants.list(...)`
 * - `authClient.robrac.grants.grant(...)`
 * - `authClient.robrac.grants.set(...)`
 * - `authClient.robrac.grants.revoke(...)`
 *
 * `/robrac/accessible-ids` is intentionally absent: it is marked
 * `SERVER_ONLY`, because it is a query-planning primitive rather than a
 * browser-facing API.
 */
export const robracClient = <
  TAuth extends BetterAuthOptions | { options: BetterAuthOptions },
>() => InferServerPlugin<TAuth, RobracPluginId>();
