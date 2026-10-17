/**
 * The core throws plain `RobracError`s so it can be used outside an HTTP
 * request. The Better Auth plugin maps them onto `APIError` status codes.
 */
export type RobracErrorCode =
  | 'UNKNOWN_RESOURCE_TYPE'
  | 'UNKNOWN_ROLE'
  | 'RESOURCE_NOT_FOUND'
  | 'FORBIDDEN'
  | 'INVALID_CONFIGURATION'
  | 'SCOPE_REQUIRED';

export class RobracError extends Error {
  readonly code: RobracErrorCode;

  constructor(code: RobracErrorCode, message: string) {
    super(message);
    this.name = 'RobracError';
    this.code = code;
  }
}

export const ROBRAC_ERROR_CODES = {
  UNKNOWN_RESOURCE_TYPE: 'Unknown resource type.',
  UNKNOWN_ROLE: 'Unknown role for this resource type.',
  RESOURCE_NOT_FOUND: 'Resource not found.',
  FORBIDDEN: 'You are not allowed to perform this action on this resource.',
  INVALID_CONFIGURATION: 'Invalid robrac configuration.',
  SCOPE_REQUIRED: 'No scope could be resolved for this request.',
} as const satisfies Record<RobracErrorCode, string>;

/** A caller passed a malformed argument. Surfaced by the plugin as HTTP 400. */
export class RobracArgumentError extends RangeError {
  constructor(message: string) {
    super(message);
    this.name = 'RobracArgumentError';
  }
}
