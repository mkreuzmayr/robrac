import type {
  PermissionRequestOf,
  ResourceRegistry,
  ResourceTypeOf,
  RoleOf,
} from '../core/engine.ts';
import type { AppliedRole, Grant, SubjectRef } from '../core/types.ts';

/**
 * Endpoint body types, expressed as discriminated unions over the resource
 * registry so that `resourceType: 'recording'` narrows `permissions` and
 * `role` to what that resource actually declares.
 */

export type ResourceScopedBody<TRegistry extends ResourceRegistry> = {
  [TType in ResourceTypeOf<TRegistry>]: {
    resourceType: TType;
    resourceId: string;
  };
}[ResourceTypeOf<TRegistry>];

export type CheckBody<TRegistry extends ResourceRegistry> = {
  [TType in ResourceTypeOf<TRegistry>]: {
    resourceType: TType;
    resourceId: string;
    permissions: PermissionRequestOf<TRegistry, TType>;
    connector?: 'AND' | 'OR';
  };
}[ResourceTypeOf<TRegistry>];

export type AccessBatchBody<TRegistry extends ResourceRegistry> = {
  [TType in ResourceTypeOf<TRegistry>]: {
    resourceType: TType;
    resourceIds: string[];
    permissions?: PermissionRequestOf<TRegistry, TType>;
    connector?: 'AND' | 'OR';
  };
}[ResourceTypeOf<TRegistry>];

export type GrantRoleBody<TRegistry extends ResourceRegistry> = {
  [TType in ResourceTypeOf<TRegistry>]: {
    resourceType: TType;
    resourceId: string;
    subject: SubjectRef;
    role: RoleOf<TRegistry, TType>;
    expiresAt?: string | Date | null;
  };
}[ResourceTypeOf<TRegistry>];

export type SetRolesBody<TRegistry extends ResourceRegistry> = {
  [TType in ResourceTypeOf<TRegistry>]: {
    resourceType: TType;
    resourceId: string;
    subject: SubjectRef;
    roles: RoleOf<TRegistry, TType>[];
    expiresAt?: string | Date | null;
  };
}[ResourceTypeOf<TRegistry>];

export type RevokeRoleBody<TRegistry extends ResourceRegistry> = {
  [TType in ResourceTypeOf<TRegistry>]: {
    resourceType: TType;
    resourceId: string;
    subject: SubjectRef;
    role?: RoleOf<TRegistry, TType>;
  };
}[ResourceTypeOf<TRegistry>];

export type AccessibleIdsBody<TRegistry extends ResourceRegistry> = {
  [TType in ResourceTypeOf<TRegistry>]: {
    resourceType: TType;
    permissions?: PermissionRequestOf<TRegistry, TType>;
    limit?: number;
    offset?: number;
  };
}[ResourceTypeOf<TRegistry>];

/**
 * A decision as it crosses the wire.
 *
 * The loaded domain object is deliberately absent: robrac answers "what may
 * this caller do", never "here is the record". Serving the record stays your
 * application's job, which keeps field-level redaction where it belongs.
 */
export type SerializedDecision = {
  found: boolean;
  scope: string | null;
  resourceType: string;
  resourceId: string;
  roles: AppliedRole[];
  effectiveRoles: string[];
  permissions: Record<string, Record<string, boolean>>;
  override: 'allow' | 'deny' | null;
};

/** Optional human-readable annotation for a subject in a share dialog. */
export type SubjectDescriptor = {
  type: string;
  id: string;
  label?: string;
  image?: string | null;
  meta?: Record<string, unknown>;
};

export type ListGrantsResult = {
  resourceType: string;
  resourceId: string;
  scope: string | null;
  /**
   * Roles within the caller's own permissions, filtered by the anti-escalation
   * rule `grants/grant` enforces. A caller whose own access expires must also
   * pass an `expiresAt` no later than that.
   */
  availableRoles: string[];
  /** Every role the resource type declares, grantable by this caller or not. */
  declaredRoles: string[];
  grants: Grant[];
  /** Present only when `subjects.describe` is configured. */
  subjects?: SubjectDescriptor[];
};
