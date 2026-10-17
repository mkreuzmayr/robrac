/** Schema key of the grant model. Also the default table/model name. */
export const GRANT_MODEL = 'robracGrant';

export type GrantField =
  | 'scope'
  | 'resourceType'
  | 'resourceId'
  | 'subjectType'
  | 'subjectId'
  | 'role'
  | 'grantedBySubjectType'
  | 'grantedBySubjectId'
  | 'expiresAt'
  | 'createdAt'
  | 'updatedAt';

export type GrantSchemaOptions = {
  /** Rename the table/model. Defaults to `robracGrant`. */
  modelName?: string;
  /** Rename individual columns. */
  fields?: Partial<Record<GrantField, string>>;
  /**
   * Turn the `scope` column into a real foreign key.
   *
   * Scope maps onto exactly one model in practice (usually `organization`),
   * so this is where robrac can still buy you database-level cascade deletes.
   * `subjectId` intentionally has no reference: subjects are heterogeneous by
   * design, so cleanup happens through `grants.revokeSubject` and the
   * organization hooks instead.
   */
  scopeReferences?: {
    model: string;
    field?: string;
    onDelete?:
      | 'no action'
      | 'restrict'
      | 'cascade'
      | 'set null'
      | 'set default';
  };
};

/**
 * Better Auth schema for the grants table.
 *
 * Better Auth's schema DSL cannot express the composite unique index over
 * `(scope, resourceType, resourceId, subjectType, subjectId, role)`; add it in
 * your own migration (the README has the SQL). The default store converges
 * concurrent duplicates without it, but the index closes the race.
 */
export function grantSchema(options: GrantSchemaOptions = {}) {
  const field = (name: GrantField) => options.fields?.[name];

  return {
    [GRANT_MODEL]: {
      modelName: options.modelName ?? GRANT_MODEL,
      fields: {
        scope: {
          type: 'string' as const,
          required: false,
          index: true,
          fieldName: field('scope'),
          references: options.scopeReferences
            ? {
                model: options.scopeReferences.model,
                field: options.scopeReferences.field ?? 'id',
                onDelete: options.scopeReferences.onDelete ?? 'cascade',
              }
            : undefined,
        },
        resourceType: {
          type: 'string' as const,
          required: true,
          fieldName: field('resourceType'),
        },
        resourceId: {
          type: 'string' as const,
          required: true,
          index: true,
          fieldName: field('resourceId'),
        },
        subjectType: {
          type: 'string' as const,
          required: true,
          fieldName: field('subjectType'),
        },
        subjectId: {
          type: 'string' as const,
          required: true,
          index: true,
          fieldName: field('subjectId'),
        },
        role: {
          type: 'string' as const,
          required: true,
          fieldName: field('role'),
        },
        grantedBySubjectType: {
          type: 'string' as const,
          required: false,
          fieldName: field('grantedBySubjectType'),
        },
        grantedBySubjectId: {
          type: 'string' as const,
          required: false,
          fieldName: field('grantedBySubjectId'),
        },
        expiresAt: {
          type: 'date' as const,
          required: false,
          fieldName: field('expiresAt'),
        },
        createdAt: {
          type: 'date' as const,
          required: true,
          defaultValue: () => new Date(),
          fieldName: field('createdAt'),
        },
        updatedAt: {
          type: 'date' as const,
          required: true,
          defaultValue: () => new Date(),
          onUpdate: () => new Date(),
          fieldName: field('updatedAt'),
        },
      },
    },
  };
}
