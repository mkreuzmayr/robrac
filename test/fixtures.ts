import { defineResource, extendRole, hasSubject } from '../src/index.ts';
import type { SubjectRef } from '../src/index.ts';

export const ORG = 'org_1';
export const OTHER_ORG = 'org_2';

export type Folder = {
  id: string;
  organizationId: string;
  parentId?: string | null;
  hold?: boolean;
};

export type Document = {
  id: string;
  organizationId: string;
  folderId?: string | null;
  createdBy?: string;
  visibility?: 'private' | 'organization';
  hold?: boolean;
};

export function createData() {
  return {
    folders: new Map<string, Folder>(),
    documents: new Map<string, Document>(),
  };
}

export type Data = ReturnType<typeof createData>;

export function registry(data: Data) {
  const folder = defineResource({
    type: 'folder',
    statements: { folder: ['read', 'update', 'delete', 'share'] },
    roles: {
      viewer: { folder: ['read'] },
      editor: extendRole(['viewer'], { folder: ['update'] }),
      owner: extendRole(['editor'], { folder: ['delete', 'share'] }),
    },
    load: ({ id }) => data.folders.get(id) ?? null,
    scope: (row) => row.organizationId,
    override: ({ data: row }) => (row.hold ? 'deny' : null),
    parent: ({ data: row }) =>
      row.parentId ? { type: 'folder', id: row.parentId } : null,
    parentTypes: ['folder'],
    manage: { folder: ['share'] },
  });

  const document = defineResource({
    type: 'document',
    statements: {
      document: ['read', 'update', 'delete', 'share'],
      comment: ['read', 'write'],
    },
    roles: {
      viewer: { document: ['read'], comment: ['read'] },
      sharer: extendRole(['viewer'], { document: ['share'] }),
      editor: extendRole(['viewer'], {
        document: ['update', 'share'],
        comment: ['write'],
      }),
      owner: extendRole(['editor'], { document: ['delete'] }),
    },
    load: ({ id }) => data.documents.get(id) ?? null,
    loadMany: ({ ids }) =>
      new Map(
        ids.flatMap((id) => {
          const row = data.documents.get(id);
          return row ? [[id, row] as const] : [];
        })
      ),
    scope: (row) => row.organizationId,
    computeRoles: ({ data: row, subjects, roles }) => {
      if (hasSubject(subjects, 'user', row.createdBy)) roles.push('owner');
      if (row.visibility === 'organization') roles.push('viewer');
    },
    override: ({ data: row }) => (row.hold ? 'deny' : null),
    parent: ({ data: row }) =>
      row.folderId ? { type: 'folder', id: row.folderId } : null,
    parentTypes: ['folder'],
    manage: { document: ['share'] },
  });

  return { folder, document };
}

export const member = (id: string): SubjectRef[] => [{ type: 'member', id }];
export const user = (id: string): SubjectRef[] => [{ type: 'user', id }];
export const at = (iso: string) => new Date(`${iso}T00:00:00Z`);
