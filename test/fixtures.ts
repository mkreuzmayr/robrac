import { defineResource, extendRole } from '../src/index.ts';

/* -------------------------------------------------------------------------- */
/* A small document store, standing in for a real application's data model.   */
/* -------------------------------------------------------------------------- */

export type Folder = {
  id: string;
  organizationId: string;
  name: string;
};

export type Document = {
  id: string;
  organizationId: string;
  folderId: string | null;
  createdBy: string;
  visibility: 'private' | 'organization';
  legalHold?: boolean;
};

export type Fixture = {
  folders: Map<string, Folder>;
  documents: Map<string, Document>;
  loads: { folder: number; document: number };
};

export function createFixture(): Fixture {
  return {
    folders: new Map(),
    documents: new Map(),
    loads: { folder: 0, document: 0 },
  };
}

export function folderResource(fixture: Fixture) {
  return defineResource({
    type: 'folder',
    statements: {
      folder: ['read', 'update', 'delete', 'share'],
    },
    roles: {
      viewer: { folder: ['read'] },
      editor: extendRole(['viewer'], { folder: ['update'] }),
      owner: extendRole(['editor'], { folder: ['delete', 'share'] }),
    },
    load: ({ id }) => {
      fixture.loads.folder++;
      return fixture.folders.get(id) ?? null;
    },
    scope: (folder) => folder.organizationId,
    manage: { folder: ['share'] },
  });
}

export function documentResource(fixture: Fixture) {
  return defineResource({
    type: 'document',
    statements: {
      document: ['read', 'update', 'delete', 'share'],
      comment: ['read', 'write'],
    },
    roles: {
      viewer: { document: ['read'], comment: ['read'] },
      commenter: extendRole(['viewer'], { comment: ['write'] }),
      editor: extendRole(['commenter'], { document: ['update'] }),
      owner: extendRole(['editor'], { document: ['delete', 'share'] }),
    },
    load: ({ id }) => {
      fixture.loads.document++;
      return fixture.documents.get(id) ?? null;
    },
    loadMany: ({ ids }) => {
      fixture.loads.document++;
      const found = new Map<string, Document>();
      for (const id of ids) {
        const document = fixture.documents.get(id);
        if (document) {
          found.set(id, document);
        }
      }
      return found;
    },
    scope: (document) => document.organizationId,
    computeRoles: ({ data, subjects, roles }) => {
      if (subjects.some((s) => s.type === 'user' && s.id === data.createdBy)) {
        roles.push('owner');
      }
      if (data.visibility === 'organization') {
        roles.push('viewer');
      }
    },
    override: ({ data }) => (data.legalHold ? 'deny' : null),
    parent: ({ data }) =>
      data.folderId ? { type: 'folder', id: data.folderId } : null,
    // The ancestor role arrives as a plain string; the return type only admits
    // this resource's declared roles, so the identity mapping needs a check.
    inheritRole: ({ role }) =>
      role === 'viewer' || role === 'editor' || role === 'owner' ? role : null,
    manage: { document: ['share'] },
  });
}

export function registry(fixture: Fixture) {
  return {
    folder: folderResource(fixture),
    document: documentResource(fixture),
  };
}
