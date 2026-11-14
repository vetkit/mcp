import { isApiError } from '#vendor/api-client';
import {
  InstallationRequiredDetailsSchema,
  PAGE_LIMIT_MAX,
  parseRepoUrl,
  type RepoProvider,
  type Repository,
} from '#vendor/shared';
import { z } from 'zod';

import { ToolInputError } from '../errors.js';
import { sanitizeLine } from '../format.js';

import type { VetkitApi } from './context.js';

const REPO_SCAN_MAX_PAGES = 50;

/** Input schema for tools that act on an already connected repository (never auto-connects). */
export const ConnectedRepoRef = z
  .string()
  .trim()
  .min(1)
  .max(500)
  .describe(
    'Connected repository: vetkit repository id (UUID), "owner/name", or a GitHub/Bitbucket/GitLab URL',
  );

/** Resolves a repository id, "owner/name" or URL to the id of a connected repository, or fails with guidance. */
export async function resolveRepoId(
  api: Pick<VetkitApi, 'listRepos'>,
  orgId: string,
  repo: string,
  signal?: AbortSignal,
): Promise<string> {
  if (z.uuid().safeParse(repo).success) return repo;
  const parsed = parseRepoUrl(repo);
  if (!parsed) {
    throw new ToolInputError(
      `"${repo}" is not a repository id, "owner/name" or a GitHub/Bitbucket Cloud/GitLab.com URL. Use vetkit_list_repos to see connected repositories.`,
    );
  }
  const hit = await findRepoByFullName(api, orgId, parsed.fullName, parsed.provider, signal);
  if (!hit) {
    throw new ToolInputError(
      `"${sanitizeLine(parsed.fullName)}" is not connected to this organization. Connect it with vetkit_connect_repo first.`,
    );
  }
  return hit.id;
}

export interface InstallRequiredInfo {
  installUrl: string | null;
  owner: string | null;
  /** The organization already has this repository connected (without the App, or under its new name). */
  repositoryId: string | null;
}

export const installRequired = (err: unknown): InstallRequiredInfo | null => {
  if (!isApiError(err, 'INSTALLATION_REQUIRED')) return null;
  const d = InstallationRequiredDetailsSchema.safeParse(err.problem.details);
  return d.success
    ? { installUrl: d.data.installUrl, owner: d.data.owner, repositoryId: d.data.repositoryId ?? null }
    : { installUrl: null, owner: null, repositoryId: null };
};
export const installText = (
  appUrl: string,
  target: string,
  info: { installUrl: string | null; owner: string | null },
): string =>
  [
    `The vetkit GitHub App is not installed for ${info.owner ? `"${sanitizeLine(info.owner)}"` : "this repository's owner"}, so ${sanitizeLine(target)} cannot be connected yet.`,
    info.installUrl
      ? `Ask the user to open this link and install the app (granting access to the repository): ${sanitizeLine(info.installUrl)}`
      : `Ask the user to install the vetkit GitHub App from ${appUrl}/repos.`,
    'Once installed, call this tool again.',
  ].join('\n');

export async function findRepoByFullName(
  api: Pick<VetkitApi, 'listRepos'>,
  orgId: string,
  fullName: string,
  provider: RepoProvider,
  signal?: AbortSignal,
): Promise<Repository | null> {
  const wanted = fullName.toLowerCase();
  let cursor: string | undefined;
  for (let i = 0; i < REPO_SCAN_MAX_PAGES; i++) {
    const page = await api.listRepos(orgId, { limit: PAGE_LIMIT_MAX, ...(cursor ? { cursor } : {}) }, signal);
    const hit = page.items.find((r) => r.provider === provider && r.fullName.toLowerCase() === wanted);
    if (hit) return hit;
    if (!page.nextCursor) return null;
    cursor = page.nextCursor;
  }
  return null;
}
