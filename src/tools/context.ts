import { type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { PAGE_LIMIT_MAX } from '#vendor/shared';
import { z } from 'zod';

import { type VetkitApi } from '../api.js';
import { ToolInputError } from '../errors.js';

import type { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import type { CallToolResult, ServerNotification, ServerRequest } from '@modelcontextprotocol/sdk/types.js';

export type { VetkitApi } from '../api.js';

export type Extra = RequestHandlerExtra<ServerRequest, ServerNotification>;

/** Shared state and helpers handed to every tool-group registrar. */
export interface ToolContext {
  server: McpServer;
  api: VetkitApi;
  appUrl: string;
  pollIntervalMs: number;
  orgs: OrgResolver;
  guard: <A>(
    scopes: readonly string[],
    fn: (args: A, extra: Extra) => Promise<CallToolResult>,
  ) => (args: A, extra: Extra) => Promise<CallToolResult>;
  requireConfirmation: (extra: Extra, lines: string[]) => Promise<void>;
}

export const RepoIdOrRef = z
  .string()
  .trim()
  .min(1)
  .max(500)
  .describe(
    'Repository to audit: vetkit repository id (UUID), "owner/name" for GitHub, or a GitHub/Bitbucket Cloud/GitLab.com URL',
  );

export const AuditId = z.uuid().describe('Audit id (UUID), as returned by vetkit_run_audit');
export const Limit = z
  .number()
  .int()
  .min(1)
  .max(PAGE_LIMIT_MAX)
  .optional()
  .describe(`Page size (1-${PAGE_LIMIT_MAX}, default 25)`);
export const Cursor = z
  .string()
  .min(1)
  .max(200)
  .optional()
  .describe("Opaque cursor from a previous response's nextCursor");

/** Resolves the org id once; after an error it retries on the next call. */
export class OrgResolver {
  private pending: Promise<string> | null = null;

  constructor(
    private readonly api: VetkitApi,
    private readonly fixed?: string,
  ) {}

  get(): Promise<string> {
    if (this.fixed) return Promise.resolve(this.fixed);
    // The shared discovery request is not tied to one call's abort signal.
    this.pending ??= this.discover().catch((err: unknown) => {
      this.pending = null;
      throw err;
    });
    return this.pending;
  }

  private async discover(): Promise<string> {
    const me = await this.api.me();
    const orgs = me.organizations;
    if (orgs.length === 1 && orgs[0]) return orgs[0].id;
    if (orgs.length === 0) {
      throw new ToolInputError(
        'This API key is not associated with any organization. Create a new key in the vetkit web app.',
      );
    }
    const list = orgs.map((o) => `${o.slug} (${o.id})`).join(', ');
    throw new ToolInputError(
      `This credential can access multiple organizations: ${list}. Set VETKIT_ORG_ID to the one you want to use and restart the MCP server.`,
    );
  }
}

export const json = (value: unknown): string => JSON.stringify(value, null, 2);
