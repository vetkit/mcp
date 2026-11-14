import { type Suppression } from '#vendor/shared';
import { z } from 'zod';

import { ToolInputError } from '../errors.js';
import { cell, sanitizeLine, table, untrusted } from '../format.js';

import { Cursor, Limit } from './context.js';
import { ConnectedRepoRef, resolveRepoId } from './repo-lookup.js';

import type { ToolContext } from './context.js';

const SuppressionOutputSchema = z.object({
  id: z.string(),
  repositoryId: z.string(),
  ruleId: z.string().nullable(),
  filePath: z.string().nullable(),
  reason: z.string(),
  active: z.boolean().describe('Not revoked and not expired at the time of the call'),
  expiresAt: z.string().nullable(),
  revokedAt: z.string().nullable(),
  createdBy: z.object({ type: z.string().describe('USER | API_KEY'), id: z.string() }),
  createdAt: z.string(),
});

const ListSuppressionsOutputSchema = z.object({
  suppressions: z.array(SuppressionOutputSchema),
  nextCursor: z.string().nullable(),
});

const isActive = (s: Suppression, now: number): boolean =>
  s.revokedAt === null && (s.expiresAt === null || Date.parse(s.expiresAt) > now);

export function toSuppressionOutput(
  s: Suppression,
  now = Date.now(),
): z.infer<typeof SuppressionOutputSchema> {
  return {
    id: s.id,
    repositoryId: s.repositoryId,
    ruleId: s.ruleId,
    filePath: s.filePath,
    reason: s.reason,
    active: isActive(s, now),
    expiresAt: s.expiresAt,
    revokedAt: s.revokedAt,
    createdBy: { type: s.createdBy.type, id: s.createdBy.id },
    createdAt: s.createdAt,
  };
}

export function registerSuppressionTools(ctx: ToolContext): void {
  const { api, appUrl, orgs, server, guard, requireConfirmation } = ctx;

  // ───────── vetkit_list_suppressions ─────────
  server.registerTool(
    'vetkit_list_suppressions',
    {
      title: 'List finding suppressions',
      description:
        'List suppressions of the organization: findings (by fingerprint, per repository) that are excluded from scores and gates with a written reason, optionally only the active ones or those of one connected repository. ' +
        'Suppressed findings still appear in vetkit_list_findings with suppressed=true. Revoking a suppression is done in the vetkit web app.',
      inputSchema: {
        repo: ConnectedRepoRef.optional(),
        active: z
          .boolean()
          .optional()
          .describe('true: only current suppressions; false: only revoked or expired ones'),
        limit: Limit,
        cursor: Cursor,
      },
      outputSchema: ListSuppressionsOutputSchema,
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    guard(
      ['findings:read'],
      async (
        args: {
          repo?: string | undefined;
          active?: boolean | undefined;
          limit?: number | undefined;
          cursor?: string | undefined;
        },
        extra,
      ) => {
        const orgId = await orgs.get();
        const repositoryId = args.repo ? await resolveRepoId(api, orgId, args.repo, extra.signal) : undefined;
        const page = await api.listSuppressions(
          orgId,
          {
            ...(repositoryId ? { repositoryId } : {}),
            ...(args.active !== undefined ? { active: args.active } : {}),
            ...(args.limit ? { limit: args.limit } : {}),
            ...(args.cursor ? { cursor: args.cursor } : {}),
          },
          extra.signal,
        );
        const now = Date.now();
        const suppressions = page.items.map((s) => toSuppressionOutput(s, now));
        const scope = [
          args.repo ? `for ${args.repo}` : '',
          args.active === undefined ? '' : args.active ? '(active)' : '(revoked or expired)',
        ]
          .filter(Boolean)
          .join(' ');
        const text =
          suppressions.length === 0
            ? args.cursor
              ? 'No more suppressions.'
              : `No suppressions ${scope}`.trim() + '.'
            : untrusted(
                [
                  `${suppressions.length} suppression${suppressions.length === 1 ? '' : 's'} ${scope}`.trim() +
                    ':',
                  table(
                    ['Rule', 'File', 'Reason', 'Active', 'Expires', 'Repository id', 'Suppression id'],
                    suppressions.map((s) => [
                      cell(s.ruleId, 40),
                      cell(s.filePath, 50),
                      cell(s.reason, 80),
                      s.active ? 'yes' : s.revokedAt ? 'revoked' : 'expired',
                      cell(s.expiresAt, 24),
                      s.repositoryId,
                      s.id,
                    ]),
                  ),
                  page.nextCursor ? `More available: call again with cursor "${page.nextCursor}".` : '',
                ]
                  .filter(Boolean)
                  .join('\n\n'),
              );
        return {
          content: [{ type: 'text', text }],
          structuredContent: { suppressions, nextCursor: page.nextCursor },
        };
      },
    ),
  );

  // ───────── vetkit_suppress_finding (write, behind findings:write) ─────────
  server.registerTool(
    'vetkit_suppress_finding',
    {
      title: 'Suppress a finding',
      description:
        'Suppress a finding with a written reason (3-500 characters), optionally until an expiry date. The suppression applies to the finding fingerprint in its repository, so the same finding in later audits stays suppressed: it is excluded from scores and PR gates but still listed with suppressed=true; nothing is deleted. ' +
        'Use it only for a confirmed false positive or an explicitly accepted risk the user has stated; prefer a time-boxed expiresAt for accepted risks. Re-suppressing the same finding updates the reason and expiry. ' +
        'Requires the findings:write scope on an API key created by an active organization member, and a user confirmation through MCP elicitation. Revoke a suppression in the vetkit web app.',
      inputSchema: {
        findingId: z.uuid().describe('Finding id (UUID), as returned by vetkit_list_findings'),
        reason: z
          .string()
          .trim()
          .min(3)
          .max(500)
          .describe(
            'Why the finding is suppressed, e.g. "False positive: test fixture, not a real credential"',
          ),
        expiresAt: z.iso
          .datetime({ offset: true })
          .optional()
          .describe(
            'ISO 8601 date-time in the future after which the suppression ends (recommended for accepted risks)',
          ),
      },
      outputSchema: SuppressionOutputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    guard(
      ['findings:write'],
      async (
        {
          findingId,
          reason,
          expiresAt,
        }: { findingId: string; reason: string; expiresAt?: string | undefined },
        extra,
      ) => {
        if (expiresAt && Date.parse(expiresAt) <= Date.now()) {
          throw new ToolInputError('expiresAt must be in the future.');
        }
        const orgId = await orgs.get();
        await requireConfirmation(extra, [
          `Suppress vetkit finding ${findingId}${expiresAt ? ` until ${expiresAt}` : ' indefinitely'}.`,
          `Reason: ${sanitizeLine(reason)}`,
          'The finding will be excluded from scores and PR gates in this repository until the suppression expires or is revoked in the web app. It remains visible as suppressed; nothing is deleted.',
        ]);
        const suppression = await api.suppressFinding(
          orgId,
          findingId,
          { reason, ...(expiresAt ? { expiresAt } : {}) },
          extra.signal,
        );
        const output = toSuppressionOutput(suppression);
        const text = `Suppressed ${suppression.ruleId ? `${sanitizeLine(suppression.ruleId)} ` : ''}${suppression.filePath ? `in ${sanitizeLine(suppression.filePath)} ` : ''}(suppression ${suppression.id})${suppression.expiresAt ? ` until ${suppression.expiresAt}` : ''}. It no longer counts toward scores or gates in this repository; later audits list it as suppressed. Revoke it at ${appUrl}/findings when it is no longer justified.`;
        return { content: [{ type: 'text', text }], structuredContent: output };
      },
    ),
  );
}
