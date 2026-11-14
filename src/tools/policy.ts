import { POLICY_FILE_NAME } from '#vendor/shared';
import { z } from 'zod';

import { sanitizeLine, untrusted } from '../format.js';

import type { ToolContext } from './context.js';

const ValidatePolicyOutputSchema = z.object({
  ok: z.boolean(),
  issues: z.array(
    z.object({
      path: z.string(),
      message: z.string(),
      line: z.number().nullable(),
      column: z.number().nullable(),
    }),
  ),
  sha256: z.string().nullable(),
  ignoredByOrgPolicy: z.array(z.object({ path: z.string(), message: z.string() })),
});

export function registerPolicyTools(ctx: ToolContext): void {
  const { api, orgs, server, guard } = ctx;

  // ───────── vetkit_validate_policy ─────────
  server.registerTool(
    'vetkit_validate_policy',
    {
      title: `Validate a ${POLICY_FILE_NAME}`,
      description: `Validate the YAML text of a ${POLICY_FILE_NAME} against the Vetkit policy schema and preview how the organization policy treats it (a repository file may only tighten the organization policy). Returns syntax errors with line/column, schema errors with field paths, and the fields the organization would ignore. Nothing is saved.`,
      inputSchema: {
        yaml: z
          .string()
          .min(1)
          .max(256 * 1024)
          .describe(`Full ${POLICY_FILE_NAME} text`),
      },
      outputSchema: ValidatePolicyOutputSchema,
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    guard(['repos:read'], async ({ yaml }: { yaml: string }, extra) => {
      const orgId = await orgs.get();
      const result = await api.validateOrgPolicy(orgId, yaml, extra.signal);
      const structured = {
        ok: result.ok,
        issues: result.issues,
        sha256: result.sha256,
        ignoredByOrgPolicy: result.ignoredByOrgPolicy,
      };
      const lines = result.ok
        ? [
            `${POLICY_FILE_NAME} is valid (sha256 ${result.sha256?.slice(0, 12)}).`,
            ...(result.ignoredByOrgPolicy.length
              ? [
                  'Fields the organization policy would ignore (they loosen it):',
                  ...result.ignoredByOrgPolicy.map(
                    (i) => `- ${sanitizeLine(i.path)}: ${sanitizeLine(i.message)}`,
                  ),
                ]
              : ['Every field tightens or matches the organization policy.']),
          ]
        : [
            `${POLICY_FILE_NAME} is invalid:`,
            ...result.issues.map((i) => {
              const where =
                i.line !== null
                  ? `line ${i.line}${i.column !== null ? `, column ${i.column}` : ''}`
                  : i.path || 'document';
              return `- ${sanitizeLine(where)}: ${sanitizeLine(i.message)}`;
            }),
          ];
      return {
        content: [{ type: 'text', text: untrusted(lines.join('\n')) }],
        structuredContent: structured,
      };
    }),
  );
}
