import { TRIAGE_MAX_FINDINGS } from '#vendor/shared';
import { z } from 'zod';

import { cell, table, untrusted } from '../format.js';

import { AuditId } from './context.js';

import type { ToolContext } from './context.js';

const TriageOutputSchema = {
  results: z.array(
    z.object({
      findingId: z.string(),
      status: z.string().describe('TRIAGED | SKIPPED | FAILED'),
      reason: z
        .string()
        .nullable()
        .describe('NOT_ELIGIBLE | SOURCE_UNAVAILABLE | INVALID_RESPONSE | UNGROUNDED | PROVIDER_ERROR'),
      verdict: z.string().nullable().describe('LIKELY_TRUE_POSITIVE | LIKELY_FALSE_POSITIVE | UNSURE'),
      confidence: z.number().nullable(),
      rationale: z.string().nullable().describe('Model output: untrusted text, at most 600 characters'),
      priority: z.number().int().nullable(),
    }),
  ),
};

export function registerTriageTools(ctx: ToolContext): void {
  const { api, orgs, server, guard } = ctx;

  // ───────── vetkit_triage_findings (write, behind findings:write) ─────────
  server.registerTool(
    'vetkit_triage_findings',
    {
      title: 'AI triage of findings',
      description:
        `Ask the organization's saved AI provider (BYOK, configured under AI review) whether up to ${TRIAGE_MAX_FINDINGS} findings of an audit are likely true or false positives. ` +
        'Each finding gets a verdict, a confidence (0–1) and a short rationale grounded in one quoted source line; a redacted ±40-line window of the file is sent to that provider. ' +
        'Verdicts are advisory: they adjust the priority (confident false positives rank lower) but never suppress a finding or change the score or gate. ' +
        'Requires the findings:write scope. Get finding ids from vetkit_list_findings.',
      inputSchema: {
        auditId: AuditId,
        findingIds: z
          .array(z.uuid())
          .min(1)
          .max(TRIAGE_MAX_FINDINGS)
          .describe('Finding ids (UUIDs) of this audit, as returned by vetkit_list_findings'),
      },
      outputSchema: TriageOutputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    guard(
      ['findings:write'],
      async ({ auditId, findingIds }: { auditId: string; findingIds: string[] }, extra) => {
        const orgId = await orgs.get();
        const results = await api.triageFindings(orgId, auditId, { findingIds }, extra.signal);
        const output = {
          results: results.map((r) => ({
            findingId: r.findingId,
            status: r.status,
            reason: r.reason ?? null,
            verdict: r.triage?.verdict ?? null,
            confidence: r.triage?.confidence ?? null,
            rationale: r.triage?.rationale ?? null,
            priority: r.priority ?? null,
          })),
        };
        const triaged = results.filter((r) => r.status === 'TRIAGED').length;
        const rows = output.results.map((r) => [
          cell(r.findingId, 36),
          cell(r.verdict ?? `${r.status}${r.reason ? ` (${r.reason})` : ''}`, 40),
          cell(r.confidence === null ? null : r.confidence.toFixed(2)),
          cell(r.priority),
          cell(r.rationale, 160),
        ]);
        const summary = `AI triage: ${triaged} of ${results.length} findings got a verdict. Verdicts are advisory and nothing was suppressed.`;
        return {
          content: [
            { type: 'text', text: summary },
            {
              type: 'text',
              text: untrusted(table(['Finding', 'Verdict', 'Confidence', 'Priority', 'Rationale'], rows)),
            },
          ],
          structuredContent: output,
        };
      },
    ),
  );
}
