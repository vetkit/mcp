import { randomUUID } from 'node:crypto';

import { EVALUATION_RUN_PAGE_SIZE } from '#vendor/shared';
import { z } from 'zod';

import { ToolInputError } from '../errors.js';
import {
  formatBaselineComparison,
  formatBaselineList,
  formatBaselineVersions,
  formatEvaluationList,
  formatEvaluationRun,
} from '../evaluations.js';
import { sanitizeLine, untrusted } from '../format.js';

import type { ToolContext } from './context.js';

export function registerEvaluationTools(ctx: ToolContext): void {
  const { api, orgs, server, guard, requireConfirmation } = ctx;

  // ───────── AI Evaluation (read-only) ─────────
  const EvaluationId = z.uuid().describe('Evaluation run id (UUID), as returned by vetkit_list_evaluations');
  const readOnly = { readOnlyHint: true, idempotentHint: true, openWorldHint: false };

  server.registerTool(
    'vetkit_list_evaluations',
    {
      title: 'List AI evaluation runs',
      description:
        'List AI Evaluation runs of the organization with name, id, mode (demo/model), profile (deterministic/rubric), status and creation time. ' +
        `Returns up to ${EVALUATION_RUN_PAGE_SIZE} runs, newest first; pass before from the next-page instruction to read older runs.`,
      inputSchema: {
        before: z
          .uuid()
          .optional()
          .describe('Run id from the previous page; return runs older than this run'),
      },
      annotations: readOnly,
    },
    guard(['audits:read'], async ({ before }: { before?: string }, extra) => {
      const orgId = await orgs.get();
      const runs = await api.listEvaluationRuns(orgId, extra.signal, { before });
      const text = runs.length === 0 && before ? 'No more evaluation runs.' : formatEvaluationList(runs);
      const continuation =
        runs.length === EVALUATION_RUN_PAGE_SIZE
          ? `More may be available: call vetkit_list_evaluations again with before: "${runs.at(-1)!.id}".`
          : '';
      return {
        content: [{ type: 'text', text: untrusted([text, continuation].filter(Boolean).join('\n\n')) }],
      };
    }),
  );

  server.registerTool(
    'vetkit_get_evaluation',
    {
      title: 'Get an AI evaluation run',
      description:
        'Get an AI Evaluation run: status, profile, verdict, summary counts, pass rate, calls and cost (unknown cost is stated, never shown as zero) and up to 50 result cells. Model outputs and prompts are omitted; export the full report from the web UI. Queued or running runs have no result yet.',
      inputSchema: { evaluationId: EvaluationId },
      annotations: readOnly,
    },
    guard(['audits:read'], async ({ evaluationId }: { evaluationId: string }, extra) => {
      const orgId = await orgs.get();
      const run = await api.getEvaluationRun(orgId, evaluationId, extra.signal);
      return { content: [{ type: 'text', text: untrusted(formatEvaluationRun(run)) }] };
    }),
  );

  server.registerTool(
    'vetkit_list_evaluation_baselines',
    {
      title: 'List AI evaluation baselines',
      description:
        "List AI Evaluation baselines. With baselineId, list that baseline's versions instead (version ids are used by vetkit_compare_evaluation_baseline).",
      inputSchema: {
        baselineId: z.uuid().optional().describe('Baseline id (UUID); when set, its versions are listed'),
      },
      annotations: readOnly,
    },
    guard(['audits:read'], async ({ baselineId }: { baselineId?: string }, extra) => {
      const orgId = await orgs.get();
      const text = baselineId
        ? formatBaselineVersions(
            baselineId,
            await api.listEvaluationBaselineVersions(orgId, baselineId, extra.signal),
          )
        : formatBaselineList(await api.listEvaluationBaselines(orgId, extra.signal));
      return { content: [{ type: 'text', text: untrusted(text) }] };
    }),
  );

  server.registerTool(
    'vetkit_compare_evaluation_baseline',
    {
      title: 'Compare an evaluation run to a baseline',
      description:
        'Compare an evaluation run against a baseline version using its stored policy. Returns the verdict (PASS, FAIL or BLOCKED), blocking reasons and regression/improvement counts. Informational only: it is not a release gate or a pull request check.',
      inputSchema: {
        baselineVersionId: z
          .uuid()
          .describe('Baseline version id (UUID) from vetkit_list_evaluation_baselines'),
        evaluationId: EvaluationId,
      },
      annotations: readOnly,
    },
    guard(
      ['audits:read'],
      async (
        { baselineVersionId, evaluationId }: { baselineVersionId: string; evaluationId: string },
        extra,
      ) => {
        const orgId = await orgs.get();
        const result = await api.compareEvaluationBaseline(
          orgId,
          baselineVersionId,
          evaluationId,
          extra.signal,
        );
        return { content: [{ type: 'text', text: untrusted(formatBaselineComparison(result)) }] };
      },
    ),
  );

  // ───────── AI Evaluation (write, behind audits:write) ─────────
  server.registerTool(
    'vetkit_start_evaluation',
    {
      title: 'Start an AI evaluation run',
      description:
        'Start an AI Evaluation run from a suite definition (prompts, cases, targets, assertions, execution limits). Requires the audits:write scope and a user confirmation through MCP elicitation. ' +
        'mode "demo" (default) runs locally without calling a model provider. mode "model" sends the suite prompts and test data to the configured model provider and may incur provider charges: the user is asked to confirm this through MCP elicitation (refused when the client cannot ask) and a saved connection id per target in `connections` (targetId -> connection UUID). ' +
        'Hosted limits apply (40 cells/calls, concurrency 2, 30-second calls). Rubric runs are not supported from MCP; use the web app. ' +
        'Pass the returned idempotencyKey again to retry safely without creating a duplicate run. The run is queued: poll with vetkit_get_evaluation.',
      inputSchema: {
        name: z.string().trim().min(1).max(120).describe('Run name'),
        suite: z.record(z.string(), z.unknown()).describe('Evaluation suite definition object'),
        mode: z.enum(['demo', 'model']).default('demo').describe('demo (default) or model'),
        connections: z
          .record(z.string().max(128), z.uuid())
          .optional()
          .describe('Model mode only: targetId -> saved connection id (UUID), one per target'),
        sourceVersionId: z.uuid().optional().describe('Optional source suite version id (UUID)'),
        projectId: z.uuid().optional().describe('Optional project id (UUID)'),
        idempotencyKey: z
          .uuid()
          .optional()
          .describe('Optional UUID; generated if omitted. Reuse it to retry the same start safely'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    guard(
      ['audits:write'],
      async (
        args: {
          name: string;
          suite: Record<string, unknown>;
          mode?: 'demo' | 'model';
          connections?: Record<string, string>;
          sourceVersionId?: string;
          projectId?: string;
          idempotencyKey?: string;
        },
        extra,
      ) => {
        const mode = args.mode ?? 'demo';
        if (mode === 'model') {
          if (!args.connections || Object.keys(args.connections).length === 0)
            throw new ToolInputError(
              'Model mode requires connections (targetId -> saved connection id), one per suite target.',
            );
        } else if (args.connections && Object.keys(args.connections).length > 0) {
          throw new ToolInputError(
            'Demo runs cannot use model connections. Use mode "model" or drop connections.',
          );
        }
        const idempotencyKey = args.idempotencyKey ?? randomUUID();
        const orgId = await orgs.get();
        const count = (key: string): string => {
          const v = args.suite[key];
          return Array.isArray(v) ? String(v.length) : 'unknown number of';
        };
        await requireConfirmation(extra, [
          `Start an AI Evaluation run named "${sanitizeLine(args.name).slice(0, 120)}" in ${mode.toUpperCase()} mode (${count('prompts')} prompts, ${count('cases')} cases, ${count('targets')} targets in the suite).`,
          mode === 'model'
            ? `The suite prompts and test data will be SENT TO THE MODEL PROVIDER(S) behind these saved connections (targetId -> connection id): ${Object.entries(
                args.connections ?? {},
              )
                .map(([t, c]) => `${sanitizeLine(t)} -> ${c}`)
                .join(', ')}. This may incur provider charges billed to you.`
            : 'Demo mode runs locally in vetkit and calls no model provider.',
          `Idempotency key: ${idempotencyKey}.`,
        ]);
        const run = await api.createEvaluationRun(orgId, {
          name: args.name,
          idempotencyKey,
          mode,
          suite: args.suite,
          ...(mode === 'model' ? { consent: true, connections: args.connections } : {}),
          ...(args.sourceVersionId ? { sourceVersionId: args.sourceVersionId } : {}),
          ...(args.projectId ? { projectId: args.projectId } : {}),
        });
        return {
          content: [
            {
              type: 'text',
              text: untrusted(
                [
                  `Started evaluation "${run.name}" (${run.id}); status ${run.status}, mode ${run.mode}.`,
                  `Idempotency key: ${idempotencyKey} (reuse it to retry this start without creating a duplicate).`,
                  'Poll with vetkit_get_evaluation until the run is no longer QUEUED or RUNNING.',
                ].join('\n'),
              ),
            },
          ],
        };
      },
    ),
  );

  server.registerTool(
    'vetkit_cancel_evaluation',
    {
      title: 'Cancel an AI evaluation run',
      description:
        'Request cancellation of a queued or running AI Evaluation run. Requires the audits:write scope and a user confirmation through MCP elicitation. Provider calls already in flight may still complete and be billed. Check the final state with vetkit_get_evaluation.',
      inputSchema: { evaluationId: EvaluationId },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    guard(['audits:write'], async ({ evaluationId }: { evaluationId: string }, extra) => {
      const orgId = await orgs.get();
      await requireConfirmation(extra, [
        `Cancel AI Evaluation run ${evaluationId}.`,
        'Provider calls already in flight may still complete and be billed.',
      ]);
      const run = await api.cancelEvaluationRun(orgId, evaluationId);
      return {
        content: [
          {
            type: 'text',
            text: untrusted(
              `Evaluation ${run.id} is now ${run.status}${run.cancelRequested ? ' (cancel requested)' : ''}. In-flight provider calls may still be billed. Check again with vetkit_get_evaluation.`,
            ),
          },
        ],
      };
    }),
  );
}
