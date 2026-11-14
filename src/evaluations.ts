import { cell, table } from './format.js';

import type {
  EvaluationBaseline,
  EvaluationBaselineVersion,
  EvaluationComparison,
  EvaluationRunDetail,
  EvaluationRunListItem,
  RubricComparison,
  EmbeddingComparison,
} from '#vendor/shared';

/** Maximum number of cells listed by vetkit_get_evaluation. */
export const EVALUATION_CELL_LIMIT = 50;

const usd = (value: number): string => `$${value.toFixed(value < 0.01 && value > 0 ? 6 : 4)}`;

/** Known cost, with unknown-cost calls stated explicitly (never shown as zero cost). */
function costLine(knownCostUsd: number, unknownCostCalls: number): string {
  if (unknownCostCalls === 0) return `Known cost: ${usd(knownCostUsd)} (all calls priced).`;
  return `Known cost: ${usd(knownCostUsd)} for priced calls only; ${unknownCostCalls} call${
    unknownCostCalls === 1 ? ' has' : 's have'
  } unknown cost, so the total cost is unknown (not zero).`;
}

export function formatEvaluationList(runs: EvaluationRunListItem[]): string {
  if (runs.length === 0) return 'No evaluation runs yet.';
  return [
    `${runs.length} evaluation run${runs.length === 1 ? '' : 's'}:`,
    table(
      ['Name', 'Id', 'Mode', 'Profile', 'Status', 'Created'],
      runs.map((r) => [
        cell(r.name),
        cell(r.id),
        cell(r.mode),
        cell(r.profile ?? 'deterministic'),
        cell(r.status),
        cell(r.createdAt),
      ]),
    ),
  ].join('\n\n');
}

/** Outputs, prompts and assertion details are deliberately omitted. */
export function formatEvaluationRun(run: EvaluationRunDetail): string {
  const profile =
    run.profile ?? (run.rubricResult ? 'rubric' : run.embeddingResult ? 'embedding' : 'deterministic');
  const head = [
    `Evaluation: ${cell(run.name, 200)} (${run.id})`,
    `Status: ${cell(run.status)}; mode: ${cell(run.mode)}; profile: ${cell(profile)}`,
  ];
  const report = run.rubricResult ?? run.embeddingResult ?? run.result;
  if (!report) {
    if (run.status === 'QUEUED' || run.status === 'RUNNING')
      return [
        ...head,
        `The run is ${run.status.toLowerCase()} and has no result yet. Check again later with vetkit_get_evaluation.`,
      ].join('\n');
    return [...head, `No result was recorded.${run.error ? ` Error: ${cell(run.error, 300)}` : ''}`].join(
      '\n',
    );
  }

  const s = report.summary;
  const lines = [
    ...head,
    `Verdict: ${cell(report.verdict)} (report status ${cell(report.status)})`,
    `Cells: ${s.planned} planned, ${s.passed} passed, ${s.failed} failed, ${s.incomplete} incomplete; pass rate ${(
      s.passRate * 100
    ).toFixed(1)}%`,
  ];
  if (run.rubricResult) {
    const r = run.rubricResult.summary;
    lines.push(
      `Calls started: ${r.callsStarted} (${r.targetCallsStarted} target, ${r.judgeCallsStarted} judge). The verdict and counts combine target and rubric judge results.`,
    );
  } else if (run.embeddingResult) {
    const e = run.embeddingResult.summary;
    lines.push(
      `Calls started: ${e.callsStarted} (${e.targetCallsStarted} target, ${e.embeddingCallsStarted} embedding). The verdict and counts combine target and embedding results.`,
    );
  } else {
    lines.push(`Calls started: ${s.callsStarted}`);
  }
  lines.push(costLine(s.knownCostUsd, s.unknownCostCalls));

  const target = run.result;
  if (target) {
    const judged = new Map(run.rubricResult?.results.map((c) => [c.cellId, c]));
    const embedded = new Map(run.embeddingResult?.results.map((c) => [c.cellId, c]));
    const rows = target.results.slice(0, EVALUATION_CELL_LIMIT).map((c) => {
      const j = judged.get(c.cellId);
      const e = embedded.get(c.cellId);
      return [
        cell(c.caseId),
        cell(c.promptId),
        cell(c.targetId),
        String(c.repeatIndex),
        cell(j?.verdict ?? e?.verdict ?? c.verdict),
        cell(c.error ?? j?.skipped ?? e?.embedding?.error),
      ];
    });
    lines.push(
      '',
      table(['Case', 'Prompt', 'Target', 'Repeat', 'Verdict', 'Error'], rows),
      target.results.length > EVALUATION_CELL_LIMIT
        ? `Showing ${EVALUATION_CELL_LIMIT} of ${target.results.length} cells.`
        : '',
    );
  }
  lines.push(
    'Model outputs and prompt text are not included here; export the full report from the vetkit web UI.',
  );
  return lines.filter((l, i, a) => l !== '' || a[i - 1] !== '').join('\n');
}

export function formatBaselineList(baselines: EvaluationBaseline[]): string {
  if (baselines.length === 0) return 'No evaluation baselines yet.';
  return [
    `${baselines.length} baseline${baselines.length === 1 ? '' : 's'}:`,
    table(
      ['Name', 'Id', 'Latest version', 'Created'],
      baselines.map((b) => [cell(b.name), cell(b.id), String(b.latestVersion), cell(b.createdAt)]),
    ),
  ].join('\n\n');
}

export function formatBaselineVersions(baselineId: string, versions: EvaluationBaselineVersion[]): string {
  if (versions.length === 0) return `Baseline ${cell(baselineId)} has no versions.`;
  return [
    `Versions of baseline ${cell(baselineId)} (use a version id with vetkit_compare_evaluation_baseline):`,
    table(
      ['Version', 'Version id', 'Run id', 'Created'],
      versions.map((v) => [String(v.version), cell(v.id), cell(v.runId), cell(v.createdAt)]),
    ),
  ].join('\n\n');
}

function phaseLines(label: string, c: EvaluationComparison): string[] {
  const lines = [
    `${label}: ${cell(c.verdict)}${c.reasons.length ? ` (${c.reasons.map((r) => cell(r, 200)).join(', ')})` : ''}`,
  ];
  if (!c.compatible || !c.summary) {
    lines.push(`  The runs are not comparable, so no regression metrics are available.`);
    return lines;
  }
  const s = c.summary;
  lines.push(
    `  Regressions: ${s.regressions}; improvements: ${s.improvements}; unchanged: ${s.unchanged}; incomplete: ${s.incomplete}`,
    `  Pass rate delta: ${(s.passRateDelta * 100).toFixed(1)} points (baseline ${(s.baseline.passRate * 100).toFixed(1)}%, candidate ${(s.candidate.passRate * 100).toFixed(1)}%)`,
    s.costDeltaUsd === null
      ? '  Cost delta: unknown (some calls have unknown cost).'
      : `  Cost delta: ${s.costDeltaUsd >= 0 ? '+' : '-'}${usd(Math.abs(s.costDeltaUsd))}`,
  );
  return lines;
}

type AnyComparison = EvaluationComparison | RubricComparison | EmbeddingComparison;
const isRubric = (c: AnyComparison): c is RubricComparison => 'profile' in c && c.profile === 'rubric';
const isEmbedding = (c: AnyComparison): c is EmbeddingComparison =>
  'profile' in c && c.profile === 'embedding';

export function formatBaselineComparison(c: AnyComparison): string {
  const lines = [
    `Comparison verdict: ${cell(c.verdict)}`,
    c.reasons.length
      ? `Blocking reasons: ${c.reasons.map((r) => cell(r, 200)).join(', ')}`
      : 'Blocking reasons: none',
  ];
  if (isRubric(c)) {
    lines.push(...phaseLines('Target phase', c.target));
    if (c.judge) lines.push(...phaseLines('Judge phase', c.judge));
    lines.push(
      c.totalCostDeltaUsd === null
        ? 'Total cost delta: unknown or not computed.'
        : `Total cost delta: ${c.totalCostDeltaUsd >= 0 ? '+' : '-'}${usd(Math.abs(c.totalCostDeltaUsd))}`,
    );
  } else if (isEmbedding(c)) {
    lines.push(...phaseLines('Target phase', c.target));
    const s = c.embedding?.summary;
    lines.push(
      s
        ? `Embedding phase: ${s.regressions} similarity regression(s); mean similarity delta ${
            s.meanSimilarityDelta === null ? 'unknown' : s.meanSimilarityDelta.toFixed(4)
          }. Similarities are compared as recorded and are not independently reproducible without stored vectors.`
        : 'Embedding phase: not comparable.',
    );
  } else {
    lines.push(...phaseLines('Comparison', c));
  }
  lines.push(
    'This is an informational comparison against the stored baseline policy. It is not a release gate or a pull request check.',
  );
  return lines.join('\n');
}
