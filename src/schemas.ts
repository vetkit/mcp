import { z } from 'zod';

import type {
  AnalyzerCatalogResponse,
  Audit,
  DeterministicFix,
  Finding,
  Repository,
  SuiteScores,
} from '#vendor/shared';

/*
 * Tool output schemas (MCP `outputSchema`). Deliberately loose: clients validate with JSON Schema,
 * and MCP clients must not break when the API adds a field or enum value.
 */

const Counts = z.record(z.string(), z.number().int());

const SuiteScoresOutput = z
  .record(z.string(), z.object({ score: z.number().int(), grade: z.string() }))
  .describe(
    'Grade and score per suite that ran: SECURITY, QUALITY, SUSTAINABILITY, AI_RISKS and/or PRODUCTION (empty for audits before suites)',
  );

export const AuditOutputSchema = z.object({
  id: z.string(),
  url: z.string().describe('Link to the audit in the vetkit web app'),
  status: z.string().describe('QUEUED | RUNNING | SUCCEEDED | FAILED | CANCELLED'),
  repository: z.object({
    id: z.string(),
    provider: z.enum(['GITHUB', 'BITBUCKET', 'GITLAB']),
    fullName: z.string(),
    htmlUrl: z.string(),
  }),
  ref: z.string(),
  commitSha: z.string(),
  mode: z
    .enum(['QUICK', 'FULL'])
    .describe('QUICK: free monthly Quick Scan with fixed checks; FULL: full scan that costs 1 credit'),
  credited: z
    .boolean()
    .describe('A credit was reserved for this audit (spent when its complete report is saved)'),
  excludeAssets: z.boolean().describe('Media files were not downloaded or scanned'),
  analyzers: z
    .array(z.string())
    .describe(
      'Checks selected for this audit (empty for audits created before suites, which ran the legacy set)',
    ),
  createdAt: z.string(),
  startedAt: z.string().nullable(),
  finishedAt: z.string().nullable(),
  errorCode: z.string().nullable(),
  errorMessage: z.string().nullable(),
  summary: z
    .object({
      score: z.number().int(),
      grade: z.string(),
      scoringApplicable: z
        .boolean()
        .optional()
        .describe('False for privacy-only reviews: score and grade are not applicable'),
      suiteScores: SuiteScoresOutput,
      totalFindings: z.number().int(),
      bySeverity: Counts,
    })
    .nullable(),
  steps: z.array(
    z.object({
      analyzerId: z.string(),
      status: z.string(),
      findingsCount: z.number().int(),
      durationMs: z.number().int().nullable(),
      toolVersion: z.string().nullable(),
      errorMessage: z.string().nullable(),
      metrics: z
        .record(z.string(), z.union([z.number(), z.string()]))
        .describe(
          'Analyzer metrics, e.g. duplicationPct, avgComplexity, testRatioPct, docCoveragePct, busFactor, deprecated',
        ),
    }),
  ),
});
export type AuditOutput = z.infer<typeof AuditOutputSchema>;

export const RepoOutputSchema = z.object({
  id: z.string(),
  provider: z.enum(['GITHUB', 'BITBUCKET', 'GITLAB']),
  fullName: z.string(),
  htmlUrl: z.string(),
  defaultBranch: z.string(),
  isPrivate: z.boolean(),
  appInstalled: z.boolean().describe('Whether the vetkit GitHub App currently has access'),
  defaultAnalyzers: z
    .array(z.string())
    .describe("Checks this repository's audits run by default (empty = vetkit's recommended defaults)"),
  lastAudit: z
    .object({
      id: z.string(),
      status: z.string(),
      grade: z.string().nullable(),
      score: z.number().int().nullable(),
      suiteScores: SuiteScoresOutput,
      createdAt: z.string(),
      url: z.string(),
    })
    .nullable(),
});
export type RepoOutput = z.infer<typeof RepoOutputSchema>;

export const ListReposOutputSchema = z.object({
  repositories: z.array(RepoOutputSchema),
  nextCursor: z.string().nullable().describe('Pass as `cursor` to fetch the next page; null when done'),
});

export const ConnectRepoOutputSchema = z.object({
  outcome: z.enum(['connected', 'installation_required']),
  repository: RepoOutputSchema.nullable(),
  installUrl: z.string().nullable().describe('GitHub App install URL when outcome is installation_required'),
});

export const RunAuditOutputSchema = z.object({
  outcome: z
    .enum(['completed', 'started', 'still_running', 'installation_required'])
    .describe(
      'completed: audit reached a terminal status; started: wait=false; still_running: wait timed out; installation_required: GitHub App must be installed first',
    ),
  audit: AuditOutputSchema.nullable(),
  installUrl: z.string().nullable(),
});

/**
 * Rule-provided fix of a finding, verbatim from the API. Lines and columns are 1-based, `endCol` exclusive.
 * Current fixes carry `columnUnit: "utf16"` and `original`; legacy rows (UTF-8 byte columns, no `original`)
 * are only safe on pure-ASCII lines, which is why consumers must re-check the range before applying it.
 */
export const DeterministicFixOutputSchema = z.object({
  replacement: z.string().describe('Text that replaces the range [startLine:startCol, endLine:endCol)'),
  startLine: z.number().int(),
  startCol: z.number().int().describe('1-based; UTF-16 code units when columnUnit is "utf16"'),
  endLine: z.number().int(),
  endCol: z.number().int().describe('1-based, exclusive'),
  original: z
    .string()
    .nullable()
    .describe(
      'Exact scanned text of the range. Compare it with the current file content before applying the replacement; if it differs, the file changed and the fix must not be applied blindly.',
    ),
  columnUnit: z
    .string()
    .nullable()
    .describe(
      '"utf16": columns count UTF-16 code units (JavaScript string indices, VS Code, LSP). null: legacy fix with UTF-8 byte columns and no original; apply only when every line of the range is ASCII.',
    ),
});

export const toDeterministicFixOutput = (
  fix: DeterministicFix | null | undefined,
): z.infer<typeof DeterministicFixOutputSchema> | null =>
  fix
    ? {
        replacement: fix.replacement,
        startLine: fix.startLine,
        startCol: fix.startCol,
        endLine: fix.endLine,
        endCol: fix.endCol,
        original: fix.original ?? null,
        columnUnit: fix.columnUnit ?? null,
      }
    : null;

export const FindingOutputSchema = z.object({
  id: z.string(),
  severity: z.string(),
  category: z.string(),
  analyzerId: z.string(),
  ruleId: z.string(),
  title: z.string(),
  message: z.string(),
  filePath: z.string().nullable(),
  startLine: z.number().int().nullable(),
  endLine: z.number().int().nullable(),
  snippet: z.string().nullable().describe('Redacted code snippet; never contains secret values'),
  status: z.string().describe('NEW (first seen in this audit) | EXISTING'),
  suppressed: z.boolean(),
  confidence: z.string().nullable(),
  identifiers: z.record(z.string(), z.array(z.string())).nullable(),
  references: z.array(z.string()),
  remediation: z.string().nullable(),
  htmlUrl: z.string().nullable(),
  deterministicFix: DeterministicFixOutputSchema.nullable().describe(
    'Rule-provided replacement for the source range, when the analyzer supplies one (no LLM involved); null otherwise',
  ),
});

export const ListFindingsOutputSchema = z.object({
  auditId: z.string(),
  findings: z.array(FindingOutputSchema),
  nextCursor: z.string().nullable(),
});

export const ListChecksOutputSchema = z.object({
  suites: z.array(z.object({ id: z.string(), label: z.string(), description: z.string() })),
  checks: z.array(
    z.object({
      id: z.string().describe('Pass in vetkit_run_audit `analyzers`'),
      suite: z.string(),
      label: z.string(),
      description: z.string(),
      tool: z.string(),
      toolVersion: z.string().nullable(),
      categories: z.array(z.string()),
      beta: z.boolean(),
      defaultEnabled: z.boolean(),
      available: z.boolean(),
      unavailableReason: z.string().nullable(),
    }),
  ),
  defaults: z.array(z.string()).describe('Checks that run when an audit does not select any'),
});

export const auditUrl = (appUrl: string, auditId: string): string =>
  `${appUrl}/audits/${encodeURIComponent(auditId)}`;

function suiteScoresOutput(scores: SuiteScores): Record<string, { score: number; grade: string }> {
  const out: Record<string, { score: number; grade: string }> = {};
  for (const [suite, s] of Object.entries(scores)) if (s) out[suite] = { score: s.score, grade: s.grade };
  return out;
}

export function toChecksOutput(catalog: AnalyzerCatalogResponse): z.infer<typeof ListChecksOutputSchema> {
  return {
    suites: catalog.suites.map((s) => ({ id: s.id, label: s.label, description: s.description })),
    checks: catalog.analyzers.map((a) => ({
      id: a.id,
      suite: a.suite,
      label: a.label,
      description: a.description,
      tool: a.tool,
      toolVersion: a.toolVersion,
      categories: [...a.categories],
      beta: a.beta,
      defaultEnabled: a.defaultEnabled,
      available: a.available,
      unavailableReason: a.unavailableReason,
    })),
    defaults: [...catalog.defaults],
  };
}

export function toAuditOutput(audit: Audit, appUrl: string): AuditOutput {
  return {
    id: audit.id,
    url: auditUrl(appUrl, audit.id),
    status: audit.status,
    repository: {
      id: audit.repositoryId,
      provider: audit.repository.provider,
      fullName: audit.repository.fullName,
      htmlUrl: audit.repository.htmlUrl,
    },
    ref: audit.ref,
    commitSha: audit.commitSha,
    mode: audit.mode,
    credited: audit.credited,
    excludeAssets: audit.excludeAssets,
    analyzers: [...audit.analyzers],
    createdAt: audit.createdAt,
    startedAt: audit.startedAt,
    finishedAt: audit.finishedAt,
    errorCode: audit.errorCode,
    errorMessage: audit.errorMessage,
    summary: audit.summary
      ? {
          score: audit.summary.overallScore,
          grade: audit.summary.grade,
          suiteScores: suiteScoresOutput(audit.summary.suiteScores),
          ...(audit.summary.scoringApplicable === false ? { scoringApplicable: false } : {}),
          totalFindings: audit.summary.total,
          bySeverity: { ...audit.summary.bySeverity },
        }
      : null,
    steps: audit.steps.map((s) => ({
      analyzerId: s.analyzerId,
      status: s.status,
      findingsCount: s.findingsCount,
      durationMs: s.durationMs,
      toolVersion: s.toolVersion,
      errorMessage: s.errorMessage,
      metrics: { ...s.metrics },
    })),
  };
}

export function toRepoOutput(repo: Repository, appUrl: string): RepoOutput {
  const last = repo.lastAudit;
  return {
    id: repo.id,
    provider: repo.provider,
    fullName: repo.fullName,
    htmlUrl: repo.htmlUrl,
    defaultBranch: repo.defaultBranch,
    isPrivate: repo.isPrivate,
    appInstalled: repo.installationId !== null,
    defaultAnalyzers: [...repo.defaultAnalyzers],
    lastAudit: last
      ? {
          id: last.id,
          status: last.status,
          grade: last.grade,
          score: last.overallScore,
          suiteScores: suiteScoresOutput(last.suiteScores),
          createdAt: last.createdAt,
          url: auditUrl(appUrl, last.id),
        }
      : null,
  };
}

export function toFindingOutput(f: Finding): z.infer<typeof FindingOutputSchema> {
  const identifiers = f.identifiers
    ? Object.fromEntries(
        Object.entries(f.identifiers).filter((e): e is [string, string[]] => Array.isArray(e[1])),
      )
    : null;
  return {
    id: f.id,
    severity: f.severity,
    category: f.category,
    analyzerId: f.analyzerId,
    ruleId: f.ruleId,
    title: f.title,
    message: f.message,
    filePath: f.filePath,
    startLine: f.startLine,
    endLine: f.endLine,
    snippet: f.snippet,
    status: f.status,
    suppressed: f.suppressed,
    confidence: f.confidence,
    identifiers,
    references: f.references,
    remediation: f.remediation,
    htmlUrl: f.htmlUrl,
    deterministicFix: toDeterministicFixOutput(f.deterministicFix),
  };
}

export const OpenFixPrOutputSchema = z.object({
  actionId: z.string(),
  status: z.string().describe('SUCCEEDED | FAILED | UNKNOWN | RUNNING'),
  url: z.string().nullable().describe('Pull request URL once opened'),
  prNumber: z.number().int().nullable(),
  prState: z.string().nullable().describe('OPEN | MERGED | CLOSED, kept current by the GitHub webhook'),
  branch: z.string().nullable(),
  error: z.string().nullable(),
});

export const SuggestFixOutputSchema = z.object({
  findingId: z.string(),
  path: z.string(),
  diff: z.string().describe('Unified diff of the proposed change (untrusted repository content)'),
  explanation: z.string(),
  confidence: z.string().describe('high | medium | low'),
  provider: z.string().describe('AI provider id, or "rule" for a rule-provided deterministic fix'),
  model: z.string().nullable(),
  verification: z.object({
    status: z.string().describe('VERIFIED | FAILED | NOT_RUN'),
    analyzer: z.string().nullable(),
    detail: z.string(),
  }),
  expectedCommitSha: z.string(),
  expectedBlobSha: z.string(),
});
