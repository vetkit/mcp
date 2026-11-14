import { VetkitApiError, VetkitNetworkError } from '#vendor/api-client';
import {
  ANALYZER_CATALOG,
  type Audit,
  type AuditAnalyzerId,
  AuditAnalyzerIdSchema,
  AUDIT_ANALYZER_IDS,
  type AuditMode,
  AuditModeSchema,
  CreateAuditInputSchema,
  FULL_SCAN_COST_CREDITS,
  QUICK_SCAN,
  isTerminalAuditStatus,
  parseRepoUrl,
  repositoryHtmlUrl,
  type RepoProvider,
  type Suite,
  SUITE_ANALYZERS,
  SUITE_INFO,
  STANDARD_IDS,
  StandardIdSchema,
  type StandardId,
  StandardsReportSchema,
} from '#vendor/shared';
import { z } from 'zod';

import { ToolInputError, toToolError } from '../errors.js';
import { formatAudit, formatCatalog, sanitizeLine, stepProgress, untrusted } from '../format.js';
import {
  auditUrl,
  ListChecksOutputSchema,
  RunAuditOutputSchema,
  AuditOutputSchema,
  toAuditOutput,
  toChecksOutput,
} from '../schemas.js';

import { RepoIdOrRef, AuditId } from './context.js';
import { findRepoByFullName, installRequired, installText } from './repo-lookup.js';

import type { Extra, ToolContext } from './context.js';

const POLL_MAX_CONSECUTIVE_ERRORS = 5;

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason as Error);
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal?.reason as Error);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

const isTransient = (err: unknown): boolean =>
  err instanceof VetkitNetworkError ||
  (err instanceof VetkitApiError && (err.status >= 500 || err.code === 'RATE_LIMITED'));

async function sendProgress(extra: Extra, progress: number, message: string): Promise<void> {
  const progressToken = extra._meta?.progressToken;
  if (progressToken === undefined) return;
  try {
    await extra.sendNotification({
      method: 'notifications/progress',
      params: { progressToken, progress, message },
    });
  } catch {
    // Progress notifications are best effort; a failure must not break waiting for the audit.
  }
}

function describeProgress(audit: Audit): string {
  const p = stepProgress(audit);
  const base = `Audit ${audit.status.toLowerCase()} (${audit.repository.fullName})`;
  if (p.total === 0) return base;
  const running = p.running.length > 0 ? `, running: ${p.running.join(', ')}` : '';
  return `${base}: ${p.done}/${p.total} checks finished${running}`;
}

/** MCP takes suites in lowercase with hyphens (same as the engine CLI `--suites`). */
const SUITE_PARAMS = [
  'security',
  'quality',
  'sustainability',
  'ai-risks',
  'production',
  'privacy',
  'git-history',
] as const;
type SuiteParam = (typeof SUITE_PARAMS)[number];
const SUITE_PARAM: Record<SuiteParam, Suite> = {
  security: 'SECURITY',
  quality: 'QUALITY',
  sustainability: 'SUSTAINABILITY',
  'ai-risks': 'AI_RISKS',
  production: 'PRODUCTION',
  privacy: 'PRIVACY',
  'git-history': 'GIT_HISTORY',
};

const checksBySuite = (suite: Suite): string =>
  SUITE_ANALYZERS[suite].map((id) => `${id} (${ANALYZER_CATALOG[id].label})`).join(', ');

export function registerAuditTools(ctx: ToolContext): void {
  const { api, appUrl, orgs, server, guard, requireConfirmation, pollIntervalMs } = ctx;

  async function waitForTerminal(
    orgId: string,
    initial: Audit,
    timeoutMs: number,
    extra: Extra,
  ): Promise<{ audit: Audit; timedOut: boolean }> {
    const deadline = Date.now() + timeoutMs;
    let audit = initial;
    let seq = 0;
    let errors = 0;
    let delayMs = pollIntervalMs;
    await sendProgress(extra, ++seq, describeProgress(audit));
    while (!isTerminalAuditStatus(audit.status)) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) return { audit, timedOut: true };
      await sleep(Math.min(delayMs, remaining), extra.signal);
      delayMs = pollIntervalMs;
      try {
        audit = await api.getAudit(orgId, audit.id, extra.signal);
        errors = 0;
      } catch (err) {
        // Do not give up on transient network or 5xx errors; surface them after many in a row.
        if (extra.signal.aborted || !isTransient(err) || ++errors >= POLL_MAX_CONSECUTIVE_ERRORS) throw err;
        // A rate-limited poll waits as long as the server asks instead of burning the remaining attempts.
        if (err instanceof VetkitApiError && err.retryAfterSeconds)
          delayMs = Math.max(pollIntervalMs, err.retryAfterSeconds * 1000);
        continue;
      }
      await sendProgress(extra, ++seq, describeProgress(audit));
    }
    return { audit, timedOut: false };
  }

  /** Checks of the suites that are available on this server and on by default. */
  async function suiteSelection(
    orgId: string,
    suites: SuiteParam[],
    signal: AbortSignal,
  ): Promise<AuditAnalyzerId[]> {
    const wanted = new Set(suites.map((s) => SUITE_PARAM[s]));
    const catalog = await api.getAnalyzers(orgId, signal);
    const ids = catalog.analyzers
      .filter(
        (a) =>
          wanted.has(a.suite) &&
          a.available &&
          (a.defaultEnabled || a.suite === 'PRIVACY' || a.suite === 'GIT_HISTORY'),
      )
      .map((a) => a.id);
    if (!ids.some((id) => id !== 'ai-signal')) {
      const names = [...wanted].map((s) => SUITE_INFO[s].label).join(' and ');
      const reasons = [
        ...new Set(
          catalog.analyzers
            .filter((a) => wanted.has(a.suite) && !a.available && a.unavailableReason)
            .map((a) => sanitizeLine(a.unavailableReason!)),
        ),
      ].slice(0, 3);
      throw new ToolInputError(
        `No ${names} checks are available on this vetkit server${reasons.length ? ` (${reasons.join('; ')})` : ''}. Use vetkit_list_checks to see which checks can run.`,
      );
    }
    return ids;
  }

  server.registerTool(
    'vetkit_run_audit',
    {
      title: 'Run a vetkit audit',
      description:
        'Run a vetkit code audit on a GitHub, Bitbucket Cloud or GitLab.com repository and return applicable grades, score and finding counts. Privacy & Data Protection is an opt-in beta unscored review, not a GDPR/KVKK compliance certificate. Git history is an opt-in unscored sample of commits, contributors, daily activity, churn and performance intent; not a productivity score or measured speedup. ' +
        `Security checks: ${checksBySuite('SECURITY')}. Code quality checks: ${checksBySuite('QUALITY')}. Sustainability checks: ${checksBySuite('SUSTAINABILITY')}. AI code risks checks: ${checksBySuite('AI_RISKS')}. Production readiness checks: ${checksBySuite('PRODUCTION')}. ` +
        `Two modes: mode "QUICK" is a free Quick Scan (${QUICK_SCAN.scansPerMonth} per month per workspace owner) that always runs ${QUICK_SCAN.analyzers.join(', ')} on the latest commit of the default branch without media files; mode "FULL" is a full scan that costs ${FULL_SCAN_COST_CREDITS} credit (charged to the workspace owner for API keys, reserved while it runs and only spent when the complete report is saved) and may choose any branch, commit and checks. ` +
        'When mode is omitted, a Quick Scan runs unless ref, suites or analyzers are given, which need a full scan. ' +
        "In a full scan the repository's default checks run unless suites or analyzers choose others. " +
        'The repository can be given as a vetkit repository id, "owner/name" for GitHub or a GitHub/Bitbucket Cloud/GitLab.com URL; it is connected automatically if needed. Connect private Bitbucket or GitLab repositories first with vetkit_connect_repo and accessToken; this tool does not accept a token. ' +
        'By default waits for the audit to finish (usually 1-3 minutes) and reports progress; set wait=false to return immediately and poll with vetkit_get_audit.',
      inputSchema: {
        repo: RepoIdOrRef,
        mode: AuditModeSchema.optional().describe(
          `QUICK: free monthly Quick Scan (fixed checks, latest commit of the default branch). FULL: full scan, costs ${FULL_SCAN_COST_CREDITS} credit. Defaults to QUICK, or FULL when ref, suites or analyzers are given.`,
        ),
        ref: CreateAuditInputSchema.shape.ref.describe(
          "Branch, tag or commit SHA to audit (full scan). Defaults to the ref in the URL, or the repository's default branch.",
        ),
        excludeAssets: CreateAuditInputSchema.shape.excludeAssets.describe(
          'Skip downloading media files (images, video, audio, 3D models, fonts, design files, PDFs); they are not scanned anyway. ' +
            'Use for asset-heavy repositories that fail with REPO_TOO_LARGE. Defaults to the repository setting.',
        ),
        suites: z
          .array(z.enum(SUITE_PARAMS))
          .min(1)
          .optional()
          .describe(
            'Run available checks enabled by default in the selected suites. Explicit privacy or git-history selection includes their available opt-in checks. Use analyzers for exact checks; analyzers overrides suites. Defaults to the repository setting.',
          ),
        analyzers: z
          .array(AuditAnalyzerIdSchema)
          .min(1)
          .optional()
          .describe(
            `Exact checks to run (at least one besides ai-signal): ${AUDIT_ANALYZER_IDS.join(', ')}. See vetkit_list_checks. Defaults to the repository setting.`,
          ),
        wait: z.boolean().optional().describe('Wait for the audit to finish (default true)'),
        timeoutSeconds: z
          .number()
          .int()
          .min(10)
          .max(1800)
          .optional()
          .describe(
            'Maximum seconds to wait when wait=true (default 600). The audit keeps running after a timeout.',
          ),
      },
      outputSchema: RunAuditOutputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    guard(
      [
        'repos:read',
        'audits:read',
        'audits:run (or audits:write)',
        'repos:write (only when connecting a new repository)',
      ],
      async (
        {
          repo,
          mode: requestedMode,
          ref,
          excludeAssets,
          suites,
          analyzers,
          wait = true,
          timeoutSeconds = 600,
        }: {
          repo: string;
          mode?: AuditMode | undefined;
          ref?: string | undefined;
          excludeAssets?: boolean | undefined;
          suites?: SuiteParam[] | undefined;
          analyzers?: AuditAnalyzerId[] | undefined;
          wait?: boolean;
          timeoutSeconds?: number;
        },
        extra,
      ) => {
        const orgId = await orgs.get();

        let repositoryId: string | null;
        let urlRef: string | undefined;
        let parsedRepo: { provider: RepoProvider; fullName: string } | null = null;
        if (z.uuid().safeParse(repo).success) {
          repositoryId = repo;
        } else {
          const parsed = parseRepoUrl(repo);
          if (!parsed) {
            throw new ToolInputError(
              `"${repo}" is not a repository id, "owner/name", GitHub, Bitbucket Cloud or GitLab.com URL. Use vetkit_list_repos to see connected repositories.`,
            );
          }
          urlRef = parsed.ref;
          parsedRepo = parsed;
          repositoryId =
            (await findRepoByFullName(api, orgId, parsed.fullName, parsed.provider, extra.signal))?.id ??
            null;
        }

        const effectiveRef = ref ?? urlRef;
        if (effectiveRef !== undefined && !CreateAuditInputSchema.shape.ref.safeParse(effectiveRef).success) {
          throw new ToolInputError(`"${effectiveRef}" is not a valid git ref.`);
        }
        const mode: AuditMode =
          requestedMode ?? (effectiveRef !== undefined || suites || analyzers ? 'FULL' : 'QUICK');
        if (mode === 'QUICK' && suites) {
          throw new ToolInputError(
            `A Quick Scan always runs ${QUICK_SCAN.analyzers.join(', ')}; suites need mode "FULL" (${FULL_SCAN_COST_CREDITS} credit).`,
          );
        }
        const selection =
          analyzers ?? (suites ? await suiteSelection(orgId, suites, extra.signal) : undefined);

        await requireConfirmation(extra, [
          `Start a vetkit audit of ${
            parsedRepo
              ? `${parsedRepo.provider} repository "${sanitizeLine(parsedRepo.fullName)}"`
              : `the connected repository with id ${sanitizeLine(repo)}`
          } at ${effectiveRef !== undefined ? `ref "${sanitizeLine(effectiveRef)}"` : 'the default ref'}.`,
          mode === 'QUICK'
            ? "Mode: Quick Scan (free, uses one of the workspace owner's monthly Quick Scans)."
            : `Mode: full scan (costs ${FULL_SCAN_COST_CREDITS} credit, charged to the workspace owner for API keys; released if the scan does not complete).`,
          `Checks: ${selection ? selection.join(', ') : mode === 'QUICK' ? QUICK_SCAN.analyzers.join(', ') : "the repository's default checks"}.`,
          repositoryId === null
            ? 'The repository is not connected yet and will be connected to your vetkit organization first.'
            : 'The repository is already connected.',
          'vetkit will fetch and analyze the repository code and store the audit results.',
        ]);

        if (repositoryId === null && parsedRepo) {
          try {
            repositoryId = (
              await api.connectRepo(orgId, {
                url: repositoryHtmlUrl(parsedRepo.provider, parsedRepo.fullName),
                ...(parsedRepo.provider !== 'GITHUB' ? { access: 'manual' as const } : {}),
              })
            ).id;
          } catch (err) {
            const info = installRequired(err);
            if (!info) throw err;
            if (!info.repositoryId) {
              return {
                content: [{ type: 'text', text: installText(appUrl, parsedRepo.fullName, info) }],
                structuredContent: {
                  outcome: 'installation_required',
                  audit: null,
                  installUrl: info.installUrl,
                },
              };
            }
            // Already connected (without the App, or under its new name after a rename): audit that repository.
            repositoryId = info.repositoryId;
          }
        }
        if (repositoryId === null) throw new ToolInputError('Repository could not be resolved.');

        const created = await api.createAudit(orgId, {
          repositoryId,
          mode,
          ...(effectiveRef !== undefined ? { ref: effectiveRef } : {}),
          ...(excludeAssets !== undefined ? { excludeAssets } : {}),
          ...(selection ? { analyzers: selection } : {}),
        });
        const url = auditUrl(appUrl, created.id);

        if (!wait) {
          return {
            content: [
              {
                type: 'text',
                text: untrusted(
                  `Audit started for ${created.repository.fullName} (status ${created.status}).\nAudit id: ${created.id}\nView: ${url}\nCheck progress with vetkit_get_audit.`,
                ),
              },
            ],
            structuredContent: {
              outcome: 'started',
              audit: toAuditOutput(created, appUrl),
              installUrl: null,
            },
          };
        }

        let audit: Audit;
        let timedOut: boolean;
        try {
          ({ audit, timedOut } = await waitForTerminal(orgId, created, timeoutSeconds * 1000, extra));
        } catch (error) {
          if (extra.signal.aborted) throw error;
          const failure = toToolError(error, { scopes: ['audits:read'], appUrl });
          return {
            ...failure,
            content: [
              ...failure.content,
              {
                type: 'text',
                text: untrusted(
                  `The audit was created, but its latest status could not be retrieved. It may still be running.\nAudit id: ${created.id}\nView: ${url}\nResume checking this audit with vetkit_get_audit (auditId ${created.id}). Do not start another audit to retry this status lookup.`,
                ),
              },
            ],
          };
        }
        const lines: string[] = [];
        if (timedOut) {
          lines.push(
            `The audit is still ${audit.status.toLowerCase()} after ${timeoutSeconds}s; it continues in the background. Check again with vetkit_get_audit (auditId ${audit.id}).`,
            '',
          );
        }
        lines.push(untrusted(formatAudit(audit, url)));
        if (audit.status === 'SUCCEEDED') {
          lines.push(
            '',
            !audit.summary
              ? 'Finding totals are unavailable. Use vetkit_list_findings or vetkit_get_report to inspect the audit.'
              : audit.summary.total > 0
                ? 'Next: vetkit_list_findings to inspect findings (e.g. severity ["CRITICAL","HIGH"]) or vetkit_get_report for the full report.'
                : 'No findings. vetkit_get_report returns the full report.',
          );
        }
        return {
          content: [{ type: 'text', text: lines.join('\n') }],
          structuredContent: {
            outcome: timedOut ? 'still_running' : 'completed',
            audit: toAuditOutput(audit, appUrl),
            installUrl: null,
          },
        };
      },
    ),
  );

  // ───────── vetkit_list_checks ─────────
  server.registerTool(
    'vetkit_list_checks',
    {
      title: 'List audit checks',
      description:
        'List the checks vetkit can run, grouped into Security, Code quality, Sustainability, AI code risks, Production readiness, Privacy & Data Protection and Git history suites, with the tool each uses, whether it is available on this server and which run by default. ' +
        'Use the ids with vetkit_run_audit `analyzers`.',
      inputSchema: {},
      outputSchema: ListChecksOutputSchema,
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    guard(['audits:read'], async (_args: Record<string, never>, extra) => {
      const orgId = await orgs.get();
      const catalog = await api.getAnalyzers(orgId, extra.signal);
      return {
        content: [{ type: 'text', text: untrusted(formatCatalog(catalog)) }],
        structuredContent: toChecksOutput(catalog),
      };
    }),
  );

  // ───────── vetkit_get_audit ─────────
  server.registerTool(
    'vetkit_get_audit',
    {
      title: 'Get a vetkit audit',
      description:
        'Get the status, applicable overall and per-suite grades, score, finding counts and per-check progress of a vetkit audit. Privacy is a beta unscored source review, not a GDPR/KVKK compliance certificate.',
      inputSchema: { auditId: AuditId },
      outputSchema: AuditOutputSchema,
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    guard(['audits:read'], async ({ auditId }: { auditId: string }, extra) => {
      const orgId = await orgs.get();
      const audit = await api.getAudit(orgId, auditId, extra.signal);
      return {
        content: [{ type: 'text', text: untrusted(formatAudit(audit, auditUrl(appUrl, audit.id))) }],
        structuredContent: toAuditOutput(audit, appUrl),
      };
    }),
  );

  // ───────── vetkit_get_standards_report ─────────
  server.registerTool(
    'vetkit_get_standards_report',
    {
      title: 'Get a security standards report',
      description:
        `Map an audit's open findings to a security standard: ${STANDARD_IDS.join(', ')}. ` +
        'Each category is "fail" (mapped findings), "pass" (no mapped findings from checks that can detect it) or "not_covered" (no enabled check detects it). ' +
        'This is coverage of findings mapped by CWE, not a compliance certification: never present "pass" as compliant.',
      inputSchema: {
        auditId: AuditId,
        standard: StandardIdSchema.describe('Security standard to map against'),
      },
      outputSchema: StandardsReportSchema,
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    guard(
      ['reports:read', 'findings:read'],
      async ({ auditId, standard }: { auditId: string; standard: StandardId }, extra) => {
        const orgId = await orgs.get();
        const report = await api.getAuditStandards(orgId, auditId, standard, extra.signal);
        const lines = [
          `${report.title}: ${report.totals.failed} categories with findings, ${report.totals.passed} without mapped findings, ${report.totals.notCovered} not covered by enabled checks.`,
          `Mapped findings: ${report.totals.mappedFindings}; not mapped to this standard: ${report.totals.unmappedCount}.`,
          ...(report.partial
            ? ['Partial audit: some checks did not finish, so categories may be under-reported.']
            : []),
          ...(report.limited ? ['Finding limit reached: not every open finding was classified.'] : []),
          '',
          ...report.categories.map(
            (c) =>
              `- ${c.id} ${c.name}: ${c.status}${c.total ? ` (${c.total}: ${c.counts.CRITICAL} critical, ${c.counts.HIGH} high)` : ''}`,
          ),
          '',
          'Mapping aid only, not a certification. Use vetkit_list_findings to inspect the findings.',
        ];
        return {
          content: [{ type: 'text', text: untrusted(lines.join('\n')) }],
          structuredContent: report,
        };
      },
    ),
  );
}
