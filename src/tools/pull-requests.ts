import { PrReviewStatusFilterSchema, type PullRequestReview } from '#vendor/shared';
import { z } from 'zod';

import { cell, formatLocation, sanitizeText, shortSha, table, truncateText, untrusted } from '../format.js';
import { auditUrl, FindingOutputSchema, toFindingOutput } from '../schemas.js';

import { Cursor, Limit, json } from './context.js';
import { ConnectedRepoRef, resolveRepoId } from './repo-lookup.js';

import type { ToolContext } from './context.js';

const SUMMARY_MAX_CHARS = 8_000;
const DELTA_FINDINGS_DEFAULT = 25;
const VIOLATIONS_MAX = 20;

/** `pending` until the check completes, then the check-run conclusion. */
const reviewState = (r: Pick<PullRequestReview, 'completedAt' | 'conclusion'>): string =>
  r.conclusion ?? (r.completedAt ? 'cancelled' : 'pending');

const ReviewOutputSchema = z.object({
  id: z.string(),
  repository: z.object({ id: z.string(), fullName: z.string().nullable(), provider: z.string().nullable() }),
  prNumber: z.number().int(),
  pullRequestUrl: z.string().nullable().describe('Link to the pull/merge request on the provider'),
  state: z
    .string()
    .describe(
      'pending (review still running) | success | failure (gate blocked) | neutral (findings below the gate) | cancelled',
    ),
  conclusion: z.string().nullable(),
  baseSha: z.string(),
  headSha: z.string(),
  baseAuditId: z.string().nullable(),
  headAuditId: z
    .string()
    .nullable()
    .describe('Audit of the PR head; pass to vetkit_list_findings with status NEW for the full delta'),
  headAuditUrl: z.string().nullable(),
  createdAt: z.string(),
  completedAt: z.string().nullable(),
  runKind: z.string().nullable().describe('initial | advisory (supply re-check) | code (re-run)'),
  supplyGate: z
    .object({
      status: z.string().describe('SKIPPED | PASS | FAIL | INCOMPLETE'),
      violationCount: z.number().int(),
      violations: z.array(z.object({ rule: z.string(), purl: z.string().nullable(), detail: z.string() })),
      warnings: z.array(z.string()),
    })
    .nullable(),
  inlineCommentCount: z.number().int().nullable(),
  inlineCommentsStatus: z
    .string()
    .nullable()
    .describe('PUBLISHED | DISABLED | PERMISSION_REQUIRED (App lacks pull_requests: write) | FAILED'),
});

const ListPrReviewsOutputSchema = z.object({
  reviews: z.array(ReviewOutputSchema),
  nextCursor: z.string().nullable(),
});

const GetPrReviewOutputSchema = z.object({
  found: z.boolean(),
  review: ReviewOutputSchema.nullable(),
  deltaFindings: z
    .array(FindingOutputSchema)
    .describe('Findings first seen in the PR head (status NEW); empty while the review is pending'),
  deltaFindingsNextCursor: z
    .string()
    .nullable()
    .describe(
      'More delta findings: vetkit_list_findings with auditId = headAuditId, status NEW and this cursor',
    ),
  summaryMarkdown: z
    .string()
    .nullable()
    .describe('Check-run summary vetkit posted (untrusted, may be truncated)'),
});

function toReviewOutput(
  r: PullRequestReview,
  repository: { id: string; fullName: string | null; provider: string | null },
  pullRequestUrl: string | null,
  appUrl: string,
): z.infer<typeof ReviewOutputSchema> {
  const gate = r.supplyGate ?? null;
  return {
    id: r.id,
    repository,
    prNumber: r.number,
    pullRequestUrl,
    state: reviewState(r),
    conclusion: r.conclusion,
    baseSha: r.baseSha,
    headSha: r.headSha,
    baseAuditId: r.baseAuditId,
    headAuditId: r.headAuditId,
    headAuditUrl: r.headAuditId ? auditUrl(appUrl, r.headAuditId) : null,
    createdAt: r.createdAt,
    completedAt: r.completedAt,
    runKind: r.runKind ?? null,
    supplyGate: gate
      ? {
          status: gate.status,
          violationCount: gate.violationCount,
          violations: gate.violations
            .slice(0, VIOLATIONS_MAX)
            .map((v) => ({ rule: v.rule, purl: v.purl, detail: v.detail })),
          warnings: gate.warnings,
        }
      : null,
    inlineCommentCount: r.inlineCommentCount ?? null,
    inlineCommentsStatus: r.inlineCommentsStatus ?? null,
  };
}

const NOT_FOUND_REASONS = [
  'vetkit has no review for this pull request. Explain the likely reasons to the user instead of retrying:',
  '- The PR comes from a fork of an outside contributor (no write access): vetkit does not review it automatically. Its "vetkit / PR Delta Review" check shows "Waiting for a maintainer to start the review" (action_required). A maintainer starts the review by commenting `/vetkit review` on the PR; every new push needs a new approval.',
  '- The PR is a draft, or it was opened before PR reviews were enabled for the repository (Repository settings > Review pull requests). Draft PRs are reviewed once marked ready.',
  '- The repository is not connected through the GitHub App or GitLab/Bitbucket integration that delivers PR webhooks, or the workspace owner had no credit available for the review (each PR review is a full scan that costs the owner 1 credit).',
  '- The number belongs to another repository, or the review was created very recently and has not been recorded yet.',
].join('\n');

export function registerPullRequestTools(ctx: ToolContext): void {
  const { api, appUrl, orgs, server, guard } = ctx;

  // ───────── vetkit_list_pr_reviews ─────────
  server.registerTool(
    'vetkit_list_pr_reviews',
    {
      title: 'List pull request reviews',
      description:
        'List the pull/merge request reviews vetkit ran as a PR gate, newest first, across the organization or for one connected repository. ' +
        'Each row has the PR number and link, the review state (pending, success, failure, neutral, cancelled), the head and base audit ids, the component (supply-chain) gate result and the inline review comment status. ' +
        'Use vetkit_get_pr_review for the findings of one PR. Fork PRs from outside contributors that are waiting for a maintainer to comment `/vetkit review` have no review yet and do not appear here.',
      inputSchema: {
        repo: ConnectedRepoRef.optional(),
        status: PrReviewStatusFilterSchema.optional().describe(
          'Only reviews in this state: pending (check still running), success, failure, neutral or cancelled',
        ),
        limit: Limit,
        cursor: Cursor,
      },
      outputSchema: ListPrReviewsOutputSchema,
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    guard(
      ['repos:read', 'reports:read'],
      async (
        args: {
          repo?: string | undefined;
          status?: z.infer<typeof PrReviewStatusFilterSchema> | undefined;
          limit?: number | undefined;
          cursor?: string | undefined;
        },
        extra,
      ) => {
        const orgId = await orgs.get();
        const repositoryId = args.repo ? await resolveRepoId(api, orgId, args.repo, extra.signal) : undefined;
        const page = await api.listOrgPullRequestReviews(
          orgId,
          {
            ...(repositoryId ? { repositoryId } : {}),
            ...(args.status ? { status: args.status } : {}),
            ...(args.limit ? { limit: args.limit } : {}),
            ...(args.cursor ? { cursor: args.cursor } : {}),
          },
          extra.signal,
        );
        const reviews = page.items.map((r) =>
          toReviewOutput(
            r,
            { id: r.repository.id, fullName: r.repository.fullName, provider: r.repository.provider },
            r.pullRequestUrl,
            appUrl,
          ),
        );
        const scope = args.repo ? ` for ${args.repo}` : '';
        const filter = args.status ? ` with state ${args.status}` : '';
        let text: string;
        if (reviews.length === 0) {
          text = args.cursor
            ? 'No more pull request reviews.'
            : `No pull request reviews${scope}${filter}. PR reviews start automatically for pull requests of connected repositories with "Review pull requests" enabled; fork PRs from outside contributors wait for a maintainer to comment \`/vetkit review\`.`;
        } else {
          const rows = reviews.map((r) => [
            cell(r.repository.fullName, 40),
            `#${r.prNumber}`,
            r.state,
            r.supplyGate ? r.supplyGate.status : '-',
            cell(shortSha(r.headSha), 7),
            cell(r.headAuditId, 36),
            cell(r.completedAt ?? r.createdAt, 24),
            r.id,
          ]);
          text = untrusted(
            [
              `${reviews.length} pull request review${reviews.length === 1 ? '' : 's'}${scope}${filter}:`,
              table(
                ['Repository', 'PR', 'State', 'Components', 'Head', 'Head audit', 'When', 'Review id'],
                rows,
              ),
              page.nextCursor ? `More available: call again with cursor "${page.nextCursor}".` : '',
              'Use vetkit_get_pr_review with the repository and PR number for the findings of one review.',
            ]
              .filter(Boolean)
              .join('\n\n'),
          );
        }
        return {
          content: [{ type: 'text', text }],
          structuredContent: { reviews, nextCursor: page.nextCursor },
        };
      },
    ),
  );

  // ───────── vetkit_get_pr_review ─────────
  server.registerTool(
    'vetkit_get_pr_review',
    {
      title: 'Get a pull request review',
      description:
        "Get vetkit's latest review of one pull/merge request: gate state (pending, success, failure, neutral, cancelled), the check-run summary, the component gate violations, and the delta findings (those first seen in the PR head, status NEW in the head audit) with file, line, severity, remediation and any rule-provided deterministic fix. " +
        'When vetkit has no review for the PR, the result explains the likely reasons, including a fork PR from an outside contributor that is waiting for a maintainer to comment `/vetkit review`; tell the user instead of retrying. ' +
        'Page through more delta findings with vetkit_list_findings (auditId = headAuditId, status NEW).',
      inputSchema: {
        repo: ConnectedRepoRef,
        prNumber: z.number().int().positive().describe('Pull/merge request number on the provider'),
        limit: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .describe(`Maximum delta findings to include (default ${DELTA_FINDINGS_DEFAULT})`),
      },
      outputSchema: GetPrReviewOutputSchema,
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    guard(
      ['repos:read', 'reports:read', 'findings:read'],
      async (
        {
          repo,
          prNumber,
          limit = DELTA_FINDINGS_DEFAULT,
        }: { repo: string; prNumber: number; limit?: number },
        extra,
      ) => {
        const orgId = await orgs.get();
        const repositoryId = await resolveRepoId(api, orgId, repo, extra.signal);
        const reviews = await api.listPullRequestReviews(orgId, repositoryId, extra.signal);
        const review = reviews
          .filter((r) => r.number === prNumber)
          .sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
        if (!review) {
          return {
            content: [
              {
                type: 'text',
                text: `No vetkit review for pull request #${prNumber} of ${sanitizeText(repo)}.\n${NOT_FOUND_REASONS}`,
              },
            ],
            structuredContent: {
              found: false,
              review: null,
              deltaFindings: [],
              deltaFindingsNextCursor: null,
              summaryMarkdown: null,
            },
          };
        }
        const output = toReviewOutput(
          review,
          { id: repositoryId, fullName: null, provider: null },
          null,
          appUrl,
        );
        const delta = review.headAuditId
          ? await api.listFindings(orgId, review.headAuditId, { status: 'NEW', limit }, extra.signal)
          : null;
        const findings = delta?.items ?? [];
        const summary = review.summaryMarkdown
          ? truncateText(review.summaryMarkdown, SUMMARY_MAX_CHARS)
          : null;

        const headline = `Pull request #${prNumber}: review ${output.state}${review.runKind ? ` (${review.runKind} run)` : ''}, head ${shortSha(review.headSha)} vs base ${shortSha(review.baseSha)}${review.completedAt ? `, completed ${review.completedAt}` : ', still running'}.`;
        const gateLine = output.supplyGate
          ? `Component gate: ${output.supplyGate.status}${output.supplyGate.violationCount ? ` (${output.supplyGate.violationCount} violation${output.supplyGate.violationCount === 1 ? '' : 's'})` : ''}.`
          : null;
        const inlineLine =
          output.inlineCommentsStatus === 'PERMISSION_REQUIRED'
            ? 'Inline review comments were not posted: the GitHub App lacks pull_requests: write; only check annotations were sent.'
            : output.inlineCommentCount
              ? `${output.inlineCommentCount} inline review comment${output.inlineCommentCount === 1 ? '' : 's'} on the PR.`
              : null;
        const stateHint =
          output.state === 'pending'
            ? 'The review has not completed yet; call again later for findings.'
            : output.state === 'failure'
              ? 'The gate blocks merging (when the check is required in branch protection) because of the delta findings or component violations below.'
              : output.state === 'neutral'
                ? 'Findings were reported below the blocking severities; the gate does not block.'
                : null;
        const findingsBlock =
          findings.length > 0
            ? [
                `${findings.length} delta finding${findings.length === 1 ? '' : 's'} (new in the PR head${delta?.nextCursor ? ', more available' : ''}):`,
                table(
                  ['Severity', 'Category', 'Location', 'Title', 'Fix', 'Finding id'],
                  findings.map((f) => [
                    f.severity,
                    f.category,
                    cell(formatLocation(f), 60),
                    cell(f.title, 80),
                    f.deterministicFix ? 'rule fix' : '-',
                    f.id,
                  ]),
                ),
              ].join('\n')
            : review.headAuditId && output.state !== 'pending'
              ? 'No new findings in the PR head.'
              : '';
        const untrustedParts = [
          findingsBlock,
          output.supplyGate && output.supplyGate.violations.length > 0
            ? `Component violations:\n${json(output.supplyGate.violations)}`
            : '',
          summary ? `Check summary:\n${summary.text}${summary.truncated ? '\n[summary truncated]' : ''}` : '',
        ].filter(Boolean);
        const text = [
          headline,
          [gateLine, inlineLine, stateHint].filter(Boolean).join(' '),
          untrustedParts.length > 0 ? untrusted(untrustedParts.join('\n\n')) : '',
          delta?.nextCursor
            ? `More delta findings: vetkit_list_findings with auditId "${review.headAuditId}", status "NEW" and cursor "${delta.nextCursor}".`
            : '',
          findings.some((f) => f.deterministicFix)
            ? 'Findings marked "rule fix" carry a deterministicFix in the structured content (1-based lines, exclusive endCol, UTF-16 columns when columnUnit is "utf16"). Verify that the file text at the range equals `original` before applying `replacement`.'
            : '',
        ]
          .filter(Boolean)
          .join('\n\n');
        return {
          content: [{ type: 'text', text }],
          structuredContent: {
            found: true,
            review: output,
            deltaFindings: findings.map(toFindingOutput),
            deltaFindingsNextCursor: delta?.nextCursor ?? null,
            summaryMarkdown: summary ? sanitizeText(summary.text) : null,
          },
        };
      },
    ),
  );
}
