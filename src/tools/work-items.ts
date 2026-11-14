import {
  VerificationStatusSchema,
  type WorkItem,
  WorkPrioritySchema,
  WorkStatusSchema,
} from '#vendor/shared';
import { z } from 'zod';

import { ToolInputError } from '../errors.js';
import { cell, sanitizeLine, table, untrusted } from '../format.js';

import { Cursor, Limit } from './context.js';
import { ConnectedRepoRef, resolveRepoId } from './repo-lookup.js';

import type { ToolContext } from './context.js';

const WorkItemOutputSchema = z.object({
  id: z.string(),
  repository: z.object({ id: z.string(), fullName: z.string() }),
  title: z.string(),
  ruleId: z.string(),
  severity: z.string(),
  filePath: z.string().nullable(),
  status: z
    .string()
    .describe(
      'OPEN | IN_PROGRESS | RESOLVED | ACCEPTED_RISK | FALSE_POSITIVE (effective status; an expired risk acceptance shows as OPEN)',
    ),
  priority: z.string().describe('URGENT | HIGH | NORMAL | LOW'),
  assignee: z.string().nullable(),
  codeowners: z.array(z.string()),
  dueAt: z.string().nullable(),
  fixUrl: z.string().nullable().describe('GitHub commit or pull request URL recorded as the fix'),
  issueLinks: z.array(z.string()),
  verificationStatus: z
    .string()
    .describe(
      'NOT_CHECKED | MANUAL_CLOSED (resolved without a scan) | NOT_OBSERVED (a newer comparable scan no longer finds it) | REAPPEARED | UNVERIFIABLE',
    ),
  verification: z
    .object({
      auditId: z.string(),
      commitSha: z.string(),
      checkedAt: z.string(),
      reason: z
        .string()
        .describe(
          'COMPARABLE_SCAN | FINGERPRINT_OBSERVED | RELATED_FINDING_OBSERVED | AMBIGUOUS_FINDING_MATCH | NO_BASELINE | AUDIT_INCOMPLETE | NOT_NEWER | DIFFERENT_REF | FIX_COMMIT_MISMATCH | SCOPE_CHANGED | VERSION_UNKNOWN_OR_CHANGED | ANALYZER_INCOMPLETE | COVERAGE_INCOMPLETE | NON_DETERMINISTIC',
        ),
      matchedFindingId: z.string().nullable(),
    })
    .nullable()
    .describe('Result of the last fix verification against a newer audit'),
  decision: z
    .object({
      kind: z.string(),
      reason: z.string(),
      expiresAt: z.string().nullable(),
      requestedBy: z.string(),
    })
    .nullable()
    .describe('Pending ACCEPTED_RISK / FALSE_POSITIVE request awaiting an administrator'),
  riskExpiresAt: z.string().nullable(),
  version: z.number().int().describe('Optimistic-concurrency version; pass to vetkit_update_work_item'),
  resolvedAt: z.string().nullable(),
  updatedAt: z.string(),
});

const ListWorkItemsOutputSchema = z.object({
  items: z.array(WorkItemOutputSchema),
  nextCursor: z.string().nullable(),
});

const UpdateWorkItemOutputSchema = z.object({
  item: WorkItemOutputSchema,
  changed: z
    .array(z.string())
    .describe('Fields that were sent: status, priority, fixUrl and/or verification'),
});

export function toWorkItemOutput(w: WorkItem): z.infer<typeof WorkItemOutputSchema> {
  return {
    id: w.id,
    repository: { id: w.repositoryId, fullName: w.repositoryName },
    title: w.title,
    ruleId: w.ruleId,
    severity: w.severity,
    filePath: w.filePath,
    status: w.status,
    priority: w.priority,
    assignee: w.assigneeLabel,
    codeowners: [...w.codeowners],
    dueAt: w.dueAt,
    fixUrl: w.fixUrl,
    issueLinks: [...w.issueLinks],
    verificationStatus: w.verificationStatus,
    verification: w.verification
      ? {
          auditId: w.verification.auditId,
          commitSha: w.verification.commitSha,
          checkedAt: w.verification.checkedAt,
          reason: w.verification.reason,
          matchedFindingId: w.verification.matchedFindingId,
        }
      : null,
    decision: w.decision
      ? {
          kind: w.decision.kind,
          reason: w.decision.reason,
          expiresAt: w.decision.expiresAt,
          requestedBy: w.decision.requestedByLabel,
        }
      : null,
    riskExpiresAt: w.riskExpiresAt,
    version: w.version,
    resolvedAt: w.resolvedAt,
    updatedAt: w.updatedAt,
  };
}

const verificationCell = (w: WorkItem): string =>
  w.verification ? `${w.verificationStatus} (${w.verification.reason})` : w.verificationStatus;

function workItemRows(items: WorkItem[]): string[][] {
  return items.map((w) => [
    cell(w.repositoryName, 36),
    w.severity,
    w.status,
    w.priority,
    cell(w.filePath, 50),
    cell(w.title, 70),
    cell(verificationCell(w), 40),
    w.id,
  ]);
}

const WORK_ITEM_HEADERS = [
  'Repository',
  'Severity',
  'Status',
  'Priority',
  'File',
  'Title',
  'Fix verification',
  'Work item id',
];

export function registerWorkItemTools(ctx: ToolContext): void {
  const { api, orgs, server, guard, requireConfirmation } = ctx;

  // ───────── vetkit_list_work_items ─────────
  server.registerTool(
    'vetkit_list_work_items',
    {
      title: 'List work items',
      description:
        'List the remediation work items of the organization (one per tracked finding fingerprint and repository), with status, priority, assignee, due date, recorded fix link and fix verification status (whether a newer comparable scan still finds it). ' +
        'Filter by status, priority, repository, verification status, text search, or the convenience flags overdue, actionable (open and not pending review) and pendingReview. ' +
        'Pass workItemId for exactly one item, or findingId for the item tracking a finding (empty when none exists; items are created in the vetkit web app).',
      inputSchema: {
        workItemId: z.uuid().optional().describe('Return only this work item'),
        findingId: z.uuid().optional().describe('Return the work item tracking this finding, if any'),
        status: WorkStatusSchema.optional(),
        priority: WorkPrioritySchema.optional(),
        repo: ConnectedRepoRef.optional(),
        verificationStatus: VerificationStatusSchema.optional(),
        overdue: z.boolean().optional().describe('Only items past their due date'),
        actionable: z
          .boolean()
          .optional()
          .describe('Only open or in-progress items without a pending decision'),
        pendingReview: z.boolean().optional().describe('Only items with a pending risk decision request'),
        search: z
          .string()
          .trim()
          .min(1)
          .max(200)
          .optional()
          .describe('Text search in title, rule and file path'),
        limit: Limit,
        cursor: Cursor,
      },
      outputSchema: ListWorkItemsOutputSchema,
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    guard(
      ['findings:read'],
      async (
        args: {
          workItemId?: string | undefined;
          findingId?: string | undefined;
          status?: z.infer<typeof WorkStatusSchema> | undefined;
          priority?: z.infer<typeof WorkPrioritySchema> | undefined;
          repo?: string | undefined;
          verificationStatus?: z.infer<typeof VerificationStatusSchema> | undefined;
          overdue?: boolean | undefined;
          actionable?: boolean | undefined;
          pendingReview?: boolean | undefined;
          search?: string | undefined;
          limit?: number | undefined;
          cursor?: string | undefined;
        },
        extra,
      ) => {
        const orgId = await orgs.get();
        if (args.workItemId && args.findingId) {
          throw new ToolInputError('Pass either workItemId or findingId, not both.');
        }
        let items: WorkItem[];
        let nextCursor: string | null = null;
        if (args.workItemId) {
          items = [await api.getWorkItem(orgId, args.workItemId, extra.signal)];
        } else if (args.findingId) {
          const item = await api.getFindingWorkItem(orgId, args.findingId, extra.signal);
          items = item ? [item] : [];
          if (!item) {
            return {
              content: [
                {
                  type: 'text',
                  text: `Finding ${args.findingId} has no work item. Work items are created from a finding in the vetkit web app; the finding itself is still listed by vetkit_list_findings.`,
                },
              ],
              structuredContent: { items: [], nextCursor: null },
            };
          }
        } else {
          const repositoryId = args.repo
            ? await resolveRepoId(api, orgId, args.repo, extra.signal)
            : undefined;
          const page = await api.listWorkItems(
            orgId,
            {
              ...(args.status ? { status: args.status } : {}),
              ...(args.priority ? { priority: args.priority } : {}),
              ...(repositoryId ? { repositoryId } : {}),
              ...(args.verificationStatus ? { verificationStatus: args.verificationStatus } : {}),
              ...(args.overdue !== undefined ? { overdue: args.overdue } : {}),
              ...(args.actionable !== undefined ? { actionable: args.actionable } : {}),
              ...(args.pendingReview !== undefined ? { pendingReview: args.pendingReview } : {}),
              ...(args.search ? { search: args.search } : {}),
              ...(args.limit ? { limit: args.limit } : {}),
              ...(args.cursor ? { cursor: args.cursor } : {}),
            },
            extra.signal,
          );
          items = page.items;
          nextCursor = page.nextCursor;
        }
        const text =
          items.length === 0
            ? args.cursor
              ? 'No more work items.'
              : 'No work items match. Work items are created from findings in the vetkit web app (Work screen).'
            : untrusted(
                [
                  `${items.length} work item${items.length === 1 ? '' : 's'}:`,
                  table(WORK_ITEM_HEADERS, workItemRows(items)),
                  nextCursor ? `More available: call again with cursor "${nextCursor}".` : '',
                  'Full details (assignee, due date, fix link, issue links, verification reason, pending decision, version) are in the structured content.',
                ]
                  .filter(Boolean)
                  .join('\n\n'),
              );
        return {
          content: [{ type: 'text', text }],
          structuredContent: { items: items.map(toWorkItemOutput), nextCursor },
        };
      },
    ),
  );

  // ───────── vetkit_update_work_item (write, behind findings:write) ─────────
  server.registerTool(
    'vetkit_update_work_item',
    {
      title: 'Update a work item',
      description:
        'Change the status (OPEN, IN_PROGRESS, RESOLVED), priority or recorded fix link of a work item, and/or verify its fix against a newer audit of the same branch (verifyAgainstAuditId: vetkit checks whether the finding is still observed and sets verificationStatus to NOT_OBSERVED, REAPPEARED or UNVERIFIABLE with a reason). ' +
        'Only mark RESOLVED after the fix is merged; a status or fix-link change resets the verification until a newer scan confirms it. ' +
        'ACCEPTED_RISK and FALSE_POSITIVE are decisions that an administrator approves in the vetkit web app and are not set here. ' +
        'Uses optimistic concurrency: pass the version from vetkit_list_work_items, or omit it to update the current version. Requires the findings:write scope and a user confirmation through MCP elicitation.',
      inputSchema: {
        workItemId: z.uuid().describe('Work item id, as returned by vetkit_list_work_items'),
        status: z.enum(['OPEN', 'IN_PROGRESS', 'RESOLVED']).optional(),
        priority: WorkPrioritySchema.optional(),
        fixUrl: z
          .url()
          .max(500)
          .nullable()
          .optional()
          .describe(
            'HTTPS URL of the GitHub commit (full SHA) or pull request in the same repository that fixes it; null clears it',
          ),
        verifyAgainstAuditId: z
          .uuid()
          .optional()
          .describe('A finished, newer audit of the same ref (vetkit_run_audit) to check the fix against'),
        version: z
          .number()
          .int()
          .positive()
          .optional()
          .describe('Expected current version (default: latest)'),
      },
      outputSchema: UpdateWorkItemOutputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    guard(
      ['findings:write'],
      async (
        args: {
          workItemId: string;
          status?: 'OPEN' | 'IN_PROGRESS' | 'RESOLVED' | undefined;
          priority?: z.infer<typeof WorkPrioritySchema> | undefined;
          fixUrl?: string | null | undefined;
          verifyAgainstAuditId?: string | undefined;
          version?: number | undefined;
        },
        extra,
      ) => {
        const edits = {
          ...(args.status ? { status: args.status } : {}),
          ...(args.priority ? { priority: args.priority } : {}),
          ...(args.fixUrl !== undefined ? { fixUrl: args.fixUrl } : {}),
        };
        const hasEdits = Object.keys(edits).length > 0;
        if (!hasEdits && !args.verifyAgainstAuditId) {
          throw new ToolInputError(
            'Nothing to change: pass at least one of status, priority, fixUrl or verifyAgainstAuditId.',
          );
        }
        const orgId = await orgs.get();
        let item = await api.getWorkItem(orgId, args.workItemId, extra.signal);
        const version = args.version ?? item.version;
        const changed = Object.keys(edits);
        if (args.verifyAgainstAuditId) changed.push('verification');
        await requireConfirmation(extra, [
          `Update vetkit work item ${args.workItemId} ("${sanitizeLine(item.title)}" in ${sanitizeLine(item.repositoryName)}, currently ${item.status}, version ${version}).`,
          ...Object.entries(edits).map(([k, v]) => `- ${k}: ${v === null ? 'clear' : String(v)}`),
          ...(args.verifyAgainstAuditId
            ? [
                `- verify the fix against audit ${args.verifyAgainstAuditId} (reads that audit's findings; no scan is started)`,
              ]
            : []),
        ]);
        if (hasEdits) {
          item = await api.updateWorkItem(orgId, args.workItemId, { version, ...edits }, extra.signal);
        }
        if (args.verifyAgainstAuditId) {
          item = await api.verifyWorkItemFix(
            orgId,
            args.workItemId,
            { version: hasEdits ? item.version : version, auditId: args.verifyAgainstAuditId },
            extra.signal,
          );
        }
        const lines = [
          `Work item updated: status ${item.status}, priority ${item.priority}${item.fixUrl ? `, fix ${sanitizeLine(item.fixUrl)}` : ''} (version ${item.version}).`,
          args.verifyAgainstAuditId
            ? `Fix verification: ${verificationCell(item)}.${
                item.verificationStatus === 'NOT_OBSERVED'
                  ? ' The newer comparable scan no longer reports this finding.'
                  : item.verificationStatus === 'REAPPEARED'
                    ? ' The finding is still (or again) observed; the fix is not complete.'
                    : item.verificationStatus === 'UNVERIFIABLE'
                      ? ' The audit is not comparable (see the reason); run a full audit of the same branch with the same checks and verify again.'
                      : ''
              }`
            : '',
        ].filter(Boolean);
        return {
          content: [{ type: 'text', text: lines.join('\n') }],
          structuredContent: { item: toWorkItemOutput(item), changed },
        };
      },
    ),
  );
}
