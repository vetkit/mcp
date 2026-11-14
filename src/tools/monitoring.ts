import { RepoMonitoringScheduleSchema, RepoMonitoringSchema } from '#vendor/shared';
import { z } from 'zod';

import { sanitizeLine } from '../format.js';

import { ConnectedRepoRef as RepoRef, resolveRepoId } from './repo-lookup.js';

import type { ToolContext } from './context.js';
import type { RepoMonitoring } from '#vendor/shared';

const MonitoringOutputSchema = RepoMonitoringSchema.extend({ repositoryId: z.uuid() });

function describe(status: RepoMonitoring): string {
  const schedule =
    status.schedule === 'DEFAULT'
      ? `${status.effectiveSchedule.toLowerCase()} (organization default)`
      : status.effectiveSchedule.toLowerCase();
  const parts = [
    `Monitoring: ${schedule}.`,
    status.lastRunAt
      ? `Last run ${status.lastRunAt}: ${
          status.lastResult === 'NO_CHANGE'
            ? 'no change since the last scan'
            : status.lastResult === 'SKIPPED'
              ? 'skipped'
              : 'scan started'
        }.`
      : 'No scheduled run yet.',
    status.nextRunAt ? `Next run: ${status.nextRunAt}.` : '',
    status.newAdvisories
      ? `${status.newAdvisories} new advisor${status.newAdvisories === 1 ? 'y' : 'ies'} since the last scan.`
      : '',
  ];
  return parts.filter(Boolean).join(' ');
}

/** Continuous monitoring: read and set the per-repository schedule (thin wrapper over the monitoring endpoints). */
export function registerMonitoringTools(ctx: ToolContext): void {
  const { api, orgs, server, guard, requireConfirmation } = ctx;

  server.registerTool(
    'vetkit_get_repo_monitoring',
    {
      title: 'Get repository monitoring status',
      description:
        'Show whether a connected repository is scanned automatically (off, daily or weekly; "DEFAULT" follows the organization default), the last and next scheduled run, and new advisories that affect the last scan inventory.',
      inputSchema: { repo: RepoRef },
      outputSchema: MonitoringOutputSchema,
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    guard(['repos:read'], async ({ repo }: { repo: string }, extra) => {
      const orgId = await orgs.get();
      const repositoryId = await resolveRepoId(api, orgId, repo, extra.signal);
      const status = await api.getRepoMonitoring(orgId, repositoryId, extra.signal);
      return {
        content: [{ type: 'text', text: describe(status) }],
        structuredContent: { ...status, repositoryId },
      };
    }),
  );

  server.registerTool(
    'vetkit_set_repo_monitoring',
    {
      title: 'Set repository monitoring schedule',
      description:
        'Turn continuous monitoring of a connected repository off, or run it daily or weekly on the default branch. "DEFAULT" follows the organization default (weekly unless changed). Unchanged commits are skipped without spending a scan.',
      inputSchema: {
        repo: RepoRef,
        schedule: RepoMonitoringScheduleSchema.describe('DEFAULT, OFF, DAILY or WEEKLY'),
      },
      outputSchema: MonitoringOutputSchema,
      annotations: {
        readOnlyHint: false,
        idempotentHint: true,
        destructiveHint: false,
        openWorldHint: false,
      },
    },
    guard(
      ['repos:write'],
      async (
        { repo, schedule }: { repo: string; schedule: 'DEFAULT' | 'OFF' | 'DAILY' | 'WEEKLY' },
        extra,
      ) => {
        const orgId = await orgs.get();
        const repositoryId = await resolveRepoId(api, orgId, repo, extra.signal);
        await requireConfirmation(extra, [
          `Set the monitoring schedule of repository ${sanitizeLine(repositoryId)} to ${schedule}.`,
        ]);
        const status = await api.updateRepoMonitoring(orgId, repositoryId, { schedule });
        return {
          content: [{ type: 'text', text: `Saved. ${describe(status)}` }],
          structuredContent: { ...status, repositoryId },
        };
      },
    ),
  );
}
