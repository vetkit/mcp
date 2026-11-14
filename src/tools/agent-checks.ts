import {
  AGENT_CHECK_MAX_CHANGE_BYTES,
  AGENT_CHECK_MAX_FILES,
  AGENT_CHECK_MAX_PACKAGES,
  AgentChangeFileSchema,
  AgentCheckEcosystemSchema,
  AgentCheckPackageSchema,
  AgentCheckResultSchema,
  ScanChangesResultSchema,
  type AgentCheckEcosystem,
  type AgentCheckPackage,
  type AgentChangeFile,
} from '#vendor/shared';
import { z } from 'zod';

import { sanitizeLine, untrusted } from '../format.js';

import type { ToolContext } from './context.js';

const VERDICT_HELP =
  'verdict "block": do not proceed; choose another package or fix the change and tell the user why. "warn": proceed only if the user accepts the listed risk. "allow": nothing found. Warnings list sources that could not be reached (those checks were skipped, not passed).';

export function registerAgentCheckTools(ctx: ToolContext): void {
  const { api, orgs, server, guard } = ctx;

  // ───────── vetkit_check_packages ─────────
  server.registerTool(
    'vetkit_check_packages',
    {
      title: 'Check packages before installing them',
      description: `Call this BEFORE running npm/pnpm/yarn/bun install|add, pip install, uv add, cargo add or go get, and before adding a dependency to a manifest. Checks each package against its public registry (does it exist? catches hallucinated and slopsquatted names), its release age and adoption, OSV advisories including known malicious packages, CISA KEV, and the organization's license and release-age policy. ${VERDICT_HELP} Up to ${AGENT_CHECK_MAX_PACKAGES} packages of one ecosystem per call. Needs the agent:check scope.`,
      inputSchema: {
        ecosystem: AgentCheckEcosystemSchema.describe(
          'Package ecosystem (pypi for pip/uv, cargo for crates.io)',
        ),
        packages: z
          .array(AgentCheckPackageSchema)
          .min(1)
          .max(AGENT_CHECK_MAX_PACKAGES)
          .describe(
            'Packages to check: name (Maven "group:artifact", Go module path) and optional exact version',
          ),
      },
      outputSchema: AgentCheckResultSchema,
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    },
    guard(
      ['agent:check'],
      async ({ ecosystem, packages }: { ecosystem: AgentCheckEcosystem; packages: AgentCheckPackage[] }) => {
        const orgId = await orgs.get();
        const result = await api.checkPackages(orgId, { ecosystem, packages });
        const lines = [
          `Verdict: ${result.verdict.toUpperCase()} (${result.items.length} ${ecosystem} package${result.items.length === 1 ? '' : 's'})`,
          ...result.items.map((i) => {
            const head = `- ${i.verdict.toUpperCase()} ${sanitizeLine(i.name)}${i.version ? `@${sanitizeLine(i.version)}` : ''}`;
            return i.reasons.length === 0
              ? head
              : `${head}: ${i.reasons.map((r) => `${r.code} ${sanitizeLine(r.detail)}`).join('; ')}`;
          }),
          ...result.warnings.map((w) => `Warning: ${sanitizeLine(w)}`),
        ];
        return {
          content: [{ type: 'text', text: untrusted(lines.join('\n')) }],
          structuredContent: result,
        };
      },
    ),
  );

  // ───────── vetkit_scan_changes ─────────
  server.registerTool(
    'vetkit_scan_changes',
    {
      title: 'Scan changed files before committing them',
      description: `Call this BEFORE committing or pushing code you wrote or changed. Send the full contents of the changed files (include package.json, requirements.txt or other manifests you edited). Finds exactly-shaped secrets (API keys, tokens, private keys), risky agent configuration and hidden instructions, unfinished or placeholder code, and imports or dependencies of packages that do not exist. Files are scanned in memory and never stored; nothing is executed. ${VERDICT_HELP} Up to ${AGENT_CHECK_MAX_FILES} files and ${AGENT_CHECK_MAX_CHANGE_BYTES / 1024} KB in total per call. Needs the agent:check scope.`,
      inputSchema: {
        files: z
          .array(AgentChangeFileSchema)
          .min(1)
          .max(AGENT_CHECK_MAX_FILES)
          .describe('Changed files: repository-relative path (src/app.ts) and full UTF-8 content'),
      },
      outputSchema: ScanChangesResultSchema,
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    },
    guard(['agent:check'], async ({ files }: { files: AgentChangeFile[] }) => {
      const orgId = await orgs.get();
      const result = await api.scanChanges(orgId, { files });
      const lines = [
        `Verdict: ${result.verdict.toUpperCase()} (${result.filesScanned} file${result.filesScanned === 1 ? '' : 's'} scanned, ${result.findings.length} finding${result.findings.length === 1 ? '' : 's'})`,
        ...result.findings.map(
          (f) =>
            `- ${f.verdict.toUpperCase()} ${f.code} ${sanitizeLine(f.path)}${f.line ? `:${f.line}` : ''} [${f.severity}] ${sanitizeLine(f.title)} (${sanitizeLine(f.ruleId)})`,
        ),
        ...result.warnings.map((w) => `Warning: ${sanitizeLine(w)}`),
      ];
      return {
        content: [{ type: 'text', text: untrusted(lines.join('\n')) }],
        structuredContent: result,
      };
    }),
  );
}
