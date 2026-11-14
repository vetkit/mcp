import { type AgentCheckResult } from '#vendor/shared';

import { sanitizeLine } from './format.js';
import { parseInstallCommands } from './hook-parse.js';

/**
 * `vetkit-mcp hook pre-tool-use`: a Claude Code PreToolUse hook for the Bash tool. It reads the hook JSON
 * from stdin, finds package installs in the command (`hook-parse.ts`) and asks vetkit to check them.
 * Exit 2 (stderr shown to the agent) blocks the tool call; exit 0 lets it run. The hook fails open: a
 * missing key, an unreachable API or malformed input prints a warning and exits 0, so it never breaks
 * the agent's work.
 */

export const HOOK_EXIT_ALLOW = 0;
export const HOOK_EXIT_BLOCK = 2;

export interface PreToolUseHookOptions {
  stdin: string;
  /** Checks one ecosystem's packages; `null` when no API key is configured. */
  check: ((request: ReturnType<typeof parseInstallCommands>[number]) => Promise<AgentCheckResult>) | null;
  /** Explains why `check` is null (configuration error), shown once. */
  configProblem?: string;
  stderr: (line: string) => void;
}

const MAX_REASONS = 10;

/** Runs the hook and returns its process exit code. Never throws. */
export async function runPreToolUseHook(opts: PreToolUseHookOptions): Promise<number> {
  const warn = (msg: string) => opts.stderr(`vetkit: ${msg}`);
  let command: string | undefined;
  try {
    const event = JSON.parse(opts.stdin) as { tool_name?: unknown; tool_input?: { command?: unknown } };
    if (event.tool_name !== 'Bash') return HOOK_EXIT_ALLOW;
    command = typeof event.tool_input?.command === 'string' ? event.tool_input.command : undefined;
  } catch {
    warn('could not read the PreToolUse hook input; the command was not checked.');
    return HOOK_EXIT_ALLOW;
  }
  if (!command) return HOOK_EXIT_ALLOW;
  const requests = parseInstallCommands(command);
  if (requests.length === 0) return HOOK_EXIT_ALLOW;
  if (!opts.check) {
    warn(`package check skipped (${opts.configProblem ?? 'vetkit is not configured'}).`);
    return HOOK_EXIT_ALLOW;
  }

  const blocked: string[] = [];
  const warned: string[] = [];
  for (const request of requests) {
    let result: AgentCheckResult;
    try {
      result = await opts.check(request);
    } catch (err) {
      const why = err instanceof Error ? sanitizeLine(err.message).slice(0, 200) : 'unknown error';
      warn(`could not check ${request.ecosystem} packages (${why}); allowing the command.`);
      continue;
    }
    for (const item of result.items) {
      const label = `${request.ecosystem} ${item.name}${item.version ? `@${item.version}` : ''}`;
      const why = item.reasons.map((r) => `${r.code}: ${r.detail}`).join('; ');
      if (item.verdict === 'block') blocked.push(sanitizeLine(`${label}: ${why}`));
      else if (item.verdict === 'warn') warned.push(sanitizeLine(`${label}: ${why}`));
    }
    for (const w of result.warnings.slice(0, 3)) warn(sanitizeLine(w));
  }
  for (const w of warned.slice(0, MAX_REASONS)) warn(`warning: ${w}`);
  if (blocked.length === 0) return HOOK_EXIT_ALLOW;
  opts.stderr(
    [
      'vetkit blocked this install. Do not retry it with another package manager or spelling;',
      'pick a different, existing package or ask the user:',
      ...blocked.slice(0, MAX_REASONS).map((b) => `- ${b}`),
    ].join('\n'),
  );
  return HOOK_EXIT_BLOCK;
}
