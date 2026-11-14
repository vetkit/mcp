import { VetkitApiError, VetkitNetworkError } from '#vendor/api-client';
import { CREDIT_REQUEST_AMOUNTS, InstallationRequiredDetailsSchema, QUICK_SCAN } from '#vendor/shared';
import { z } from 'zod';

import { sanitizeLine, sanitizeText } from './format.js';

import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';

/** An error caused by user input, caught before any API call. */
export class ToolInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ToolInputError';
  }
}

export interface ErrorContext {
  /** Scopes the tool needs (for the INSUFFICIENT_SCOPE hint). */
  scopes: readonly string[];
  appUrl: string;
  apiUrl?: string;
}

export const errorResult = (text: string): CallToolResult => ({
  content: [{ type: 'text', text }],
  isError: true,
});

const MAX_ISSUES = 10;

/** `details` of a 402 `INSUFFICIENT_CREDITS` problem. */
const InsufficientCreditsSchema = z.object({
  required: z.number().int(),
  available: z.number().int(),
  reserved: z.number().int().optional(),
});

/** `details` of a `SCAN_QUOTA_EXCEEDED` / limit problem. */
const LimitDetailsSchema = z.object({ limit: z.number().int(), resetsAt: z.string().optional() });

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;
const QUICK_CHECKS = QUICK_SCAN.analyzers.join(', ');
const REQUEST_AMOUNTS = CREDIT_REQUEST_AMOUNTS.join(', ');

/** `details.issues` of a backend `VALIDATION_FAILED` problem (`ZodPipe`): one line per rejected field. */
const ValidationIssuesSchema = z.object({
  issues: z.array(z.object({ path: z.string(), message: z.string() })).min(1),
});

interface IssueLike {
  path: PropertyKey[];
  message: string;
}

/** A zod error from the api-client's own input validation, whichever zod copy produced it. */
const isZodError = (err: unknown): err is { issues: IssueLike[] } =>
  typeof err === 'object' &&
  err !== null &&
  (err as { name?: unknown }).name === 'ZodError' &&
  Array.isArray((err as { issues?: unknown }).issues);

const issueLines = (issues: readonly { path: string; message: string }[]): string[] => [
  ...issues
    .slice(0, MAX_ISSUES)
    .map((i) => `- ${sanitizeLine(i.path) || 'input'}: ${sanitizeLine(i.message)}`),
  ...(issues.length > MAX_ISSUES ? [`- (${issues.length - MAX_ISSUES} more)`] : []),
];

function hintFor(err: VetkitApiError, ctx: ErrorContext): string | null {
  const keysUrl = `${ctx.appUrl}/settings/api-keys`;
  switch (err.code) {
    case 'UNAUTHENTICATED':
    case 'API_KEY_INVALID':
      return `The API key was rejected. Check that VETKIT_API_KEY is the full key and still exists; create a new one at ${keysUrl}, then restart the MCP server.`;
    case 'API_KEY_REVOKED':
      return `This API key has been revoked. Create or rotate a key at ${keysUrl}, update VETKIT_API_KEY and restart the MCP server.`;
    case 'API_KEY_EXPIRED':
      return `This API key has expired (rotated keys stay valid for 24 hours). Create or rotate a key at ${keysUrl}, update VETKIT_API_KEY and restart the MCP server.`;
    case 'INSUFFICIENT_SCOPE':
      return `The API key is missing a required scope for this tool (needs: ${ctx.scopes.join(', ')}). Create a key with these scopes at ${keysUrl}. If the key already has them, its creator may have lost write access in this organization (for example, demoted to Viewer); a key created by an active member restores them.`;
    // Scope problems always arrive as INSUFFICIENT_SCOPE; a plain FORBIDDEN is a role, administrator-session or
    // organization-setting refusal that a new key would not fix.
    case 'FORBIDDEN':
      return `vetkit refused this action for your account's role or organization settings (see the reason above); a new API key with more scopes will not change that. Ask an organization owner or administrator, or check ${ctx.appUrl}.`;
    case 'INSUFFICIENT_CREDITS': {
      const d = InsufficientCreditsSchema.safeParse(err.problem.details);
      const need = d.success
        ? `This needs ${plural(d.data.required, 'credit')}; ${d.data.available} available${d.data.reserved ? ` (${d.data.reserved} reserved by scans still queued or running)` : ''}. `
        : 'Not enough credits are available. ';
      return `${need}A full scan costs 1 credit, charged to the workspace owner for API keys. Run a free Quick Scan instead (vetkit_run_audit with mode "QUICK": ${QUICK_CHECKS} on the latest commit of the default branch), or have the workspace owner request more credits (${REQUEST_AMOUNTS}) in the vetkit web app (${ctx.appUrl}).`;
    }
    case 'SCAN_QUOTA_EXCEEDED': {
      const d = LimitDetailsSchema.safeParse(err.problem.details);
      const reset =
        d.success && d.data.resetsAt ? ` They reset on ${sanitizeLine(d.data.resetsAt.slice(0, 10))}.` : '';
      return `The workspace owner's free monthly Quick Scans are used up.${reset} Run vetkit_run_audit with mode "FULL" to start a full scan for 1 credit.`;
    }
    case 'ORG_LIMIT_REACHED':
      return `An account can own a limited number of workspaces. Use an existing workspace or delete one you no longer need in the vetkit web app (${ctx.appUrl}).`;
    case 'REPO_LIMIT_REACHED': {
      const d = LimitDetailsSchema.safeParse(err.problem.details);
      return `This workspace already has the maximum number of connected repositories${d.success ? ` (${d.data.limit})` : ''}. Disconnect a repository you no longer need (${ctx.appUrl}/repos) or use another workspace.`;
    }
    case 'VALIDATION_FAILED': {
      const quick =
        typeof err.problem.details === 'object' &&
        err.problem.details !== null &&
        (err.problem.details as { mode?: unknown }).mode === 'QUICK';
      return quick
        ? `A Quick Scan always runs ${QUICK_CHECKS} on the latest commit of the default branch, without media files or AI review. To choose a branch, commit or other checks, run vetkit_run_audit with mode "FULL" (1 credit).`
        : null;
    }
    case 'SESSION_REQUIRED':
      return `This operation is only available in the vetkit web app (${ctx.appUrl}), not via API keys.`;
    case 'NOT_FOUND':
      return 'The resource was not found in this organization. Check the id (use vetkit_list_repos to find repositories) and that the API key belongs to the right organization.';
    case 'RATE_LIMITED':
      return err.retryAfterSeconds
        ? `Rate limit reached. Retry in ${err.retryAfterSeconds} seconds.`
        : 'Rate limit reached. Wait a minute before retrying.';
    case 'AUDIT_CONCURRENCY_LIMIT':
      return 'Too many audits are already queued or running (one Quick Scan per workspace owner, a few full scans per paying account at a time). Wait for one to finish (vetkit_get_audit) and try again.';
    case 'INSTALLATION_REQUIRED': {
      const d = InstallationRequiredDetailsSchema.safeParse(err.problem.details);
      return d.success
        ? `Install the vetkit GitHub App on "${sanitizeLine(d.data.owner)}" first: ${sanitizeLine(d.data.installUrl)}`
        : `Install the vetkit GitHub App for this repository's owner first (${ctx.appUrl}/repos).`;
    }
    case 'ANALYZER_UNAVAILABLE':
      return 'One or more requested checks cannot run on this vetkit server. Use vetkit_list_checks to see which checks are available, or pass suites instead of analyzers to run only available checks.';
    case 'REPO_NOT_ACCESSIBLE':
      return `vetkit cannot read this repository's code. Check repository access for the GitHub App, connected provider account or repository token. If using a token, replace it with vetkit_connect_repo using the repository URL and accessToken, or reconnect in the web app (${ctx.appUrl}/repos).`;
    case 'REPO_ACCESS_TOKEN_REQUIRED':
    case 'REPO_ACCESS_TOKEN_INVALID':
      return `Repository authorization is missing or invalid. Reconnect with vetkit_connect_repo using the repository URL and a valid accessToken that can read its code, or use the web app (${ctx.appUrl}/repos). For GitHub, installing the GitHub App with access to this repository is another option. Subsequent audits reuse saved authorization; vetkit_run_audit does not accept accessToken.`;
    case 'INVALID_REPO_URL':
      return 'Use a GitHub repository URL such as https://github.com/owner/name or "owner/name".';
    case 'SERVICE_UNAVAILABLE':
    case 'INTERNAL':
    case 'GITHUB_ERROR':
      return 'This is likely temporary. Retry shortly.';
    default:
      return null;
  }
}

/** Turns any error into an MCP `isError` result. Never leaks the API key. */
export function toToolError(err: unknown, ctx: ErrorContext): CallToolResult {
  if (err instanceof ToolInputError) return errorResult(err.message);
  if (err instanceof VetkitApiError) {
    const lines = [`vetkit API error ${err.status} ${err.code}: ${sanitizeLine(err.message)}`];
    // Field-level validation issues are the actionable part; without them the model only sees
    // "Request validation failed" and cannot tell which argument to change.
    const issues = ValidationIssuesSchema.safeParse(err.problem.details);
    if (issues.success) lines.push(...issueLines(issues.data.issues));
    const hint = hintFor(err, ctx);
    if (hint) lines.push(hint);
    if (err.problem.requestId) lines.push(`Request id: ${sanitizeLine(err.problem.requestId)}`);
    return errorResult(lines.join('\n'));
  }
  if (isZodError(err)) {
    // The api-client validates request bodies against the shared contract before sending them (limits
    // such as the total scan size or duplicate paths that the tool input schema cannot express).
    return errorResult(
      [
        'Invalid input: the request does not meet the vetkit API contract and was not sent. Fix the arguments and retry:',
        ...issueLines(err.issues.map((i) => ({ path: i.path.map(String).join('.'), message: i.message }))),
      ].join('\n'),
    );
  }
  if (err instanceof VetkitNetworkError && err.message.startsWith('Unexpected response shape')) {
    return errorResult(
      `The vetkit API returned a response this MCP server does not understand. It may be outdated: use \`npx -y @vetkit/mcp@latest\`.\nDetails: ${sanitizeText(err.message.slice(0, 600))}`,
    );
  }
  if (err instanceof VetkitNetworkError) {
    const where = ctx.apiUrl ? ` at ${ctx.apiUrl}` : '';
    const cause = err.cause instanceof Error ? ` (${err.cause.message})` : '';
    return errorResult(
      `Could not complete the request to the vetkit API${where}: ${err.message}${cause}. Check network connectivity and VETKIT_API_URL.`,
    );
  }
  const message = err instanceof Error ? err.message : String(err);
  return errorResult(`Unexpected error: ${message}`);
}
