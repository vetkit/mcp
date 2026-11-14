#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { mcpSetupCode } from '#vendor/shared-mcp-setup';

import { createMcpApi } from './api.js';
import { ConfigError, loadConfig } from './config.js';
import { runPreToolUseHook } from './hook.js';
import { createVetkitMcpServer } from './server.js';
import { OrgResolver } from './tools/context.js';
import { VERSION } from './version.js';

// stdout is reserved for the MCP protocol: all logs go to stderr.
const log = (msg: string): void => {
  process.stderr.write(`[vetkit-mcp] ${msg}\n`);
};

const HELP = `vetkit-mcp ${VERSION} — MCP server for vetkit (https://vetkit.dev)

Usage:
  vetkit-mcp              Start the MCP server on stdio
  vetkit-mcp --help       Show this help
  vetkit-mcp --version    Print the version
  vetkit-mcp hook pre-tool-use
                          Claude Code PreToolUse hook: reads the hook JSON on stdin and blocks
                          (exit 2) npm/pnpm/yarn/bun/pip/uv/poetry/cargo/go installs of packages vetkit rejects
                          (needs a key with the agent:check scope; fails open when vetkit is unreachable)

Environment:
  VETKIT_API_KEY   (required) API key, vk_live_... — create one at https://app.vetkit.dev/settings/api-keys
  VETKIT_API_URL   API base URL (default https://api.vetkit.dev)
  VETKIT_APP_URL   Web app base URL used in links (default https://app.vetkit.dev)
  VETKIT_ORG_ID    Organization id (default: the API key's organization)

Any MCP client with local stdio support:
  Command: npx
  Arguments: -y @vetkit/mcp
  Environment: VETKIT_API_KEY=vk_live_...
  The configuration wrapper depends on the client. No remote HTTP/SSE endpoint is provided.

Claude Code (optional client-specific shortcut):
  ${mcpSetupCode('claudeCode', 'vk_live_...')}

Setup guides for Cursor, VS Code, Codex, Claude and other clients:
  https://vetkit.dev/en/docs/mcp/
`;

/** Hook input is a small JSON document; anything larger is cut off (and then fails open as malformed). */
const MAX_HOOK_STDIN_BYTES = 1024 * 1024;

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of process.stdin as AsyncIterable<Buffer>) {
    total += chunk.length;
    if (total > MAX_HOOK_STDIN_BYTES) break;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function hookPreToolUse(): Promise<number> {
  const stdin = await readStdin();
  let config;
  let configProblem: string | undefined;
  try {
    config = loadConfig(process.env, 'hook');
  } catch (err) {
    if (!(err instanceof ConfigError)) throw err;
    configProblem = err.message;
  }
  const client = config
    ? createMcpApi({
        baseUrl: config.apiUrl,
        apiKey: config.apiKey,
        userAgent: `vetkit-mcp-hook/${VERSION} node/${process.versions.node}`,
        timeoutMs: 15_000,
      })
    : null;
  const orgs = client ? new OrgResolver(client, config?.orgId) : null;
  return runPreToolUseHook({
    stdin,
    check: client && orgs ? async (request) => client.checkPackages(await orgs.get(), request) : null,
    ...(configProblem ? { configProblem } : {}),
    stderr: (line) => process.stderr.write(`${line}\n`),
  });
}

async function main(argv: string[]): Promise<void> {
  const args = argv.slice(2);
  if (args[0] === 'hook') {
    if (args[1] !== 'pre-tool-use' || args.length > 2) {
      log('Usage: vetkit-mcp hook pre-tool-use');
      process.exitCode = 1;
      return;
    }
    // Fail open: a hook crash must never block the agent's command.
    process.exitCode = await hookPreToolUse().catch((err: unknown) => {
      log(`Hook error, command allowed: ${err instanceof Error ? err.message : String(err)}`);
      return 0;
    });
    return;
  }
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(HELP);
    return;
  }
  if (args.includes('--version') || args.includes('-v')) {
    process.stdout.write(`${VERSION}\n`);
    return;
  }
  if (args.length > 0) {
    log(`Unknown argument(s): ${args.join(' ')}. Run with --help for usage.`);
    process.exitCode = 2;
    return;
  }

  let config;
  try {
    config = loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      log(`Configuration error: ${err.message}`);
      process.exitCode = 1;
      return;
    }
    throw err;
  }

  const client = createMcpApi({
    baseUrl: config.apiUrl,
    apiKey: config.apiKey,
    userAgent: `vetkit-mcp/${VERSION} node/${process.versions.node}`,
    timeoutMs: 30_000,
  });
  const server = createVetkitMcpServer(client, {
    appUrl: config.appUrl,
    apiUrl: config.apiUrl,
    ...(config.orgId ? { orgId: config.orgId } : {}),
  });
  const transport = new StdioServerTransport();

  let closing = false;
  const shutdown = (reason: string, code = 0): void => {
    if (closing) return;
    closing = true;
    log(`Shutting down (${reason}).`);
    // Exit anyway if shutdown hangs.
    const force = setTimeout(() => process.exit(code), 2_000);
    force.unref();
    server
      .close()
      .catch((err: unknown) =>
        log(`Error during shutdown: ${err instanceof Error ? err.message : String(err)}`),
      )
      .finally(() => process.exit(code));
  };

  process.once('SIGINT', () => shutdown('SIGINT'));
  process.once('SIGTERM', () => shutdown('SIGTERM'));
  process.stdin.once('end', () => shutdown('stdin closed'));
  process.stdin.once('close', () => shutdown('stdin closed'));
  server.server.onclose = () => shutdown('transport closed');
  process.on('unhandledRejection', (err) => {
    log(`Unhandled rejection: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`);
  });

  await server.connect(transport);
  log(`v${VERSION} ready on stdio (API ${config.apiUrl}${config.orgId ? `, org ${config.orgId}` : ''}).`);
}

main(process.argv).catch((err: unknown) => {
  log(`Fatal: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`);
  process.exit(1);
});
