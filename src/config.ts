import { API_KEY_PATTERN } from '#vendor/shared';
import { z } from 'zod';

export const DEFAULT_API_URL = 'https://api.vetkit.dev';
export const DEFAULT_APP_URL = 'https://app.vetkit.dev';

export interface VetkitMcpConfig {
  apiKey: string;
  /** API base URL, without a trailing `/` or `/v1`. */
  apiUrl: string;
  /** Web app base URL (for audit links). */
  appUrl: string;
  /** Verilmezse `GET /v1/me` ile key'in org'u bulunur. */
  orgId?: string;
}

/** A missing or invalid environment variable. The message is written to be shown to the user. */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

function parseBaseUrl(name: string, raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigError(`${name} must be an absolute URL (got "${raw}").`);
  }
  // The API key may travel over plain HTTP only in local development.
  const isLoopback = LOOPBACK_HOSTS.has(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback)) {
    throw new ConfigError(`${name} must use https:// (plain http:// is only allowed for localhost).`);
  }
  if (url.username || url.password) throw new ConfigError(`${name} must not contain credentials.`);
  if (url.search || url.hash) throw new ConfigError(`${name} must not contain a query string or fragment.`);
  return url.origin + url.pathname.replace(/\/+$/, '').replace(/\/v1$/, '');
}

const read = (env: NodeJS.ProcessEnv, name: string): string | undefined => {
  const v = env[name]?.trim();
  return v ? v : undefined;
};

/** Who reads the configuration: the MCP server (started by the MCP client) or the Claude Code hook. */
export type ConfigConsumer = 'server' | 'hook';

const missingKeyMessage = (consumer: ConfigConsumer): string =>
  consumer === 'hook'
    ? // Claude Code starts hook commands with its own environment; the MCP server's `env` block never reaches them.
      'VETKIT_API_KEY is not set for the hook. Hooks do not see the MCP server’s environment: ' +
      'export VETKIT_API_KEY (a key with the agent:check scope, from https://app.vetkit.dev/settings/api-keys) ' +
      'in the shell that starts Claude Code, not in a committed file'
    : 'VETKIT_API_KEY is not set. Create an API key at https://app.vetkit.dev/settings/api-keys ' +
      'and set it in your MCP client’s server environment as VETKIT_API_KEY. ' +
      'Launch the local stdio server with command `npx` and arguments `-y @vetkit/mcp`.';

/**
 * Reads and validates the configuration from environment variables.
 * Error messages never contain the key itself.
 */
export function loadConfig(
  env: NodeJS.ProcessEnv = process.env,
  consumer: ConfigConsumer = 'server',
): VetkitMcpConfig {
  const apiKey = read(env, 'VETKIT_API_KEY');
  if (!apiKey) throw new ConfigError(missingKeyMessage(consumer));
  if (!API_KEY_PATTERN.test(apiKey)) {
    throw new ConfigError(
      'VETKIT_API_KEY is malformed. Expected the full key as shown once at creation time: ' +
        '`vk_live_<8 chars>_<32 chars>` (or `vk_test_...`). Check for truncation or extra characters.',
    );
  }

  const apiUrl = parseBaseUrl('VETKIT_API_URL', read(env, 'VETKIT_API_URL') ?? DEFAULT_API_URL);
  const appUrl = parseBaseUrl('VETKIT_APP_URL', read(env, 'VETKIT_APP_URL') ?? DEFAULT_APP_URL);

  const orgId = read(env, 'VETKIT_ORG_ID');
  if (orgId !== undefined && !z.uuid().safeParse(orgId).success) {
    throw new ConfigError(`VETKIT_ORG_ID must be an organization UUID (got "${orgId}").`);
  }

  return { apiKey, apiUrl, appUrl, ...(orgId ? { orgId } : {}) };
}
