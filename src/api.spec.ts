import { describe, expect, it } from 'vitest';

import { createMcpApi, MCP_API_METHODS } from './api.js';

describe('MCP API client', () => {
  it('exposes exactly the allowlisted methods', () => {
    const api = createMcpApi({ baseUrl: 'https://api.vetkit.dev', apiKey: 'vk_live_test' });
    const proto = Object.getPrototypeOf(api) as object;
    const own = Object.getOwnPropertyNames(proto).filter((n) => n !== 'constructor');
    expect(own.sort()).toEqual([...MCP_API_METHODS].sort());
    for (const name of MCP_API_METHODS) expect(typeof api[name]).toBe('function');
  });

  it('has no admin or account-management methods', () => {
    const api = createMcpApi({ baseUrl: 'https://api.vetkit.dev' }) as unknown as Record<string, unknown>;
    for (const name of ['adminSendNotification', 'createApiKey', 'disconnectRepo', 'updateOrgSettings']) {
      expect(api[name]).toBeUndefined();
    }
  });
});
