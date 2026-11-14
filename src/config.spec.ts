import { describe, expect, it } from 'vitest';

import { ConfigError, DEFAULT_API_URL, DEFAULT_APP_URL, loadConfig } from './config.js';
import { API_KEY, ORG_ID } from './test/fixtures.js';

const expectConfigError = (env: NodeJS.ProcessEnv, match: RegExp): ConfigError => {
  let caught: unknown;
  try {
    loadConfig(env);
  } catch (err) {
    caught = err;
  }
  expect(caught).toBeInstanceOf(ConfigError);
  expect((caught as Error).message).toMatch(match);
  return caught as ConfigError;
};

describe('loadConfig', () => {
  it('applies defaults', () => {
    expect(loadConfig({ VETKIT_API_KEY: API_KEY })).toEqual({
      apiKey: API_KEY,
      apiUrl: DEFAULT_API_URL,
      appUrl: DEFAULT_APP_URL,
    });
  });

  it('requires VETKIT_API_KEY', () => {
    const err = expectConfigError({}, /VETKIT_API_KEY is not set/);
    expect(err.message).toContain('your MCP client');
    expect(err.message).toContain('stdio');
    expect(err.message).not.toContain('claude');
    expectConfigError({ VETKIT_API_KEY: '   ' }, /VETKIT_API_KEY is not set/);
  });

  it('tells the hook to read the key from the shell, matching the README', () => {
    let caught: unknown;
    try {
      loadConfig({}, 'hook');
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ConfigError);
    const message = (caught as ConfigError).message;
    expect(message).toMatch(/VETKIT_API_KEY is not set for the hook/);
    expect(message).toContain('in the shell that starts Claude Code');
    expect(message).toContain('agent:check');
    expect(message).not.toContain('MCP client’s server environment');
  });

  it('rejects malformed keys without echoing them', () => {
    const bad = `${API_KEY}x`;
    const err = expectConfigError({ VETKIT_API_KEY: bad }, /malformed/);
    expect(err.message).not.toContain(bad);
    expectConfigError({ VETKIT_API_KEY: 'sk-live-something' }, /malformed/);
  });

  it('trims whitespace around the key', () => {
    expect(loadConfig({ VETKIT_API_KEY: ` ${API_KEY}\n` }).apiKey).toBe(API_KEY);
  });

  it('normalizes the API URL and strips a trailing /v1', () => {
    expect(
      loadConfig({ VETKIT_API_KEY: API_KEY, VETKIT_API_URL: 'https://api.example.com/v1/' }).apiUrl,
    ).toBe('https://api.example.com');
    expect(loadConfig({ VETKIT_API_KEY: API_KEY, VETKIT_API_URL: 'http://localhost:4000' }).apiUrl).toBe(
      'http://localhost:4000',
    );
  });

  it('refuses to send the key over plain http to non-local hosts', () => {
    expectConfigError({ VETKIT_API_KEY: API_KEY, VETKIT_API_URL: 'http://api.example.com' }, /https/);
    expectConfigError({ VETKIT_API_KEY: API_KEY, VETKIT_API_URL: 'not a url' }, /absolute URL/);
    expectConfigError(
      { VETKIT_API_KEY: API_KEY, VETKIT_API_URL: 'https://u:p@api.example.com' },
      /credentials/,
    );
  });

  it('validates VETKIT_ORG_ID', () => {
    expect(loadConfig({ VETKIT_API_KEY: API_KEY, VETKIT_ORG_ID: ORG_ID }).orgId).toBe(ORG_ID);
    expectConfigError({ VETKIT_API_KEY: API_KEY, VETKIT_ORG_ID: 'my-org' }, /UUID/);
  });
});
