import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

import { createMcpApi } from './api.js';
import { createVetkitMcpServer } from './server.js';
import { API_KEY, APP, BASE, ORG_ID, problem } from './test/fixtures.js';

const ORG = `${BASE}/v1/orgs/${ORG_ID}`;
const msw = setupServer();

beforeAll(() => msw.listen({ onUnhandledRequest: 'error' }));
afterEach(() => msw.resetHandlers());
afterAll(() => msw.close());

async function connect() {
  const api = createMcpApi({ baseUrl: BASE, apiKey: API_KEY });
  const server = createVetkitMcpServer(api, { appUrl: APP, orgId: ORG_ID });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'vetkit-test', version: '1.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  await client.listTools();
  return {
    client,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

const textOf = (result: Awaited<ReturnType<Client['callTool']>>): string =>
  (result.content as { type: string; text: string }[]).map((c) => c.text).join('\n');

describe('agent guardrail tools', () => {
  it('checks packages and tells agents when to call the tools', async () => {
    const bodies: unknown[] = [];
    msw.use(
      http.post(`${ORG}/agent-checks/packages`, async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json({
          verdict: 'block',
          items: [
            { name: 'express', version: '4.18.0', verdict: 'allow', reasons: [] },
            {
              name: 'expresss-ai',
              verdict: 'block',
              reasons: [{ code: 'NOT_FOUND', detail: 'expresss-ai does not exist on the public registry' }],
            },
          ],
          warnings: [],
        });
      }),
    );
    const h = await connect();
    const { tools } = await h.client.listTools();
    const check = tools.find((t) => t.name === 'vetkit_check_packages');
    expect(check?.description).toContain('BEFORE running npm/pnpm/yarn');
    expect(check?.annotations?.readOnlyHint).toBe(true);
    expect(tools.find((t) => t.name === 'vetkit_scan_changes')?.description).toContain('BEFORE committing');

    const res = await h.client.callTool({
      name: 'vetkit_check_packages',
      arguments: { ecosystem: 'npm', packages: [{ name: 'express' }, { name: 'expresss-ai' }] },
    });
    expect(res.isError).toBeFalsy();
    expect(bodies).toEqual([{ ecosystem: 'npm', packages: [{ name: 'express' }, { name: 'expresss-ai' }] }]);
    const text = textOf(res);
    expect(text).toContain('<untrusted-data');
    expect(text).toContain('Verdict: BLOCK (2 npm packages)');
    expect(text).toContain('- BLOCK expresss-ai: NOT_FOUND');
    expect(res.structuredContent).toMatchObject({ verdict: 'block' });
    await h.close();
  });

  it('scans changed files, explains a missing agent:check scope and rejects unsafe paths locally', async () => {
    let calls = 0;
    msw.use(
      http.post(`${ORG}/agent-checks/changes`, () => {
        calls++;
        return calls === 1
          ? HttpResponse.json({
              verdict: 'block',
              filesScanned: 1,
              warnings: [],
              findings: [
                {
                  path: 'src/a.ts',
                  line: 3,
                  ruleId: 'vetkit.agent-guard.secret.github-token',
                  severity: 'HIGH',
                  title: 'GitHub token in a changed file',
                  code: 'SECRET',
                  verdict: 'block',
                },
              ],
            })
          : HttpResponse.json(problem(403, 'INSUFFICIENT_SCOPE', 'Missing scope: agent:check'), {
              status: 403,
              headers: { 'content-type': 'application/problem+json' },
            });
      }),
    );
    const h = await connect();
    const args = { files: [{ path: 'src/a.ts', content: 'const t = 1;\n' }] };
    const ok = await h.client.callTool({ name: 'vetkit_scan_changes', arguments: args });
    expect(textOf(ok)).toContain('- BLOCK SECRET src/a.ts:3 [HIGH] GitHub token in a changed file');
    const denied = await h.client.callTool({ name: 'vetkit_scan_changes', arguments: args });
    expect(denied.isError).toBe(true);
    expect(textOf(denied)).toContain('agent:check');
    const unsafe = await h.client.callTool({
      name: 'vetkit_scan_changes',
      arguments: { files: [{ path: '../etc/passwd', content: 'x' }] },
    });
    expect(unsafe.isError).toBe(true);
    expect(calls).toBe(2);
    await h.close();
  });

  it('explains contract limits that are only checked client-side instead of dumping a ZodError', async () => {
    const h = await connect();
    const half = 'x'.repeat(300 * 1024);
    const tooBig = await h.client.callTool({
      name: 'vetkit_scan_changes',
      arguments: {
        files: [
          { path: 'a.txt', content: half },
          { path: 'b.txt', content: half },
        ],
      },
    });
    expect(tooBig.isError).toBe(true);
    expect(textOf(tooBig)).toContain('- files: File contents may total at most 512 KB');
    expect(textOf(tooBig)).not.toContain('Unexpected error');
    const duplicate = await h.client.callTool({
      name: 'vetkit_scan_changes',
      arguments: {
        files: [
          { path: 'a.txt', content: '1' },
          { path: 'a.txt', content: '2' },
        ],
      },
    });
    expect(duplicate.isError).toBe(true);
    expect(textOf(duplicate)).toContain('- files: Each path may appear only once');
    await h.close();
  });
});
