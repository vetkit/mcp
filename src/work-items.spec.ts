import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { type ElicitResult, ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

import { createMcpApi } from './api.js';
import { createVetkitMcpServer } from './server.js';
import {
  API_KEY,
  APP,
  AUDIT_ID,
  BASE,
  FINDING_ID,
  HEAD_AUDIT_ID,
  ORG_ID,
  problem,
  repo,
  REPO_ID,
  WORK_ITEM_ID,
  workItem,
} from './test/fixtures.js';

const ORG = `${BASE}/v1/orgs/${ORG_ID}`;
const msw = setupServer();

beforeAll(() => msw.listen({ onUnhandledRequest: 'error' }));
afterEach(() => msw.resetHandlers());
afterAll(() => msw.close());

const APPROVE: ElicitResult = { action: 'accept', content: { confirm: true } };

async function connect(elicit: false | ((message: string) => ElicitResult) = () => APPROVE) {
  const api = createMcpApi({ baseUrl: BASE, apiKey: API_KEY });
  const server = createVetkitMcpServer(api, { appUrl: APP, orgId: ORG_ID });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client(
    { name: 'vetkit-test', version: '1.0.0' },
    elicit === false ? {} : { capabilities: { elicitation: {} } },
  );
  const elicitations: string[] = [];
  if (elicit !== false) {
    client.setRequestHandler(ElicitRequestSchema, (req) => {
      elicitations.push(req.params.message);
      return elicit(req.params.message);
    });
  }
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  await client.listTools();
  return {
    client,
    elicitations,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

const textOf = (result: Awaited<ReturnType<Client['callTool']>>): string =>
  (result.content as { type: string; text: string }[]).map((c) => c.text).join('\n');

describe('vetkit_list_work_items', () => {
  it('passes filters as query params and shows the fix verification status', async () => {
    let url: URL | null = null;
    msw.use(
      http.get(`${ORG}/repos`, () => HttpResponse.json({ items: [repo()], nextCursor: null })),
      http.get(`${ORG}/work-items`, ({ request }) => {
        url = new URL(request.url);
        return HttpResponse.json({
          items: [
            workItem(),
            workItem({
              id: HEAD_AUDIT_ID,
              title: 'Use of eval',
              severity: 'HIGH',
              status: 'RESOLVED',
              priority: 'HIGH',
              fixUrl: 'https://github.com/acme/api/pull/42',
              verificationStatus: 'NOT_OBSERVED',
              verification: {
                auditId: HEAD_AUDIT_ID,
                commitSha: 'a'.repeat(40),
                ref: 'main',
                auditCreatedAt: '2026-09-28T10:00:00.000Z',
                checkedAt: '2026-09-28T10:01:00.000Z',
                reason: 'COMPARABLE_SCAN',
                matchedFindingId: null,
              },
            }),
          ],
          nextCursor: 'wi-next',
        });
      }),
    );
    const h = await connect();
    const res = await h.client.callTool({
      name: 'vetkit_list_work_items',
      arguments: { repo: 'acme/api', status: 'OPEN', overdue: true, search: 'aws', limit: 50 },
    });
    expect(res.isError, textOf(res)).toBeFalsy();
    expect(url!.searchParams.get('repositoryId')).toBe(REPO_ID);
    expect(url!.searchParams.get('status')).toBe('OPEN');
    expect(url!.searchParams.get('overdue')).toBe('true');
    expect(url!.searchParams.get('search')).toBe('aws');
    expect(url!.searchParams.get('limit')).toBe('50');
    const text = textOf(res);
    expect(text).toContain('2 work items');
    expect(text).toContain(
      '| acme/api | CRITICAL | OPEN | URGENT | config/prod.env | AWS access key committed | NOT_CHECKED |',
    );
    expect(text).toContain('NOT_OBSERVED (COMPARABLE_SCAN)');
    expect(text).toContain('cursor "wi-next"');
    expect(res.structuredContent).toMatchObject({
      nextCursor: 'wi-next',
      items: [
        {
          id: WORK_ITEM_ID,
          status: 'OPEN',
          verificationStatus: 'NOT_CHECKED',
          verification: null,
          version: 3,
        },
        {
          status: 'RESOLVED',
          fixUrl: 'https://github.com/acme/api/pull/42',
          verificationStatus: 'NOT_OBSERVED',
          verification: { auditId: HEAD_AUDIT_ID, reason: 'COMPARABLE_SCAN', matchedFindingId: null },
        },
      ],
    });
    await h.close();
  });

  it('looks up the work item of a finding and says when there is none', async () => {
    let item: unknown = workItem();
    msw.use(http.get(`${ORG}/findings/${FINDING_ID}/work-item`, () => HttpResponse.json({ item })));
    const h = await connect();
    const found = await h.client.callTool({
      name: 'vetkit_list_work_items',
      arguments: { findingId: FINDING_ID },
    });
    expect(found.isError, textOf(found)).toBeFalsy();
    expect(found.structuredContent).toMatchObject({ items: [{ id: WORK_ITEM_ID }], nextCursor: null });

    item = null;
    const none = await h.client.callTool({
      name: 'vetkit_list_work_items',
      arguments: { findingId: FINDING_ID },
    });
    expect(none.isError).toBeFalsy();
    expect(textOf(none)).toContain('has no work item');
    expect(none.structuredContent).toEqual({ items: [], nextCursor: null });

    const both = await h.client.callTool({
      name: 'vetkit_list_work_items',
      arguments: { findingId: FINDING_ID, workItemId: WORK_ITEM_ID },
    });
    expect(both.isError).toBe(true);
    expect(textOf(both)).toContain('not both');
    await h.close();
  });

  it('rejects unknown statuses at the schema level', async () => {
    const h = await connect();
    const res = await h.client.callTool({ name: 'vetkit_list_work_items', arguments: { status: 'DONE' } });
    expect(res.isError).toBe(true);
    await h.close();
  });
});

describe('vetkit_update_work_item', () => {
  it('asks for confirmation, patches with the current version and verifies the fix against an audit', async () => {
    const calls: { method: string; path: string; body: unknown }[] = [];
    msw.use(
      http.get(`${ORG}/work-items/${WORK_ITEM_ID}`, () => HttpResponse.json(workItem())),
      http.patch(`${ORG}/work-items/${WORK_ITEM_ID}`, async ({ request }) => {
        calls.push({ method: 'PATCH', path: new URL(request.url).pathname, body: await request.json() });
        return HttpResponse.json(
          workItem({
            status: 'RESOLVED',
            fixUrl: 'https://github.com/acme/api/pull/42',
            verificationStatus: 'MANUAL_CLOSED',
            version: 4,
          }),
        );
      }),
      http.post(`${ORG}/work-items/${WORK_ITEM_ID}/verify-fix`, async ({ request }) => {
        calls.push({ method: 'POST', path: new URL(request.url).pathname, body: await request.json() });
        return HttpResponse.json(
          workItem({
            status: 'RESOLVED',
            fixUrl: 'https://github.com/acme/api/pull/42',
            verificationStatus: 'NOT_OBSERVED',
            verification: {
              auditId: AUDIT_ID,
              commitSha: 'a'.repeat(40),
              ref: 'main',
              auditCreatedAt: '2026-09-28T10:00:00.000Z',
              checkedAt: '2026-09-28T10:01:00.000Z',
              reason: 'COMPARABLE_SCAN',
              matchedFindingId: null,
            },
            version: 5,
          }),
        );
      }),
    );
    const h = await connect();
    const res = await h.client.callTool({
      name: 'vetkit_update_work_item',
      arguments: {
        workItemId: WORK_ITEM_ID,
        status: 'RESOLVED',
        fixUrl: 'https://github.com/acme/api/pull/42',
        verifyAgainstAuditId: AUDIT_ID,
      },
    });
    expect(res.isError, textOf(res)).toBeFalsy();
    expect(h.elicitations).toHaveLength(1);
    expect(h.elicitations[0]).toContain('AWS access key committed');
    expect(h.elicitations[0]).toContain('- status: RESOLVED');
    expect(h.elicitations[0]).toContain(`verify the fix against audit ${AUDIT_ID}`);
    expect(calls).toEqual([
      {
        method: 'PATCH',
        path: `/v1/orgs/${ORG_ID}/work-items/${WORK_ITEM_ID}`,
        body: { version: 3, status: 'RESOLVED', fixUrl: 'https://github.com/acme/api/pull/42' },
      },
      {
        method: 'POST',
        path: `/v1/orgs/${ORG_ID}/work-items/${WORK_ITEM_ID}/verify-fix`,
        body: { version: 4, auditId: AUDIT_ID },
      },
    ]);
    const text = textOf(res);
    expect(text).toContain('status RESOLVED');
    expect(text).toContain('NOT_OBSERVED (COMPARABLE_SCAN)');
    expect(text).toContain('no longer reports this finding');
    expect(res.structuredContent).toMatchObject({
      changed: ['status', 'fixUrl', 'verification'],
      item: { version: 5, verificationStatus: 'NOT_OBSERVED' },
    });
    await h.close();
  });

  it('uses an explicit version, sends only the priority and maps a version conflict', async () => {
    let body: unknown = null;
    msw.use(
      http.get(`${ORG}/work-items/${WORK_ITEM_ID}`, () => HttpResponse.json(workItem())),
      http.patch(`${ORG}/work-items/${WORK_ITEM_ID}`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(
          problem(409, 'CONFLICT', 'The work item was changed by someone else; reload and retry'),
          { status: 409 },
        );
      }),
    );
    const h = await connect();
    const res = await h.client.callTool({
      name: 'vetkit_update_work_item',
      arguments: { workItemId: WORK_ITEM_ID, priority: 'LOW', version: 2 },
    });
    expect(res.isError).toBe(true);
    expect(body).toEqual({ version: 2, priority: 'LOW' });
    expect(textOf(res)).toContain('409 CONFLICT');
    expect(textOf(res)).toContain('changed by someone else');
    await h.close();
  });

  it('refuses without changes, without elicitation support or when the user declines, and never writes', async () => {
    let writes = 0;
    msw.use(
      http.get(`${ORG}/work-items/${WORK_ITEM_ID}`, () => HttpResponse.json(workItem())),
      http.patch(`${ORG}/work-items/${WORK_ITEM_ID}`, () => {
        writes++;
        return HttpResponse.json(workItem());
      }),
    );
    const noElicit = await connect(false);
    const empty = await noElicit.client.callTool({
      name: 'vetkit_update_work_item',
      arguments: { workItemId: WORK_ITEM_ID },
    });
    expect(empty.isError).toBe(true);
    expect(textOf(empty)).toContain('Nothing to change');
    const unsupported = await noElicit.client.callTool({
      name: 'vetkit_update_work_item',
      arguments: { workItemId: WORK_ITEM_ID, status: 'IN_PROGRESS' },
    });
    expect(unsupported.isError).toBe(true);
    expect(textOf(unsupported)).toContain('does not support MCP elicitation');
    await noElicit.close();

    const declining = await connect(() => ({ action: 'decline' }));
    const declined = await declining.client.callTool({
      name: 'vetkit_update_work_item',
      arguments: { workItemId: WORK_ITEM_ID, status: 'IN_PROGRESS' },
    });
    expect(declined.isError).toBe(true);
    expect(textOf(declined)).toContain('declined');
    await declining.close();
    expect(writes).toBe(0);
  });

  it('names the missing findings:write scope on 403', async () => {
    msw.use(
      http.get(`${ORG}/work-items/${WORK_ITEM_ID}`, () => HttpResponse.json(workItem())),
      http.patch(`${ORG}/work-items/${WORK_ITEM_ID}`, () =>
        HttpResponse.json(problem(403, 'INSUFFICIENT_SCOPE', 'Missing scope'), { status: 403 }),
      ),
    );
    const h = await connect();
    const res = await h.client.callTool({
      name: 'vetkit_update_work_item',
      arguments: { workItemId: WORK_ITEM_ID, status: 'IN_PROGRESS' },
    });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toContain('needs: findings:write');
    await h.close();
  });
});
