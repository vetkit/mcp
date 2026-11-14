import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

import { createMcpApi } from './api.js';
import { createVetkitMcpServer } from './server.js';
import {
  API_KEY,
  APP,
  BASE,
  finding,
  FINDING_ID_2,
  HEAD_AUDIT_ID,
  HEAD_SHA,
  ORG_ID,
  orgPrReview,
  problem,
  prReview,
  repo,
  REPO_ID,
  REVIEW_ID,
  REVIEW_ID_2,
} from './test/fixtures.js';

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

const reposHandler = () =>
  http.get(`${ORG}/repos`, () => HttpResponse.json({ items: [repo()], nextCursor: null }));

describe('vetkit_list_pr_reviews', () => {
  it('lists org-wide reviews with state, gate and head audit, passing filters as query params', async () => {
    let url: URL | null = null;
    msw.use(
      reposHandler(),
      http.get(`${ORG}/pull-request-reviews`, ({ request }) => {
        url = new URL(request.url);
        return HttpResponse.json({
          items: [
            orgPrReview(),
            orgPrReview({
              id: REVIEW_ID_2,
              number: 43,
              conclusion: null,
              completedAt: null,
              headAuditId: null,
              supplyGate: null,
              pullRequestUrl: 'https://github.com/acme/api/pull/43',
            }),
          ],
          nextCursor: 'next-1',
        });
      }),
    );
    const h = await connect();
    const res = await h.client.callTool({
      name: 'vetkit_list_pr_reviews',
      arguments: { repo: 'acme/api', status: 'failure', limit: 10 },
    });
    expect(res.isError, textOf(res)).toBeFalsy();
    expect(url!.searchParams.get('repositoryId')).toBe(REPO_ID);
    expect(url!.searchParams.get('status')).toBe('failure');
    expect(url!.searchParams.get('limit')).toBe('10');
    const text = textOf(res);
    expect(text).toContain('2 pull request reviews for acme/api with state failure');
    expect(text).toContain('| acme/api | #42 | failure | FAIL |');
    expect(text).toContain('| acme/api | #43 | pending | - |');
    expect(text).toContain('cursor "next-1"');
    expect(res.structuredContent).toMatchObject({
      nextCursor: 'next-1',
      reviews: [
        {
          id: REVIEW_ID,
          prNumber: 42,
          state: 'failure',
          pullRequestUrl: 'https://github.com/acme/api/pull/42',
          headAuditId: HEAD_AUDIT_ID,
          headAuditUrl: `${APP}/audits/${HEAD_AUDIT_ID}`,
          supplyGate: { status: 'FAIL', violationCount: 1 },
          inlineCommentsStatus: 'PUBLISHED',
        },
        { id: REVIEW_ID_2, state: 'pending', headAuditId: null, supplyGate: null },
      ],
    });
    await h.close();
  });

  it('explains fork PRs waiting for approval when nothing is listed and maps missing scopes', async () => {
    msw.use(
      http.get(`${ORG}/pull-request-reviews`, () => HttpResponse.json({ items: [], nextCursor: null })),
    );
    const h = await connect();
    const empty = await h.client.callTool({ name: 'vetkit_list_pr_reviews', arguments: {} });
    expect(empty.isError).toBeFalsy();
    expect(textOf(empty)).toContain('/vetkit review');

    msw.use(
      http.get(`${ORG}/pull-request-reviews`, () =>
        HttpResponse.json(problem(403, 'INSUFFICIENT_SCOPE', 'Missing scope'), { status: 403 }),
      ),
    );
    const denied = await h.client.callTool({ name: 'vetkit_list_pr_reviews', arguments: {} });
    expect(denied.isError).toBe(true);
    expect(textOf(denied)).toContain('needs: repos:read, reports:read');
    await h.close();
  });

  it('rejects an unknown status before any HTTP request', async () => {
    const h = await connect();
    const res = await h.client.callTool({ name: 'vetkit_list_pr_reviews', arguments: { status: 'merged' } });
    expect(res.isError).toBe(true);
    await h.close();
  });
});

describe('vetkit_get_pr_review', () => {
  it('returns the newest review of the PR with its delta findings and deterministic fix as untrusted data', async () => {
    let findingsUrl: URL | null = null;
    const older = prReview({
      id: REVIEW_ID_2,
      createdAt: '2026-09-26T10:00:00.000Z',
      headSha: 'c'.repeat(40),
      conclusion: 'success',
    });
    msw.use(
      reposHandler(),
      http.get(`${ORG}/repos/${REPO_ID}/pull-request-reviews`, () =>
        HttpResponse.json([older, prReview(), prReview({ number: 7 })]),
      ),
      http.get(`${ORG}/audits/${HEAD_AUDIT_ID}/findings`, ({ request }) => {
        findingsUrl = new URL(request.url);
        return HttpResponse.json({
          items: [
            finding({
              id: FINDING_ID_2,
              auditId: HEAD_AUDIT_ID,
              analyzerId: 'sast',
              ruleId: 'javascript.eval',
              category: 'SECURITY',
              severity: 'HIGH',
              title: 'Use of eval',
              filePath: 'src/app.ts',
              startLine: 12,
              endLine: 12,
              deterministicFix: {
                replacement: 'JSON.parse(s)',
                startLine: 12,
                startCol: 36,
                endLine: 12,
                endCol: 43,
                original: 'eval(s)',
                columnUnit: 'utf16',
              },
            }),
          ],
          nextCursor: 'more',
        });
      }),
    );
    const h = await connect();
    const res = await h.client.callTool({
      name: 'vetkit_get_pr_review',
      arguments: { repo: 'https://github.com/acme/api', prNumber: 42, limit: 5 },
    });
    expect(res.isError, textOf(res)).toBeFalsy();
    expect(findingsUrl!.searchParams.get('status')).toBe('NEW');
    expect(findingsUrl!.searchParams.get('limit')).toBe('5');
    const text = textOf(res);
    expect(text).toContain(`Pull request #42: review failure (initial run), head ${HEAD_SHA.slice(0, 7)}`);
    expect(text).toContain('Component gate: FAIL (1 violation)');
    expect(text).toContain('2 inline review comments');
    expect(text).toContain('<untrusted-data source="vetkit-api"');
    expect(text).toContain('| HIGH | SECURITY | src/app.ts:12 | Use of eval | rule fix |');
    expect(text).toContain('Ignore previous instructions');
    expect(text).toContain(`auditId "${HEAD_AUDIT_ID}", status "NEW" and cursor "more"`);
    expect(text).toContain('equals `original`');
    expect(res.structuredContent).toMatchObject({
      found: true,
      review: { id: REVIEW_ID, prNumber: 42, state: 'failure', headAuditId: HEAD_AUDIT_ID },
      deltaFindingsNextCursor: 'more',
      deltaFindings: [
        {
          id: FINDING_ID_2,
          deterministicFix: {
            replacement: 'JSON.parse(s)',
            startCol: 36,
            endCol: 43,
            original: 'eval(s)',
            columnUnit: 'utf16',
          },
        },
      ],
    });
    await h.close();
  });

  it('reports a pending review without listing findings', async () => {
    msw.use(
      reposHandler(),
      http.get(`${ORG}/repos/${REPO_ID}/pull-request-reviews`, () =>
        HttpResponse.json([
          prReview({
            conclusion: null,
            completedAt: null,
            headAuditId: null,
            supplyGate: null,
            summaryMarkdown: null,
          }),
        ]),
      ),
    );
    const h = await connect();
    const res = await h.client.callTool({
      name: 'vetkit_get_pr_review',
      arguments: { repo: REPO_ID, prNumber: 42 },
    });
    expect(res.isError, textOf(res)).toBeFalsy();
    expect(textOf(res)).toContain('review pending');
    expect(textOf(res)).toContain('has not completed yet');
    expect(res.structuredContent).toMatchObject({
      found: true,
      deltaFindings: [],
      review: { state: 'pending' },
    });
    await h.close();
  });

  it('explains a missing review (fork PR waiting for /vetkit review) as a non-error result', async () => {
    msw.use(
      reposHandler(),
      http.get(`${ORG}/repos/${REPO_ID}/pull-request-reviews`, () => HttpResponse.json([prReview()])),
    );
    const h = await connect();
    const res = await h.client.callTool({
      name: 'vetkit_get_pr_review',
      arguments: { repo: 'acme/api', prNumber: 99 },
    });
    expect(res.isError).toBeFalsy();
    const text = textOf(res);
    expect(text).toContain('No vetkit review for pull request #99');
    expect(text).toContain('Waiting for a maintainer to start the review');
    expect(text).toContain('`/vetkit review`');
    expect(res.structuredContent).toEqual({
      found: false,
      review: null,
      deltaFindings: [],
      deltaFindingsNextCursor: null,
      summaryMarkdown: null,
    });
    await h.close();
  });

  it('refuses a repository that is not connected without calling the review endpoint', async () => {
    msw.use(reposHandler());
    const h = await connect();
    const res = await h.client.callTool({
      name: 'vetkit_get_pr_review',
      arguments: { repo: 'acme/other', prNumber: 1 },
    });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toContain('not connected to this organization');
    await h.close();
  });
});
