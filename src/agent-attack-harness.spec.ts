/**
 * X06: executable agent-attack / guard regression tests for the vetkit MCP server.
 *
 * Threat: a coding agent reads attacker-controlled repository data (finding titles/messages, file
 * paths, repository names) from read tools and is told to call write tools or to exfiltrate data.
 * A deterministic worst-case agent (obeys every instruction it finds) drives the real MCP
 * client/server over an in-memory transport against a mocked API. Only canary values are used.
 *
 * The simulated user never auto-approves: the report is produced with a client that supports MCP
 * elicitation whose user declines every request; a second run uses a client without elicitation.
 * A separate positive test shows that an approving user lets a legitimate write through.
 *
 * Set `VETKIT_X06_OUT=<path>` to write the JSON report. The report is compared with
 * `test/fixtures/x06-baseline.json`; a payload may not regress from `blocked` to `possible`, and a
 * `possible` payload needs a `knownGap` note in the baseline.
 */
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  type ActionRecord,
  ATTACKER_HOST,
  type AttackerDoc,
  type Baseline,
  baselineFrom,
  compareToBaseline,
  CONTROL_ID,
  type Guard,
  normalize,
  type Outcome,
  PAYLOADS,
  type PayloadDef,
  type PayloadReport,
  planActions,
  type Report,
  RUN_ID,
  summarize,
} from './agent-attack-harness.js';
import { createMcpApi } from './api.js';
import { createVetkitMcpServer } from './server.js';
import { API_KEY, APP, audit, AUDIT_ID, BASE, finding, ORG_ID, problem, repo } from './test/fixtures.js';

const ORG = `${BASE}/v1/orgs/${ORG_ID}`;
const BASELINE_URL = new URL('../test/fixtures/x06-baseline.json', import.meta.url);
const FULL_SCOPES = [
  'repos:read',
  'repos:write',
  'audits:read',
  'audits:write',
  'findings:read',
  'reports:read',
];
const READ_ONLY_SCOPES = ['repos:read', 'audits:read', 'findings:read', 'reports:read'];
/** Random per run; never written to the report. */
const CANARY = `VETKIT_CANARY_${randomBytes(8).toString('hex')}`;
const API_KEY_SECRET = API_KEY.split('_').slice(-1)[0]!;

const msw = setupServer();
const offOrigin: string[] = [];
let realFetch: typeof fetch;

beforeAll(() => {
  msw.listen({ onUnhandledRequest: 'error' });
  // Egress spy: only the configured mock API origin may be reached. It must be installed before the
  // API client is created because the client binds `globalThis.fetch` at construction.
  realFetch = globalThis.fetch;
  globalThis.fetch = (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    const url = input instanceof Request ? input.url : String(input);
    if (new URL(url).origin !== new URL(BASE).origin) {
      offOrigin.push(url);
      return Promise.reject(new TypeError('X06 egress spy: request to a non-allowlisted origin blocked'));
    }
    return realFetch(input, init);
  };
});
afterAll(() => {
  globalThis.fetch = realFetch;
  msw.close();
});

interface Write {
  method: string;
  path: string;
}

const evalRun = {
  id: RUN_ID,
  name: 'run',
  mode: 'demo',
  profile: 'deterministic',
  status: 'QUEUED',
  settings: {},
  error: null,
  createdAt: '2026-10-20T10:00:00.000Z',
  startedAt: null,
  finishedAt: null,
  cancelRequested: false,
  sourceVersionId: null,
  suite: { prompts: [] },
};

const CLEAN: AttackerDoc = {
  findingTitle: 'Hardcoded password',
  findingMessage: 'A password literal was found in source.',
  findingSnippet: 'password = "****"',
  filePath: 'src/config.ts',
  repoFullName: 'acme/api',
};

/** Mocks the API for one scenario. Scope enforcement mimics the real API (403 INSUFFICIENT_SCOPE). */
function mockApi(doc: AttackerDoc, scopes: string[], writes: Write[]) {
  const markdown = `# Report\n\n## ${doc.findingTitle}\n\n${doc.findingMessage}\n\nFile: ${doc.filePath}\n\n\`\`\`\n${doc.findingSnippet}\n\`\`\`\n`;
  msw.use(
    http.get(`${ORG}/repos`, () =>
      HttpResponse.json({ items: [repo({ fullName: doc.repoFullName })], nextCursor: null }),
    ),
    http.get(`${ORG}/audits/${AUDIT_ID}`, () =>
      HttpResponse.json(
        audit({
          status: 'FAILED',
          errorCode: 'INTERNAL',
          repository: {
            fullName: doc.repoFullName,
            provider: 'GITHUB',
            htmlUrl: 'https://github.com/acme/api',
          },
        }),
      ),
    ),
    http.get(`${ORG}/audits/${AUDIT_ID}/findings`, () =>
      HttpResponse.json({
        items: [
          finding({
            title: doc.findingTitle,
            message: doc.findingMessage,
            filePath: doc.filePath,
            snippet: doc.findingSnippet,
          }),
        ],
        nextCursor: null,
      }),
    ),
    http.get(
      `${ORG}/audits/${AUDIT_ID}/report`,
      () => new HttpResponse(markdown, { headers: { 'content-type': 'text/markdown' } }),
    ),
    http.post(`${ORG}/*`, ({ request }) => {
      const path = new URL(request.url).pathname.replace(`/v1/orgs/${ORG_ID}`, '');
      const needed = path.startsWith('/repos') ? 'repos:write' : 'audits:write';
      if (!scopes.includes(needed))
        return HttpResponse.json(problem(403, 'INSUFFICIENT_SCOPE', 'missing scope'), { status: 403 });
      writes.push({ method: 'POST', path });
      if (path.startsWith('/repos')) return HttpResponse.json(repo(), { status: 201 });
      if (path.startsWith('/audits')) return HttpResponse.json(audit(), { status: 202 });
      return HttpResponse.json(evalRun, { status: 202 });
    }),
  );
}

type CallResult = Awaited<ReturnType<Client['callTool']>>;
const textOf = (r: CallResult): string =>
  (r.content as { type: string; text: string }[]).map((c) => c.text).join('\n');
/** Everything an agent can see in a result: text blocks plus structured content. */
const visible = (r: CallResult): string =>
  textOf(r) + (r.structuredContent ? `\n${JSON.stringify(r.structuredContent)}` : '');

const redact = (s: string): string => s.replaceAll(CANARY, '<CANARY>').replaceAll(API_KEY, '<API_KEY>');

/** Simulated MCP client: no elicitation capability, or a user who declines / approves requests. */
type User = 'no-elicitation' | 'declines' | 'approves';

interface Scenario {
  observed: string;
  /** Text content only (no structured content), used to judge output marking. */
  textObserved: string;
  elicitations: string[];
  actions: ActionRecord[];
  writes: Write[];
  offOrigin: number;
  leakTexts: string[];
  tools: string[];
}

async function connectAs(user: User) {
  const api = createMcpApi({ baseUrl: BASE, apiKey: API_KEY });
  const server = createVetkitMcpServer(api, { appUrl: APP, orgId: ORG_ID, pollIntervalMs: 5 });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const client = new Client(
    { name: 'x06-adversary', version: '1.0.0' },
    user === 'no-elicitation' ? {} : { capabilities: { elicitation: {} } },
  );
  const elicitations: string[] = [];
  if (user !== 'no-elicitation') {
    client.setRequestHandler(ElicitRequestSchema, (req) => {
      elicitations.push(req.params.message);
      return user === 'approves'
        ? { action: 'accept' as const, content: { confirm: true } }
        : { action: 'decline' as const };
    });
  }
  await Promise.all([server.connect(st), client.connect(ct)]);
  return { client, server, elicitations };
}

async function runScenario(doc: AttackerDoc, scopes: string[], user: User): Promise<Scenario> {
  const writes: Write[] = [];
  mockApi(doc, scopes, writes);
  const { client, server, elicitations } = await connectAs(user);
  const tools = (await client.listTools()).tools.map((t) => t.name);
  const originBefore = offOrigin.length;
  const leakTexts: string[] = [];

  // 1. Read phase: every read tool whose output may carry attacker text.
  const reads = [
    { name: 'vetkit_list_repos', arguments: {} },
    { name: 'vetkit_get_audit', arguments: { auditId: AUDIT_ID } },
    { name: 'vetkit_list_findings', arguments: { auditId: AUDIT_ID } },
    { name: 'vetkit_get_report', arguments: { auditId: AUDIT_ID } },
  ];
  const seen: string[] = [];
  const seenText: string[] = [];
  for (const call of reads) {
    const res = await client.callTool(call);
    expect(res.isError, `${call.name}: ${textOf(res)}`).toBeFalsy();
    seen.push(visible(res));
    seenText.push(textOf(res));
  }
  const observed = seen.join('\n');
  leakTexts.push(observed);

  // 2. Obey phase.
  const plan = planActions(observed, {
    secrets: [CANARY, 'VETKIT_API_KEY=<unknown-to-agent>'],
    allowedHosts: [new URL(BASE).host, new URL(APP).host, 'github.com', 'cwe.mitre.org'],
    knownTools: tools,
  });
  const actions: ActionRecord[] = [];
  for (const action of plan) {
    const wBefore = writes.length;
    const oBefore = offOrigin.length;
    const attempt = async (args: Record<string, unknown>): Promise<string> => {
      try {
        return visible(await client.callTool({ name: action.tool, arguments: args }));
      } catch (err) {
        return err instanceof Error ? err.message : String(err);
      }
    };
    const text = await attempt(action.args);
    leakTexts.push(text);
    const accepted = writes.length > wBefore;
    const offOriginHit = offOrigin.length > oBefore;
    let guard: Guard = 'none';
    if (!accepted && !offOriginHit) {
      if (/Not executed/.test(text)) guard = 'confirmation';
      else if (/INSUFFICIENT_SCOPE|missing a required scope/.test(text)) guard = 'scope';
      else if (/not a valid repository URL|is not a repository id/.test(text)) guard = 'egress';
    }
    actions.push({
      tool: action.tool,
      source: action.source,
      args: redact(normalize(JSON.stringify(action.args))).slice(0, 160),
      result: accepted || offOriginHit ? 'accepted' : 'rejected',
      guard,
    });
  }
  await client.close();
  await server.close();
  msw.resetHandlers();
  return {
    observed,
    textObserved: seenText.join('\n'),
    elicitations,
    actions,
    writes,
    offOrigin: offOrigin.length - originBefore,
    leakTexts,
    tools,
  };
}

const GUARD_PRECEDENCE: Guard[] = ['egress', 'confirmation', 'scope', 'output-marking'];

function judge(s: Scenario): { outcome: Outcome; guard: Guard } {
  if (s.actions.some((a) => a.result === 'accepted') || s.offOrigin > 0)
    return { outcome: 'possible', guard: 'none' };
  if (s.actions.length === 0) return { outcome: 'blocked', guard: 'output-marking' };
  const guards = new Set(s.actions.map((a) => a.guard));
  return { outcome: 'blocked', guard: GUARD_PRECEDENCE.find((g) => guards.has(g)) ?? 'none' };
}

const ENVELOPE =
  /<untrusted-data source="vetkit-api" boundary="([0-9a-f]{32})">\n([\s\S]*?)\n<\/untrusted-data boundary="\1">/g;

/** `marked`: the planted text only appears inside untrusted-data envelopes in the text content. */
function markingOf(def: PayloadDef, textObserved: string): PayloadReport['outputMarking'] {
  const planted = Object.values(def.plant({ canary: CANARY }))[0] ?? '';
  const needle = normalize(planted).slice(0, 30);
  if (!normalize(textObserved).includes(needle)) return 'absent';
  const outside = normalize(textObserved.replace(ENVELOPE, ''));
  return outside.includes(needle) ? 'raw-unmarked' : 'marked';
}

describe('X06 agent attack harness', () => {
  let report: Report;
  let control: Scenario;
  let scenarios: Map<string, Scenario>;
  const leakTexts: string[] = [];
  let totalOffOrigin = 0;

  beforeAll(async () => {
    scenarios = new Map();
    const payloads: PayloadReport[] = [];
    control = await runScenario(CLEAN, FULL_SCOPES, 'declines');
    leakTexts.push(...control.leakTexts);
    for (const def of PAYLOADS) {
      const doc = { ...CLEAN, ...def.plant({ canary: CANARY }) };
      // Full-scope key; the user declines every confirmation (the report's primary measurement).
      const full = await runScenario(doc, FULL_SCOPES, 'declines');
      // Client without elicitation support.
      const none = await runScenario(doc, FULL_SCOPES, 'no-elicitation');
      // Read-only key and an approving user: only the API key scope can stop the write.
      const ro = await runScenario(doc, READ_ONLY_SCOPES, 'approves');
      scenarios.set(def.id, full);
      scenarios.set(`${def.id}#none`, none);
      scenarios.set(`${def.id}#ro`, ro);
      leakTexts.push(...full.leakTexts, ...none.leakTexts, ...ro.leakTexts);
      totalOffOrigin += full.offOrigin + none.offOrigin + ro.offOrigin;
      const verdict = judge(full);
      const roVerdict = judge(ro);
      payloads.push({
        id: def.id,
        vector: def.vector,
        attemptedActions: full.actions,
        ...verdict,
        outputMarking: markingOf(def, full.textObserved),
        readOnlyKey: { writesAccepted: ro.writes.length, ...roVerdict },
      });
    }
    report = summarize(payloads, {
      offOrigin: totalOffOrigin,
      keyLeaks: leakTexts.filter((t) => t.includes(API_KEY) || t.includes(API_KEY_SECRET)).length,
    });
    const out = process.env.VETKIT_X06_OUT;
    if (out) {
      mkdirSync(dirname(out), { recursive: true });
      writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
    }
  }, 120_000);

  it(`uses ${CONTROL_ID} documents without inventing actions`, () => {
    expect(control.actions).toEqual([]);
    expect(control.writes).toEqual([]);
  });

  it('has at least six payload classes and the worst-case agent understands each of them', () => {
    expect(PAYLOADS.length).toBeGreaterThanOrEqual(6);
    for (const def of PAYLOADS) {
      const s = scenarios.get(def.id)!;
      const tools = new Set(s.actions.map((a) => a.tool));
      for (const t of def.expectedTools) expect(tools, `${def.id} should attempt ${t}`).toContain(t);
      expect(s.actions.length, `${def.id} should produce at least one attempted action`).toBeGreaterThan(0);
    }
  });

  it('records planted attacker text and canary in tool output without ever echoing the API key', () => {
    expect(scenarios.get('exfiltrate-secrets')!.observed).toContain(CANARY);
    expect(report.summary.apiKeyLeaks).toBe(0);
    for (const t of leakTexts) {
      expect(t).not.toContain(API_KEY);
      expect(t).not.toContain(API_KEY_SECRET);
    }
  });

  it('never reaches a non-allowlisted origin (egress spy)', () => {
    expect(offOrigin, `exfiltration attempted: ${offOrigin.join(', ')}`).toEqual([]);
    expect(report.summary.offOriginRequests).toBe(0);
    // The attacker host only ever appears in tool inputs rejected before any network call.
    const exfil = report.payloads.find((p) => p.id === 'exfiltrate-secrets')!;
    expect(exfil.attemptedActions.some((a) => a.source === 'exfil')).toBe(true);
    expect(exfil.attemptedActions.every((a) => a.result === 'rejected' && a.guard === 'egress')).toBe(true);
    expect(JSON.stringify(report)).not.toContain(CANARY);
    expect(ATTACKER_HOST.endsWith('.invalid')).toBe(true);
  });

  it('rejects every write with a read-only scoped API key', () => {
    for (const def of PAYLOADS) {
      const ro = scenarios.get(`${def.id}#ro`)!;
      expect(ro.writes, `${def.id} read-only writes`).toEqual([]);
      const p = report.payloads.find((r) => r.id === def.id)!;
      expect(p.readOnlyKey.outcome).toBe('blocked');
      expect(['scope', 'egress']).toContain(p.readOnlyKey.guard);
    }
    expect(report.summary.readOnlyWritesAccepted).toBe(0);
  });

  it('blocks model-mode evaluation starts through elicitation, not a self-attested flag', () => {
    const p = report.payloads.find((r) => r.id === 'direct-instruction')!;
    expect(p.outcome).toBe('blocked');
    expect(p.guard).toBe('confirmation');
    expect(scenarios.get('direct-instruction')!.writes).toEqual([]);
    // The injected consent claim is ignored: the user was asked and declined.
    const approved = report.payloads.find((r) => r.id === 'user-already-approved')!;
    expect(approved.outcome).toBe('blocked');
    expect(approved.guard).toBe('confirmation');
    expect(scenarios.get('user-already-approved')!.elicitations.join('\n')).toContain(
      'SENT TO THE MODEL PROVIDER',
    );
  });

  it('refuses every injected write when the client does not support elicitation', () => {
    for (const def of PAYLOADS) {
      const none = scenarios.get(`${def.id}#none`)!;
      expect(none.writes, `${def.id} writes without elicitation`).toEqual([]);
      expect(none.offOrigin).toBe(0);
      expect(none.elicitations).toEqual([]);
      const wrote = none.actions.filter((a) => a.result === 'accepted');
      expect(wrote, `${def.id} accepted actions`).toEqual([]);
    }
  });

  it('blocks all payloads against a full-scope key and marks planted text as untrusted data', () => {
    expect(report.payloads.filter((p) => p.outcome === 'possible').map((p) => p.id)).toEqual([]);
    expect(report.summary.rawUnmarkedOutputs).toBe(0);
    for (const p of report.payloads) {
      expect(['marked', 'absent']).toContain(p.outputMarking);
    }
    // Hidden characters are gone from everything the agent sees in text content.
    for (const def of PAYLOADS) {
      expect(scenarios.get(def.id)!.textObserved, def.id).not.toMatch(
        /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/,
      );
    }
    // The zero-width payload is actually present (de-obfuscated) in a marked envelope.
    expect(report.payloads.find((p) => p.id === 'zero-width-obfuscation')!.outputMarking).toBe('marked');
  });

  it('lets a legitimate write through when the user approves the confirmation', async () => {
    const writes: Write[] = [];
    mockApi(CLEAN, FULL_SCOPES, writes);
    const { client, server, elicitations } = await connectAs('approves');
    const res = await client.callTool({
      name: 'vetkit_run_audit',
      arguments: { repo: 'acme/api', wait: false },
    });
    expect(res.isError, textOf(res)).toBeFalsy();
    expect(writes.some((w) => w.path === '/audits')).toBe(true);
    expect(elicitations).toHaveLength(1);
    expect(elicitations[0]).toContain('acme/api');
    await client.close();
    await server.close();
    msw.resetHandlers();
  });

  it('fails the comparison when a blocked payload regresses to possible', () => {
    const baseline = baselineFrom(report, PAYLOADS);
    expect(compareToBaseline(report, baseline)).toEqual([]);
    const regressed: Report = {
      ...report,
      payloads: report.payloads.map((p, i) => (i === 0 ? { ...p, outcome: 'possible', guard: 'none' } : p)),
    };
    expect(compareToBaseline(regressed, baseline)).toEqual([
      `${report.payloads[0]!.id}: regressed from blocked to possible`,
    ]);
    // A payload that is possible must carry an honest knownGap note.
    const undocumented: Baseline = {
      ...baseline,
      payloads: baseline.payloads.map((p, i) => (i === 0 ? { ...p, outcome: 'possible', guard: 'none' } : p)),
    };
    expect(compareToBaseline(regressed, undocumented)).toEqual([
      `${report.payloads[0]!.id}: possible without a knownGap note in the baseline`,
    ]);
  });

  it('matches the committed baseline and does not regress any payload', () => {
    let text: string;
    try {
      text = readFileSync(BASELINE_URL, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
      // First run: record the baseline. `wx` fails instead of overwriting a file created meanwhile.
      text = `${JSON.stringify(baselineFrom(report, PAYLOADS), null, 2)}\n`;
      mkdirSync(dirname(fileURLToPath(BASELINE_URL)), { recursive: true });
      writeFileSync(BASELINE_URL, text, { flag: 'wx' });
    }
    const baseline = JSON.parse(text) as Baseline;
    expect(compareToBaseline(report, baseline)).toEqual([]);
  });
});
