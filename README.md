# @vetkit/mcp

[Model Context Protocol](https://modelcontextprotocol.io) server for [vetkit](https://vetkit.dev). It lets any stdio-capable MCP client — including Cursor, VS Code / GitHub Copilot, Codex, Claude Code and Claude Desktop — connect GitHub, Bitbucket Cloud and GitLab.com repositories, run vetkit code audits and read findings and reports, all from your editor or chat. Audits offer five scored suites, together or on their own: **Security** (exposed credentials, leaked secrets, vulnerable dependencies, SAST), **Code quality** (bug risks and code smells, complexity, duplicated code, test maturity, documentation, repository health), **Sustainability** (dependency licenses, deprecated or outdated dependencies, maintenance activity), **AI code risks** (hallucinated packages, unfinished code, app platform pitfalls, LLM and agent security, plus an informational AI authorship signal) and **Production readiness** (resilience, database usage and operational readiness). Two additional opt-in suites are unscored: **Privacy & Data Protection** is a beta source review, not a GDPR/KVKK compliance certificate; **Git history** samples commits, contributor activity and change hotspots, not productivity or measured speedups.

```text
> Audit acme/api and tell me what to fix first.

● vetkit_run_audit(repo: "acme/api")
  Grade D (score 78/100) — Security D (73/100) · Code quality B (89/100)
  9 findings: 1 critical, 3 medium, 5 low
● vetkit_list_findings(auditId: "…", severity: ["CRITICAL","HIGH"])
```

## Requirements

- Node.js 20.3 or newer (`npx` must be on your `PATH`)
- A vetkit API key. Create one in the vetkit app under **Settings → API keys** (<https://app.vetkit.dev/settings/api-keys>). The key is shown **once**. Copy it straight into your MCP client config.

## Quick start: any local MCP client

MCP is an open protocol, **not a Claude-only integration**. vetkit uses the standard **stdio** transport. Add a local MCP server named `vetkit` in your client with these launch settings:

```json
{
  "command": "npx",
  "args": ["-y", "@vetkit/mcp"],
  "env": { "VETKIT_API_KEY": "<your-api-key>" }
}
```

Replace the placeholder with your API key. This is a **server definition**, not a universal config file: the wrapper is client-specific (`mcpServers`, VS Code `servers`, Codex TOML, etc.). Merge the entry with existing settings, reload the client and confirm `vetkit_list_repos` appears in its tool list. All clients have the same tools and API-key scope checks.

Clients that only accept **remote HTTP/SSE MCP servers cannot connect directly**. This package does not expose a remote MCP endpoint; the REST API URL is not an MCP server URL.

Treat any configuration containing your key as a secret. Do not commit it; use the client's secure secret storage if available.

## Client setup

### VS Code / GitHub Copilot

Merge into `.vscode/mcp.json` (uses `servers`, not `mcpServers`), then start and approve vetkit from the MCP server list:

```json
{
  "servers": {
    "vetkit": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@vetkit/mcp"],
      "env": { "VETKIT_API_KEY": "<your-api-key>" }
    }
  }
}
```

### Codex CLI / IDE extension

Add to `~/.codex/config.toml` without replacing existing settings, then restart your client and verify with `codex mcp list`:

```toml
[mcp_servers.vetkit]
command = "npx"
args = ["-y", "@vetkit/mcp"]

[mcp_servers.vetkit.env]
VETKIT_API_KEY = "<your-api-key>"
```

### Claude Code

```sh
claude mcp add --transport stdio vetkit -e 'VETKIT_API_KEY=<your-api-key>' -- npx -y @vetkit/mcp
```

Add `--scope user` to make it available in every project. Then run `/mcp` inside Claude Code to check that `vetkit` is connected.

### Claude Desktop

Edit `claude_desktop_config.json` (**Settings → Developer → Edit Config**):

```json
{
  "mcpServers": {
    "vetkit": {
      "command": "npx",
      "args": ["-y", "@vetkit/mcp"],
      "env": { "VETKIT_API_KEY": "vk_live_..." }
    }
  }
}
```

### Cursor

Add to `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (project; **do not commit it** if it contains the key):

```json
{
  "mcpServers": {
    "vetkit": {
      "command": "npx",
      "args": ["-y", "@vetkit/mcp"],
      "env": { "VETKIT_API_KEY": "vk_live_..." }
    }
  }
}
```

### Other MCP clients

Any client that can launch a stdio server works: run `npx -y @vetkit/mcp` with `VETKIT_API_KEY` in its environment. You can also install it globally (`npm i -g @vetkit/mcp`) and run the `vetkit-mcp` binary directly.

## Configuration

| Variable         | Required | Default                  | Description                                                                                   |
| ---------------- | -------- | ------------------------ | --------------------------------------------------------------------------------------------- |
| `VETKIT_API_KEY` | yes      |                          | API key (`vk_live_…` or `vk_test_…`).                                                         |
| `VETKIT_API_URL` | no       | `https://api.vetkit.dev` | API base URL. Must be `https://` (plain `http://` only for `localhost`).                      |
| `VETKIT_APP_URL` | no       | `https://app.vetkit.dev` | Web app base URL, used for links to audits.                                                   |
| `VETKIT_ORG_ID`  | no       | the key's organization   | Organization id. API keys belong to exactly one organization, so this is normally not needed. |

`vetkit-mcp --help` and `vetkit-mcp --version` print usage and the version.

## Tools

- `vetkit_list_repos`: Lists connected repositories with their latest grade. Paginated (`limit`, `cursor`). Scopes: `repos:read`.
- `vetkit_connect_repo`: Connects a repository (`url`: GitHub, Bitbucket Cloud or GitLab.com URL, or `owner/name` for GitHub). Optional `accessToken` connects a private Bitbucket or GitLab repository; the token is stored for later audits. Needs user confirmation. For GitHub App access, a missing installation returns the install URL. Scopes: `repos:write`.
- `vetkit_run_audit`: Runs an audit. `repo` can be a repository id, `owner/name` for GitHub, or a GitHub, Bitbucket Cloud or GitLab.com URL. A GitHub URL can include `/tree/<branch>`. The repository is connected automatically if needed; connect private Bitbucket or GitLab repositories first with `vetkit_connect_repo` and `accessToken` (this tool does not accept a token). Needs user confirmation. `mode: "QUICK"` is a free Quick Scan (10 per month per workspace owner: `posture`, `gitleaks` and `osv` on the latest commit of the default branch, without media files); `mode: "FULL"` is a full scan that costs 1 credit, charged to the workspace owner for API keys (reserved while it runs, spent only when the complete report is saved). Without `mode`, a Quick Scan runs unless `ref`, `suites` or `analyzers` are given. Waits for the result by default (`wait`, `timeoutSeconds` = 600) and sends progress notifications. In a full scan, choose what runs with `suites` (any of `"security"`, `"quality"`, `"sustainability"`, `"ai-risks"`, `"production"`, `"privacy"` and `"git-history"`; selects available checks enabled by default, while explicit `"privacy"` and `"git-history"` include their available opt-in checks) or exact `analyzers` (check ids, see below), which override `suites`. Omitting both uses the repository setting. `excludeAssets: true` skips downloading media files (images, video, audio, 3D models, fonts, design files, PDFs); it defaults to the repository setting. Scopes: `repos:read`, `audits:read`, `audits:run` (or `audits:write`); add `repos:write` only to auto-connect.
- `vetkit_list_checks`: The checks vetkit can run, grouped by suite, with the tool and version each uses, whether it is available on the server and which run by default. Scopes: `audits:read`.
- `vetkit_get_audit`: Status, applicable overall and per-suite grades, score, finding counts and per-check progress (with metrics such as duplication % and average complexity) of an audit. Scopes: `audits:read`.
- `vetkit_list_findings`: Findings of an audit, filterable by `severity`, `suite` (`SECURITY` / `QUALITY` / `SUSTAINABILITY` / `AI_RISKS` / `PRODUCTION` / `PRIVACY` / `GIT_HISTORY`), `category` and `status` (`NEW` / `EXISTING`), paginated. Returns a compact table, plus full details (message, redacted snippet, remediation, references) as structured content. Scopes: `findings:read`.
- `vetkit_get_report`: The full report as `markdown` (default), `json` (summary, suite and category scores, diff vs. previous audit) or `sarif` (SARIF 2.1.0). Output beyond `maxChars` (default 40,000) is truncated, with a note. Optional `raw: true` (json/sarif only) returns the bare document, un-enveloped and untrusted, plus a warning item; it is refused instead of truncated when over `maxChars`. Scopes: `reports:read`.
- `vetkit_list_evaluations`: AI Evaluation runs with id, mode, profile and status. Scopes: `audits:read`.
- `vetkit_get_evaluation`: One evaluation run: verdict, summary counts, pass rate, calls and cost (unknown cost is stated, never zero) and up to 50 result cells. Model outputs and prompts are omitted; export the full report from the web UI. Scopes: `audits:read`.
- `vetkit_list_evaluation_baselines`: Evaluation baselines, or with `baselineId` the versions of one baseline. Scopes: `audits:read`.
- `vetkit_compare_evaluation_baseline`: Compares a run to a baseline version (`baselineVersionId`, `evaluationId`): PASS, FAIL or BLOCKED, reasons and regression/improvement counts. Informational only, not a release gate or PR check. Scopes: `audits:read`.
- `vetkit_start_evaluation`: Starts an evaluation run from a `suite` (demo by default). Model mode needs `connections`; prompts and test data go to the model provider and charges may apply, which the user must confirm (see below). Optional `idempotencyKey` for safe retries. Rubric runs are not supported from MCP. Scopes: `audits:write`.
- `vetkit_cancel_evaluation`: Requests cancellation of a queued or running run (`evaluationId`). In-flight provider calls may still be billed. Needs user confirmation. Scopes: `audits:write`.
- `vetkit_open_fix_pr`: Opens a draft GitHub PR upgrading the vulnerable npm dependency of a dependency finding (`findingId`) to its fixed version; `package.json` and `package-lock.json` change together, offline and deterministically. Needs user confirmation and an API key created by an organization administrator. pnpm/yarn lockfiles, manifest-only scans, non-npm ecosystems and missing GitHub App write permissions are refused with a reason. Draft only: CI and review are still required. Scopes: `findings:write`.
- `vetkit_suggest_fix`: Proposes a minimal source patch for a code finding (`findingId`: SAST, secrets, LLM-app, IaC) using the AI provider the organization saved and verified in Settings, or the rule's deterministic fix when the analyzer supplies one. Returns a unified diff, explanation, confidence and a verification status (`VERIFIED` when the producing rule no longer matches the patched file, `NOT_RUN` otherwise). Only a redacted window of about 60 lines is sent to the provider; nothing is written (no branch, commit or PR). Dependency findings use `vetkit_open_fix_pr`. Scopes: `findings:write` (or the preview-only `findings:ai-fix`) on an API key created by an organization administrator.
- `vetkit_triage_findings`: Asks the organization's saved AI provider whether up to 20 findings of an audit (`auditId`, `findingIds`) are likely true or false positives: verdict, confidence and a one-line rationale each; a redacted ±40-line window is sent. Advisory only: it adjusts priority but never suppresses a finding or changes the score or gate. Scopes: `findings:write`.
- `vetkit_get_standards_report`: Maps an audit's open findings to a security standard (OWASP Top 10, CWE Top 25, OWASP LLM Top 10); each category is `fail`, `pass` or `not_covered`. Coverage of CWE-mapped findings, not a compliance certification. Scopes: `reports:read`, `findings:read`.
- `vetkit_get_repo_monitoring`: Shows whether a connected repository (`repo`) is scanned automatically (off, daily, weekly or the organization default), the last and next scheduled run and new advisories affecting the last scan inventory. Scopes: `repos:read`.
- `vetkit_set_repo_monitoring`: Sets the continuous-monitoring `schedule` of a repository (`DEFAULT`, `OFF`, `DAILY`, `WEEKLY`) on the default branch; unchanged commits are skipped without spending a scan. Needs user confirmation. Scopes: `repos:write`.
- `vetkit_validate_policy`: Validates the YAML text of a `vetkit.policy.yaml` against the policy schema and previews how the organization policy treats it (a repository file may only tighten it): syntax errors with line/column, schema errors with field paths and the fields the organization would ignore. Nothing is saved. See [policy and exceptions](https://vetkit.dev/en/docs/policy-exceptions/). Scopes: `repos:read`.
- `vetkit_list_pr_reviews`: Pull/merge request reviews vetkit ran as a PR gate, newest first, org-wide or for one `repo` (connected UUID, `owner/name` or URL), filterable by `status` (`pending`, `success`, `failure`, `neutral`, `cancelled`). Each row has the PR link, head and base audit ids, the component gate result and the inline comment status. Fork PRs from outside contributors that still wait for a maintainer's `/vetkit review` comment have no review and are not listed. Paginated. Scopes: `repos:read`, `reports:read`.
- `vetkit_get_pr_review`: vetkit's latest review of one PR (`repo`, `prNumber`): gate state, check-run summary, component violations and the delta findings (new in the PR head, including any rule-provided `deterministicFix`). When there is no review, the result explains the likely reasons (fork PR waiting for `/vetkit review`, draft, PR reviews not enabled) instead of failing. Scopes: `repos:read`, `reports:read`, `findings:read`.
- `vetkit_list_work_items`: Remediation work items with status, priority, assignee, due date, fix link and fix verification status (`NOT_CHECKED`, `MANUAL_CLOSED`, `NOT_OBSERVED`, `REAPPEARED`, `UNVERIFIABLE` with the reason). Filter by `status`, `priority`, `repo`, `verificationStatus`, `search`, `overdue`, `actionable`, `pendingReview`; `workItemId` returns one item and `findingId` the item tracking a finding. Paginated. Scopes: `findings:read`.
- `vetkit_update_work_item`: Changes the `status` (`OPEN`, `IN_PROGRESS`, `RESOLVED`), `priority` or `fixUrl` of a work item (`workItemId`, optional `version` for optimistic concurrency) and/or verifies its fix against a newer audit of the same branch (`verifyAgainstAuditId`). Risk acceptance and false-positive decisions stay in the web app. Needs user confirmation. Scopes: `findings:write`.
- `vetkit_list_suppressions`: Suppressions of the organization (finding fingerprints excluded from scores and gates with a reason), optionally only the `active` ones or those of one `repo`. Paginated. Scopes: `findings:read`.
- `vetkit_suppress_finding`: Suppresses a finding (`findingId`) with a `reason` (3–500 characters) and an optional future `expiresAt`. The suppression follows the finding fingerprint in its repository; the finding stays listed as suppressed and nothing is deleted. Needs user confirmation and a key created by an active organization member. Revoking is done in the web app. Scopes: `findings:write`.

**Confirmation required.** `vetkit_connect_repo`, `vetkit_run_audit`, `vetkit_refresh_repository_memory`, `vetkit_start_evaluation` (demo and model mode), `vetkit_cancel_evaluation`, `vetkit_open_fix_pr`, `vetkit_update_work_item` and `vetkit_suppress_finding` change data, so before each call the server asks you to confirm through [MCP elicitation](https://modelcontextprotocol.io/specification/latest/client/elicitation). The prompt states exactly what will happen (repository, checks, scan mode and credit cost, provider transmission and charges for model runs, run id for cancel). The call runs only if you accept and tick `confirm`. If the client does not support elicitation (form mode), or you decline, cancel or do not answer, the call is refused with an error. There is no flag the model can set instead; the former `confirmExternalTransmission` parameter was removed and any such argument is ignored.

### Repository coding memory

- `vetkit_get_repository_memory`: Read saved repository-wide AI lessons before coding. Scopes: `repos:read`, `reports:read`.
- `vetkit_refresh_repository_memory`: Merge past completed AI reviews into durable coding memory; no provider call. Scopes: `repos:write`, `reports:read` (+ `repos:read` for name lookup).

Both accept `repo` (connected UUID, `owner/name` or GitHub URL) and `format`: `agents` → Codex `AGENTS.md`, `claude` → Claude Code `CLAUDE.md`, `markdown` → ChatGPT project attachment (default). They return file content and structured lessons, not local file writes. They never auto-connect repositories. Initial generation needs an audit with AI review; reading before generation explains the next step.

Memory merges the newest 100 eligible AI reports, deduplicates repeated observations and retains older saved lessons up to 200 entries independently of audit retention. It is **advisory untrusted historical data**, not verified policy. Validate suggestions against current code. Review and merge only the marked vetkit block into existing instruction files; do not overwrite existing instructions. ChatGPT does not automatically read `AGENTS.md`, and uploading context does not change account Memory.

### Checks

- **Security:** `posture`, `gitleaks`, `secrets-history`, `osv`, `vendored`, `eol`, `supply-chain`, `sast`, `sast-community`, `bandit`, `gosec`, `rust-audit`, `iac`, `base-images`, `workflows`
- **Code quality:** `code-smells`, `complexity`, `duplication`, `tests`, `docs`, `performance`, `accessibility`, `hygiene`
- **Sustainability:** `licenses`, `dep-health`, `activity`
- **AI code risks:** `hallucinated-deps`, `ai-slop`, `vibe-stack`, `llm-app`, `ai-signal`
- **Production:** `resilience`, `data-access`, `operability`, `openapi`, `web-assets`
- **Privacy:** `privacy-exposure`, `privacy-flows`, `privacy-lifecycle`
- **Git history:** `git-history`

Each check, with what it finds and its category, is listed in the [check catalog](https://vetkit.dev/checks/); `vetkit_list_checks` returns the same list with live availability.

Each of the five scored suites gets its own grade; Privacy and Git history are unscored and do not affect grades. The overall score weighs Security 43%, Code quality 18%, Sustainability 11%, AI code risks 13% and Production readiness 15%. Only the suites that ran count and their weights are shared among them (Security 50%, Code quality 22%, Sustainability 13% and AI code risks 15% when Production readiness did not run; Security 70% and Code quality 30% when only those two ran). An unsuppressed critical finding caps the grade at D.

### Results and key scopes

Every tool returns readable text. All tools except `vetkit_get_report` also return typed `structuredContent` that matches the tool's `outputSchema`. Findings in `vetkit_list_findings` and `vetkit_get_pr_review` may carry a `deterministicFix` (rule-provided replacement: 1-based lines, exclusive `endCol`, columns in UTF-16 code units when `columnUnit` is `utf16`, plus the `original` text of the range). Agents must check that the current file text equals `original` before applying `replacement`; legacy fixes without `columnUnit` use UTF-8 byte columns and are only safe on ASCII lines. Tools carry MCP annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`), so clients can auto-approve the read-only ones. None of the tools delete anything.

**Attack-path lens:** new full JS/TS security audits include bounded endpoint → authorization → sensitive-operation hypotheses in `vetkit_get_report` JSON/Markdown, with evidence and uncertainty on every link. These are not verified attacks and do not add scored findings. Historical/quick-scan/failed/limited reports are not safety verdicts. SARIF stores the lens in run properties, not new results. If `maxChars` truncates the report, raise the limit or open the full report before drawing conclusions.

**Recommended key scopes for repository audits and AI Evaluations:** `repos:read`, `repos:write`, `audits:read`, `audits:write`, `findings:read`, `reports:read`. Starting and cancelling AI Evaluation runs require `audits:write`. Updating work items and suppressing findings require `findings:write`.

For repository audits alone, use `audits:run` instead of `audits:write`: it allows starting audits without granting audit cancellation, deletion or AI provider verification. `repos:write` is needed only when connecting a new repository; already-connected repositories need `repos:read`. Keep `audits:read` to select checks and follow progress, and `findings:read` / `reports:read` to inspect results. Existing keys with `audits:write` continue to work.

For a read-only setup, omit `repos:write`, `audits:write` and `audits:run`. Attempts to start audits or change data then return `INSUFFICIENT_SCOPE`; reading existing audits remains available.

### Agent guardrails

- `vetkit_check_packages`: Call before `npm`/`pnpm`/`yarn`/`bun` install or add, `pip install`, `uv add`, `cargo add` or `go get`. Checks up to 50 packages of one ecosystem (`npm`, `pypi`, `cargo`, `go`, `rubygems`, `nuget`, `maven`) against the public registry and the org policy. Scopes: `agent:check`.
- `vetkit_scan_changes`: Call before committing. Scans up to 30 changed files (512 KB in total) in memory for exactly-shaped secrets, risky agent configuration and hidden instructions, unfinished code, and imports or dependencies of packages that do not exist. Nothing is stored or run. Scopes: `agent:check`.

Both return `verdict` `allow`, `warn` or `block` with reasons. **Block:** the package does not exist (hallucinated or slopsquatted name), an OSV `MAL-` record, a CISA KEV advisory (when the policy blocks known-exploited), a license on the organization's `licenses.deny` list, or a committed secret. **Warn:** an unpublished version, a release younger than `releaseAge.minDays` (7 days by default), low adoption (fewer than 100 npm downloads a week, or a package first published in the last 30 days), an advisory at or above `vulnerabilities.minimumSeverity`, or other code findings. Approved policy exceptions waive license and advisory reasons. Sources that cannot be reached are listed under `warnings`; those checks are skipped, never guessed. The API is `POST /v1/orgs/{orgId}/agent-checks/packages` and `/changes` (60 calls per minute per key; a browser session needs the MEMBER role). The audit log records counts and verdicts only.

**Claude Code hook.** `vetkit-mcp hook pre-tool-use` reads Claude Code's PreToolUse JSON from stdin, finds package installs in `Bash` commands and exits `2` with the reason on stderr when vetkit blocks a package, so Claude Code stops the command. Otherwise it exits `0` and prints warnings. It fails open: without `VETKIT_API_KEY`, or when the API cannot be reached, it warns and allows the command. Add it to `.claude/settings.json` and export `VETKIT_API_KEY` (a key with `agent:check`) in the shell that starts Claude Code, not in a committed file. Claude Code runs hook commands with its own environment, so the `env` block of the MCP server entry does not reach the hook:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "npx -y @vetkit/mcp hook pre-tool-use", "timeout": 30 }]
      }
    ]
  }
}
```

For Cursor and other clients without hooks, add a rule telling the agent to call `vetkit_check_packages` before installing and `vetkit_scan_changes` before committing. The MCP page in the web app has a ready-made Cursor rule.

### Long-running audits

An audit usually finishes in 1–3 minutes. `vetkit_run_audit` polls every 3 seconds and sends MCP progress notifications while it waits. Some clients stop tool calls after a fixed time (for example, Claude Code respects `MCP_TOOL_TIMEOUT`). If yours does, pass `wait: false` and poll with `vetkit_get_audit`. When `timeoutSeconds` runs out, the audit keeps running and the tool returns `outcome: "still_running"`.

## Errors

API errors come back as tool results with `isError: true`. Each one carries the HTTP status, the vetkit error code, the detail message, the request id and a hint. For example:

- `401 API_KEY_REVOKED` / `API_KEY_EXPIRED` / `API_KEY_INVALID`: the key no longer works. Create or rotate one at <https://app.vetkit.dev/settings/api-keys>, update `VETKIT_API_KEY` and restart the server. After a rotation, the old key stays valid for 24 hours.
- `403 INSUFFICIENT_SCOPE`: the key lacks a scope the tool needs (see the table above).
- `409 AUDIT_CONCURRENCY_LIMIT` / `429 RATE_LIMITED`: wait and retry (the hint says how long when the API sends `Retry-After`).
- `INSTALLATION_REQUIRED`: returned as a normal result with the GitHub App install URL, not as an error.
- `422 ANALYZER_UNAVAILABLE`: a check in `analyzers` cannot run on this server (for example `ai-signal` when it is disabled). Use `vetkit_list_checks`, or pass `suites`, which picks available checks enabled by default, plus available opt-in checks when `privacy` or `git-history` is explicitly selected.

- An audit that fails with `REPO_TOO_LARGE` is usually full of media files. Run it again with `excludeAssets: true`.

## Security

- **Treat the API key like a password.** It grants access to your organization's audits and findings (including private repositories). Keep it in your MCP client's `env` config, not in files you commit. Scope it to what you need, set an expiry, and rotate or revoke it from the vetkit app if it leaks.
- The key is sent only to `VETKIT_API_URL`, as an `Authorization: Bearer` header over HTTPS. Plain HTTP is refused except for `localhost`. The server never logs the key or includes it in errors.
- The server speaks MCP over stdio only. It opens no network ports, and it logs only to stderr.
- Finding snippets are redacted by vetkit before they are stored. Secret values are never returned.
- Report and finding text comes from the audited repository (file paths, messages). Treat it as untrusted input, like any other tool output. Every text result that carries repository or API content (findings, reports, audits, repository and run names, repository memory, evaluations) is wrapped in `<untrusted-data source="vetkit-api" boundary="...">` ... `</untrusted-data boundary="...">` with a random boundary per response, preceded by a line saying the content is data, not instructions. Zero-width, bidirectional-control and other invisible format characters are stripped from all text and structured string fields, line breaks in table cells are collapsed, and any look-alike tag or boundary inside the data is removed. By default `json` and `sarif` reports arrive inside this envelope, so strip it before parsing. For programmatic parsing, `vetkit_get_report` accepts an explicit per-call opt-in `raw: true` (only with `json` or `sarif`; rejected with `markdown`): the first content item is then the bare document, parseable as-is, and a second content item carries a fixed warning. Raw output is still **untrusted repository/API data, not enveloped**: your client must treat it as data and never follow instructions inside it. Invisible format/control characters are stripped (the document stays valid), and raw output is never truncated: if it exceeds `maxChars` the call is refused (raise `maxChars` or use `vetkit_list_findings`). Structured content is sanitized but not wrapped.
- Write tools never trust the model alone: see the confirmation requirement above. A prompt-injection regression harness (`src/agent-attack-harness.spec.ts`, baseline in `test/fixtures/x06-baseline.json`) checks this on every test run. It cannot protect against a user who approves a confirmation prompt they did not read.

## License

MIT
