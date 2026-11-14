# Changelog

All notable changes to `@vetkit/mcp` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.3.2] - 2026-11-14

### Security

- Trailing slashes are trimmed from `VETKIT_API_URL` and `VETKIT_APP_URL` in linear time. The previous regular
  expression could take quadratic time on a value with a very long run of `/` characters (found by CodeQL). Both
  values come from your own environment, so the practical risk was low.

### Changed

- Source, tests and the release pipeline are public at <https://github.com/vetkit/mcp>. Releases are built by
  GitHub Actions with npm trusted publishing and carry a provenance statement.

## [0.3.1] - 2026-11-14

### Security

- The bundled API client exposes only the 37 methods the tools and the hook call. Admin, billing and
  account-management endpoints and their types are no longer in the package.
- Internal source comments are stripped from the published JavaScript and type declarations.
- Added `SECURITY.md` with the reporting address, supported versions, what the package does on your machine and
  the fail-open behaviour of the Claude Code hook.

### Changed

- The README is shorter: tool tables are lists, and the per-check table moved to the
  [check catalog](https://vetkit.dev/checks/).

## [0.3.0] - 2026-11-12

### Changed

- vetkit has no Pro or Free plans any more: every workspace has every feature and scans use credits.
  `vetkit_run_audit` takes `mode`: `"QUICK"` is the free monthly Quick Scan (posture, gitleaks and osv on the
  latest commit of the default branch) and `"FULL"` is a full scan that costs 1 credit. Without `mode`, a Quick
  Scan runs unless `ref`, `suites` or `analyzers` are given. The confirmation prompt states the mode and its cost,
  and audit results report `mode` and `credited`.
- Errors explain `INSUFFICIENT_CREDITS` (402, with required and available credits), used-up Quick Scans,
  `ORG_LIMIT_REACHED`, `REPO_LIMIT_REACHED` and Quick Scan scope violations instead of the removed
  `PLAN_REQUIRED`. Tool descriptions no longer mention plans.

## [0.2.0] - 2026-11-08

### Added

- `vetkit_list_evaluations` pages through older AI Evaluation runs with an optional `before` argument instead
  of stopping at the first page.
- `vetkit_run_audit` accepts keys with the start-only `audits:run` scope as well as `audits:write`.
- The pre-tool-use hook (`vetkit-mcp hook pre-tool-use`) also checks `pnpm install <pkg>` / `pnpm i <pkg>`,
  `yarn global add`, `yarn workspace <name> add`, `poetry add` and installs run through `bash -c` / `sh -lc`.
- The code quality suite now includes the performance analyzer, which left beta.
- `vetkit_list_pr_reviews` and `vetkit_get_pr_review` read the PR gate reviews: state (pending, success,
  failure, neutral, cancelled), component gate violations, the check-run summary and the delta findings of a
  pull request. A PR without a review is explained (fork PR waiting for a maintainer's `/vetkit review`
  comment, draft, PR reviews not enabled) instead of failing.
- Findings returned by `vetkit_list_findings` and `vetkit_get_pr_review` include the rule-provided
  `deterministicFix` (UTF-16 columns and the `original` text of the range) so an agent can verify the range
  before applying the replacement.
- `vetkit_list_work_items` and `vetkit_update_work_item` read remediation work items with their fix
  verification status, change status, priority or fix link, and verify a fix against a newer audit.
- `vetkit_list_suppressions` and `vetkit_suppress_finding` list suppressions and suppress a finding with a
  reason and optional expiry (`findings:write`, confirmed through MCP elicitation).

### Fixed

- `vetkit_run_audit` with a suite that the organization's Free Quick Scan plan does not include says so
  instead of reporting that the checks are unavailable on the server, and other unavailable suites name the
  server's reason.
- A rate-limited audit status poll waits for the server's `Retry-After` instead of using up its retries in
  seconds.
- `vetkit_connect_repo` reports a GitHub repository that is already connected without the GitHub App (with a
  token or provider account) as connected instead of asking you to install the App.
- `vetkit_connect_repo` and `vetkit_run_audit` also find a repository connected under its new name after a
  GitHub rename or transfer (the API resolves the old name by its GitHub repository id), instead of asking you
  to install the App.
- When polling a started audit fails, the tool result keeps the audit id, its link and a hint not to start
  another audit. A succeeded audit without a summary shows unknown totals instead of zeros.
- Validation errors list each rejected field (`- field: message`) instead of only "Request validation failed",
  and limits checked before sending (total scan size, duplicate paths) no longer surface as an unexpected
  error.
- Repository authorization errors explain how to recover for GitHub App, provider account and token
  connections, and missing-scope errors mention that a key whose creator lost write access must be replaced.
- Without `VETKIT_API_KEY`, the pre-tool-use hook now says to export the key in the shell that starts Claude
  Code (hooks do not see the MCP server's environment), matching the README, instead of pointing at the MCP
  client's server environment.
- The pre-tool-use hook no longer blocks on here-document bodies, on values of options that take an argument
  (`--omit dev`, `--report out.json`, `--marker ...`), or on a whole ecosystem group when one version
  specifier is rejected.
- Cancelling a tool call also cancels reading an error response, unknown API error codes keep their problem
  details, and request timeouts are reported as timeouts.

## [0.1.0] - 2026-11-01

### Added

- First public release: stdio MCP server for connecting GitHub, Bitbucket and GitLab repositories, running
  audits and reading findings and reports, plus the `vetkit-mcp hook pre-tool-use` check. Listed in the MCP
  Registry as `dev.vetkit/mcp`.
