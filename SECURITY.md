# Security policy

## Reporting a vulnerability

Email **security@vetkit.dev** with a description, the affected version and steps to reproduce. Please do not
open a public issue for a suspected vulnerability. We acknowledge reports within 3 business days and keep you
updated until a fix ships. Our full disclosure policy is at <https://vetkit.dev/en/security/> and our
`security.txt` is at <https://vetkit.dev/.well-known/security.txt>.

Never include a real API key in a report. If a key may have leaked, revoke it at
<https://app.vetkit.dev/settings/api-keys> first.

## Supported versions

Only the latest `0.x` release of `@vetkit/mcp` receives security fixes. Update with `npx -y @vetkit/mcp@latest`
or by bumping the version in your MCP client configuration.

## What the package does and does not do

`@vetkit/mcp` is a thin client for the vetkit REST API. Audits run on vetkit's servers, not on your machine.

- **Transport:** MCP over stdio only. The server opens no network ports and logs only to stderr.
- **Network:** the only outbound requests go to `VETKIT_API_URL` (default `https://api.vetkit.dev`). There is no
  telemetry or analytics. `https://` is required; plain `http://` is accepted only for `localhost`.
- **API key:** read from `VETKIT_API_KEY` and sent only as an `Authorization: Bearer` header to `VETKIT_API_URL`.
  It is never logged, written to disk or included in error messages.
- **Hosted runners:** some MCP directories, such as Glama, can run the server for you. The API key is then stored
  by that service, not only on your machine. Give such a deployment a narrowly scoped key with an expiry, or run
  the package locally with `npx`.
- **Narrow API surface:** the bundled client exposes only the 37 API methods the tools use. Administrative,
  billing and account-management endpoints are not in the package. The API key's scopes decide what the server
  can do; read-only keys cannot start audits or change data.
- **Local system:** the package does not spawn processes, run repository code or write files. Repository memory
  tools return file content; they never write `AGENTS.md` or `CLAUDE.md` themselves.
- **Untrusted content:** repository and API text in tool results is wrapped in an `<untrusted-data>` envelope with
  a random boundary per response, so clients can tell data from instructions.
- **Confirmation:** tools that change data ask the user to confirm through MCP elicitation before they run. A
  prompt-injection regression suite (`src/agent-attack-harness.spec.ts`) checks this on every test run.
- **Dependencies:** three runtime dependencies (`@modelcontextprotocol/sdk`, `re2js`, `zod`). `re2js` gives
  linear-time regular expressions for user-supplied AI Evaluation patterns, so a crafted pattern cannot stall
  the process.

## Claude Code hook fails open

`vetkit-mcp hook pre-tool-use` blocks package installs that vetkit rejects. By design it **fails open**: when
`VETKIT_API_KEY` is missing, the API cannot be reached, the request times out (15 seconds) or the hook input is
malformed, it prints a warning and allows the command. A coding agent is never stuck because vetkit is
unavailable, but it also means the hook is a guardrail, not an enforcement boundary. For enforcement, use the
organization policy and the pull request gate, which run on vetkit's servers.
