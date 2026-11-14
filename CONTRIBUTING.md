# Contributing

Thanks for helping improve `@vetkit/mcp`. Please report security issues privately as described in
[SECURITY.md](SECURITY.md), not in public issues.

## How this repository works

`@vetkit/mcp` is developed inside vetkit's private monorepo and exported here with every release. This
repository holds the complete source of the published package, its tests and its release pipeline:

- `src/`: the MCP server, its tools and the Claude Code hook.
- `vendor/`: generated, read-only code from vetkit's internal packages: the API client and the shared schemas
  the server uses. It contains only what `src/` imports, the same code that ships in the npm package. Do not edit
  it by hand; changes are made in the monorepo and exported.
- `test/` and `src/**/*.spec.ts`: unit tests, including a prompt-injection regression suite
  (`src/agent-attack-harness.spec.ts`).

Pull requests are welcome. A maintainer ports accepted changes to the monorepo, and they come back here with the
next export, credited to you in the changelog.

## Development

Requires Node.js 22.12 or newer for the toolchain (the published server runs on Node.js 20.3+).

```sh
npm ci
npm run typecheck
npm run lint
npm test
npm run build
npm run smoke
```

The smoke test starts the built server over stdio and sends no API request.

## Releases

Releases are cut by pushing a `vX.Y.Z` tag that matches `package.json`. The
[release workflow](.github/workflows/release.yml) runs the checks and publishes to npm with
[trusted publishing](https://docs.npmjs.com/trusted-publishers): no npm token is stored, and every version carries
a provenance statement that links it to the commit and workflow run that built it. Verify a version with:

```sh
npm view @vetkit/mcp dist.attestations
npm audit signatures
```
