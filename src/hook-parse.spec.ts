import { type AgentCheckResult } from '#vendor/shared';
import { describe, expect, it, vi } from 'vitest';

import { parseInstallCommands, splitShell } from './hook-parse.js';
import { HOOK_EXIT_ALLOW, HOOK_EXIT_BLOCK, runPreToolUseHook } from './hook.js';

describe('splitShell', () => {
  it('splits on operators and honours quotes and escapes', () => {
    expect(splitShell(`cd app && npm i "left pad" 'a;b' x\\ y; echo "x && y" | cat # npm i evil`)).toEqual([
      ['cd', 'app'],
      ['npm', 'i', 'left pad', 'a;b', 'x y'],
      ['echo', 'x && y'],
      ['cat'],
    ]);
  });
});

describe('parseInstallCommands', () => {
  it.each([
    'npm --save-dev install expresss',
    'pnpm -D add expresss',
    'npm --ignore-scripts install expresss',
    'yarn --dev add expresss',
    'npm -P install expresss',
    'pnpm --save-optional add expresss',
    'npm --ignore-scripts=true install expresss',
    'npm --save-dev=false install expresss',
  ])('keeps checking installs with known leading boolean options: %s', (command) => {
    expect(parseInstallCommands(command)).toEqual([{ ecosystem: 'npm', packages: [{ name: 'expresss' }] }]);
  });

  it.each([
    [
      'npm install express lodash@4.17.21',
      'npm',
      [{ name: 'express' }, { name: 'lodash', version: '4.17.21' }],
    ],
    ['npm i -D @types/node@^20 --save-exact', 'npm', [{ name: '@types/node', version: '^20' }]],
    ['pnpm add -w zod@latest', 'npm', [{ name: 'zod' }]],
    ['yarn add react@18.3.1 --dev', 'npm', [{ name: 'react', version: '18.3.1' }]],
    ['npm add alias@npm:real-pkg@2.0.0', 'npm', [{ name: 'real-pkg', version: '2.0.0' }]],
    [
      'pip install requests==2.31.0 "flask>=3" -r requirements.txt',
      'pypi',
      [{ name: 'requests', version: '2.31.0' }, { name: 'flask' }],
    ],
    ['python3 -m pip install --upgrade numpy[extra]==1.26.4', 'pypi', [{ name: 'numpy', version: '1.26.4' }]],
    ['uv add httpx', 'pypi', [{ name: 'httpx' }]],
    ['uv pip install -i https://pypi.org/simple pydantic', 'pypi', [{ name: 'pydantic' }]],
    [
      'cargo add serde@1.0.200 -F derive tokio',
      'cargo',
      [{ name: 'serde', version: '1.0.200' }, { name: 'tokio' }],
    ],
    [
      'go get github.com/gin-gonic/gin@v1.10.0 golang.org/x/net',
      'go',
      [{ name: 'github.com/gin-gonic/gin', version: 'v1.10.0' }, { name: 'golang.org/x/net' }],
    ],
    ['sudo FOO=1 npm install -g typescript', 'npm', [{ name: 'typescript' }]],
  ])('%s', (command, ecosystem, packages) => {
    expect(parseInstallCommands(command)).toEqual([{ ecosystem, packages }]);
  });

  it.each([
    'npm install',
    'npm ci',
    'npm run build',
    'npm install ./local-pkg ../other /abs file:x git+https://github.com/a/b.git https://x.dev/a.tgz',
    'pip install -e . -r requirements.txt',
    'cargo add --path ../crate mycrate',
    'cargo add --git https://github.com/a/b crate',
    'go get ./... ',
    'go get github.com/a/b@none',
    'echo npm install express',
    'pnpm install',
  ])('ignores %s', (command) => {
    expect(parseInstallCommands(command)).toEqual([]);
  });

  it.each([
    ['pnpm --filter app add lodash', 'npm', 'lodash'],
    ['npm --prefix app install lodash', 'npm', 'lodash'],
    ['yarn --cwd app add lodash', 'npm', 'lodash'],
    ['uv --directory app add requests', 'pypi', 'requests'],
    ['go -C app get github.com/acme/module', 'go', 'github.com/acme/module'],
    ['pnpm --filter=app --recursive add lodash', 'npm', 'lodash'],
  ])('recognizes leading option values without treating them as the verb: %s', (command, ecosystem, name) => {
    expect(parseInstallCommands(command)).toEqual([{ ecosystem, packages: [{ name }] }]);
  });

  it.each(['pnpm --filter add exec tool', 'npm --prefix install run build', 'pnpm --unknown add tool'])(
    'does not infer install packages from option values or ambiguous options: %s',
    (command) => {
      expect(parseInstallCommands(command)).toEqual([]);
    },
  );

  it.each([
    ['pnpm install lodash', 'npm', [{ name: 'lodash' }]],
    ['pnpm i -D lodash@4.17.21', 'npm', [{ name: 'lodash', version: '4.17.21' }]],
    ['yarn global add typescript', 'npm', [{ name: 'typescript' }]],
    ['yarn workspace @acme/app add lodash', 'npm', [{ name: 'lodash' }]],
    [
      'poetry add requests@^2.31 "flask[async]>=3" httpx==0.27.0 rich@13.7.1 ../local git+https://x/y.git',
      'pypi',
      [
        { name: 'requests' },
        { name: 'flask' },
        { name: 'httpx', version: '0.27.0' },
        { name: 'rich', version: '13.7.1' },
      ],
    ],
    ['poetry add --group dev pytest', 'pypi', [{ name: 'pytest' }]],
    ['poetry -C app add -G dev --source private pytest', 'pypi', [{ name: 'pytest' }]],
    ['bash -c "cd app && npm i expresss"', 'npm', [{ name: 'expresss' }]],
    ["sh -lc 'pip install requestz'", 'pypi', [{ name: 'requestz' }]],
  ])('recognizes %s', (command, ecosystem, packages) => {
    expect(parseInstallCommands(command)).toEqual([{ ecosystem, packages }]);
  });

  it.each(['poetry install', 'poetry add', 'poetry add ../local', 'yarn workspace app run build'])(
    'ignores %s',
    (command) => {
      expect(parseInstallCommands(command)).toEqual([]);
    },
  );

  it('treats here-document bodies as data, not commands', () => {
    expect(
      parseInstallCommands(
        'cat > notes.md <<\'EOF\'\nnpm i fake-package\nEOF\nnpm i real\ncat <<-EOT > f\n\tpip install nope\n\tEOT\npython3 - <<"END"\nimport x\nEND',
      ),
    ).toEqual([{ ecosystem: 'npm', packages: [{ name: 'real' }] }]);
    // An unterminated here-document swallows the rest of the input.
    expect(parseInstallCommands('cat <<EOF\nnpm i fake\n')).toEqual([]);
    // A here-string is an ordinary (quoted) argument.
    expect(parseInstallCommands('cat <<< "npm i x" && npm i real')).toEqual([
      { ecosystem: 'npm', packages: [{ name: 'real' }] },
    ]);
  });

  it.each([
    ['npm i real --omit dev --loglevel verbose', 'npm'],
    ['pnpm add real --reporter silent --filter app', 'npm'],
    ['yarn add real --network-timeout 100000', 'npm'],
    ['bun add real --backend copyfile', 'npm'],
    ['pip install real --use-feature fast-deps --report out.json', 'pypi'],
    ['pip install real -C key=value --hash sha256:abc', 'pypi'],
    ['uv add real --marker "python_version>=\'3.8\'" --bounds major', 'pypi'],
    ['uv add --constraints constraints.txt real', 'pypi'],
    ['cargo add real --base dir', 'cargo'],
    ['go get -overlay o.json -ldflags -s real.dev/x', 'go'],
  ])('does not mistake option values for packages: %s', (command, ecosystem) => {
    const [group] = parseInstallCommands(command);
    expect(group?.ecosystem).toBe(ecosystem);
    expect(group?.packages.map((p) => p.name)).toEqual([ecosystem === 'go' ? 'real.dev/x' : 'real']);
  });

  it('drops versions the API would reject instead of failing the whole group', () => {
    expect(parseInstallCommands(`npm i 'foo@>=1 <2' "bar@1 || 2" baz@1.2.3`)).toEqual([
      { ecosystem: 'npm', packages: [{ name: 'foo' }, { name: 'bar' }, { name: 'baz', version: '1.2.3' }] },
    ]);
    expect(parseInstallCommands(`npm i ${'a'.repeat(215)} ok`)).toEqual([
      { ecosystem: 'npm', packages: [{ name: 'ok' }] },
    ]);
  });

  it('groups chained installs per ecosystem and deduplicates', () => {
    expect(parseInstallCommands('npm i a && pip install b; npm i a c')).toEqual([
      { ecosystem: 'npm', packages: [{ name: 'a' }, { name: 'c' }] },
      { ecosystem: 'pypi', packages: [{ name: 'b' }] },
    ]);
  });

  it('caps a group at 50 packages', () => {
    const names = Array.from({ length: 80 }, (_, i) => `p${i}`).join(' ');
    expect(parseInstallCommands(`npm i ${names}`)[0]!.packages).toHaveLength(50);
  });
});

const hookInput = (command: string, tool = 'Bash') =>
  JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: tool, tool_input: { command } });

const result = (
  verdict: AgentCheckResult['verdict'],
  items: AgentCheckResult['items'],
): AgentCheckResult => ({
  verdict,
  items,
  warnings: [],
});

describe('runPreToolUseHook', () => {
  it.each(['npm i expresss', 'pnpm --filter app add expresss'])(
    'blocks %s with exit 2 and a reason on stderr',
    async (command) => {
      const stderr: string[] = [];
      const check = vi.fn(() =>
        Promise.resolve(
          result('block', [
            {
              name: 'expresss',
              verdict: 'block',
              reasons: [{ code: 'NOT_FOUND', detail: 'does not exist' }],
            },
          ]),
        ),
      );
      const code = await runPreToolUseHook({
        stdin: hookInput(command),
        check,
        stderr: (l) => stderr.push(l),
      });
      expect(code).toBe(HOOK_EXIT_BLOCK);
      expect(check).toHaveBeenCalledWith({ ecosystem: 'npm', packages: [{ name: 'expresss' }] });
      expect(stderr.join('\n')).toContain('- npm expresss: NOT_FOUND: does not exist');
    },
  );

  it('allows warnings with exit 0 and prints them', async () => {
    const stderr: string[] = [];
    const code = await runPreToolUseHook({
      stdin: hookInput('pip install fresh'),
      check: () =>
        Promise.resolve(
          result('warn', [
            {
              name: 'fresh',
              version: '1.0.0',
              verdict: 'warn',
              reasons: [{ code: 'TOO_NEW', detail: '2 days' }],
            },
          ]),
        ),
      stderr: (l) => stderr.push(l),
    });
    expect(code).toBe(HOOK_EXIT_ALLOW);
    expect(stderr[0]).toContain('warning: pypi fresh@1.0.0: TOO_NEW: 2 days');
  });

  it('does not call the API for other tools or non-install commands', async () => {
    const check = vi.fn();
    expect(await runPreToolUseHook({ stdin: hookInput('ls -la'), check, stderr: () => {} })).toBe(0);
    expect(await runPreToolUseHook({ stdin: hookInput('npm i x', 'Edit'), check, stderr: () => {} })).toBe(0);
    expect(check).not.toHaveBeenCalled();
  });

  it('fails open when the API is down, vetkit is not configured or the input is malformed', async () => {
    const stderr: string[] = [];
    const down = await runPreToolUseHook({
      stdin: hookInput('npm i express'),
      check: () => Promise.reject(new Error('fetch failed')),
      stderr: (l) => stderr.push(l),
    });
    expect(down).toBe(HOOK_EXIT_ALLOW);
    expect(stderr.pop()).toContain('could not check npm packages (fetch failed)');
    const unconfigured = await runPreToolUseHook({
      stdin: hookInput('npm i express'),
      check: null,
      configProblem: 'VETKIT_API_KEY is not set',
      stderr: (l) => stderr.push(l),
    });
    expect(unconfigured).toBe(HOOK_EXIT_ALLOW);
    expect(stderr.pop()).toContain('VETKIT_API_KEY is not set');
    expect(await runPreToolUseHook({ stdin: '{not json', check: null, stderr: (l) => stderr.push(l) })).toBe(
      0,
    );
  });
});
