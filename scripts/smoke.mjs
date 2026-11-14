// Starts the built server over stdio, lists its tools and checks the hook's fail-open path.
// Needs `npm run build` first. No API request is sent, so a well-formed dummy key is enough.
import { spawn, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const bin = new URL('../dist/bin.js', import.meta.url).pathname;

const version = spawnSync(process.execPath, [bin, '--version'], { encoding: 'utf8' });
if (version.stdout.trim() !== pkg.version) throw new Error(`--version printed ${version.stdout.trim()}`);

// Assembled from parts so secret scanners do not mistake the dummy for a real key.
const dummyKey = ['vk', 'test', '0'.repeat(8), '0'.repeat(32)].join('_');
const server = spawn(process.execPath, [bin], {
  stdio: ['pipe', 'pipe', 'inherit'],
  env: { ...process.env, VETKIT_API_KEY: dummyKey },
});
const send = (msg) => server.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', ...msg })}\n`);
const tools = await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('no tools/list response within 10 s')), 10_000);
  let buffer = '';
  server.stdout.on('data', (chunk) => {
    buffer += chunk;
    for (let i = buffer.indexOf('\n'); i >= 0; i = buffer.indexOf('\n')) {
      const msg = JSON.parse(buffer.slice(0, i));
      buffer = buffer.slice(i + 1);
      if (msg.id === 1) {
        if (msg.result?.serverInfo?.version !== pkg.version) reject(new Error('wrong server version'));
        send({ method: 'notifications/initialized' });
        send({ id: 2, method: 'tools/list' });
      }
      if (msg.id === 2) {
        clearTimeout(timer);
        resolve(msg.result.tools.map((t) => t.name));
      }
    }
  });
  send({
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'smoke', version: '0' } },
  });
});
server.kill();
if (tools.length < 20 || !tools.includes('vetkit_run_audit')) throw new Error(`unexpected tools: ${tools}`);

// Without a key the hook must allow the command (exit 0) and explain why on stderr.
const env = { ...process.env };
delete env.VETKIT_API_KEY;
const hook = spawnSync(process.execPath, [bin, 'hook', 'pre-tool-use'], {
  input: JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'npm install left-pad' } }),
  encoding: 'utf8',
  env,
});
if (hook.status !== 0 || !hook.stderr.includes('VETKIT_API_KEY')) throw new Error('hook did not fail open');

process.stdout.write(`ok: v${pkg.version}, ${tools.length} tools, hook fails open\n`);
