import { readdirSync, readFileSync, writeFileSync } from 'node:fs';

import { defineConfig } from 'tsdown';
import ts from 'typescript';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as {
  version: string;
  dependencies: Record<string, string>;
};

/**
 * Declarations of prebuilt workspace packages keep their internal JSDoc. The TypeScript printer
 * rewrites each emitted `.d.ts` without comments, so the public package ships only the types.
 */
function stripDeclarationComments(outDir: URL): void {
  const printer = ts.createPrinter({ removeComments: true });
  for (const name of readdirSync(outDir).filter((n) => n.endsWith('.d.ts'))) {
    const file = new URL(name, outDir);
    const source = ts.createSourceFile(name, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, false);
    // The printer indents with four spaces; halve it to keep the declaration file compact.
    const printed = printer
      .printFile(source)
      .replace(/^(?: {4})+/gm, (indent) => ' '.repeat(indent.length / 2));
    writeFileSync(file, printed);
  }
}

// The published package must be self-contained: the generated vendor modules are
// bundled, real dependencies (MCP SDK, zod) stay external.
export default defineConfig({
  entry: ['src/index.ts', 'src/bin.ts'],
  format: 'esm',
  platform: 'node',
  target: 'node20',
  outDir: 'dist',
  onSuccess: () => stripDeclarationComments(new URL('./dist/', import.meta.url)),
  clean: true,
  sourcemap: false,
  // The npm package is public: keep license notices, drop internal source and JSDoc comments
  // that workspace packages carry into the bundle.
  outputOptions: { comments: { legal: true, annotation: true, jsdoc: false } },
  fixedExtension: false,
  dts: { sourcemap: false },
  define: { __VETKIT_MCP_VERSION__: JSON.stringify(pkg.version) },
  deps: {
    neverBundle: [...Object.keys(pkg.dependencies).map((d) => new RegExp(`^${d}(/.*)?$`))],
    alwaysBundle: [/^#vendor\//],
    // No package from node_modules may enter the bundle (local sources and vendor only).
    onlyBundle: [],
    dts: { alwaysBundle: [/^#vendor\//] },
  },
});
