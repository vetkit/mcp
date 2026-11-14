// Inlined by tsdown `define` at build time; undefined in tests and development.
declare const __VETKIT_MCP_VERSION__: string | undefined;

export const VERSION: string =
  typeof __VETKIT_MCP_VERSION__ === 'string' ? __VETKIT_MCP_VERSION__ : '0.0.0-dev';
