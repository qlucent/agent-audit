import { normalize, parseFile } from '@qlucent/mcp-audit';
import type { Action } from '../types.ts';
import { action } from './json.ts';

/** Anything mcp-audit recognises as an MCP client config: one action per server. */
export function parse(input: { name: string; text: string }): Action[] | null {
  const f = parseFile(input);
  if (!f.client || f.error) return null;
  return normalize([f]).servers.map((s) => action(input.name, s.loc, { name: s.name, kind: 'mcp-server' }));
}
