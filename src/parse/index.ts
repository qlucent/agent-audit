import type { Action, FileSummary, Manifest } from '../types.ts';
import { detect } from './detect.ts';

export interface ParsedInputs {
  files: FileSummary[];
  actions: Action[];
  manifest?: Manifest;
  /** Inputs recognised as MCP client configs, for mcp-audit's own audit. */
  mcpFiles: { name: string; text: string }[];
}

/** Several files describe one agent. Actions keep their own source; effects and data are filled later. */
export function parseInputs(inputs: { name: string; text: string }[]): ParsedInputs {
  const out: ParsedInputs = { files: [], actions: [], mcpFiles: [] };
  const firstByName = new Map<string, number>();
  for (const input of inputs) {
    const d = detect(input);
    const summary: FileSummary = { file: input.name, format: d.format, actions: d.actions.length };
    if (d.error) summary.error = d.error;
    else if (!d.format) summary.unrecognised = true;
    if (d.manifest && out.manifest) summary.error = { message: 'Only one manifest is used; this second manifest was ignored', line: 1, column: 1 };
    else if (d.manifest) out.manifest = d.manifest;
    if (d.format === 'mcp-config') out.mcpFiles.push(input);
    for (const a of d.actions) {
      const first = firstByName.get(a.name);
      if (first === undefined) firstByName.set(a.name, out.actions.length);
      else if (out.actions[first]!.file !== a.file) a.duplicateOf = first;
      out.actions.push(a);
    }
    out.files.push(summary);
  }
  return out;
}
