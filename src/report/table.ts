import type { AuditResult, FileSummary, Finding } from '../types.ts';

const color = { critical: 31, high: 31, medium: 33, low: 36 } as const;

/** Makes spec-derived text safe for a terminal: control chars become visible \xNN. */
export function clean(s: string): string {
  return s.replace(/[\u0000-\u001f\u007f-\u009f]/g, (c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

/** Like clean(), but keeps line breaks and tabs: for whole multi-line reports written to a terminal. */
export function cleanBlock(s: string): string {
  return s.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, (c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

export const unrecognisedNote = (f: FileSummary) => `Couldn't recognise ${clean(f.file)} as an agent spec`;

/** The Finding shape is mcp-audit's: its `server`/`servers` fields carry action names here. */
export const actionsOf = (f: Finding): string | undefined =>
  f.server ? `action: ${f.server}` : f.servers?.length ? `action${f.servers.length === 1 ? '' : 's'}: ${f.servers.join(', ')}` : undefined;

/** Plain-text table. Colour only when the caller says the terminal supports it. */
export function toTable(result: AuditResult, useColor = false): string {
  const out: string[] = [];
  for (const f of result.findings) {
    const sev = f.severity.toUpperCase().padEnd(8);
    const who = actionsOf(f);
    out.push(`${useColor ? `\x1b[${color[f.severity]}m${sev}\x1b[0m` : sev} ${clean(f.file)}:${f.line}  ${f.ruleId}  ${clean(f.title)}${who ? ` (${clean(who)})` : ''}`);
    out.push(`${' '.repeat(9)}${f.helpUri}`);
  }
  for (const f of result.files) {
    if (f.error) {
      const partial = result.findings.some((x) => x.file === f.file);
      out.push(`${partial ? 'PARSED WITH ERRORS' : 'NOT AUDITED'} ${clean(f.file)}: couldn't parse at line ${f.error.line}, column ${f.error.column}: ${clean(f.error.message)}`);
    } else if (f.unrecognised) out.push(unrecognisedNote(f));
  }
  if (out.length) out.push('');
  out.push(clean(result.verdict.text));
  if (result.verdict.level === 'clear') out.push(CLEAR_NOTE);
  return out.join('\n');
}

export const CLEAR_NOTE = "That doesn't make it safe: this checks what the spec declares, not what the agent's code does.";
