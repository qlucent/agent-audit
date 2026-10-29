import type { ExcerptLine } from '@qlucent/mcp-audit';

const WIDTH = 160;

/**
 * Lines line-2 … line+2 of the already redacted `lines`; `hit` marks `line`. Long lines are cut to WIDTH characters
 * (the hit line around `column`), cuts shown as `…`, as in mcp-audit.
 */
export function excerpt(lines: string[], line: number, column: number): ExcerptLine[] {
  const out: ExcerptLine[] = [];
  for (let n = Math.max(1, line - 2); n <= Math.min(lines.length, line + 2); n++) {
    const t = lines[n - 1]!.replace(/\r$/, '');
    let s = 0;
    if (t.length > WIDTH && n === line) s = Math.max(0, Math.min(column - 1 - WIDTH / 2, t.length - WIDTH));
    const e = Math.min(t.length, s + WIDTH);
    out.push({ line: n, text: (s > 0 ? '…' : '') + t.slice(s, e) + (e < t.length ? '…' : ''), hit: n === line });
  }
  return out;
}
