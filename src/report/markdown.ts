import type { Action, AuditResult, MatrixCell } from '../types.ts';
import { actionsOf, CLEAR_NOTE } from './table.ts';

/** Spec-derived text outside a fence: no links, images, HTML, table breaks or new lines. */
const esc = (s: string) => s.replace(/\s*[\r\n]+\s*/g, ' ').replace(/[\\`*_[\]()<>!|~#]/g, '\\$&');
/** A fence longer than any backtick run inside, so content cannot close it. */
const fence = (lines: string[]) => {
  const run = Math.max(2, ...lines.map((l) => Math.max(0, ...(l.match(/`+/g) ?? []).map((m) => m.length))));
  const f = '`'.repeat(run + 1);
  return [f, ...lines, f];
};
const row = (cells: string[]) => `| ${cells.join(' | ')} |`.replace(/ {2,}\|/g, ' |');
const head = (cells: string[]) => [row(cells), row(cells.map(() => '---'))];

const CELL: Record<MatrixCell, string> = {
  allowed: 'allowed', declared: 'declared', exceeds: '**exceeds**', 'exceeds-minor': 'exceeds-minor', yes: 'yes', '': '',
};

/** `Label (name)`; an MCP server by name only, since its label is a catalogue sentence (M5). */
const actionName = (a: Action | undefined, label: string) =>
  !a ? esc(label) : a.kind === 'mcp-server' || !a.label || a.label === a.name ? esc(a.name) : `${esc(a.label)} (${esc(a.name)})`;

function note(a: Action, all: Action[]): string {
  const n: string[] = [];
  if (a.evidence.some((e) => e.via === 'declared')) n.push('declared');
  if (a.unclassified) n.push('unclassified');
  const files = new Set(all.filter((x) => x.name === a.name).map((x) => x.file)).size;
  if (files > 1) n.push(`defined in ${files} files`);
  return n.join(', ');
}

export function toMarkdown(result: AuditResult): string {
  const { verdict, findings, actions, matrix } = result;
  const out = ['# AI agent permission audit', '', `**${esc(verdict.text)}**`, ''];
  for (const f of result.files) {
    if (f.error) out.push(`- Couldn't parse ${esc(f.file)} at line ${f.error.line}, column ${f.error.column}: ${esc(f.error.message)}`);
    else if (f.unrecognised) out.push(`- Couldn't recognise ${esc(f.file)} as an agent spec`);
  }
  if (out.length > 4) out.push('');

  if (actions.length) {
    out.push('## Inventory', '', ...head(['Action', 'Kind', 'Effects', 'Data', 'Where', 'Note']));
    for (const a of actions) {
      out.push(row([actionName(a, a.label), a.kind, a.effects.join(', '), a.data.join(', '), `${esc(a.file)}:${a.loc.line}:${a.loc.column}`, note(a, actions)]));
    }
    out.push('');
  }

  out.push('## Findings', '');
  if (findings.length) {
    out.push(...head(['Severity', 'Rule', 'Action', 'Location']));
    for (const f of findings) out.push(row([f.severity, f.ruleId, esc((f.server ?? f.servers?.join(', ')) || ''), `${esc(f.file)}:${f.line}:${f.column}`]));
    out.push('');
  } else out.push(verdict.level === 'clear' ? CLEAR_NOTE : 'No findings.', '');
  for (const f of findings) {
    out.push(`### ${f.severity.toUpperCase()}: ${esc(f.title)}`, '', `${esc(f.file)}:${f.line}:${f.column} · [${f.ruleId}](${f.helpUri})`, '');
    const who = actionsOf(f);
    if (who) out.push(esc(who.charAt(0).toUpperCase() + who.slice(1)), '');
    if (f.detail) out.push(esc(f.detail), '');
    if (f.excerpt.length) out.push(...fence(f.excerpt.map((l) => `${l.hit ? '>' : ' '} ${l.line}: ${l.text}`)), '');
    else if (result.files.some((x) => x.file === f.file && x.error)) out.push("_Excerpt hidden: this file couldn't be fully parsed_", '');
    out.push('**Why it matters**', '', f.why, '', '**Fix**', '', ...fence(f.fix.split('\n')), '');
  }

  if (matrix.rows.length && matrix.columns.length) {
    out.push('## Permission matrix', '');
    out.push(matrix.mode === 'roles'
      ? 'What the agent can do, compared with each role it acts for. Legend: allowed · exceeds · exceeds-minor · declared ' +
        '(exceeds-minor: a plain read the role lacks; declared: granted only by an own-records entry the spec cannot verify).'
      : 'Effects of each action. Add a manifest with `acts_for` roles to compare the agent with the people it acts for.', '');
    out.push(...head(['Action', ...matrix.columns.map(esc)]));
    const byId = new Map(actions.map((a) => [a.id, a]));
    for (const r of matrix.rows) out.push(row([actionName(byId.get(r.actionId), r.label), ...r.cells.map((c) => CELL[c])]));
    out.push('');
  }
  return out.join('\n');
}
