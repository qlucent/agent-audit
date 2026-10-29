#!/usr/bin/env node
import fs from 'node:fs';
import { parseArgs } from 'node:util';
import { audit, toMarkdown, toSarif } from './index.ts';
import { toTable, clean, cleanBlock, unrecognisedNote } from './report/table.ts';
import type { Severity } from './types.ts';

const HELP = `Usage: agent-audit <files...> [options]

Audits an AI agent's tool definitions, OpenAPI spec, MCP config, OAuth scopes, AWS IAM policy
and agent manifest, given together as one agent. Runs locally; makes no network calls.

Options:
  --format table|md|sarif   output format (default table)
  --output <file>           write the report to a file instead of stdout
  --fail-on <level>         critical|high|medium|low|none (default high)
  --help, --version
`;

const parseErr = (f: { file: string; error?: { message: string; line: number; column: number } }) =>
  `agent-audit: ${clean(f.file)}: couldn't parse at line ${f.error!.line}, column ${f.error!.column}: ${clean(f.error!.message)}`;

const rank: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

function main(): number {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        format: { type: 'string', default: 'table' },
        output: { type: 'string' },
        'fail-on': { type: 'string', default: 'high' },
        help: { type: 'boolean' },
        version: { type: 'boolean' },
      },
    });
  } catch (e) {
    console.error(`agent-audit: ${clean((e as Error).message)}\n\n${HELP}`);
    return 2;
  }
  const { values, positionals: paths } = parsed;
  const version: string = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
  if (values.help) { console.log(HELP); return 0; }
  if (values.version) { console.log(version); return 0; }
  const format = values.format!;
  const failOn = values['fail-on']!;
  if (!['table', 'md', 'sarif'].includes(format) || !['none', ...Object.keys(rank)].includes(failOn)) {
    console.error(`agent-audit: invalid --format or --fail-on value\n\n${HELP}`);
    return 2;
  }
  // Agent specs live in project repos: no auto-discovery.
  if (!paths.length) { console.error(`agent-audit: no files given\n\n${HELP}`); return 2; }
  // Progress notes must not corrupt machine-readable stdout.
  const note = format === 'table' && !values.output ? console.log : console.error;

  const inputs = [];
  for (const p of paths) {
    try {
      inputs.push({ name: p, text: fs.readFileSync(p, 'utf8') });
      note(`Auditing ${clean(p)}`);
    } catch {
      console.error(`agent-audit: skipping ${clean(p)} (cannot read)`);
    }
  }
  if (!inputs.length) { console.error('agent-audit: no readable files'); return 2; }

  const result = audit(inputs);
  for (const f of result.files) {
    if (f.error) console.error(parseErr(f));
    else if (f.unrecognised) console.error(`agent-audit: ${unrecognisedNote(f)}`);
  }
  // Nothing auditable (a manifest alone describes no actions): no report, usage-style exit.
  if (result.files.every((f) => f.error || f.unrecognised || f.format === 'manifest')) {
    console.error(`agent-audit: ${clean(result.verdict.text)}`);
    return 2;
  }
  const color = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR && !values.output;
  const text = format === 'md' ? toMarkdown(result) : format === 'sarif' ? JSON.stringify(toSarif(result, version), null, 2) : toTable(result, color);
  if (values.output) {
    try {
      fs.writeFileSync(values.output, text + '\n');
    } catch (e) {
      console.error(`agent-audit: cannot write ${clean(values.output)}: ${clean((e as Error).message)}`);
      return 2;
    }
    console.error(`agent-audit: wrote ${clean(values.output)}`);
  } else console.log(format === 'table' ? text : cleanBlock(text)); // table fields are already clean()ed

  // A file named on the command line that could not be parsed fully is an error, whatever was found.
  if (result.files.some((f) => f.error)) return 2;
  return failOn !== 'none' && result.findings.some((f) => rank[f.severity] >= rank[failOn as Severity]) ? 1 : 0;
}

process.exitCode = main();
