// R23 (final review C1): comments are free text. Their bodies become "(comment hidden)", delimiters and line count kept.
// Fixtures: test/fixtures/leaks4, each with a prose credential no pattern recognises.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { audit, toMarkdown, toSarif, toTable } from '../src/index.ts';
import { redactFile } from '../src/secrets.ts';

const dir = path.resolve(import.meta.dirname, 'fixtures/leaks4');
const read = (f: string) => ({ name: f, text: fs.readFileSync(path.join(dir, f), 'utf8') });
const probes = (s: string) => [s, ...(s.length >= 12 ? [s.slice(0, -4)] : [])].map((p) => p.toLowerCase());
const leaksIn = (secrets: string[], s: string) => secrets.filter((x) => probes(x).some((p) => s.toLowerCase().includes(p)));

const CASES: [file: string, secrets: string[]][] = [
  ['comment-line.yaml', ['Hunter2Hunter2Line']],
  ['comment-trailing.yaml', ['TrailPass2026Qx', 'bob@example.com']],
  ['tools-line.jsonc', ['Wonderland2026Line', 'alice@example.com']],
  ['tools-block.jsonc', ['BlockSecret2026Qx', 'carol@example.com']],
  ['claude_desktop_config.json', ['McpComment2026Qx', 'dave@example.com', 'RootPw2026Qx']],
];

for (const [file, secrets] of CASES) {
  test(`R23: no comment text in any output: ${file}`, () => {
    const input = read(file);
    assert.ok(secrets.every((s) => input.text.includes(s)), 'fixture holds its secrets');
    const r = audit([input]);
    assert.ok(r.findings.length > 0, 'fixture produces findings with excerpts');
    assert.equal(r.files[0]!.error, undefined, JSON.stringify(r.files));
    const red = redactFile(input.name, input.text);
    assert.equal(red.text.split('\n').length, input.text.split('\n').length, 'line count');
    assert.deepEqual(leaksIn(secrets, red.text), [], red.text);
    assert.ok(red.text.includes('(comment hidden)'), red.text);
    for (const [kind, out] of [['result', JSON.stringify(r)], ['md', toMarkdown(r)], ['sarif', JSON.stringify(toSarif(r, '1'))], ['table', toTable(r)]] as const)
      assert.deepEqual(leaksIn(secrets, out), [], `${kind}: ${out}`);
  });
}

test('R23: delimiters kept', () => {
  assert.match(redactFile('a.yaml', read('comment-line.yaml').text).text, /^# \(comment hidden\)$/m);
  assert.match(redactFile('a.yaml', read('comment-trailing.yaml').text).text, /operationId: issueRefund # \(comment hidden\)$/m);
  assert.match(redactFile('t.jsonc', read('tools-line.jsonc').text).text, /^ {2}\/\/ \(comment hidden\)$/m);
  assert.match(redactFile('t.jsonc', read('tools-block.jsonc').text).text, /^ {2}\/\* \(comment hidden\)\n\n *\*\/$/m);
  // A `#` inside a quoted value or a block scalar is not a comment.
  const y = 'openapi: 3.0.3\ninfo: { title: "a # b", version: "1" }\nx: |\n  # not a comment\npaths: {}\n';
  assert.equal(redactFile('a.yaml', y).text.includes('# not a comment'), true);
  assert.equal(redactFile('a.yaml', y).text.includes('(comment hidden)'), false);
  // A comment on a block scalar's header line.
  for (const key of ['x-n', 'note']) {
    const blk = `openapi: 3.0.3\ninfo: { title: t, version: "1" }\npaths: {}\n${key}: | # header note HdrNote2026Qx\n  body\n`;
    assert.match(redactFile('a.yaml', blk).text, new RegExp(`${key}: \\| # \\(comment hidden\\)\\n`));
  }
  // CRLF keeps its CRs.
  const crlf = '# secret note Abc12345678\r\nopenapi: 3.0.3\r\n';
  assert.equal(redactFile('a.yaml', crlf).text, '# (comment hidden)\r\nopenapi: 3.0.3\r\n');
});

test('R23 CLI: no comment text on stdout, stderr or --output', () => {
  const all = CASES.flatMap(([, s]) => s);
  const files = CASES.map(([f]) => path.join(dir, f));
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'agentaudit-r23-')), 'o.txt');
  for (const fmt of ['table', 'md', 'sarif']) for (const extra of [[], ['--output', out]]) {
    const r = spawnSync(process.execPath, [path.resolve(import.meta.dirname, '../src/cli.ts'), ...files, '--format', fmt, ...extra], { encoding: 'utf8' });
    const text = r.stdout + r.stderr + (extra.length ? fs.readFileSync(out, 'utf8') : '');
    assert.ok(text.length > 100, r.stderr);
    assert.deepEqual(leaksIn(all, text), [], `${fmt} ${extra.join(' ')}`);
  }
  fs.rmSync(path.dirname(out), { recursive: true });
});
