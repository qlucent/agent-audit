import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const cli = path.resolve(import.meta.dirname, '../src/cli.ts');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'agentaudit-'));

function run(args: string[], cwd = tmp()) {
  const r = spawnSync(process.execPath, [cli, ...args], { cwd, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
function write(file: string, body: unknown) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof body === 'string' ? body : JSON.stringify(body, null, 2));
  return file;
}
const tool = (name: string, properties: Record<string, unknown> = {}) => ({ name, description: '', input_schema: { type: 'object', properties } });
// money-no-cap is high: fails the default --fail-on high.
const risky = [tool('issue_refund', { amount: { type: 'number' } })];
// A read-only tool and a manifest: nothing above low.
const quiet = [tool('get_order', { order_ref: { type: 'string' } })];

test('no files: usage and exit 2 (no auto-discovery)', () => {
  const r = run([]);
  assert.equal(r.code, 2);
  assert.ok(r.err.includes('Usage: agent-audit'), r.err);
});

test('findings at or above --fail-on exit 1; below exit 0; none exits 0', () => {
  const f = write(path.join(tmp(), 'tools.json'), risky);
  assert.equal(run([f]).code, 1);
  assert.equal(run([f, '--fail-on', 'critical']).code, 0);
  assert.equal(run([f, '--fail-on', 'none']).code, 0);
  assert.equal(run([f, '--fail-on', 'low']).code, 1);
});

test('clean spec exits 0', () => {
  const d = tmp();
  const f = write(path.join(d, 'tools.json'), quiet);
  const m = write(path.join(d, 'agent.json'), { agent: { name: 'B' } });
  const r = run([f, m]);
  assert.equal(r.code, 0, r.out + r.err);
});

test('unknown flag, bad --format or --fail-on exit 2', () => {
  assert.equal(run(['--nope']).code, 2);
  const f = write(path.join(tmp(), 'tools.json'), risky);
  assert.equal(run([f, '--format', 'html']).code, 2);
  assert.equal(run([f, '--fail-on', 'severe']).code, 2);
});

test('unreadable file exits 2', () => {
  const r = run([path.join(tmp(), 'missing.json')]);
  assert.equal(r.code, 2);
  assert.ok(r.err.includes('cannot read'), r.err);
});

test('a named file that fails to parse is reported and exits 2', () => {
  const d = tmp();
  const ok = write(path.join(d, 'tools.json'), risky);
  const bad = write(path.join(d, 'bad.json'), '{ "tools": ');
  for (const fmt of ['table', 'md', 'sarif']) {
    const r = run([ok, bad, '--format', fmt]);
    assert.ok(r.err.includes(`agent-audit: ${bad}: couldn't parse at line`), r.err);
    assert.equal(r.code, 2);
  }
  assert.ok(run([ok, bad]).out.includes(`NOT AUDITED ${bad}`));
});

test('only unrecognised files, or only a manifest: says so and exits 2', () => {
  const d = tmp();
  const f = write(path.join(d, 'settings.json'), { 'editor.fontSize': 14 });
  const r = run([f]);
  assert.equal(r.code, 2);
  assert.ok(r.err.includes(`Couldn't recognise ${f} as an agent spec`), r.err);
  const m = write(path.join(d, 'agent.json'), { agent: { name: 'B' } });
  assert.equal(run([m]).code, 2);
});

test('sarif --output file is valid SARIF; md goes to stdout', () => {
  const d = tmp();
  const f = write(path.join(d, 'tools.json'), risky);
  const out = path.join(d, 'out.sarif');
  const r = run([f, '--format', 'sarif', '--output', out]);
  assert.ok(r.err.includes(`agent-audit: wrote ${out}`), r.err);
  assert.equal(JSON.parse(fs.readFileSync(out, 'utf8')).version, '2.1.0');
  assert.ok(run([f, '--format', 'md']).out.startsWith('# AI agent permission audit'));
});

test('unwritable --output exits 2', () => {
  const d = tmp();
  const f = write(path.join(d, 'tools.json'), risky);
  const r = run([f, '--output', path.join(d, 'missing', 'dir', 'out.sarif')]);
  assert.equal(r.code, 2);
  assert.ok(r.err.includes('cannot write'), r.err);
});

test('--version prints the package version; --help exits 0', () => {
  const v = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, '../package.json'), 'utf8')).version;
  assert.equal(run(['--version']).out.trim(), v);
  const h = run(['--help']);
  assert.equal(h.code, 0);
  assert.ok(h.out.includes('--fail-on'));
});

test('control characters from the spec are escaped on stdout, kept in --output', () => {
  const d = tmp();
  const f = write(path.join(d, 'tools.json'), [tool('issue_refund\u001b[2J\u009bx', { amount: { type: 'number' } })]);
  for (const fmt of ['table', 'md', 'sarif']) {
    const r = run([f, '--format', fmt]);
    assert.ok(!/[\u001b\u009b]/.test(r.out) && !/[\u001b\u009b]/.test(r.err), fmt);
    assert.ok(r.out.includes('\\x1b') || r.out.includes('\\u001b'), fmt + r.out);
  }
  const out = path.join(d, 'out.md');
  run([f, '--format', 'md', '--output', out]);
  assert.ok(fs.readFileSync(out, 'utf8').includes('\u001b'));
});
