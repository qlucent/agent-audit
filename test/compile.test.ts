import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const script = new URL('../scripts/compile-data.ts', import.meta.url);
const compile = (dir: string) =>
  spawnSync(process.execPath, [script.pathname.replace(/^\/(\w:)/, '$1'), dir, join(dir, 'out.json')], { encoding: 'utf8' });
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), 'aa-'));
  for (const s of ['rules', 'lexicon', 'catalog']) mkdirSync(join(d, s));
  return d;
};

test('empty data dirs compile to empty data', () => {
  const d = tmp();
  const r = compile(d);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(readFileSync(join(d, 'out.json'), 'utf8')), { rules: [], lexicon: {}, scopes: [], iam: [] });
});

test('rule missing fixtures.pass fails with the filename', () => {
  const d = tmp();
  writeFileSync(join(d, 'rules', 'money-no-cap.yaml'), `id: money-no-cap
title: Money action has no cap
severity: high
check: money-no-cap
why: w
fix: f
references: []
fixtures:
  fail:
    - config: {}
`);
  const r = compile(d);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /rules[\/]money-no-cap\.yaml/);
  assert.match(r.stderr, /pass/);
});
