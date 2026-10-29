import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { audit } from '../src/index.ts';

const root = path.resolve(import.meta.dirname, '..');
const run = (sample: string) => {
  const dir = path.join(root, 'samples', sample);
  const r = audit(fs.readdirSync(dir).map((f) => ({ name: f, text: fs.readFileSync(path.join(dir, f), 'utf8') })));
  const has = (id: string, severity?: string) => r.findings.some((f) => f.ruleId === id && (!severity || f.severity === severity));
  return { r, has };
};

test('fintech sample is not ready: money without cap or approval, customer exceeded', () => {
  const { r, has } = run('fintech-refund-bot');
  assert.equal(r.verdict.level, 'not-ready');
  assert.ok(has('money-no-cap') && has('money-no-approval'));
  assert.ok(r.findings.some((f) => f.ruleId === 'exceeds-role' && /customer/.test(f.detail ?? '')));
});

test('healthcare sample: unscoped record access is critical and sensitive data can be sent out', () => {
  const { has } = run('healthcare-records-assistant');
  assert.ok(has('unscoped-record-access', 'critical'));
  assert.ok(has('external-send-sensitive'));
});

test('helpdesk sample: identity admin is critical and out of scope', () => {
  const { has } = run('l1-helpdesk-agent');
  assert.ok(has('identity-admin-action', 'critical'));
  assert.ok(has('out-of-scope-action'));
});

test('read-only sample is never not-ready', () => {
  const { r } = run('read-only-agent');
  assert.notEqual(r.verdict.level, 'not-ready');
  assert.equal(r.findings.length, 0);
});

test('package contents: dist, LICENSE, README, package.json only; no email', () => {
  const out = execFileSync('npm', ['pack', '--dry-run', '--json'], { cwd: root, shell: true, encoding: 'utf8' });
  const files: string[] = JSON.parse(out)[0].files.map((f: { path: string }) => f.path);
  const bad = files.filter((f) => !/^(dist\/|LICENSE$|README\.md$|package\.json$)/.test(f));
  assert.deepEqual(bad, []);
  assert.ok(files.includes('README.md') && files.includes('LICENSE'));
  assert.doesNotMatch(fs.readFileSync(path.join(root, 'package.json'), 'utf8'), /[\w.+-]+@[\w-]+\.[\w.]+/);
});
