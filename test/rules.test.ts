import { test } from 'node:test';
import assert from 'node:assert/strict';
import { audit, rules } from '../src/engine.ts';
import { checks } from '../src/checks/index.ts';
import { KNOWN_CHECKS } from '../src/checks/names.ts';

// Each fixture is one input file (`config`), plus an optional `manifest` given as a second file.
for (const r of rules) {
  const run = (f: { file?: string; config: unknown; manifest?: unknown }) =>
    audit([
      { name: f.file ?? 'pasted-1', text: JSON.stringify(f.config, null, 2) },
      ...(f.manifest ? [{ name: 'manifest.json', text: JSON.stringify(f.manifest, null, 2) }] : []),
    ]).findings.filter((x) => x.ruleId === r.id);
  r.fixtures.fail.forEach((f, i) => test(`${r.id} fail #${i + 1}`, () => assert.ok(run(f).length >= 1)));
  r.fixtures.pass.forEach((f, i) => test(`${r.id} pass #${i + 1}`, () => assert.equal(run(f).length, 0)));
}

test('every named check is registered', () => assert.deepEqual(Object.keys(checks).sort(), [...KNOWN_CHECKS].sort()));
test('batch A rules are present', () => {
  const ids = rules.map((r) => r.id);
  for (const id of ['money-no-cap', 'money-no-approval', 'purchase-without-consent', 'unscoped-record-access',
    'identity-admin-action', 'destructive-no-approval', 'unclassified-action']) assert.ok(ids.includes(id), id);
});
