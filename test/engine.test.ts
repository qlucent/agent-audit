import { test } from 'node:test';
import assert from 'node:assert/strict';
import { audit, applySeverity, rules, classify, parseInputs } from '../src/index.ts';
import type { Severity } from '../src/index.ts';

type P = Record<string, Record<string, unknown>>;
/** Anthropic tool list: [name, params] pairs. */
const tools = (...ts: [string, P?][]) => ({
  name: 'tools.json',
  text: JSON.stringify(ts.map(([name, properties = {}]) => ({ name, description: '', input_schema: { type: 'object', properties } })), null, 2),
});
const manifest = (m: Record<string, unknown>) => ({ name: 'agent.json', text: JSON.stringify({ agent: { name: 'Bot' }, ...m }, null, 2) });
const sev = (inputs: { name: string; text: string }[], id: string) =>
  audit(inputs).findings.filter((f) => f.ruleId === id).map((f) => f.severity);

test('applySeverity: at most one step each way, both cancel, clamped', () => {
  const t: [Severity, boolean, boolean, Severity][] = [
    ['high', false, false, 'high'],
    ['high', true, false, 'critical'],
    ['high', false, true, 'medium'],
    ['high', true, true, 'high'],
    ['critical', true, false, 'critical'],
    ['low', false, true, 'low'],
    ['medium', true, true, 'medium'],
  ];
  for (const [base, up, down, want] of t) assert.equal(applySeverity(base, up, down), want, `${base} up=${up} down=${down}`);
});

test('issue_refund(amount) with no manifest: money-no-cap high, money-no-approval medium', () => {
  const r = audit([tools(['issue_refund', { amount: { type: 'number' } }])]);
  const by = (id: string) => r.findings.filter((f) => f.ruleId === id);
  assert.deepEqual(by('money-no-cap').map((f) => f.severity), ['high']);
  const na = by('money-no-approval');
  assert.deepEqual(na.map((f) => f.severity), ['medium']);
  assert.match(na[0]!.detail!, /no approval step is declared/);
  assert.equal(na[0]!.server, 'issue_refund');
  assert.equal(na[0]!.helpUri, 'https://qlucent.com/tools/agent-audit/rules/money-no-approval');
  assert.equal(r.verdict.level, 'not-ready');
});

test('schema maximum and a manifest approval clear both money rules', () => {
  const ins = [tools(['issue_refund', { amount: { type: 'number', maximum: 100 } }]), manifest({ approvals: ['issue_*'] })];
  assert.deepEqual(sev(ins, 'money-no-cap'), []);
  assert.deepEqual(sev(ins, 'money-no-approval'), []);
});

test('manifest limits entry is a cap; cap lowers money-no-approval to medium', () => {
  const ins = [tools(['issue_refund', { amount: { type: 'number' } }]), manifest({ limits: { issue_refund: { max_amount: 50 } } })];
  assert.deepEqual(sev(ins, 'money-no-cap'), []);
  assert.deepEqual(sev(ins, 'money-no-approval'), ['medium']);
  assert.deepEqual(sev([tools(['issue_refund', { amount: { type: 'number' } }]), manifest({})], 'money-no-approval'), ['high']);
});

test('fintech domain bumps money-no-cap to critical; purpose alone can set the domain', () => {
  const t = tools(['issue_refund', { amount: { type: 'number' } }]);
  assert.deepEqual(sev([t, manifest({ agent: { name: 'B', domain: 'fintech' } })], 'money-no-cap'), ['critical']);
  assert.deepEqual(sev([t, manifest({ agent: { name: 'B', purpose: 'Online store checkout assistant' } })], 'money-no-cap'), ['critical']);
  assert.deepEqual(sev([t, manifest({ agent: { name: 'B', domain: 'helpdesk' } })], 'money-no-cap'), ['high']);
});

test('L1 purpose + reset_user_mfa: identity-admin-action critical; plain purpose high', () => {
  const t = tools(['reset_user_mfa', { user_id: { type: 'string' } }]);
  assert.deepEqual(sev([t, manifest({ agent: { name: 'B', purpose: 'L1 helpdesk for employees' } })], 'identity-admin-action'), ['critical']);
  assert.deepEqual(sev([t, manifest({ agent: { name: 'B', acts_for: ['customer'] } })], 'identity-admin-action'), ['critical']);
  assert.deepEqual(sev([t, manifest({ out_of_scope: ['identity-admin'] })], 'identity-admin-action'), ['critical']);
  assert.deepEqual(sev([t, manifest({ agent: { name: 'B', purpose: 'Identity governance for IT admins' } })], 'identity-admin-action'), ['high']);
  assert.deepEqual(sev([t], 'identity-admin-action'), ['high']);
});

test('purchase-without-consent: high with manifest, medium without, none when approved', () => {
  const t = tools(['purchase_item', { item_id: { type: 'string' } }]);
  assert.deepEqual(sev([t], 'purchase-without-consent'), ['medium']);
  assert.deepEqual(sev([t, manifest({})], 'purchase-without-consent'), ['high']);
  assert.deepEqual(sev([t, manifest({ approvals: ['purchase_item'] })], 'purchase-without-consent'), []);
  assert.deepEqual(sev([tools(['get_purchase_history'])], 'purchase-without-consent'), []);
});

test('unscoped-record-access: phi critical, pii high, one step lower without a manifest, own-scoped role clears it', () => {
  const phi = tools(['get_patient_record', { patient_id: { type: 'string' } }]);
  const pii = tools(['get_customer', { customer_id: { type: 'string' } }]);
  assert.deepEqual(sev([phi, manifest({})], 'unscoped-record-access'), ['critical']);
  assert.deepEqual(sev([phi], 'unscoped-record-access'), ['high']);
  assert.deepEqual(sev([pii, manifest({})], 'unscoped-record-access'), ['high']);
  assert.deepEqual(sev([pii], 'unscoped-record-access'), ['medium']);
  const own = manifest({ agent: { name: 'B', acts_for: ['customer'] }, roles: { customer: { allow: ['read:own-*'] } } });
  assert.deepEqual(sev([pii, own], 'unscoped-record-access'), []);
  assert.deepEqual(sev([tools(['get_order_status', { order_id: { type: 'string' } }]), manifest({})], 'unscoped-record-access'), []);
});

test('destructive-no-approval: medium, high if bulk, lower without a manifest, none when approved', () => {
  const del = tools(['delete_document', { document_id: { type: 'string' } }]);
  const bulk = tools(['bulk_delete_documents']);
  assert.deepEqual(sev([del, manifest({})], 'destructive-no-approval'), ['medium']);
  assert.deepEqual(sev([del], 'destructive-no-approval'), ['low']);
  assert.deepEqual(sev([bulk, manifest({})], 'destructive-no-approval'), ['high']);
  assert.deepEqual(sev([bulk], 'destructive-no-approval'), ['medium']);
  assert.deepEqual(sev([del, manifest({ approvals: ['delete_*'] })], 'destructive-no-approval'), []);
});

test('unclassified-action: one low finding per file listing the actions', () => {
  const r = audit([tools(['frobnicate_widget'], ['zorp_gadget'], ['get_widget'])]);
  const f = r.findings.filter((x) => x.ruleId === 'unclassified-action');
  assert.equal(f.length, 1);
  assert.equal(f[0]!.severity, 'low');
  assert.deepEqual(f[0]!.servers, ['frobnicate_widget', 'zorp_gadget']);
});

test('declared effects in the manifest drive the rules', () => {
  const t = tools(['zorp_gadget', { amount: { type: 'number' } }]);
  assert.deepEqual(sev([t, manifest({ actions: { zorp_gadget: { effects: ['money'] } } })], 'money-no-cap'), ['high']);
});

test('verdict tiers and texts match mcp-audit', () => {
  const clear = audit([tools(['get_widget'])]);
  assert.equal(clear.verdict.level, 'clear');
  assert.equal(clear.verdict.text, `None of the ${rules.length} rules matched this config`);
  assert.equal(clear.rulesChecked, rules.length);
  assert.deepEqual(clear.matrix, { columns: [], rows: [] });
  const review = audit([tools(['delete_document'])]);
  assert.equal(review.verdict.level, 'review');
  assert.match(review.verdict.text, /^Review before rollout: 1 low/);
  const none = audit([{ name: 'x.json', text: '{"hello": 1}' }]);
  assert.equal(none.verdict.level, 'unrecognised');
  assert.match(none.verdict.text, /x\.json/);
});

test('result carries classified actions, files and manifest; index re-exports parse and classify', () => {
  const r = audit([tools(['issue_refund']), manifest({})]);
  assert.ok(r.actions[0]!.effects.includes('money'));
  assert.equal(r.files.length, 2);
  assert.equal(r.manifest!.agent.name, 'Bot');
  assert.equal(typeof classify, 'function');
  assert.equal(typeof parseInputs, 'function');
});
