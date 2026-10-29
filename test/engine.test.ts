import { test } from 'node:test';
import assert from 'node:assert/strict';
import { audit, applySeverity, rules, classify, parseInputs } from '../src/index.ts';
import { verdictFor } from '../src/engine.ts';
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
  // No manifest adds one low no-manifest finding: review, still not "not ready".
  const bare = audit([tools(['get_widget'])]);
  assert.equal(bare.verdict.level, 'review');
  assert.deepEqual(bare.findings.map((f) => `${f.ruleId}:${f.severity}`), ['no-manifest:low']);
  const clear = audit([tools(['get_widget']), manifest({})]);
  assert.equal(clear.verdict.level, 'clear');
  assert.equal(clear.verdict.text, `None of the ${rules.length} rules matched this config`);
  assert.equal(clear.rulesChecked, rules.length);
  assert.deepEqual(clear.matrix, { mode: 'effects', columns: ['read'], rows: [{ actionId: clear.actions[0]!.id, label: 'Get widget', cells: ['yes'] }] });
  const review = audit([tools(['delete_document'])]);
  assert.equal(review.verdict.level, 'review');
  assert.match(review.verdict.text, /^Review before rollout: 2 low/);
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

// Fix round 1
const ids = (inputs: { name: string; text: string }[]) => audit(inputs).findings.map((f) => `${f.ruleId}:${f.server}`);
const APPROVAL = ['money-no-approval', 'purchase-without-consent', 'destructive-no-approval'];

test('R10: approval rules skip OAuth scopes and IAM statements', () => {
  const iam = { name: 'iam.json', text: JSON.stringify({ Version: '2012-10-17', Statement: [
    { Effect: 'Allow', Action: '*', Resource: '*' },
    { Effect: 'Allow', Action: ['ec2:PurchaseHostReservation', 's3:DeleteObject'], Resource: '*' }] }, null, 2) };
  const scopes = { name: 'scopes.json', text: JSON.stringify(['https://www.googleapis.com/auth/drive']) };
  const r = audit([iam, scopes, manifest({})]);
  assert.ok(r.actions.length >= 4);
  assert.deepEqual(r.findings.filter((f) => APPROVAL.includes(f.ruleId)).map((f) => f.ruleId), []);
});

test('R11: a purchase gets purchase-without-consent, not also money-no-approval', () => {
  const api = { name: 'openapi.json', text: JSON.stringify({ openapi: '3.0.3', info: { title: 'x', version: '1' }, paths: {
    '/v1/charges': { post: { responses: { 200: { description: 'ok' } } } },
    '/v1/checkout/sessions': { post: { responses: { 200: { description: 'ok' } } } } } }, null, 2) };
  const got = ids([tools(['charge_saved_card', { amount: { type: 'number' } }]), api, manifest({})]);
  for (const a of ['charge_saved_card', 'POST /v1/charges', 'POST /v1/checkout/sessions']) {
    assert.ok(got.includes(`purchase-without-consent:${a}`), `${a}: ${got}`);
    assert.ok(!got.includes(`money-no-approval:${a}`), `${a}: ${got}`);
  }
  assert.ok(got.includes('money-no-cap:charge_saved_card'));
  assert.ok(ids([tools(['issue_refund']), manifest({})]).includes('money-no-approval:issue_refund'));
});

test('M1: an action defined in two files reports a finding once unless the copies differ', () => {
  const a = { ...tools(['issue_refund', { amount: { type: 'number' } }]), name: 'a.json' };
  const b = { ...tools(['issue_refund', { amount: { type: 'number' } }]), name: 'b.json' };
  assert.equal(sev([a, b], 'money-no-cap').length, 1);
  assert.equal(sev([a, b], 'money-no-approval').length, 1);
  const capped = { ...tools(['issue_refund', { amount: { type: 'number', maximum: 5 } }]), name: 'b.json' };
  assert.deepEqual(sev([a, capped, manifest({})], 'money-no-approval'), ['high', 'medium']);
  assert.deepEqual(sev([a, capped], 'money-no-cap'), ['high']);
});

test('M3: a manifest on its own is unrecognised, not clear', () => {
  const r = audit([{ ...manifest({}), name: 'agent.yaml' }]);
  assert.equal(r.verdict.level, 'unrecognised');
  assert.match(r.verdict.text, /agent\.yaml is a manifest; add the agent's tool definitions, OpenAPI, scopes or IAM policy/);
});

test('M4: a partly read file uses mcp-audit wording, without the "Couldn\'t check any input" prefix', () => {
  const v = verdictFor([], [{ file: 'x.json', format: 'openai-tools', actions: 2, error: { message: 'e', line: 7, column: 1 } }]);
  assert.equal(v.level, 'unrecognised');
  assert.equal(v.text, `Only part of x.json could be read (parse error at line 7); none of the ${rules.length} rules matched the part that was read`);
  const none = verdictFor([], [{ file: 'y.json', format: null, actions: 0, error: { message: 'e', line: 1, column: 1 } }]);
  assert.equal(none.text, "Couldn't check any input: y.json couldn't be parsed");
});
