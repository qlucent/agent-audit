import { test } from 'node:test';
import assert from 'node:assert/strict';
import { audit } from '../src/index.ts';
import { allows, buildMatrix } from '../src/scope.ts';
import type { Action } from '../src/index.ts';

type P = Record<string, Record<string, unknown>>;
const tools = (...ts: [string, P?][]) => ({
  name: 'tools.json',
  text: JSON.stringify(ts.map(([name, properties = {}]) => ({ name, description: '', input_schema: { type: 'object', properties } })), null, 2),
});
const manifest = (m: Record<string, unknown>) => ({ name: 'agent.json', text: JSON.stringify({ agent: { name: 'Bot' }, ...m }, null, 2) });
const refund = (max?: number) => tools(['issue_refund', { amount: { type: 'number', ...(max === undefined ? {} : { maximum: max }) } }]);
const act = (inputs: { name: string; text: string }[], name: string) => audit(inputs).actions.find((a) => a.name === name)!;
const by = (inputs: { name: string; text: string }[], id: string) => audit(inputs).findings.filter((f) => f.ruleId === id);

const customer = { allow: ['read:own-orders', 'refund:<=50'] };

test('refund:<=50 vs cap 200 exceeds, vs cap 40 allowed, vs no cap exceeds', () => {
  assert.equal(allows(customer, act([refund(200)], 'issue_refund')), false);
  assert.equal(allows(customer, act([refund(40)], 'issue_refund')), true);
  assert.equal(allows(customer, act([refund()], 'issue_refund')), false);
  // A manifest limit is a cap too; the lower of schema maximum and limit counts.
  assert.equal(allows(customer, act([refund()], 'issue_refund'), { issue_refund: { max_amount: 50 } }), true);
  assert.equal(allows(customer, act([refund(500)], 'issue_refund'), { 'issue_*': { max_amount: 30 } }), true);
});

test('grammar: effect targets, name globs, word targets, noun qualifiers, default deny', () => {
  const a = (name: string, effects: Action['effects'] = []) => ({ name, effects, data: [], params: [] }) as unknown as Action;
  const t = (allow: string[], x: Action) => allows({ allow }, x);
  assert.equal(t(['read:*'], a('get_order', ['read'])), true);
  assert.equal(t(['read'], a('get_order', ['read'])), true);
  assert.equal(t(['write'], a('get_order', ['read'])), false);
  assert.equal(t(['delete_*'], a('delete_ticket', ['delete'])), true);
  assert.equal(t(['email:send'], a('send_email', ['external-send'])), true);
  assert.equal(t(['email:send'], a('list_emails', ['read'])), false);
  assert.equal(t(['read:orders'], a('get_order', ['read'])), true);
  assert.equal(t(['read:orders'], a('get_invoice', ['read'])), false);
  assert.equal(t(['read:own-orders'], a('get_order', ['read'])), true);
  assert.equal(t(['refund:<=50'], a('POST /refunds', ['write', 'money'])), false);
  assert.equal(t([], a('get_order', ['read'])), false);
});

test('read:own-* clears unscoped-record-access for that role', () => {
  const t = tools(['get_customer', { customer_id: { type: 'string' } }]);
  const m = (allow: string[]) => manifest({ agent: { name: 'B', acts_for: ['customer'] }, roles: { customer: { allow } } });
  assert.equal(by([t, m(['read:own-*'])], 'unscoped-record-access').length, 0);
  assert.equal(by([t, m(['read:own-customers'])], 'unscoped-record-access').length, 0);
  assert.equal(by([t, m(['read:own-orders'])], 'unscoped-record-access').length, 1);
  assert.equal(by([t, m(['read:*'])], 'unscoped-record-access').length, 1);
});

test('matrix roles mode: agent column yes, then one column per acts_for role', () => {
  const ins = [
    tools(['issue_refund', { amount: { type: 'number', maximum: 200 } }], ['get_order', { order_id: { type: 'string' } }], ['close_ticket']),
    manifest({
      agent: { name: 'B', acts_for: ['customer', 'support-agent'] },
      roles: { customer, 'support-agent': { allow: ['read:*', 'refund:<=200'] } },
    }),
  ];
  const r = audit(ins);
  assert.equal(r.matrix.mode, 'roles');
  assert.deepEqual(r.matrix.columns, ['agent', 'customer', 'support-agent']);
  const row = (n: string) => r.matrix.rows.find((x) => x.label === r.actions.find((a) => a.name === n)!.label)!.cells;
  assert.deepEqual(row('issue_refund'), ['yes', 'exceeds', 'allowed']);
  assert.deepEqual(row('get_order'), ['yes', 'allowed', 'allowed']);
  // Granted to some role but narrower for another: exceeds-role for the narrower role, high for money.
  const ex = r.findings.filter((f) => f.ruleId === 'exceeds-role');
  assert.deepEqual(ex.map((f) => [f.severity, f.servers]), [['high', ['issue_refund']]]);
  assert.match(ex[0]!.detail!, /customer/);
});

test('default deny; a plain non-sensitive read that exceeds is amber with no finding', () => {
  const r = audit([
    tools(['get_store_hours'], ['update_ticket', { ticket_id: { type: 'string' } }]),
    manifest({ agent: { name: 'B', acts_for: ['customer', 'staff'] }, roles: { customer: { allow: [] }, staff: { allow: ['read', 'write'] } } }),
  ]);
  const cells = (n: string) => r.matrix.rows.find((x) => x.actionId === r.actions.find((a) => a.name === n)!.id)!.cells;
  assert.deepEqual(cells('get_store_hours'), ['yes', 'exceeds-minor', 'allowed']);
  assert.deepEqual(cells('update_ticket'), ['yes', 'exceeds', 'allowed']);
  const ex = r.findings.filter((f) => f.ruleId === 'exceeds-role');
  assert.deepEqual(ex.map((f) => [f.severity, f.servers]), [['medium', ['update_ticket']]]);
});

test('out_of_scope effect, or a non-read effect no role grants at all: out-of-scope-action high', () => {
  const idm = tools(['reset_user_mfa', { user_id: { type: 'string' } }]);
  const oos = by([idm, manifest({ out_of_scope: ['identity-admin'] })], 'out-of-scope-action');
  assert.deepEqual(oos.map((f) => f.severity), ['high']);
  assert.match(oos[0]!.detail!, /out_of_scope/);
  const none = by([idm, manifest({ agent: { name: 'B', acts_for: ['employee'] }, roles: { employee: { allow: ['read:*'] } } })], 'out-of-scope-action');
  assert.deepEqual(none.map((f) => f.severity), ['high']);
  // Reported as out of scope, so not again as exceeds-role.
  assert.equal(by([idm, manifest({ agent: { name: 'B', acts_for: ['employee'] }, roles: { employee: { allow: ['read:*'] } } })], 'exceeds-role').length, 0);
  assert.equal(by([idm, manifest({ out_of_scope: ['delete'] })], 'out-of-scope-action').length, 0);
  assert.equal(by([idm], 'out-of-scope-action').length, 0);
});

test('no manifest (or no acts_for): effects-mode matrix', () => {
  const r = audit([tools(['issue_refund', { amount: { type: 'number' } }], ['get_patient_record', { patient_id: { type: 'string' } }])]);
  assert.equal(r.matrix.mode, 'effects');
  assert.ok(r.matrix.columns.includes('money') && r.matrix.columns.includes('phi'));
  const i = r.matrix.columns.indexOf('money');
  const rowOf = (n: string) => r.matrix.rows.find((x) => x.actionId === r.actions.find((a) => a.name === n)!.id)!.cells;
  assert.equal(rowOf('issue_refund')[i], 'yes');
  assert.equal(rowOf('get_patient_record')[i], '');
  assert.equal(audit([tools(['get_widget']), manifest({})]).matrix.mode, 'effects');
  assert.equal(buildMatrix([]).rows.length, 0);
});

test('manifest schema rejects malformed allow entries', () => {
  const r = audit([tools(['get_widget']), manifest({ roles: { customer: { allow: ['read: own'] } } })]);
  assert.match(r.files.find((f) => f.file === 'agent.json')!.error!.message, /allow/);
});
