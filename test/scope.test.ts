import { test } from 'node:test';
import assert from 'node:assert/strict';
import { audit } from '../src/index.ts';
import { allows, buildMatrix } from '../src/scope.ts';
import { checks } from '../src/checks/index.ts';
import { rules } from '../src/engine.ts';
import type { Action, CheckContext, Rule } from '../src/index.ts';

type P = Record<string, Record<string, unknown>>;
type In = { name: string; text: string };
const tools = (...ts: [string, P?][]) => ({
  name: 'tools.json',
  text: JSON.stringify(ts.map(([name, properties = {}]) => ({ name, description: '', input_schema: { type: 'object', properties } })), null, 2),
});
const manifest = (m: Record<string, unknown>) => ({ name: 'agent.json', text: JSON.stringify({ agent: { name: 'Bot' }, ...m }, null, 2) });
const refund = (max?: number) => tools(['issue_refund', { amount: { type: 'number', ...(max === undefined ? {} : { maximum: max }) } }]);
const act = (inputs: In[], name: string) => audit(inputs).actions.find((a) => a.name === name)!;
const by = (inputs: In[], id: string) => audit(inputs).findings.filter((f) => f.ruleId === id);
const stub = (name: string, effects: Action['effects'] = [], operationId?: string) =>
  ({ name, effects, data: [], params: [], operationId }) as unknown as Action;

const customer = { allow: ['read:own-orders', '*refund*:<=50'] };

test('*refund*:<=50 vs cap 200 exceeds, vs cap 40 allowed, vs no cap exceeds', () => {
  assert.equal(allows(customer, act([refund(200)], 'issue_refund')), false);
  assert.equal(allows(customer, act([refund(40)], 'issue_refund')), true);
  assert.equal(allows(customer, act([refund()], 'issue_refund')), false);
  // A manifest limit is a cap too; the lower of schema maximum and limit counts.
  assert.equal(allows(customer, act([refund()], 'issue_refund'), { issue_refund: { max_amount: 50 } }), true);
  assert.equal(allows(customer, act([refund(500)], 'issue_refund'), { 'issue_*': { max_amount: 30 } }), true);
});

test('grammar: effect targets, full-name globs, noun qualifiers, default deny', () => {
  const t = (allow: string[], x: Action) => allows({ allow }, x);
  assert.equal(t(['read:*'], stub('get_order', ['read'])), true);
  assert.equal(t(['read'], stub('get_order', ['read'])), true);
  assert.equal(t(['write'], stub('get_order', ['read'])), false);
  assert.equal(t(['delete_*'], stub('delete_ticket', ['delete'])), true);
  assert.equal(t(['send_email'], stub('send_email', ['external-send'])), true);
  assert.equal(t(['*refund*'], stub('POST /orders/{id}/refund', ['write', 'money'])), true);
  assert.equal(t(['refundOrder'], stub('POST /orders/{id}/refund', ['write', 'money'], 'refundOrder')), true);
  assert.equal(t(['read:orders'], stub('get_order', ['read'])), true);
  assert.equal(t(['read:orders'], stub('get_invoice', ['read'])), false);
  assert.equal(t(['read:addresses'], stub('get_address', ['read'])), true);
  assert.equal(t(['read:own-orders'], stub('get_order', ['read'])), true);
  assert.equal(t(['*refund*:<=50'], stub('POST /refunds', ['write', 'money'])), false);
  assert.equal(t([], stub('get_order', ['read'])), false);
});

test('R20: targets are effects or full-name globs, never one word of the name', () => {
  assert.equal(allows({ allow: ['orders'] }, stub('POST /orders/{id}/refund', ['write', 'money'])), false);
  assert.equal(allows({ allow: ['refund'] }, stub('issue_refund', ['money'])), false);
  assert.equal(allows({ allow: ['user'] }, stub('reset_user_mfa', ['identity-admin'])), false);
  const f = by([tools(['reset_user_mfa', { user_id: { type: 'string' } }]),
    manifest({ agent: { name: 'B', acts_for: ['employee'] }, roles: { employee: { allow: ['user'] } } })], 'out-of-scope-action');
  assert.equal(f.length, 1);
});

test('R17: an effect target grants only when it covers every high-risk effect of the action', () => {
  const run = (tool: [string, P?], effects: string[], allow: string[]) => audit([tools(tool),
    manifest({ agent: { name: 'B', acts_for: ['r'] }, roles: { r: { allow } }, actions: { [tool[0]]: { effects } } })]);
  const cell = (x: ReturnType<typeof audit>) => x.matrix.rows[0]!.cells[1];
  const capped: P = { amount: { type: 'number', maximum: 40 } };
  const refundW = run(['issue_refund', capped], ['write', 'money'], ['write']);
  assert.equal(cell(refundW), 'exceeds');
  assert.ok(refundW.findings.some((f) => f.ruleId === 'out-of-scope-action' || f.ruleId === 'exceeds-role'));
  const mfaW = run(['reset_user_mfa'], ['write', 'identity-admin'], ['write']);
  assert.equal(cell(mfaW), 'exceeds');
  assert.equal(mfaW.findings.filter((f) => f.ruleId === 'out-of-scope-action').length, 1);
  assert.equal(cell(run(['issue_refund', capped], ['write', 'money'], ['money:<=50'])), 'allowed');
  assert.equal(cell(run(['pay_and_notify', capped], ['money', 'external-send'], ['money'])), 'exceeds');
  assert.equal(cell(run(['pay_and_notify', capped], ['money', 'external-send'], ['pay_*'])), 'allowed');
});

test('R19: own is a declaration: unscoped-record-access drops to low and the cell is declared', () => {
  const t = tools(['get_customer', { customer_id: { type: 'string' } }]);
  const m = (allow: string[]) => manifest({ agent: { name: 'B', acts_for: ['customer'] }, roles: { customer: { allow } } });
  for (const allow of [['read:own-*'], ['read:own-customers'], ['read:own']]) {
    const f = by([t, m(allow)], 'unscoped-record-access');
    assert.deepEqual(f.map((x) => x.severity), ['low'], allow.join());
    assert.equal(f[0]!.detail, 'get_customer: declared own-only; make sure the server binds customer_id to the signed-in user (the spec accepts any value)');
    assert.deepEqual(audit([t, m(allow)]).matrix.rows[0]!.cells, ['yes', 'declared']);
  }
  assert.deepEqual(by([t, m(['read:own-orders'])], 'unscoped-record-access').map((x) => x.severity), ['high']);
  assert.deepEqual(by([t, m(['read:*'])], 'unscoped-record-access').map((x) => x.severity), ['high']);
  // A grant without own on another acted-for role is green there; the own role stays declared.
  const both = audit([t, manifest({ agent: { name: 'B', acts_for: ['customer', 'staff'] },
    roles: { customer: { allow: ['read:own'] }, staff: { allow: ['read'] } } })]);
  assert.deepEqual(both.matrix.rows[0]!.cells, ['yes', 'declared', 'allowed']);
  // No record-id param: the server derives the requester, so own is simply allowed.
  assert.deepEqual(audit([tools(['get_my_orders']), m(['read:own'])]).matrix.rows[0]!.cells, ['yes', 'allowed']);
});

test('R19 healthcare: read:own + get_patient_record(patient_id) is a low finding and a declared cell', () => {
  const r = audit([tools(['get_patient_record', { patient_id: { type: 'string' } }]),
    manifest({ agent: { name: 'B', domain: 'healthcare', acts_for: ['patient'] }, roles: { patient: { allow: ['read:own'] } } })]);
  assert.deepEqual(r.findings.filter((f) => f.ruleId === 'unscoped-record-access').map((f) => f.severity), ['low']);
  assert.deepEqual(r.matrix.rows[0]!.cells, ['yes', 'declared']);
});

test('matrix roles mode: agent column yes, then one column per acts_for role', () => {
  const r = audit([
    tools(['issue_refund', { amount: { type: 'number', maximum: 200 } }], ['get_order', { order_id: { type: 'string' } }], ['close_ticket']),
    manifest({
      agent: { name: 'B', acts_for: ['customer', 'support-agent'] },
      roles: { customer, 'support-agent': { allow: ['read:*', '*refund*:<=200'] } },
    }),
  ]);
  assert.equal(r.matrix.mode, 'roles');
  assert.deepEqual(r.matrix.columns, ['agent', 'customer', 'support-agent']);
  const row = (n: string) => r.matrix.rows.find((x) => x.actionId === r.actions.find((a) => a.name === n)!.id)!.cells;
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
  const emp = manifest({ agent: { name: 'B', acts_for: ['employee'] }, roles: { employee: { allow: ['read:*'] } } });
  assert.deepEqual(by([idm, emp], 'out-of-scope-action').map((f) => f.severity), ['high']);
  // Reported as out of scope, so not again as exceeds-role.
  assert.equal(by([idm, emp], 'exceeds-role').length, 0);
  assert.equal(by([idm, manifest({ out_of_scope: ['delete'] })], 'out-of-scope-action').length, 0);
  assert.equal(by([idm], 'out-of-scope-action').length, 0);
});

test('matrix: an out_of_scope action exceeds in every role column even when granted', () => {
  const r = audit([tools(['reset_user_mfa']),
    manifest({ agent: { name: 'B', acts_for: ['it'] }, roles: { it: { allow: ['reset_*'] } }, out_of_scope: ['identity-admin'] })]);
  assert.deepEqual(r.matrix.rows[0]!.cells, ['yes', 'exceeds']);
});

test('an acts_for role with no roles entry is named in the detail', () => {
  const f = by([tools(['update_ticket']), manifest({ agent: { name: 'B', acts_for: ['custmer'] }, roles: { customer: { allow: ['write'] } } })], 'out-of-scope-action');
  assert.match(f[0]!.detail!, /no roles entry for custmer/);
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

test('manifest schema rejects malformed allow entries and a role named agent', () => {
  const err = (m: Record<string, unknown>) => audit([tools(['get_widget']), manifest(m)]).files.find((f) => f.file === 'agent.json')!.error?.message;
  assert.match(err({ roles: { customer: { allow: ['read: own'] } } })!, /allow/);
  assert.match(err({ roles: { customer: { allow: ['read:own-'] } } })!, /allow/);
  assert.match(err({ agent: { name: 'B', acts_for: ['agent'] } })!, /acts_for/);
  assert.match(err({ roles: { agent: { allow: ['read'] } } })!, /roles/);
  assert.equal(err({ agent: { name: 'B', acts_for: ['agents', 'support-agent'] }, roles: { agents: { allow: ['read'] } } }), undefined);
});

test('scope check is roughly linear: 20 roles x 500 actions x 10 entries < 300 ms, 40 roles < 600 ms', () => {
  const shapes: [string, P][] = [
    ['get_item', {}], ['update_ticket', {}], ['issue_refund', { amount: { type: 'number', maximum: 80 } }],
    ['delete_doc', {}], ['get_customer', { customer_id: { type: 'string' } }],
  ];
  const ts = Array.from({ length: 500 }, (_, i): [string, P] => [`${shapes[i % 5]![0]}_${i}`, shapes[i % 5]![1]]);
  const entries = ['read:own', 'write:tickets', '*refund*:<=100', 'delete_doc_1*', 'get_*', 'money:<=50', 'read:items', 'update_*', 'send_email', '*customer*:own-*'];
  const rule = (id: string) => rules.find((x) => x.id === id)! as Rule;
  for (const [n, limit] of [[20, 300], [40, 600]] as const) {
    const roles = Array.from({ length: n }, (_, i) => `role${i}`);
    const r = audit([tools(...ts), manifest({ agent: { name: 'B', acts_for: roles },
      roles: Object.fromEntries(roles.map((x, i) => [x, { allow: entries.slice(0, 10 - (i % 3)) }])) })]);
    const ctx = { actions: r.actions, manifest: r.manifest, files: r.files } as CheckContext;
    const start = performance.now();
    buildMatrix(r.actions, r.manifest);
    for (const id of ['out-of-scope-action', 'exceeds-role']) checks[id]!(ctx, rule(id));
    const ms = performance.now() - start;
    assert.ok(ms < limit, `${n} roles: ${ms.toFixed(0)} ms`);
  }
});

test('I1: exceeds-role names the entry whose qualifier failed, and its fix asks for a cap, not the entry', () => {
  const roles = { agent: { name: 'Bot', acts_for: ['customer'] }, roles: { customer: { allow: ['*refund*:<=50'] } } };
  const [none] = by([refund(), manifest(roles)], 'exceeds-role');
  assert.match(none!.detail!, /customer allows `\*refund\*:<=50`, but issue_refund has no cap/);
  assert.doesNotMatch(none!.fix, /add an allow entry/);
  assert.match(none!.fix, /maximum|max_amount/);
  const [over] = by([refund(200), manifest(roles)], 'exceeds-role');
  assert.match(over!.detail!, /customer allows `\*refund\*:<=50`, but issue_refund's cap 200 is above 50/);
  // A word qualifier that fails.
  const words = { agent: { name: 'Bot', acts_for: ['customer'] }, roles: { customer: { allow: ['write:orders'] } } };
  const [w] = by([tools(['update_ticket', { ticket_id: { type: 'string' } }]), manifest(words)], 'exceeds-role');
  assert.match(w!.detail!, /customer allows `write:orders`, but update_ticket has no word matching "orders"/);
  // No entry targets the action: the generic text stays.
  const generic = { agent: { name: 'Bot', acts_for: ['customer', 'staff'] }, roles: { customer: { allow: ['read'] }, staff: { allow: ['write'] } } };
  const [g] = by([tools(['update_ticket', { ticket_id: { type: 'string' } }]), manifest(generic)], 'exceeds-role');
  assert.match(g!.detail!, /which the customer role does not allow$/);
  assert.match(g!.fix, /add an allow entry/);
});
