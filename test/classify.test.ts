import { test } from 'node:test';
import assert from 'node:assert/strict';
import raw from '../src/generated/data.json' with { type: 'json' };
import { classify, detectDomain } from '../src/classify.ts';
import { action } from '../src/parse/json.ts';
import type { Action, GeneratedData } from '../src/types.ts';

const data = raw as unknown as GeneratedData;
const loc = { line: 1, column: 1, offset: 0, length: 0 };
const one = (a: Partial<Action> & Pick<Action, 'name'>) => classify([action('t.json', loc, { kind: 'tool', ...a })], data)[0]!;
const tool = (name: string, params: string[] = [], extra: Partial<Action> = {}) =>
  one({ name, params: params.map((p) => ({ name: p, type: 'string' })), ...extra });
const has = (a: Action, ...xs: string[]) => {
  for (const x of xs) assert.ok([...a.effects, ...a.data].includes(x as never), `${a.name}: expected ${x}, got ${[...a.effects, ...a.data]}`);
};
const lacks = (a: Action, ...xs: string[]) => {
  for (const x of xs) assert.ok(![...a.effects, ...a.data].includes(x as never), `${a.name}: did not expect ${x}`);
};

test('money: refunds and payment intents', () => {
  const r = tool('issue_refund', ['order_id', 'amount']);
  has(r, 'money');
  assert.match(r.evidence.find((e) => e.effect === 'money')!.why, /refund/);
  assert.equal(r.label, 'Issue refund');
  has(tool('create_payment_intent'), 'money');
  has(tool('issueRefund'), 'money');
});

test('benign names with trigger words are not money / credentials / identity-admin', () => {
  for (const n of ['refund_policy_lookup', 'get_payment_status']) {
    const a = tool(n);
    has(a, 'read');
    lacks(a, 'money');
  }
  lacks(tool('list_password_rules'), 'credentials', 'identity-admin');
  lacks(tool('get_deployment_status'), 'code-exec');
  lacks(tool('search', ['query']), 'code-exec');
  lacks(tool('transfer_ticket'), 'money');
  lacks(tool('send_payment_reminder'), 'money');
  has(tool('send_payment_reminder'), 'external-send');
  lacks(tool('send_payment'), 'external-send');
  has(tool('send_payment'), 'money');
});

test('identity-admin', () => {
  has(tool('reset_user_mfa'), 'identity-admin');
  has(tool('assign_role'), 'identity-admin');
  has(tool('disable_user'), 'identity-admin');
});

test('data classes from names and params', () => {
  const p = tool('get_patient_record', ['patient_id']);
  has(p, 'read', 'phi');
  assert.ok(p.evidence.some((e) => e.effect === 'phi' && e.via === 'param'));
  const e = tool('export_all_customers');
  has(e, 'bulk', 'pii');
  has(tool('update_profile', ['ssn']), 'pii');
  has(tool('save_card', ['card_number']), 'financial-data');
  has(tool('connect_service', ['api_key']), 'credentials');
  lacks(tool('lookup', ['country_code']), 'pii', 'phi', 'financial-data', 'credentials');
});

test('external-send and code-exec', () => {
  has(tool('send_email', ['to', 'body']), 'external-send');
  has(tool('run_sql', ['query']), 'code-exec');
  has(tool('execute_shell_command'), 'code-exec');
  lacks(tool('get_email_template'), 'external-send');
});

test('unknown names stay unclassified', () => {
  const a = tool('frobnicate');
  assert.deepEqual([a.effects, a.data, a.evidence], [[], [], []]);
});

test('HTTP methods', () => {
  const ep = (method: string, path: string, operationId?: string) =>
    one({ name: `${method} ${path}`, kind: 'endpoint', method, ...(operationId && { operationId }) });
  has(ep('GET', '/orders'), 'read');
  has(ep('HEAD', '/orders'), 'read');
  for (const m of ['POST', 'PUT', 'PATCH']) has(ep(m, '/orders'), 'write');
  has(ep('DELETE', '/orders/{id}'), 'delete');
  has(ep('POST', '/v1/refunds'), 'write', 'money');
  lacks(ep('GET', '/v1/refunds'), 'money');
  has(ep('POST', '/x', 'createRefund'), 'money');
});

test('MCP annotations', () => {
  const ro = tool('update_notes', [], { annotations: { readOnlyHint: true } });
  assert.deepEqual(ro.effects, ['read']);
  has(tool('purge_cache', [], { annotations: { destructiveHint: true } }), 'delete');
  has(tool('frobnicate', ['url'], { annotations: { openWorldHint: true } }), 'external-send');
  lacks(tool('frobnicate', ['id'], { annotations: { openWorldHint: true } }), 'external-send');
});

test('OAuth scope catalogue', () => {
  const s = (name: string) => one({ name, kind: 'scope' });
  const drive = s('https://www.googleapis.com/auth/drive');
  has(drive, 'read', 'write', 'delete');
  assert.equal(drive.broad, true);
  assert.notEqual(drive.label, drive.name);
  assert.notEqual(s('https://www.googleapis.com/auth/drive.file').broad, true);
  has(s('Mail.Send'), 'external-send');
  has(s('https://graph.microsoft.com/Mail.Send'), 'external-send');
  has(s('chat:write'), 'external-send');
  assert.equal(s('repo').broad, true);
  assert.deepEqual(s('unknown:scope').effects, []);
});

test('AWS IAM catalogue', () => {
  const i = (name: string) => one({ name, kind: 'iam', resource: ['*'] });
  has(i('s3:DeleteObject'), 'delete');
  has(i('iam:CreateUser'), 'identity-admin');
  lacks(i('iam:GetUser'), 'identity-admin');
  has(i('iam:GetUser'), 'read');
  has(i('IAM:createuser'), 'identity-admin');
  has(i('iam:*'), 'identity-admin');
  has(i('s3:*'), 'read', 'write', 'delete');
  has(i('s3:Get*'), 'read');
  lacks(i('s3:Get*'), 'delete');
  const all = i('*');
  has(all, 'read', 'write', 'delete', 'money', 'external-send', 'identity-admin', 'code-exec', 'bulk');
  has(i('secretsmanager:GetSecretValue'), 'read', 'credentials');
});

test('detectDomain: manifest domain, else purpose lexicon', () => {
  assert.equal(detectDomain({ agent: { name: 'x', purpose: 'L1 helpdesk for employees' } }, data), 'helpdesk');
  assert.equal(detectDomain({ agent: { name: 'x', purpose: 'L1 helpdesk', domain: 'fintech' } }, data), 'fintech');
  assert.equal(detectDomain({ agent: { name: 'x', purpose: 'Answers patient questions for a clinic' } }, data), 'healthcare');
  assert.equal(detectDomain({ agent: { name: 'x', purpose: 'Writes haiku' } }, data), undefined);
  assert.equal(detectDomain(undefined, data), undefined);
});
