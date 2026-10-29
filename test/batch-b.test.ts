import { test } from 'node:test';
import assert from 'node:assert/strict';
import { audit } from '../src/index.ts';

type P = Record<string, Record<string, unknown>>;
const tools = (...ts: [string, P?][]) => ({
  name: 'tools.json',
  text: JSON.stringify(ts.map(([name, properties = {}]) => ({ name, description: '', input_schema: { type: 'object', properties } })), null, 2),
});
const manifest = (m: Record<string, unknown>) => ({ name: 'agent.json', text: JSON.stringify({ agent: { name: 'Bot' }, ...m }, null, 2) });
const iam = (...Statement: Record<string, unknown>[]) => ({ name: 'iam.json', text: JSON.stringify({ Version: '2012-10-17', Statement }, null, 2) });
const of = (inputs: { name: string; text: string }[], id: string) => audit(inputs).findings.filter((f) => f.ruleId === id);
const sev = (inputs: { name: string; text: string }[], id: string) => of(inputs, id).map((f) => f.severity);
const str = { type: 'string' };

test('decision 2: send_email(to) + get_customer(id) without data-class evidence does not fire', () => {
  assert.deepEqual(sev([tools(['send_email', { to: str, body: str }], ['get_customer', { id: str }])], 'external-send-sensitive'), []);
});

test('decision 2: send_email(to) + get_patient_record(patient_id) is high', () => {
  const f = of([tools(['send_email', { to: str, body: str }], ['get_patient_record', { patient_id: str }])], 'external-send-sensitive');
  assert.deepEqual(f.map((x) => x.severity), ['high']);
  assert.deepEqual(f[0]!.servers, ['send_email', 'get_patient_record']);
});

test('external-send-sensitive: medium for pii, high in a fintech domain; a send with no free destination does not count', () => {
  const t = tools(['send_email', { to: str }], ['lookup_person', { ssn: str }]);
  assert.deepEqual(sev([t], 'external-send-sensitive'), ['medium']);
  assert.deepEqual(sev([t, manifest({ agent: { name: 'B', domain: 'fintech' } })], 'external-send-sensitive'), ['high']);
  assert.deepEqual(sev([tools(['send_reminder'], ['lookup_person', { ssn: str }])], 'external-send-sensitive'), []);
  // MCP openWorldHint with a destination param is a free destination.
  const ow = { name: 'mcp-tools.json', text: JSON.stringify({ tools: [
    { name: 'notify', inputSchema: { type: 'object', properties: { url: str } }, annotations: { openWorldHint: true } },
    { name: 'get_secret', inputSchema: { type: 'object', properties: { api_key: str } } }] }, null, 2) };
  assert.deepEqual(sev([ow], 'external-send-sensitive'), ['high']);
});

test('code-exec-action: high per action', () => {
  assert.deepEqual(sev([tools(['run_sql', { query: str }])], 'code-exec-action'), ['high']);
  assert.deepEqual(sev([tools(['get_widget'])], 'code-exec-action'), []);
});

test('bulk-export: medium on sensitive data or without a capped limit param', () => {
  assert.deepEqual(sev([tools(['export_all_customers'])], 'bulk-export'), ['medium']);
  assert.deepEqual(sev([tools(['export_orders', { limit: { type: 'integer' } }])], 'bulk-export'), ['medium']);
  assert.deepEqual(sev([tools(['export_orders', { limit: { type: 'integer', maximum: 100 } }])], 'bulk-export'), []);
});

test('broad-oauth-scope: medium for broad read/write, high for send/admin, none for narrow', () => {
  const s = (...xs: string[]) => [{ name: 'scopes.json', text: JSON.stringify(xs) }];
  assert.deepEqual(sev(s('https://www.googleapis.com/auth/drive'), 'broad-oauth-scope'), ['medium']);
  assert.deepEqual(sev(s('https://www.googleapis.com/auth/gmail.send'), 'broad-oauth-scope'), ['high']);
  assert.deepEqual(sev(s('https://www.googleapis.com/auth/admin.directory.user'), 'broad-oauth-scope'), ['high']);
  assert.deepEqual(sev(s('https://www.googleapis.com/auth/drive.file'), 'broad-oauth-scope'), []);
});

test('iam-wildcard: * on * critical, PassRole on * high, scoped write none', () => {
  assert.deepEqual(sev([iam({ Effect: 'Allow', Action: '*', Resource: '*' })], 'iam-wildcard'), ['critical']);
  assert.deepEqual(sev([iam({ Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' })], 'iam-wildcard'), ['high']);
  assert.deepEqual(sev([iam({ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: '*' })], 'iam-wildcard'), ['high']);
  assert.deepEqual(sev([iam({ Effect: 'Allow', Action: 's3:DeleteObject', Resource: '*' })], 'iam-wildcard'), ['high']);
  assert.deepEqual(sev([iam({ Effect: 'Allow', Action: '*', Resource: 'arn:aws:s3:::b/*' })], 'iam-wildcard'), ['high']);
  assert.deepEqual(sev([iam({ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' })], 'iam-wildcard'), []);
  assert.deepEqual(sev([iam({ Effect: 'Allow', Action: 's3:PutObject', Resource: 'arn:aws:s3:::b/*' })], 'iam-wildcard'), []);
  assert.deepEqual(sev([iam({ Effect: 'Deny', Action: '*', Resource: '*' })], 'iam-wildcard'), []);
});

test('carry-over 1: Allow + NotAction is parsed as a broad action and fires iam-wildcard', () => {
  const r = audit([iam({ Effect: 'Allow', NotAction: ['iam:*', 'organizations:*'], Resource: '*' })]);
  const a = r.actions.find((x) => x.kind === 'iam')!;
  assert.ok(a, 'NotAction statement yields an action');
  assert.equal(a.loc.line, 6);
  assert.deepEqual(a.resource, ['*']);
  for (const e of ['read', 'write', 'delete', 'code-exec']) assert.ok(a.effects.includes(e as never), e);
  assert.deepEqual(r.findings.filter((f) => f.ruleId === 'iam-wildcard').map((f) => f.severity), ['critical']);
  assert.deepEqual(sev([iam({ Effect: 'Allow', NotAction: 's3:*', Resource: 'arn:aws:s3:::b' })], 'iam-wildcard'), ['high']);
  assert.deepEqual(audit([iam({ Effect: 'Deny', NotAction: 's3:*', Resource: '*' })]).actions, []);
});

test('carry-over 2: iam-wildcard is the one finding for * and iam:* statements', () => {
  const r = audit([iam({ Effect: 'Allow', Action: ['*', 'iam:*'], Resource: '*' })]);
  const ids = r.findings.map((f) => `${f.ruleId}:${f.server}`);
  assert.ok(ids.includes('iam-wildcard:*'), ids.join());
  assert.ok(ids.includes('iam-wildcard:iam:*'), ids.join());
  for (const id of ['identity-admin-action', 'code-exec-action', 'bulk-export']) assert.ok(!ids.some((x) => x.startsWith(id)), ids.join());
  // A scoped iam:CreateUser is still identity-admin.
  assert.deepEqual(sev([iam({ Effect: 'Allow', Action: 'iam:CreateUser', Resource: 'arn:aws:iam::111122223333:user/x' })], 'identity-admin-action'), ['high']);
});

test('carry-over 4: policy attach/put tools and IAM actions are identity-admin', () => {
  for (const n of ['attach_user_policy', 'attach_role_policy', 'put_user_policy', 'put_role_policy'])
    assert.deepEqual(sev([tools([n, { user_name: str }])], 'identity-admin-action'), ['high'], n);
  assert.deepEqual(sev([tools(['attach_policy_document', { claim_id: str }])], 'identity-admin-action'), []);
});

test('no-manifest: one low finding without a manifest, none with one', () => {
  assert.deepEqual(sev([tools(['get_widget'])], 'no-manifest'), ['low']);
  assert.deepEqual(sev([tools(['get_widget']), manifest({})], 'no-manifest'), []);
  assert.deepEqual(sev([{ name: 'x.json', text: '{"hello":1}' }], 'no-manifest'), []);
});

const TOKEN = 'ghp_EXAMPLE' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7';
const github = (extra: Record<string, unknown> = {}) => ({
  name: 'claude_desktop_config.json',
  text: JSON.stringify({ mcpServers: {
    github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github@2025.4.8'], env: { GITHUB_PERSONAL_ACCESS_TOKEN: TOKEN } },
    ...extra } }, null, 2),
});

test('MCP pass-through: plaintext token gives mcp/secret-in-env with masked evidence and the mcp-audit helpUri', () => {
  const r = audit([github()]);
  const f = r.findings.find((x) => x.ruleId === 'mcp/secret-in-env');
  assert.ok(f, r.findings.map((x) => x.ruleId).join());
  assert.equal(f.severity, 'critical');
  assert.equal(f.helpUri, 'https://qlucent.com/tools/mcp-audit/rules/secret-in-env');
  assert.ok(f.evidence && !f.evidence.includes(TOKEN));
  assert.ok(!JSON.stringify(r).includes(TOKEN), 'token never appears raw');
  assert.equal(r.verdict.level, 'not-ready');
  assert.ok(r.verdict.counts.critical >= 1);
});

test('MCP pass-through: a github server action gets external-send from mcp-audit caps; unknown servers stay unclassified', () => {
  const r = audit([github({ mine: { command: 'node', args: ['./server.js'] } })]);
  const gh = r.actions.find((a) => a.name === 'github')!;
  for (const e of ['external-send', 'write']) assert.ok(gh.effects.includes(e as never), e);
  assert.ok(gh.data.includes('pii'));
  assert.ok(gh.evidence.every((e) => e.via === 'catalog'));
  assert.equal(gh.unclassified, undefined);
  assert.equal(r.actions.find((a) => a.name === 'mine')!.unclassified, true);
});

test('MCP github server + get_patient_record(patient_id) is an exfiltration path', () => {
  assert.deepEqual(sev([github(), tools(['get_patient_record', { patient_id: str }])], 'external-send-sensitive'), ['high']);
});
