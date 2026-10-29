import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseInputs } from '../src/parse/index.ts';

const fx = (name: string) => ({ name, text: readFileSync(new URL(`./fixtures/specs/${name}`, import.meta.url), 'utf8') });
const one = (name: string) => parseInputs([fx(name)]);
const j = (v: unknown) => JSON.stringify(v, null, 2);
const lines = (r: ReturnType<typeof parseInputs>) => r.actions.map((a) => [a.name, a.loc.line, a.loc.column]);

test('OpenAI Chat Completions tools (JSONC with comment and trailing comma)', () => {
  const r = one('openai-tools.json');
  assert.deepEqual(r.files, [{ file: 'openai-tools.json', format: 'openai-tools', actions: 2 }]);
  assert.deepEqual(lines(r), [['get_order', 6, 7], ['issue_refund', 20, 7]]);
  const refund = r.actions[1]!;
  assert.equal(refund.kind, 'tool');
  assert.equal(refund.description, 'Refund part or all of an order to the original card.');
  assert.deepEqual(
    refund.params.map((p) => [p.name, p.type, p.maximum, p.loc?.line]),
    [['order_id', 'string', undefined, 25], ['amount', 'number', 200, 26], ['reason', 'string', undefined, 27]],
  );
  assert.deepEqual([refund.effects, refund.data, refund.evidence], [[], [], []]);
});

test('OpenAI Responses-API flat form', () => {
  const text = JSON.stringify({ tools: [{ type: 'function', name: 'send_email', parameters: { type: 'object', properties: { to: { type: 'string' } } } }] }, null, 2);
  const r = parseInputs([{ name: 'responses.json', text }]);
  assert.equal(r.files[0]!.format, 'openai-tools');
  assert.equal(r.actions[0]!.name, 'send_email');
  assert.equal(r.actions[0]!.loc.line, 5);
  assert.deepEqual(r.actions[0]!.params.map((p) => p.name), ['to']);
});

test('Anthropic tools', () => {
  const r = one('anthropic-tools.json');
  assert.equal(r.files[0]!.format, 'anthropic-tools');
  assert.deepEqual(lines(r), [['get_patient_record', 4, 7], ['send_message', 16, 7]]);
  assert.deepEqual(r.actions[0]!.params.map((p) => [p.name, p.type, p.loc?.line]), [['patient_id', 'string', 9], ['sections', 'array', 10]]);
});

test('MCP tools/list dump with annotations and nested params', () => {
  const r = one('mcp-tools.json');
  assert.equal(r.files[0]!.format, 'mcp-tools');
  assert.deepEqual(lines(r), [['search_tickets', 4, 7], ['reset_user_mfa', 16, 7]]);
  assert.deepEqual(r.actions[0]!.annotations, { readOnlyHint: true, openWorldHint: false });
  assert.deepEqual(r.actions[0]!.params.map((p) => [p.name, p.maximum]), [['query', undefined], ['limit', 100]]);
  assert.deepEqual(r.actions[1]!.params.map((p) => [p.name, p.loc?.line]), [['user', 21], ['user.user_id', 23]]);
});

test('MCP tools/list wrapped in a JSON-RPC result', () => {
  const text = JSON.stringify({ jsonrpc: '2.0', id: 1, result: { tools: [{ name: 'get_ticket', inputSchema: { type: 'object' } }] } });
  const r = parseInputs([{ name: 'list.json', text }]);
  assert.equal(r.files[0]!.format, 'mcp-tools');
  assert.deepEqual(r.actions.map((a) => a.name), ['get_ticket']);
});

test('OpenAPI 3 (YAML): METHOD /path actions, operationId label, per-operation scopes, $ref params', () => {
  const r = one('openapi.yaml');
  assert.equal(r.files[0]!.format, 'openapi');
  assert.deepEqual(lines(r), [['GET /refunds', 9, 5], ['POST /refunds', 16, 5], ['DELETE /customers/{customer_id}', 29, 5]]);
  const [list, create, del] = r.actions as [any, any, any];
  assert.deepEqual([list.kind, list.method, list.operationId, list.label], ['endpoint', 'GET', 'listRefunds', 'List refunds']);
  assert.equal(create.label, 'Create refund');
  assert.equal(del.label, 'Delete a customer');
  assert.deepEqual(list.scopes, ['payments.read']);
  assert.deepEqual(create.scopes, ['payments.write', 'refunds.create']);
  assert.deepEqual(list.params.map((p: any) => [p.name, p.type, p.maximum, p.loc.line, p.loc.column]), [['limit', 'integer', 500, 13, 11]]);
  assert.deepEqual(create.params.map((p: any) => [p.name, p.type, p.loc.line]), [['charge_id', 'string', 42], ['amount', 'integer', 43]]);
  assert.deepEqual(del.params.map((p: any) => [p.name, p.loc.line]), [['customer_id', 34]]);
});

test('AWS IAM: one action per Allow action pattern, with resource and condition', () => {
  const r = one('iam.json');
  assert.equal(r.files[0]!.format, 'aws-iam');
  assert.deepEqual(lines(r), [['s3:GetObject', 7, 18], ['s3:ListBucket', 7, 34], ['iam:PassRole', 19, 17]]);
  assert.deepEqual(r.actions[0]!.resource, ['arn:aws:s3:::example-reports', 'arn:aws:s3:::example-reports/*']);
  assert.deepEqual(r.actions[2]!.resource, ['*']);
  assert.deepEqual(JSON.parse(JSON.stringify(r.actions[2]!.condition)), { StringEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } });
  assert.equal(r.actions[2]!.kind, 'iam');
});

test('OAuth scopes', () => {
  const r = one('oauth-scopes.json');
  assert.equal(r.files[0]!.format, 'oauth-scopes');
  assert.deepEqual(lines(r), [
    ['https://www.googleapis.com/auth/drive', 3, 5], ['Mail.Send', 4, 5], ['chat:write', 5, 5], ['repo', 6, 5],
  ]);
  assert.equal(r.actions[0]!.kind, 'scope');
  const bare = parseInputs([{ name: 's.yaml', text: '- openid\n- admin.users:write\n- Files.ReadWrite.All\n' }]);
  assert.equal(bare.files[0]!.format, 'oauth-scopes');
  assert.deepEqual(bare.actions.map((a) => a.loc.line), [1, 2, 3]);
});

test('manifest (YAML) is validated and returned', () => {
  const r = one('manifest.yaml');
  assert.deepEqual(r.files, [{ file: 'manifest.yaml', format: 'manifest', actions: 0 }]);
  assert.equal(r.manifest?.agent.name, 'Support refund bot');
  assert.deepEqual(r.manifest?.roles?.customer?.allow, ['read:own', '*refund*:<=50']);
  assert.equal(r.manifest?.limits?.issue_refund?.max_amount, 200);
});

test('invalid manifest is a file error naming the path, at its location', () => {
  const text = 'agent:\n  name: Bot\n  domain: banking\nroles:\n  customer: { allow: read }\n';
  const r = parseInputs([{ name: 'm.yaml', text }]);
  assert.equal(r.manifest, undefined);
  const f = r.files[0]!;
  assert.equal(f.format, 'manifest');
  assert.match(f.error!.message, /\/agent\/domain/);
  assert.deepEqual([f.error!.line, f.error!.column], [3, 11]);
  const extra = parseInputs([{ name: 'm.json', text: '{"agent": {"name": "x"}, "scope": []}' }]).files[0]!;
  assert.match(extra.error!.message, /\/scope/);
  assert.match(parseInputs([{ name: 'm.json', text: '{"agent": {}}' }]).files[0]!.error!.message, /\/agent.*name/);
});

test('MCP client config: one action per server, file passed through', () => {
  const r = one('claude_desktop_config.json');
  assert.equal(r.files[0]!.format, 'mcp-config');
  assert.deepEqual(lines(r), [['filesystem', 3, 5], ['github', 7, 5]]);
  assert.equal(r.actions[0]!.kind, 'mcp-server');
  assert.deepEqual(r.mcpFiles.map((f) => f.name), ['claude_desktop_config.json']);
});

test('OpenAPI: external or missing $ref parameters stay as placeholders', () => {
  const text = j({
    openapi: '3.0.0',
    paths: { '/a': { get: { parameters: [{ $ref: 'common.yaml#/components/parameters/AccountId' }, { $ref: '#/components/parameters/Missing' }] } } },
  });
  const p = parseInputs([{ name: 'o.json', text }]).actions[0]!.params;
  assert.deepEqual(p.map((x) => [x.name, x.type, x.loc?.line]), [['AccountId', undefined, 8], ['Missing', undefined, 11]]);
});
