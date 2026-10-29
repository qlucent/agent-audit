// Fix round 1 (R21): structural redaction. Each case puts a fake secret somewhere a spec can hold one; it must reach
// no output: the redacted text excerpts are cut from, the AuditResult JSON, md, sarif, table and the CLI.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { audit, toMarkdown, toSarif, toTable } from '../src/index.ts';
import { redactFile, redactFree } from '../src/secrets.ts';

type Case = [label: string, name: string, text: string, secrets: string[]];
const j = (o: unknown) => JSON.stringify(o, null, 2);
const api = (op: string) => `openapi: 3.0.3
info: { title: t, version: '1' }
paths:
  /pay:
    post:
${op.replace(/^/gm, '      ')}
      requestBody:
        content:
          application/json:
            schema:
              properties:
                amount: { type: number }
      responses: { '200': { description: ok } }
`;

const CASES: Case[] = [
  // Reviewer's C1: pairs inside the quoted value of a non-secret key.
  ['C1 tools/list description pairs', 'tools2.json', j({ tools: [
    { name: 'send_email', description: 'Send email. auth token: xoxb-123456789012-abcdefghijkl and api_key=TOOLDESC0001xyz, password: "Pw0rdInDesc12345"',
      inputSchema: { type: 'object', properties: { to: { type: 'string', default: 'sk-proj-EXAMPLEaaaaaaaaaaaaaaaaaaaa1' }, body: { type: 'string' } } } },
    { name: 'get_patient_record', description: 'x', inputSchema: { type: 'object', properties: { patient_id: { type: 'string' } } } },
  ] }), ['xoxb-123456789012-abcdefghijkl', 'TOOLDESC0001xyz', 'Pw0rdInDesc12345', 'sk-proj-EXAMPLEaaaaaaaaaaaaaaaaaaaa1']],
  ['C1 YAML summary pair', 'summary.yaml', api('summary: "call with api_key=XYZ12345678abc"'), ['XYZ12345678abc']],
  // Reviewer's C2: block scalar under a secret-named key.
  ['C2 literal block scalar', 'block2.yaml', api('x-client-secret: |\n  BlockScalarRaw2026qq'), ['BlockScalarRaw2026qq']],
  ['C2 folded block, two lines', 'folded.yaml', api('x-password: >-\n  FoldedLineOne2026aa\n  FoldedLineTwo2026bb'), ['FoldedLineOne2026aa', 'FoldedLineTwo2026bb']],
  // Reviewer's C3: quoted key with `:` and `/`.
  ['C3 IAM condition key', 'iam.json', JSON.stringify({ Version: '2012-10-17', Statement: [
    { Effect: 'Allow', Action: 's3:DeleteObject', Resource: '*', Condition: { StringEquals: { 'aws:PrincipalTag/token': 'CondSecret12345678', 's3:x-amz-server-side-encryption-aws-kms-key-id': 'AKIAEXAMPLE000000001' } } },
    { Effect: 'Allow', Action: '*', Resource: '*' },
  ] }), ['CondSecret12345678', 'AKIAEXAMPLE000000001']],
  ['IAM condition, pretty-printed', 'iam2.json', j({ Version: '2012-10-17', Statement: [
    { Effect: 'Allow', Action: 'iam:CreateUser', Resource: '*', Condition: { StringEquals: { 'aws:RequestTag/api-key': 'ReqTagKey99887766' } } },
  ] }), ['ReqTagKey99887766']],
  ['schema default under a secret-named property', 'openai.json', j([{ type: 'function', function: { name: 'issue_refund', parameters: { type: 'object', properties: {
    amount: { type: 'number' }, client_secret: { type: 'string', default: 'DefaultSecret4455' } } } } }]), ['DefaultSecret4455']],
  ['Authorization: Bearer in a description', 'anthropic.json', j([{ name: 'issue_refund', description: 'Call with Authorization: Bearer abcDEF1234567890xyz',
    input_schema: { type: 'object', properties: { amount: { type: 'number' } } } }]), ['abcDEF1234567890xyz']],
  ['JSONC line comment', 'tools.jsonc', `[\n  // api_key: Lk9Jh8Gf7Ds6Aq5WzX\n  { "type": "function", "function": { "name": "issue_refund",\n    "parameters": { "type": "object", "properties": { "amount": { "type": "number" } } } } }\n]`, ['Lk9Jh8Gf7Ds6Aq5WzX']],
  ['YAML single-quoted value under secret', 'single.yaml', api("x-secret: 'SingleQuoted5566aa'"), ['SingleQuoted5566aa']],
  ['YAML flow mapping', 'flow.yaml', api("x-login: { user: bot, password: 'FlowPw0rd5566778899' }"), ['FlowPw0rd5566778899']],
  ['nested object under a secret key', 'nested.yaml', api('x-credentials:\n  user: admin\n  pass: NestedPw0rd998877'), ['NestedPw0rd998877']],
  ['URL userinfo in a description', 'url.json', j([{ name: 'issue_refund', description: 'Posts to https://bob:UrlPw0rd7788@hooks.example.com/x',
    input_schema: { type: 'object', properties: { amount: { type: 'number' } } } }]), ['UrlPw0rd7788']],
  ['multi-line plain scalar with a pair', 'multi.yaml', api('description: Calls the upstream\n  with password=MultiLinePw0rd9988 each time'), ['MultiLinePw0rd9988']],
  ['numeric value under a secret key', 'num.yaml', api('x-pin-secret: 98765432123456789'), ['98765432123456789']],
  ['manifest purpose pair', 'agent.yaml', 'agent:\n  name: Bot\n  purpose: "support; token=Qz81mXc0vB7nPLk2Ra9s"\n', ['Qz81mXc0vB7nPLk2Ra9s']],
  ['private key in a YAML block', 'pem.yaml', api(`description: |\n  -----BEGIN PRIVATE KEY-----\n  ${'PEMBODYSENTINEL'.repeat(4)}\n  -----END PRIVATE KEY-----`), ['PEMBODYSENTINEL']],
];
const manifestOnly = (c: Case) => c[1] === 'agent.yaml';
const withTools = (c: Case) => [{ name: c[1], text: c[2] }, ...(manifestOnly(c) ? [{ name: 'tools.json', text: j([{ name: 'issue_refund', input_schema: { type: 'object', properties: { amount: { type: 'number' } } } }]) }] : [])];

for (const c of CASES) {
  const [label, name, text, secrets] = c;
  test(`no raw secret anywhere: ${label}`, () => {
    const leaks = (s: string) => secrets.filter((x) => s.includes(x));
    assert.ok(secrets.every((x) => text.includes(x)), 'case holds its secrets');
    const red = redactFile(name, text);
    assert.equal(red.text.split('\n').length, text.split('\n').length, 'line count kept');
    assert.deepEqual(leaks(red.text), [], red.text);
    const r = audit(withTools(c));
    assert.ok(r.findings.length > 0);
    assert.ok(r.files.every((f) => !f.error), JSON.stringify(r.files));
    for (const [kind, out] of [['result', JSON.stringify(r)], ['md', toMarkdown(r)], ['sarif', JSON.stringify(toSarif(r, '1'))], ['table', toTable(r)]] as const)
      assert.deepEqual(leaks(out), [], `${kind}: ${out}`);
  });
}

test('reviewer C1-C3 secrets sit inside an excerpt window, masked', () => {
  for (const c of CASES.filter(([l]) => /^C[123] /.test(l))) {
    const ex = audit(withTools(c)).findings.flatMap((f) => f.excerpt.map((l) => l.text)).join('\n');
    assert.ok(ex.includes('••••') || ex.includes('(description hidden)'), `${c[0]}: ${ex}`);
  }
});

test('CLI: no raw secret on stdout or stderr in any format', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentaudit-leaks2-'));
  const files = CASES.filter((c) => !manifestOnly(c)).map(([, name, text]) => { const p = path.join(d, name); fs.writeFileSync(p, text); return p; });
  const all = CASES.flatMap((c) => c[3]);
  for (const fmt of ['table', 'md', 'sarif']) {
    const r = spawnSync(process.execPath, [path.resolve(import.meta.dirname, '../src/cli.ts'), ...files, '--format', fmt], { encoding: 'utf8' });
    assert.ok(r.stdout.length > 0, r.stderr);
    assert.deepEqual(all.filter((x) => (r.stdout + r.stderr).includes(x)), [], fmt);
  }
});

test('the backstop does not mangle names, versions, UUIDs, ARNs or URLs (M1, M2)', () => {
  const text = `openapi: 3.0.3
info: { title: Orders, version: 2.4.1 }
components:
  securitySchemes:
    bearerAuth: { type: http, scheme: bearer, bearerFormat: JWT }
paths:
  /v2/refunds/{refund_id}:
    post:
      operationId: issue_refund_v2
      summary: Issue a refund (see https://docs.example.com/refunds?version=2024-06-01)
      parameters:
        - name: Idempotency-Key
          in: header
          example: 8e03978e-40d5-43e8-bc93-6894a57f9324
      x-signing-key: issue_refund_v2
      requestBody:
        content:
          application/json:
            schema:
              properties:
                amount: { type: number }
      responses: { '200': { description: ok } }
`;
  const iam = j({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'secretsmanager:GetSecretValue',
    Resource: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:token-AbC123' }] });
  const r = audit([{ name: 'api.yaml', text }, { name: 'iam.json', text: iam }]);
  const a = r.actions.find((x) => x.operationId)!;
  assert.equal(a.operationId, 'issue_refund_v2');
  assert.equal(a.description, undefined, 'R22: no free text in the result');
  assert.ok(redactFree('Issue a refund (see https://docs.example.com/refunds?version=2024-06-01)').endsWith('?version=••••••)'));
  assert.deepEqual(r.actions.find((x) => x.kind === 'iam')!.resource, ['arn:aws:secretsmanager:us-east-1:123456789012:secret:token-AbC123']);
  const red = redactFile('api.yaml', text).text;
  assert.ok(red.includes('8e03978e-40d5-43e8-bc93-6894a57f9324') && red.includes('version: 2.4.1') && red.includes('bearerFormat: JWT'), red);
  assert.ok(red.includes('operationId: issue_refund_v2'), red);
});
