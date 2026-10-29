// Fix round 3 (R22): free-text fields are never output verbatim; plus R3-R6. Fixtures: test/fixtures/leaks3, from the
// second re-review. Same checks as round 2: raw, minus its last 4 characters, lowercased; every output; the CLI.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { audit, toMarkdown, toSarif, toTable } from '../src/index.ts';
import { redactFile } from '../src/secrets.ts';

const dir = path.resolve(import.meta.dirname, 'fixtures/leaks3');
const read = (f: string) => ({ name: f, text: fs.readFileSync(path.join(dir, f), f.startsWith('u16') ? 'utf16le' : 'utf8') });
const probes = (s: string) => [s, ...(s.length >= 12 ? [s.slice(0, -4)] : [])].map((p) => p.toLowerCase());
const leaksIn = (secrets: string[], s: string) => secrets.filter((x) => probes(x).some((p) => s.toLowerCase().includes(p)));

const CRLF = ['CrlfComment2026Qx9', 'CrlfDesc2026QxQx9', 'dXNlcjpDcmxmQmFzaWMyMDI2UXg5', 'CrlfBlock2026QxQx9', 'CrlfBlock2nd2026Qx9', 'CrlfFolded2026Qx9', 'CrlfFolded2nd2026Qx9'];
const CASES: [file: string, secrets: string[]][] = [
  ['base.yaml', CRLF],
  ['crlf.yaml', CRLF],
  ['form2.yaml', ['FormBlock2026Qx9', 'FormRefresh2026Qx9', 'RespAccess2026Qx9']],
  ['srv.yaml', ['FormExs2026QxQx9', 'FormEx2026QxQx9', 'CodeSample2026QxQx9', 'FormConst2026Qx9', 'FormObj2026QxQx9', 'HdrEnum2026QxQx9', 'IntegHdr2026QxQx9',
    'SrvVarDefault2026Qx9', 'SrvVarEnumA2026Qx9', 'SrvVarEnumB2026Qx9', 'SrvVarTok2026QxQx9', 'XApiKeyInfo2026Qx9', 'XDefHdr2026QxQx9', 'XPostman2026QxQx9',
    'XSampleAuth2026QxQx9', 'XSrvTok2026QxQx9']],
  ['tabs.yaml', ['TabHdr2026QxQx9', 'TabKey2026QxQx9', 'TabVal2026QxQx9']],
  ['tabs2.yaml', ['Tab2Key2026QxQx9', 'Tab2Val2026QxQx9']],
  ['u8bom.yaml', ['B8yComment2026Qx9', 'B8yDesc2026QxQx9', 'B8yBlock2026QxQx9', 'B8yBlock2nd2026Qx9', 'B8yFolded2026Qx9', 'B8yFolded2nd2026Qx9']],
  ['iam.json', ['AKIAIOSFODNN7EXAMPLE', 'AKIAIOSFODNN7EXAMPLF', 'AKIAIOSFODNN7EXAMPLG']],
  ['mcpt.json', ['AnnBearer2026QxQx9', 'AnnKey2026QxQx9', 'xoxb-0000000000-EXAMPLEEXAMPLE']],
  ['md.json', ['MdQuery2026Qx9', 'MdBold2026QxQx9z', 'MdBoldTok2026Qx9z', 'MdFence2026QxQx9', 'MdFenceKey2026Qx9', 'MdInline2026QxQx9', 'MdTable2026QxQx9',
    'ParamDesc2026QxQx9', 'SchemaApiDef2026Qx9', 'SchemaApiEx2026Qx9', 'SchemaConst2026Qx9', 'SchemaDef2026Qx9', 'sk-ant-api03-EXAMPLE0000000000000000000',
    '7c1f9e2a4b6d8c0e1f2a3b4c5d6e7f80']],
  ['oai.json', ['OaiConst2026QxQx9', 'OaiDefault2026Qx9', 'OaiDescKey2026Qx9', 'OaiEnum2026QxQx9', 'OaiHdrDef2026Qx9', 'OaiInline2026Qx9', 'sk-proj-EXAMPLE000000000000000000000077']],
  ['tabs.json', ['TabJsonHdr2026Qx9', 'TabJson2026QxQx9']],
  ['u8bom.json', ['Bom8Hdr2026Qx9', 'Bom82026QxQx9']],
  ['u16.json', ['U162026QxQx9', 'U16Hdr2026Qx9']],
  ['u16.yaml', ['U16yComment2026Qx9', 'U16yDesc2026QxQx9', 'dXNlcjpDcmxmQmFzaWMyMDI2UXg5', 'U16yBlock2026QxQx9', 'U16yBlock2nd2026Qx9', 'U16yFolded2026Qx9', 'U16yFolded2nd2026Qx9']],
  ['man.yaml', ['ghp_EXAMPLE0000000000000000000000000066', 'xoxb-0000000000-EXAMPLEROLE', 'sk_live_EXAMPLE00000000000000000088']],
];
const tools = { name: 'tools.json', text: JSON.stringify([{ name: 'refund_payment', input_schema: { type: 'object', properties: { amount: { type: 'number' } } } }], null, 2) };

for (const [file, secrets] of CASES) {
  test(`no raw secret in any output: ${file}`, () => {
    const input = read(file);
    assert.ok(secrets.every((s) => input.text.includes(s)), 'fixture holds its secrets');
    const r = audit(file === 'man.yaml' ? [input, tools] : [input]);
    const red = redactFile(input.name, input.text);
    assert.equal(red.text.split('\n').length, input.text.split('\n').length, 'line count');
    assert.equal(red.text.split('\r').length, input.text.split('\r').length, 'CR count');
    if (!r.files[0]!.error) assert.deepEqual(leaksIn(secrets, red.text), [], red.text);
    for (const [kind, out] of [['result', JSON.stringify(r)], ['md', toMarkdown(r)], ['sarif', JSON.stringify(toSarif(r, '1'))], ['table', toTable(r)]] as const)
      assert.deepEqual(leaksIn(secrets, out), [], `${kind}: ${out}`);
  });
}

test('CLI: no raw secret on stdout, stderr or --output', () => {
  const all = CASES.flatMap(([, s]) => s);
  const files = CASES.map(([f]) => f).filter((f) => !f.startsWith('u16')).map((f) => path.join(dir, f));
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'agentaudit-r3-')), 'o.txt');
  for (const fmt of ['table', 'md', 'sarif']) for (const extra of [[], ['--output', out]]) {
    const r = spawnSync(process.execPath, [path.resolve(import.meta.dirname, '../src/cli.ts'), ...files, '--format', fmt, ...extra], { encoding: 'utf8' });
    const text = r.stdout + r.stderr + (extra.length ? fs.readFileSync(out, 'utf8') : '');
    assert.ok(text.length > 100, r.stderr);
    assert.deepEqual(leaksIn(all, text), [], `${fmt} ${extra.join(' ')}`);
  }
  fs.rmSync(path.dirname(out), { recursive: true });
});

test('R22: free-text fields are hidden in the redacted text, kept out of the result, and still classified', () => {
  const md = read('md.json');
  const red = redactFile(md.name, md.text).text;
  assert.ok(red.includes('"description": "(description hidden)"'), red);
  const y = read('base.yaml');
  const ry = redactFile(y.name, y.text).text;
  assert.ok(ry.includes('description: "(description hidden)"') && ry.includes('title: "(description hidden)"'), ry);
  // An x-* block scalar keeps one line per original line.
  assert.match(ry, /x-client-secret: \|\n {8}\(description hidden\)\n {8}\(description hidden\)\n/);
  const r = audit([md]);
  assert.ok(r.actions.every((a) => a.description === undefined), JSON.stringify(r.actions));
  assert.ok(r.actions[0]!.effects.includes('money'), 'still classified');
  const desc = audit([{ name: 't.json', text: JSON.stringify([{ name: 'do_it', description: 'Issue a refund to the card', input_schema: { type: 'object', properties: {} } }]) }]);
  for (const e of desc.actions[0]!.evidence.filter((x) => x.via === 'description')) assert.match(e.why, /^description mentions "[\w -]{1,40}"$/);
  const mcp = audit([read('mcpt.json')]);
  assert.ok(!JSON.stringify(mcp).includes('Delete user (key'), 'annotations.title hidden');
});

test('R22: an OpenAPI label never comes from the summary', () => {
  const r = audit([{ name: 'a.yaml', text: 'openapi: 3.0.3\npaths:\n  /x:\n    post:\n      summary: Refund with token=Abc123Def456Ghi7\n      responses: {}\n' }]);
  assert.equal(r.actions[0]!.label, 'POST /x');
});

test('R5/R3: names under properties stay readable; real values under secret names masked', () => {
  const c = read('clean2.yaml');
  const red = redactFile(c.name, c.text).text;
  for (const s of ['arn:aws:iam::123456789012:role/token-rotator', 'example: us-east-1', 'example: v2.1.0', 'enum: [access_token, refresh_token, id_token]',
    'enum: [strict, relaxed]', 'operationId: revokeApiToken2024', 'example: 3fa85f64-5717-4562-b3fc-2c963f66afa6', 'example: 2024-06-01',
    'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/api-key-AbCdEf', 'example: 3600'])
    assert.ok(red.includes(s), `${s}\n${red}`);
  const i = read('iamc.json');
  const ri = redactFile(i.name, i.text).text;
  for (const s of ['RotateApiKeys2024', 'AWSCURRENT', 'arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab']) assert.ok(ri.includes(s), ri);
});

test('R6: a UTF-8 BOM YAML file parses', () => {
  const r = audit([read('u8bom.yaml')]);
  assert.ok(!r.files[0]!.error, JSON.stringify(r.files));
  assert.equal(r.files[0]!.format, 'openapi');
  assert.ok(r.findings.some((f) => f.excerpt.length > 0));
});
