// Fix round 2: the re-review's probe fixtures (test/fixtures/leaks2). A secret must reach no output, not even with its
// last 4 characters dropped (mask keeps those) or lowercased in a label; and plain spec text must stay readable.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseDocument } from 'yaml';
import { audit, toMarkdown, toSarif, toTable } from '../src/index.ts';
import { redactFile, redactFree } from '../src/secrets.ts';

const dir = path.resolve(import.meta.dirname, 'fixtures/leaks2');
const read = (f: string) => ({ name: f, text: fs.readFileSync(path.join(dir, f), 'utf8') });
const probes = (s: string) => [s, ...(s.length >= 12 ? [s.slice(0, -4)] : [])];

const CASES: [files: string[], secrets: string[]][] = [
  [['hdr.yaml'], ['dXNlcjpIZHJCYXNpYzIwMjZReDk=', 'HdrSchemaEx2026Qx9', 'ChainedHdr2026QxQx9']],
  [['agent.yaml', 'tools.json'], ['ManPurpose2026QxQx9', 'ManCurrency2026Qx9', 'ManApproval2026Qx9', 'ManOOSChain2026Qx9', 'sk_live_EXAMPLE00000000000000000042']],
  [['agent2.yaml', 'tools.json'], ['ManLimitKey2026Qx9']],
  [['agent3.yaml', 'tools.json'], ['ManRolePw2026Qx9z', 'ManOOS2026Qx9zz']],
  [['long.json'], ['LongLineTok2026QxQx9', 'LongLineHdr2026QxQx9', 'LongLineKey2026QxQx9']],
  [['api.yaml'], ['SrvQuerySec2026Qx', 'SrvSig2026QxQx9', 'SrvQuoted2026Qx9', 'dXNlcjpCYXNpY1Bhc3MyMDI2UXg=', 'dXNlcjpYRXhhbXBsZTIwMjZReDk=',
    'ApiKeyDesc2026Qx9', 'ApiKeyExample2026Q', 'sk_live_EXAMPLE00000000000000000099', 'BearerNoColon2026Q', 'SigPart2026QxQxQx', 'QueryInDesc2026Qx',
    'TokInUrlDesc2026Q', 'dXNlcjpQYXJhbUJhc2ljMjAyNg==', 'ParamExampleKey2026Q', 'BodyExKey2026Qx9']],
  [['prev-openapi.yaml'], ['Hunter2Pass99', 'QWERTY12345678', 'sk_live_EXAMPLE00000000000000000001', '9f8e7d6c5b4a39281706f5e4d3c2b1a0', 'HDRDEFAULT9876543210xyz',
    'dozjgNryP4J3', 'BlockScalarSecret777xyz', 'CLIENTSECRET0123456789abcdef']],
  [['anchor.yaml'], ['AnchorPass2026xyzQ', 'AliasTokVal2026abcd']],
  [['anchor2.yaml'], ['AnchoredPlainVal2026Q9']],
  [['anchor3.yaml'], ['AnchoredVal2026Qx9']],
  [['anchor4.yaml'], ['AnchoredSecret2026Qx9']],
  [['merge.yaml'], ['MergeSecret2026Qx9']],
  [['names.json'], ['ghp_EXAMPLE0000000000000000000000000055']],
];

for (const [files, secrets] of CASES) {
  test(`no raw secret in any output: ${files.join(' + ')}`, () => {
    const inputs = files.map(read);
    const leaks = (s: string) => secrets.filter((x) => probes(x).some((p) => s.includes(p) || s.toLowerCase().includes(p.toLowerCase())));
    const r = audit(inputs);
    // The redacted text is what excerpts are cut from; a file with an error shows none.
    for (const i of inputs.filter((x) => !r.files.find((f) => f.file === x.name)!.error)) {
      const red = redactFile(i.name, i.text);
      assert.equal(red.text.split('\n').length, i.text.split('\n').length);
      assert.deepEqual(leaks(red.text), [], `${i.name}:\n${red.text}`);
    }
    for (const [kind, out] of [['result', JSON.stringify(r)], ['md', toMarkdown(r)], ['sarif', JSON.stringify(toSarif(r, '1'))], ['table', toTable(r)]] as const)
      assert.deepEqual(leaks(out), [], `${kind}: ${out}`);
  });
}

test('CLI: no raw secret on stdout, stderr or --output', () => {
  const all = CASES.flatMap(([, s]) => s).flatMap(probes);
  const files = [...new Set(CASES.flatMap(([f]) => f).filter((f) => !f.startsWith('agent')))].map((f) => path.join(dir, f));
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'agentaudit-r2-')), 'o.txt');
  for (const fmt of ['table', 'md', 'sarif']) for (const extra of [[], ['--output', out]]) {
    const r = spawnSync(process.execPath, [path.resolve(import.meta.dirname, '../src/cli.ts'), ...files, path.join(dir, 'agent.yaml'), '--format', fmt, ...extra], { encoding: 'utf8' });
    const text = r.stdout + r.stderr + (extra.length ? fs.readFileSync(out, 'utf8') : '');
    assert.ok(text.length > 100, r.stderr);
    assert.deepEqual(all.filter((x) => text.includes(x)), [], `${fmt} ${extra.join(' ')}`);
  }
  fs.rmSync(path.dirname(out), { recursive: true });
});

test('N2: a Word: label does not hide the pair after it', () => {
  for (const s of ['Note: api_key=LabelKey2026Qx9', 'Example: Authorization: Bearer LabelBearer2026Qx9', 'Header: X-API-Key: LabelHdr2026Qx9',
    'Note: password: LabelPw2026Qx9']) {
    const r = redactFree(s);
    assert.ok(!/Label\w+2026/.test(r), `${s} => ${r}`);
    assert.ok(r.startsWith(s.split(':')[0]! + ':'), r);
  }
});

test('N3: bare bearer tokens, CLI flags and curl -u in prose', () => {
  for (const [s, gone] of [
    ['Use Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.ProseJwt2026QxQx', 'ProseJwt2026'],
    ['send Authorization Bearer NoColonTok2026Qx', 'NoColonTok2026'],
    ['send Authorization:Bearer TightTok2026QxQx', 'TightTok2026'],
    ['header Basic dXNlcjpCYXNpY1Byb3NlMjAyNg==', 'dXNlcjpCYXNpY1Byb3NlMjAyNg'],
    ['Authorization NoSchemeTok2026QxQx9 here', 'NoSchemeTok2026'],
    ['run it --password Hunter2Pass2026Q now', 'Hunter2Pass2026'],
    ['run it --token FlagTok2026QxQx9', 'FlagTok2026'],
    ['run it --api-key FlagKey2026QxQx9', 'FlagKey2026'],
    ['curl -u admin:CurlPw2026QxQx9 https://x', 'CurlPw2026'],
    ['curl --user admin:CurlUserPw2026Qx https://x', 'CurlUserPw2026'],
  ]) {
    const r = redactFree(s!);
    assert.ok(!r.includes(gone!), `${s} => ${r}`);
  }
  assert.ok(redactFree('curl -u admin:CurlPw2026QxQx9').includes('admin:'), 'user kept');
});

test('N5: less over-masking: paths, operationIds, enums, scopes, booleans, prose', () => {
  const tok = read('tokpath.yaml'), clean = read('clean.yaml');
  const rt = redactFile(tok.name, tok.text).text, rc = redactFile(clean.name, clean.text).text;
  for (const s of ['operationId: createOAuthToken2024v2', 'operationId: deleteUserApiKeyV2x9', 'operationId: refundPaymentV2x9Q', 'example: client_credentials'])
    assert.ok(rt.includes(s), `${s}\n${rt}`);
  for (const s of ['Token: returned by', 'Key: see docs', 'writeOnly: true', 'enum: [bearer, mac]', 'enum: [active, revoked]', 'enum: [oauth2_v2, saml_v1]',
    '"accounts:read": read accounts', 'x-secret-rotation-days: 90', 'operationId: resetAccountPassword', 'Rate limit: 5 per hour', 'token: none'])
    assert.ok(rc.includes(s), `${s}\n${rc}`);
  const r = audit([tok]);
  assert.deepEqual(r.actions.map((a) => a.operationId), ['createOAuthToken2024v2', 'deleteUserApiKeyV2x9', 'refundPaymentV2x9Q']);
});

test('N6: a token in a tool name leaves the label too, in any case', () => {
  const r = audit([read('names.json')]);
  const a = r.actions[0]!;
  assert.ok(!/example0{10}/i.test(a.label), a.label);
  assert.ok(a.label.includes('••••'), a.label);
});

test('N7: a 6 MB YAML file redacts in under 2 s with the parser\'s Document', () => {
  const parts = ['openapi: 3.0.3', 'info: { title: t, version: "1" }', 'paths:'];
  let size = 0;
  for (let i = 0; size < 6e6; i++) {
    const add = [`  /r${i}:`, '    get:', `      operationId: op${i}`,
      `      description: "api_key=BigKey${i}Qx9zz token: Tok${i}QxQx9 see https://u:p${i}@x.example.com/a?b=c${i}"`,
      '      responses: { "200": { description: ok } }'];
    parts.push(...add);
    size += add.join('\n').length + 1;
  }
  const text = parts.join('\n') + '\n';
  assert.ok(text.length >= 6e6);
  const doc = parseDocument(text, { uniqueKeys: false });
  const t0 = performance.now();
  const r = redactFile('big.yaml', text, { yaml: doc });
  const ms = performance.now() - t0;
  assert.ok(!r.text.includes('BigKey10Qx9zz'));
  assert.ok(ms < 2000, `${Math.round(ms)} ms`);
});
