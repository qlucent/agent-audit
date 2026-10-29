// Review Focus 4: secrets inside specs never appear raw in any output, nor anywhere in the AuditResult.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { audit, toMarkdown, toSarif, toTable } from '../src/index.ts';

const STRIPE = 'sk_live_EXAMPLEexampleEXAMPLE000000';
const GITHUB = 'ghp_EXAMPLEexampleEXAMPLEexample0000';
const ENTROPY = 'Zx8vQ2mN7pL4rT9wK3jH';
const PASSWORD = 'hunter2hunter2';
const URLPASS = 'urlPassw0rd77';
const PEMBODY = 'PEMBODYSENTINEL'.repeat(4);

const openapi = `openapi: 3.0.3
info: { title: Payments, version: 1.0.0 }
servers:
  - url: https://svc:${URLPASS}@api.example.com/v1?api_key=${ENTROPY}
paths:
  /refunds:
    post:
      operationId: createRefund
      summary: Create a refund (test key ${STRIPE})
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                amount: { type: number, example: 10 }
                api_key: { type: string, example: ${STRIPE} }
            example: { amount: 10, client_secret: "${ENTROPY}", password: ${PASSWORD} }
  /keys:
    delete:
      summary: Delete a key
      description: |
        -----BEGIN PRIVATE KEY-----
        ${PEMBODY}
        -----END PRIVATE KEY-----
`;

const manifest = `agent:
  name: Refund bot
  purpose: L1 support; deploy token ${GITHUB} (rotate monthly)
  acts_for: [customer]
roles:
  customer: { allow: ["read"] }
actions:
  "createRefund${GITHUB}": { effects: [money] }
`;
const badManifest = JSON.stringify({ agent: { name: 'Bot', [GITHUB]: true } }, null, 2);
const tools = JSON.stringify([{ name: 'issue_refund', description: `Uses ${GITHUB}`, input_schema: { type: 'object', properties: { amount: { type: 'number', default: STRIPE } } } }], null, 2);

const SECRETS = [STRIPE, GITHUB, ENTROPY, PASSWORD, URLPASS, PEMBODY, 'EXAMPLEexampleEXAMPLE'];
const CASES: [string, { name: string; text: string }[]][] = [
  ['openapi + manifest', [{ name: 'openapi.yaml', text: openapi }, { name: 'agent.yaml', text: manifest }]],
  ['invalid manifest + tools', [{ name: 'tools.json', text: tools }, { name: 'agent.json', text: badManifest }]],
  ['broken file', [{ name: 'tools.json', text: tools.slice(0, -2) + `, "x": "${STRIPE}" nope` }]],
];

const leaks = (s: string) => SECRETS.filter((x) => s.includes(x));

for (const [label, inputs] of CASES) {
  test(`no raw secret in the AuditResult or any report: ${label}`, () => {
    const r = audit(inputs);
    assert.ok(r.findings.length > 0 || r.files.some((f) => f.error), 'something was audited');
    for (const [kind, out] of [['result', JSON.stringify(r)], ['md', toMarkdown(r)], ['sarif', JSON.stringify(toSarif(r, '1'))], ['table', toTable(r)]] as const)
      assert.deepEqual(leaks(out), [], `${kind}: ${out}`);
  });
}

test('masked values still show their prefix and last 4, so the reader can tell which key it is', () => {
  const r = audit(CASES[0]![1]);
  assert.ok(JSON.stringify(r).includes('sk_live_••••0000') && JSON.stringify(r.manifest).includes('ghp_••••0000'), JSON.stringify(r.manifest));
  assert.ok(toMarkdown(r).includes('sk_live_••••0000'));
});

test('excerpts show the masked lines', () => {
  const r = audit(CASES[0]![1]);
  const ex = r.findings.flatMap((f) => f.excerpt.map((l) => l.text)).join('\n');
  assert.ok(ex.length > 0);
  assert.deepEqual(leaks(ex), []);
});

test('CLI output never contains a raw secret', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentaudit-leaks-'));
  const files = CASES[0]![1].map((i) => { const p = path.join(d, i.name); fs.writeFileSync(p, i.text); return p; });
  const bad = path.join(d, 'bad', 'agent.json');
  fs.mkdirSync(path.dirname(bad));
  fs.writeFileSync(bad, badManifest);
  for (const fmt of ['table', 'md', 'sarif']) for (const args of [files, [path.join(d, 'openapi.yaml'), bad]]) {
    const r = spawnSync(process.execPath, [path.resolve(import.meta.dirname, '../src/cli.ts'), ...args, '--format', fmt], { encoding: 'utf8' });
    assert.deepEqual(leaks(r.stdout + r.stderr), [], `${fmt}: ${r.stdout}${r.stderr}`);
  }
});
