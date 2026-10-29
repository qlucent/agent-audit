// Review Focus 3: a large spec audits in under 2 s, reports included.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { audit, toMarkdown, toSarif, toTable } from '../src/index.ts';

const VERBS = ['get', 'list', 'create', 'update', 'delete', 'refund', 'export', 'send'];
const NOUNS = ['customer', 'order', 'invoice', 'patient', 'ticket', 'user', 'payment', 'report'];

function openapi(n: number): string {
  const lines = ['openapi: 3.0.3', 'info: { title: Big, version: 1.0.0 }', 'paths:'];
  const methods = ['get', 'post', 'put', 'patch', 'delete'];
  for (let i = 0; i < n / 5; i++) {
    lines.push(`  /r${i}/{customer_id}:`);
    for (const m of methods) {
      const op = `${VERBS[(i + m.length) % VERBS.length]}${NOUNS[i % NOUNS.length]![0]!.toUpperCase()}${NOUNS[i % NOUNS.length]!.slice(1)}${i}`;
      lines.push(`    ${m}:`, `      operationId: ${op}`, `      summary: Operation ${i} ${m}`,
        '      parameters:', '        - { name: customer_id, in: path, required: true, schema: { type: string } }',
        '        - { name: amount, in: query, schema: { type: number } }');
    }
  }
  return lines.join('\n') + '\n';
}

function iam(n: number): string {
  const acts = ['s3:GetObject', 's3:PutObject', 's3:DeleteObject', 'iam:CreateUser', 'dynamodb:Scan', 'ses:SendEmail', 'lambda:InvokeFunction', 'ec2:*'];
  const Statement = Array.from({ length: n }, (_, i) => ({
    Sid: `S${i}`, Effect: 'Allow', Action: [acts[i % acts.length], acts[(i + 3) % acts.length]],
    Resource: i % 7 === 0 ? '*' : `arn:aws:s3:::bucket-${i}/*`,
  }));
  return JSON.stringify({ Version: '2012-10-17', Statement }, null, 2);
}

test('500-operation OpenAPI + 200-statement IAM audit and report in < 2000 ms', () => {
  const spec = openapi(500);
  assert.equal((spec.match(/^ {4}(get|post|put|patch|delete):$/gm) ?? []).length, 500);
  const inputs = [{ name: 'openapi.yaml', text: spec }, { name: 'iam.json', text: iam(200) }];
  const t0 = performance.now();
  const r = audit(inputs);
  toMarkdown(r); toSarif(r); toTable(r);
  const ms = performance.now() - t0;
  assert.ok(r.actions.length >= 500 + 200, String(r.actions.length));
  assert.ok(r.findings.every((f) => f.excerpt.length > 0 || f.ruleId === 'no-manifest' || f.ruleId.startsWith('mcp/')));
  assert.ok(ms < 2000, `${Math.round(ms)} ms`);
});
