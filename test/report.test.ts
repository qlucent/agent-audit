import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import AjvMod from 'ajv-draft-04';
import { audit, toMarkdown, toSarif, toTable } from '../src/index.ts';
import { uri } from '../src/report/sarif.ts';
import type { AuditResult, Finding, Severity } from '../src/index.ts';

const Ajv = ((AjvMod as any).default ?? AjvMod) as typeof AjvMod.default;
const tools = (list: unknown[]) => ({ name: 'tools.json', text: JSON.stringify(list, null, 2) });
const refund = { name: 'issue\_refund', description: 'Refund a charge', input_schema: { type: 'object', properties: { charge_id: { type: 'string' }, amount: { type: 'number' } } } };
const lookup = { name: 'lookup_order', description: 'Look up an order', input_schema: { type: 'object', properties: { order_ref: { type: 'string' } } } };
const base = audit([tools([refund, lookup])]);
const sevs: Severity[] = ['critical', 'high', 'medium', 'low'];
const f0 = base.findings[0]!;
const multi: AuditResult = { ...base, findings: sevs.map((severity, i): Finding => ({ ...f0, severity, ruleId: `r${i}` })) };
const sarif = (r: AuditResult) => toSarif(r, '1.2.3') as any;

test('findings carry a ±2-line excerpt with the hit line marked', () => {
  const f = base.findings.find((x) => x.ruleId === 'money-no-cap')!;
  assert.ok(f.excerpt.length >= 3 && f.excerpt.length <= 5, JSON.stringify(f.excerpt));
  const hit = f.excerpt.filter((l) => l.hit);
  assert.equal(hit.length, 1);
  assert.equal(hit[0]!.line, f.line);
  assert.ok(f.excerpt.every((l) => Math.abs(l.line - f.line) <= 2));
});

test('no excerpt for a file with a parse error', () => {
  const r = audit([{ name: 'tools.json', text: JSON.stringify([refund], null, 2).replace(/\]\s*$/, ', nope') }]);
  assert.ok(r.files[0]!.error);
  assert.ok(r.findings.every((f) => f.excerpt.length === 0), JSON.stringify(r.findings));
});

test('sarif validates against the 2.1.0 schema', () => {
  const ajv = new (Ajv as any)({ strict: false });
  const validate = ajv.compile(JSON.parse(readFileSync(new URL('./fixtures/sarif-schema-2.1.0.json', import.meta.url), 'utf8')));
  for (const r of [multi, base]) assert.ok(validate(sarif(r)), JSON.stringify(validate.errors));
  assert.ok(validate(toSarif(base)), 'without a tool version');
});

test('sarif maps severity, driver and location; action names under properties', () => {
  const s = sarif(multi).runs[0];
  assert.deepEqual(s.results.map((r: any) => r.level), ['error', 'error', 'warning', 'note']);
  const d = sarif(base).runs[0].tool.driver;
  assert.equal(d.name, 'qlucent-agent-audit');
  assert.equal(d.version, '1.2.3');
  assert.equal(d.informationUri, 'https://qlucent.com/tools/agent-audit');
  assert.ok(d.rules.every((r: any) => r.helpUri.startsWith('https://qlucent.com/tools/agent-audit/rules/')));
  const f = base.findings.find((x) => x.ruleId === 'money-no-cap')!;
  const res = sarif({ ...base, findings: [f] }).runs[0].results[0];
  const loc = res.locations[0].physicalLocation;
  assert.equal(loc.artifactLocation.uri, 'tools.json');
  assert.equal(loc.region.startLine, f.line);
  assert.equal(loc.region.snippet.text, f.excerpt.find((l) => l.hit)!.text);
  assert.equal(res.properties.action, 'issue\_refund');
  assert.ok(!JSON.stringify(res).includes('"server'));
});

test('sarif uri: file:/// for Windows absolute paths, encoded relative paths', () => {
  assert.equal(uri('C:\\work\\agent\\tools.json'), 'file:///C:/work/agent/tools.json');
  assert.equal(uri('my dir\\a#1.json'), 'my%20dir/a%231.json');
});

test('markdown: verdict, inventory, findings, matrix, in that order', () => {
  const md = toMarkdown(base);
  assert.ok(md.startsWith('# AI agent permission audit\n'), md);
  const at = (s: string) => { const i = md.indexOf(s); assert.ok(i >= 0, `missing ${s}\n${md}`); return i; };
  const v = at(`**${base.verdict.text}**`), inv = at('## Inventory'), fi = at('## Findings'), mx = at('## Permission matrix');
  assert.ok(v < inv && inv < fi && fi < mx);
  at('| Action | Kind | Effects | Data | Where | Note |');
  at('| Issue refund (issue\\_refund) | tool | money | | tools.json:');
  at('| Severity | Rule | Action | Location |');
  assert.ok(md.includes('Action: issue\\_refund'), md);
  assert.ok(!/\bservers?:/i.test(md), 'no "server" label');
  assert.ok(md.includes('Why it matters') && md.includes('**Fix**'));
});

test('markdown snapshot of a small spec with a manifest', () => {
  const spec = [{ name: 'get_order', description: 'Get an order', input_schema: { type: 'object', properties: { order_ref: { type: 'string' } } } },
    { name: 'tag_ticket', description: '', input_schema: { type: 'object', properties: {} } }];
  const r = audit([
    tools(spec),
    { name: 'agent.yaml', text: 'agent:\n  name: Bot\n  acts_for: [customer]\nroles:\n  customer: { allow: ["get_*"] }\nactions:\n  get_order: { effects: [read] }\n' },
  ]);
  assert.equal(toMarkdown(r), SNAPSHOT);
});

test('markdown matrix legend and cells; effects mode without a manifest', () => {
  const md = toMarkdown(base);
  assert.ok(md.includes('Effects of each action. Add a manifest with `acts_for` roles'), md);
  assert.ok(/\| Action \| read \| money \|/.test(md), md);
  const roles = toMarkdown(audit([tools([refund]), { name: 'agent.json', text: JSON.stringify({ agent: { name: 'B', acts_for: ['customer'] }, roles: { customer: { allow: ['read'] } } }) }]));
  assert.ok(roles.includes('| Action | agent | customer |'), roles);
  assert.ok(roles.includes('Legend: allowed · exceeds · exceeds-minor · declared'), roles);
  assert.ok(/\| Issue refund \(issue\\_refund\) \| yes \| \*\*exceeds\*\* \|/.test(roles), roles);
});

test('markdown escapes spec text and cannot be broken out of', () => {
  const evil = 'x](https://evil.example)![i](https://evil.example/p.png)|<img src=x>';
  const r = audit([{ name: `a|${evil}.json`, text: JSON.stringify([{ ...refund, name: `issue_refund${evil}` }], null, 2) }]);
  const md = toMarkdown(r).replace(/^(`{3,})\n[^]*?\n\1$/gm, '');
  assert.ok(!/(?<!\\)\]\\?\(https:\/\/evil/.test(md) && !/(?<!\\)<img/.test(md), md);
  assert.ok(md.includes('evil'));
  // Every table row has as many cells as its header.
  const lines = md.split('\n');
  let cols = 0;
  for (const [i, l] of lines.entries()) {
    const n = l.split(/(?<!\\)\|/).length;
    if (lines[i + 1]?.startsWith('| ---')) cols = n;
    else if (l.startsWith('| ') && !l.startsWith('| ---')) assert.equal(n, cols, l);
  }
});

test('markdown lists unrecognised and unparsable files', () => {
  const md = toMarkdown(audit([{ name: 'settings.json', text: '{"foo":1}' }, { name: 'b.json', text: '{ nope' }]));
  assert.ok(md.includes("Couldn't recognise settings.json as an agent spec"), md);
  assert.ok(md.includes("Couldn't parse b.json"), md);
});

test('table names the role of each exceeds-role line (I1)', () => {
  const r = audit([tools([refund]), { name: 'agent.json', text: JSON.stringify({ agent: { name: 'B', acts_for: ['customer', 'clerk', 'admin'] }, roles: { customer: { allow: ['read'] }, clerk: { allow: ['read'] }, admin: { allow: ['issue_refund'] } } }) }]);
  const lines = toTable(r).split('\n');
  for (const role of ['customer', 'clerk'])
    assert.ok(lines.some((l, i) => l.includes('exceeds-role') && lines[i + 1]!.includes(`Acting for ${role}`)), `${role}: ${lines.join('\n')}`);
});

test('table labels action names and lists the rule URL', () => {
  const t = toTable(base);
  assert.ok(t.includes('(action: issue\_refund)'), t);
  assert.ok(t.includes('https://qlucent.com/tools/agent-audit/rules/money-no-cap'), t);
  assert.ok(t.trimEnd().endsWith(base.verdict.text), t);
  assert.ok(!/server/i.test(t));
  const many = toTable({ ...base, findings: [{ ...f0, server: undefined, servers: ['a', 'b'] }] });
  assert.ok(many.includes('(actions: a, b)'), many);
});

const SNAPSHOT = "# AI agent permission audit\n\n**Review before rollout: 1 low**\n\n## Inventory\n\n| Action | Kind | Effects | Data | Where | Note |\n| --- | --- | --- | --- | --- | --- |\n| Get order (get\\_order) | tool | read | | tools.json:3:5 | declared |\n| Tag ticket (tag\\_ticket) | tool | | | tools.json:15:5 | unclassified |\n\n## Findings\n\n| Severity | Rule | Action | Location |\n| --- | --- | --- | --- |\n| low | unclassified-action | tag\\_ticket | tools.json:15:5 |\n\n### LOW: Actions with no recognised effect\n\ntools.json:15:5 · [unclassified-action](https://qlucent.com/tools/agent-audit/rules/unclassified-action)\n\nAction: tag\\_ticket\n\n1 action with no recognised effect: tag\\_ticket\n\n```\n  13:   },\n  14:   {\n> 15:     \"name\": \"tag_ticket\",\n  16:     \"description\": \"\",\n  17:     \"input_schema\": {\n```\n\n**Why it matters**\n\nThese actions are not read-only by HTTP method or annotation, and their names matched nothing the auditor knows, so no other rule could check them. They may move money, change accounts or delete data.\n\n**Fix**\n\n```\nReview each action and declare what it does in the manifest (`actions: { frobnicate_widget: { effects: [write] } }`), or rename it to say what it does.\n```\n\n## Permission matrix\n\nWhat the agent can do, compared with each role it acts for. Legend: allowed · exceeds · exceeds-minor · declared (exceeds-minor: a plain read the role lacks; declared: granted only by an own-records entry the spec cannot verify).\n\n| Action | agent | customer |\n| --- | --- | --- |\n| Get order (get\\_order) | yes | allowed |\n| Tag ticket (tag\\_ticket) | yes | exceeds-minor |\n";
