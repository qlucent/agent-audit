import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseInputs } from '../src/parse/index.ts';

const fmt = (text: string, name = 'x.json') => parseInputs([{ name, text }]).files[0]!;
const j = (v: unknown) => JSON.stringify(v, null, 2);

test('detection order: manifest beats everything', () => {
  assert.equal(fmt(j({ agent: { name: 'a' } })).format, 'manifest');
  // agent + Statement: manifest wins, then fails schema (extra key) rather than becoming IAM.
  const f = fmt(j({ agent: { name: 'a' }, Version: '2012-10-17', Statement: [] }));
  assert.equal(f.format, 'manifest');
  assert.ok(f.error);
});

test('detection order: IAM before OpenAPI before MCP config before tool lists', () => {
  assert.equal(fmt(j({ Version: '2012-10-17', Statement: [], openapi: '3.0.0', paths: {} })).format, 'aws-iam');
  // OpenAPI has a top-level `servers`, which mcp-audit would read as a VS Code config.
  assert.equal(fmt(j({ openapi: '3.1.0', servers: [{ url: 'https://api.example.com' }], paths: {} })).format, 'openapi');
  assert.equal(fmt(j({ mcpServers: { s: { command: 'node' } }, tools: [{ name: 't', inputSchema: {} }] })).format, 'mcp-config');
  assert.equal(fmt(j([{ name: 't', input_schema: {}, type: 'function' }])).format, 'anthropic-tools');
});

test('Swagger 2.0 is unrecognised', () => {
  const f = fmt(j({ swagger: '2.0', paths: { '/a': { get: {} } } }));
  assert.deepEqual(f, { file: 'x.json', format: null, actions: 0, unrecognised: true });
});

test('array of plain strings that are not scope-shaped is unrecognised', () => {
  assert.equal(fmt(j(['apple', 'banana', 'cherry'])).unrecognised, true);
  // One odd entry spoils the whole list: no partial guess.
  assert.equal(fmt(j(['chat:write', 'Mail.Send', 'hello world'])).unrecognised, true);
  assert.equal(fmt(j([])).unrecognised, true);
});

test('tools whose items have no inputSchema/input_schema/function are unrecognised', () => {
  assert.equal(fmt(j({ tools: [{ name: 'a', description: 'x' }, { name: 'b', parameters: {} }] })).unrecognised, true);
  // Mixed list (one MCP item, one bare) is a partial match: unrecognised.
  assert.equal(fmt(j({ tools: [{ name: 'a', inputSchema: {} }, { name: 'b' }] })).unrecognised, true);
  assert.equal(fmt(j({ tools: [{ type: 'function', function: { description: 'no name' } }] })).unrecognised, true);
  assert.equal(fmt(j({ tools: [] })).unrecognised, true);
  // IAM shape with a malformed statement is not guessed at.
  assert.equal(fmt(j({ Version: '2012-10-17', Statement: [{ Action: 's3:GetObject' }] })).unrecognised, true);
});

test('scalars, empty files and plain YAML text are unrecognised', () => {
  assert.equal(fmt('', 'a.yaml').unrecognised, true);
  assert.equal(fmt('just some notes\n', 'a.txt').unrecognised, true);
  assert.equal(fmt('42').unrecognised, true);
});

test('JSON parse error gives line and column, no actions', () => {
  const f = fmt('{\n  "tools": [\n    { "name": "a" \n  ]\n}');
  assert.equal(f.format, null);
  assert.equal(f.actions, 0);
  assert.equal(f.unrecognised, undefined);
  assert.deepEqual([f.error!.line, f.error!.column], [4, 3]);
  assert.match(f.error!.message, /\w/);
});

test('YAML parse error gives line and column, single-line message', () => {
  const f = fmt('openapi: 3.0.0\npaths:\n  /a: [\n', 'a.yaml');
  assert.equal(f.format, null);
  assert.ok(f.error!.line >= 3);
  assert.ok(f.error!.column >= 1);
  assert.doesNotMatch(f.error!.message, /\n/);
});

test('duplicate action names across files: second gets duplicateOf; same file does not', () => {
  const a = j({ tools: [{ name: 'issue_refund', inputSchema: {} }, { name: 'get_order', inputSchema: {} }] });
  const b = j([{ type: 'function', function: { name: 'issue_refund' } }]);
  const r = parseInputs([{ name: 'a.json', text: a }, { name: 'b.json', text: b }]);
  assert.deepEqual(r.actions.map((x) => [x.file, x.name, x.duplicateOf]), [
    ['a.json', 'issue_refund', undefined], ['a.json', 'get_order', undefined], ['b.json', 'issue_refund', 0],
  ]);
  assert.equal(new Set(r.actions.map((x) => x.id)).size, 3);
});

test('second manifest is a file error; first one is kept', () => {
  const m = (n: string) => ({ name: `${n}.yaml`, text: `agent:\n  name: ${n}\n` });
  const r = parseInputs([m('one'), m('two')]);
  assert.equal(r.manifest?.agent.name, 'one');
  assert.match(r.files[1]!.error!.message, /manifest/i);
});

test('BOM and CRLF keep locations right', () => {
  const text = '﻿{\r\n  "tools": [\r\n    { "name": "a", "inputSchema": {} }\r\n  ]\r\n}';
  const r = parseInputs([{ name: 'x.json', text }]);
  assert.deepEqual([r.actions[0]!.loc.line, r.actions[0]!.loc.column], [3, 7]);
  const y = parseInputs([{ name: 'x.yaml', text: 'tools:\r\n  - name: a\r\n    inputSchema: {}\r\n' }]);
  assert.deepEqual([y.actions[0]!.loc.line, y.actions[0]!.loc.column], [2, 5]);
});

test('a file that throws while parsing becomes that file error; the batch goes on', () => {
  const deep = '['.repeat(5000) + ']'.repeat(5000);
  const ok = j({ tools: [{ name: 'a', inputSchema: {} }] });
  const r = parseInputs([{ name: 'deep.json', text: deep }, { name: 'ok.json', text: ok }]);
  assert.equal(r.files[0]!.format, null);
  assert.ok(r.files[0]!.error);
  assert.equal(r.files[0]!.actions, 0);
  assert.equal(r.files[1]!.format, 'mcp-tools');
  assert.deepEqual(r.actions.map((a) => a.name), ['a']);
});

test('`agent` that is not an object is not a manifest (Claude Code settings.json)', () => {
  const f = fmt(j({ agent: 'reviewer', permissions: { allow: ['Bash(npm test)'] } }), 'settings.json');
  assert.equal(f.format, 'mcp-config');
  assert.equal(f.error, undefined);
});

test('mcp-config by filename with 0 servers falls through to later formats', () => {
  const r = parseInputs([{ name: '.mcp.json', text: j({ tools: [{ name: 'a', inputSchema: {} }] }) }]);
  assert.equal(r.files[0]!.format, 'mcp-tools');
  assert.deepEqual(r.mcpFiles, []);
  // No later format matches: still mcp-config.
  assert.equal(fmt(j({ mcpServers: {} }), '.mcp.json').format, 'mcp-config');
});

test('item with both inputSchema and input_schema is ambiguous: unrecognised', () => {
  assert.equal(fmt(j({ tools: [{ name: 't', inputSchema: {}, input_schema: {} }] })).unrecognised, true);
});

test('manifest actions: declared effects and data validate against the schema', () => {
  const ok = parseInputs([{ name: 'm.json', text: j({ agent: { name: 'a' }, actions: { 'stripe_*': { effects: ['money', 'write'], data: ['financial-data'] } } }) }]);
  assert.equal(ok.files[0]!.error, undefined);
  assert.deepEqual({ ...ok.manifest?.actions?.['stripe_*'] }, { effects: ['money', 'write'], data: ['financial-data'] });
  const bad = fmt(j({ agent: { name: 'a' }, actions: { x: { effects: ['launch-missiles'] } } }));
  assert.match(bad.error!.message, /\/actions\/x\/effects\/0 must be one of/);
  assert.match(fmt(j({ agent: { name: 'a' }, actions: { x: { risk: 'high' } } })).error!.message, /\/actions\/x\/risk is not allowed/);
});
