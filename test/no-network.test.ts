// M6 (CLAUDE.md: CI fails on any outbound request from tool logic): every network entry point throws, then every
// sample and fixture is audited and reported.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
import dns from 'node:dns';
import { syncBuiltinESMExports } from 'node:module';

const calls: string[] = [];
const block = (name: string) => () => { calls.push(name); throw new Error(`network call: ${name}`); };
const stubs: [object, string][] = [[http, 'request'], [http, 'get'], [https, 'request'], [https, 'get'], [net, 'connect'],
  [net, 'createConnection'], [tls, 'connect'], [dgram, 'createSocket'], [dns, 'lookup'], [dns, 'resolve']];
for (const [mod, key] of stubs) (mod as Record<string, unknown>)[key] = block(key);
syncBuiltinESMExports();
globalThis.fetch = block('fetch') as typeof fetch;
(globalThis as Record<string, unknown>).WebSocket = block('WebSocket');

const { audit, toMarkdown, toSarif, toTable } = await import('../src/index.ts');

const root = path.resolve(import.meta.dirname, '..');
const walk = (d: string): string[] => fs.readdirSync(d, { withFileTypes: true })
  .flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));

test('no network call while auditing every sample and fixture', () => {
  const groups = [...fs.readdirSync(path.join(root, 'samples')).map((s) => walk(path.join(root, 'samples', s))),
    ...walk(path.join(root, 'test/fixtures')).map((f) => [f])];
  for (const files of groups) {
    const r = audit(files.map((f) => ({ name: path.basename(f), text: fs.readFileSync(f, 'utf8') })));
    toMarkdown(r); toSarif(r, '1'); toTable(r);
  }
  assert.ok(groups.length > 20);
  assert.deepEqual(calls, []);
});
