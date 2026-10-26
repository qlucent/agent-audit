// Labelled regression corpus of real-world action names (public API docs). Expectations are the exact effect and
// data-class sets; `forbid` lists classes that must never be assigned (false positives feed high/critical rules).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import corpus from './fixtures/classify-corpus.json' with { type: 'json' };
import { classify } from '../src/classify.ts';
import { action } from '../src/parse/json.ts';
import type { Action } from '../src/types.ts';

interface Case {
  src: string; name: string; kind: Action['kind']; params?: string[]; method?: string; path?: string; operationId?: string;
  expect: { effects: string[]; data: string[] }; forbid?: string[];
}
const cases = corpus as Case[];
const loc = { line: 1, column: 1, offset: 0, length: 0 };
const actions = classify(
  cases.map((c) =>
    action('corpus', loc, {
      name: c.name,
      kind: c.kind,
      params: (c.params ?? []).map((name) => ({ name, type: 'string' })),
      ...(c.method && { method: c.method }),
      ...(c.operationId && { operationId: c.operationId }),
    }),
  ),
);
const same = (a: string[], b: string[]) => a.length === b.length && a.every((x) => b.includes(x));
const show = (a: Action) => `{${[...a.effects, ...a.data].join(',')}} | ${a.evidence.map((e) => `${e.effect}: ${e.why}`).join('; ')}`;

test('corpus: no false positives on forbidden classes', () => {
  const bad = cases.flatMap((c, i) => {
    const got = [...actions[i]!.effects, ...actions[i]!.data] as string[];
    const hit = (c.forbid ?? []).filter((f) => got.includes(f));
    return hit.length ? [`[${c.src}] ${c.name}: forbidden ${hit} -> ${show(actions[i]!)}`] : [];
  });
  assert.deepEqual(bad, []);
});

test('corpus: exact-match accuracy >= 95%', () => {
  const misses = cases.flatMap((c, i) => {
    const a = actions[i]!;
    return same(a.effects, c.expect.effects) && same(a.data, c.expect.data)
      ? []
      : [`[${c.src}] ${c.name}: expected {${[...c.expect.effects, ...c.expect.data]}} got ${show(a)}`];
  });
  const acc = (cases.length - misses.length) / cases.length;
  console.log(`corpus accuracy ${cases.length - misses.length}/${cases.length} = ${(acc * 100).toFixed(1)}%`);
  for (const m of misses) console.log(`  miss ${m}`);
  assert.ok(acc >= 0.95, `accuracy ${(acc * 100).toFixed(1)}% < 95%\n${misses.join('\n')}`);
});
