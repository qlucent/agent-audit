// Labelled regression corpus of real-world action names (public API docs). Expectations are the exact effect and
// data-class sets; `forbid` lists classes that must never be assigned. `set` marks merged held-out rounds.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import corpus from './fixtures/classify-corpus.json' with { type: 'json' };
import { classify } from '../src/classify.ts';
import { action } from '../src/parse/json.ts';
import type { Action } from '../src/types.ts';

interface Case {
  set?: string; src: string; name: string; kind: Action['kind']; params?: string[]; method?: string; path?: string; operationId?: string;
  expect: { effects: string[]; data: string[] }; forbid?: string[];
}
const cases = corpus as Case[];
// Classes that feed high/critical rules: no false positives, at most 2% false negatives.
const KEY = ['money', 'identity-admin', 'code-exec', 'phi'];
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
const got = (i: number) => [...actions[i]!.effects, ...actions[i]!.data] as string[];
const want = (c: Case) => [...c.expect.effects, ...c.expect.data];
const exact = (i: number) => {
  const g = got(i), w = want(cases[i]!);
  return g.length === w.length && g.every((x) => w.includes(x));
};
const show = (i: number) => `{${got(i)}} | ${actions[i]!.evidence.map((e) => `${e.effect}: ${e.why}`).join('; ')}`;

function stats(idx: number[]) {
  const per = Object.fromEntries(KEY.map((k) => [k, { pos: 0, fp: [] as string[], fn: [] as string[] }]));
  for (const i of idx) {
    for (const k of KEY) {
      const w = want(cases[i]!).includes(k), g = got(i).includes(k);
      if (w) per[k]!.pos++;
      if (g && !w) per[k]!.fp.push(cases[i]!.name);
      if (w && !g) per[k]!.fn.push(cases[i]!.name);
    }
  }
  return { ok: idx.filter(exact).length, n: idx.length, per };
}
const all = cases.map((_, i) => i);
for (const set of [undefined, ...new Set(cases.map((c) => c.set).filter(Boolean))]) {
  const s = stats(set ? all.filter((i) => cases[i]!.set === set) : all);
  console.log(`corpus ${set ?? 'all'}: exact ${s.ok}/${s.n} = ${((s.ok / s.n) * 100).toFixed(1)}%`);
  for (const k of KEY) console.log(`  ${k}: positives ${s.per[k]!.pos}, FP ${s.per[k]!.fp.length} [${s.per[k]!.fp}], FN ${s.per[k]!.fn.length} [${s.per[k]!.fn}]`);
}

test('corpus: no false positives on forbidden classes', () => {
  const bad = cases.flatMap((c, i) => {
    const hit = (c.forbid ?? []).filter((f) => got(i).includes(f));
    return hit.length ? [`[${c.src}] ${c.name}: forbidden ${hit} -> ${show(i)}`] : [];
  });
  assert.deepEqual(bad, []);
});

test('corpus: key classes have zero false positives and at most 2% false negatives', () => {
  const { per } = stats(all);
  for (const k of KEY) {
    assert.deepEqual(per[k]!.fp, [], `${k} false positives`);
    assert.ok(per[k]!.fn.length <= Math.floor(per[k]!.pos * 0.02), `${k}: ${per[k]!.fn.length} false negatives of ${per[k]!.pos} [${per[k]!.fn}]`);
  }
});

test('corpus: exact-match accuracy >= 97%', () => {
  const misses = all.filter((i) => !exact(i)).map((i) => `[${cases[i]!.src}] ${cases[i]!.name}: expected {${want(cases[i]!)}} got ${show(i)}`);
  for (const m of misses) console.log(`  miss ${m}`);
  const acc = (cases.length - misses.length) / cases.length;
  assert.ok(acc >= 0.97, `accuracy ${(acc * 100).toFixed(1)}% < 97%\n${misses.join('\n')}`);
});
