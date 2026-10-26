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
// Classes that feed high/critical rules: no false positives.
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
for (const set of ['all', 'base', ...new Set(cases.map((c) => c.set).filter(Boolean))]) {
  const s = stats(set === 'all' ? all : all.filter((i) => (cases[i]!.set ?? 'base') === set));
  console.log(`corpus ${set}: exact ${s.ok}/${s.n} = ${((s.ok / s.n) * 100).toFixed(1)}%`);
  for (const k of KEY) console.log(`  ${k}: positives ${s.per[k]!.pos}, FP ${s.per[k]!.fp.length} [${s.per[k]!.fp}], FN ${s.per[k]!.fn.length} [${s.per[k]!.fn}]`);
}

test('corpus: no false positives on forbidden classes', () => {
  const bad = cases.flatMap((c, i) => {
    const hit = (c.forbid ?? []).filter((f) => got(i).includes(f));
    return hit.length ? [`[${c.src}] ${c.name}: forbidden ${hit} -> ${show(i)}`] : [];
  });
  assert.deepEqual(bad, []);
});

// Held-out sets that were not tuned against: misses are accepted (R8) but surfaced, so FN is capped at 10% per class
// and exact match is printed, not gated. Every other subset is tuned: FN <= 2% per class, exact match >= 97%.
const UNTUNED = new Set(['heldout-2']);
const tuned = all.filter((i) => !UNTUNED.has(cases[i]!.set ?? ''));
const untuned = all.filter((i) => UNTUNED.has(cases[i]!.set ?? ''));

test('corpus: key classes have zero false positives on every subset', () => {
  const { per } = stats(all);
  for (const k of KEY) assert.deepEqual(per[k]!.fp, [], `${k} false positives`);
});

test('corpus: key-class false negatives at most 2% on tuned subsets, 10% on held-out subsets', () => {
  for (const [idx, max] of [[tuned, 0.02], ...[...UNTUNED].map((u) => [all.filter((i) => cases[i]!.set === u), 0.1] as const)] as const) {
    const { per } = stats(idx);
    for (const k of KEY)
      assert.ok(per[k]!.fn.length <= Math.floor(per[k]!.pos * max), `${k}: ${per[k]!.fn.length} false negatives of ${per[k]!.pos} (max ${max * 100}%) [${per[k]!.fn}]`);
  }
});

test('corpus: exact-match accuracy >= 97% on tuned subsets', () => {
  const misses = tuned.filter((i) => !exact(i)).map((i) => `[${cases[i]!.src}] ${cases[i]!.name}: expected {${want(cases[i]!)}} got ${show(i)}`);
  for (const m of misses) console.log(`  miss ${m}`);
  const u = stats(untuned);
  console.log(`held-out (ungated) exact ${u.ok}/${u.n}`);
  const acc = (tuned.length - misses.length) / tuned.length;
  assert.ok(acc >= 0.97, `accuracy ${(acc * 100).toFixed(1)}% < 97%\n${misses.join('\n')}`);
});
