import raw from './generated/data.json' with { type: 'json' };
import { ALL, glob, words } from './classify.ts';
import { capOf } from './checks/money.ts';
import { actionText, has, paramMatcher } from './checks/util.ts';
import type { Action, CheckContext, DataClass, Effect, GeneratedData, Manifest, Matrix, MatrixCell, RoleSpec } from './types.ts';

/*
 * Allow grammar (spec decision 4, rulings R17-R20). An entry is `<target>[:<qualifier>]`.
 *   target     an effect name (`read`, `money`, ...) the action has, granting it only when that effect is the only
 *              high-risk effect the action has (R17); or a glob (`*`, `?`, case-insensitive) over the FULL action name
 *              or operationId (R20): `*refund*`, `delete_*`, `send_email`. A glob grants the whole action.
 *   qualifier  `<=N`         the action's cap (lower of the amount params' schema `maximum` and `limits.max_amount`)
 *                            exists and is <= N; an uncapped action fails it.
 *              `own`         a builder declaration that the action is scoped to the requester (R19).
 *              `own-<glob>`  as `own`, limited to actions with a word matching the glob (`own-orders`, `own-*`).
 *              `<glob>`      limited to actions with a word matching the glob (`read:orders`, `read:*`).
 * Roles in `acts_for` allow nothing unless an entry grants it (default deny).
 */

const data = raw as unknown as GeneratedData;
const DATA: DataClass[] = ['pii', 'phi', 'financial-data', 'credentials'];
/** R17: an effect target must cover each of these the action has. */
const HIGH_RISK: Effect[] = ['money', 'identity-admin', 'code-exec', 'delete', 'external-send'];
const isRecordId = paramMatcher(data.lexicon['record-ids']);

type Limits = Manifest['limits'];
interface Entry { kind: Miss['kind']; target: (a: Action) => boolean; holds: (a: Action, limits: Limits) => boolean; own: boolean; why: (a: Action, limits: Limits) => string }
/** An entry whose target names the action but whose qualifier fails (I1): why, in words, and what kind of fix. */
export interface Miss { entry: string; why: string; kind: 'cap' | 'word' }

const wordsOf = new WeakMap<Action, string[]>();
const wordHit = (re: RegExp, a: Action) => {
  let ws = wordsOf.get(a);
  if (!ws) wordsOf.set(a, ws = words(actionText(a)).split(' '));
  return ws.some((w) => re.test(w) || re.test(`${w}s`) || re.test(`${w}es`) || re.test(w.replace(/s$/, '')) || re.test(w.replace(/es$/, '')));
};

const caps = new WeakMap<Action, Map<Limits, number | undefined>>();
function cap(a: Action, limits: Limits): number | undefined {
  let m = caps.get(a);
  if (!m) caps.set(a, m = new Map());
  if (!m.has(limits)) m.set(limits, capOf({ actions: [], data, files: [], manifest: { agent: { name: '' }, limits } } as CheckContext, a));
  return m.get(limits);
}

const cache = new Map<string, Entry>();
function compile(entry: string): Entry {
  const hit = cache.get(entry);
  if (hit) return hit;
  const i = entry.indexOf(':');
  const [t, q] = i < 0 ? [entry, ''] : [entry.slice(0, i), entry.slice(i + 1)];
  const effect = (ALL as string[]).includes(t) ? t as Effect : undefined;
  const re = glob(t);
  const target = effect
    ? (a: Action) => a.effects.includes(effect) && HIGH_RISK.every((h) => h === effect || !a.effects.includes(h))
    : (a: Action) => re.test(a.name) || (a.operationId !== undefined && re.test(a.operationId));
  const n = /^<=(\d+(?:\.\d+)?)$/.exec(q);
  const own = /^own(?:-(.+))?$/.exec(q);
  const noun = own ? (own[1] ? glob(own[1]) : undefined) : q ? glob(q) : undefined;
  const holds = n
    ? (a: Action, limits: Limits) => { const c = cap(a, limits); return c !== undefined && c <= Number(n[1]); }
    : (a: Action) => !noun || wordHit(noun, a);
  const why = (a: Action, limits: Limits) => {
    if (!n) return `${a.name} has no word matching "${own ? own[1] : q}"`;
    const c = cap(a, limits);
    return c === undefined ? `${a.name} has no cap` : `${a.name}'s cap ${c} is above ${n[1]}`;
  };
  const e = { target, holds, own: !!own, why, kind: n ? 'cap' as const : 'word' as const };
  cache.set(entry, e);
  return e;
}

/** The entry's target names this action, whatever the qualifier says. */
export const targets = (entry: string, a: Action) => compile(entry).target(a);

/**
 * How a role grants the action: `allowed`, `declared` (only through an `own` entry while the action takes a free
 * record-id param, so the spec cannot show the binding: R19), or denied: the first entry whose target names the action
 * but whose qualifier fails (I1), else undefined.
 */
export function grant(role: RoleSpec | undefined, a: Action, limits?: Limits): 'allowed' | 'declared' | Miss | undefined {
  let declared = false, miss: Miss | undefined;
  for (const s of role?.allow ?? []) {
    const e = compile(s);
    if (!e.target(a)) continue;
    if (!e.holds(a, limits)) { miss ??= { entry: s, why: e.why(a, limits), kind: e.kind }; continue; }
    if (!e.own || !a.params.some(isRecordId)) return 'allowed';
    declared = true;
  }
  return declared ? 'declared' : miss;
}

/** Spec decision 4: allowed when any entry's target and qualifier both hold (a declared own-grant counts). */
export const allows = (role: RoleSpec | undefined, a: Action, limits?: Limits) => typeof grant(role, a, limits) === 'string';

/** An `own` entry of an acted-for role (any role when `acts_for` is empty) grants the action. */
export function ownScoped(m: Manifest | undefined, a: Action): boolean {
  if (!m?.roles) return false;
  const roles = m.agent.acts_for?.length ? m.agent.acts_for : Object.keys(m.roles);
  return roles.some((r) => (m.roles![r]?.allow ?? []).some((s) => { const e = compile(s); return e.own && e.target(a) && e.holds(a, m.limits); }));
}

/** Effects and data classes of the action that the manifest lists in `out_of_scope`. */
export const listedOut = (m: Manifest | undefined, a: Action) => (m?.out_of_scope ?? []).filter((x) => has(a, x));

/** Worth a finding when exceeded: a non-read effect or a sensitive data class. Plain reads are amber only. */
export const significant = (a: Action) => a.effects.some((e) => e !== 'read') || a.data.length > 0;

export function buildMatrix(actions: Action[], manifest?: Manifest): Matrix {
  const roles = manifest?.agent.acts_for ?? [];
  if (roles.length) {
    const specs = roles.map((r) => manifest!.roles?.[r]);
    return {
      mode: 'roles',
      columns: ['agent', ...roles],
      rows: actions.map((a) => {
        const out = listedOut(manifest, a).length > 0;
        const denied: MatrixCell = significant(a) ? 'exceeds' : 'exceeds-minor';
        return { actionId: a.id, label: a.label, cells: ['yes', ...specs.map((s) => { const g = out ? 'exceeds' : grant(s, a, manifest!.limits); return typeof g === 'string' ? g : denied; })] };
      }),
    };
  }
  const columns = [...ALL, ...DATA].filter((c) => actions.some((a) => has(a, c)));
  return {
    mode: 'effects', columns,
    rows: actions.map((a) => ({ actionId: a.id, label: a.label, cells: columns.map((c) => (has(a, c) ? 'yes' as const : '' as const)) })),
  };
}
