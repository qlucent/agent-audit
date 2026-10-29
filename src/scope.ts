import raw from './generated/data.json' with { type: 'json' };
import { ALL, glob, words } from './classify.ts';
import { capOf } from './checks/money.ts';
import { actionText, has } from './checks/util.ts';
import type { Action, CheckContext, DataClass, GeneratedData, Manifest, Matrix, RoleSpec } from './types.ts';

/*
 * Allow grammar (spec decision 4). An entry is `<target>[:<qualifier>]`.
 *   target     an effect name (`read`, `money`, ...) the action has, or a glob (`*`, `?`, case-insensitive) matching
 *              the action name, its operationId, or one word of either (singular or plural): `refund` matches
 *              `issue_refund` and `POST /refunds`.
 *   qualifier  `<=N`         the action's cap (lower of the amount params' schema `maximum` and `limits.max_amount`)
 *                            exists and is <= N; an uncapped action fails it.
 *              `own`         scoped to the requester; satisfies unscoped-record-access.
 *              `own-<glob>`  as `own`, limited to actions with a word matching the glob (`own-orders`, `own-*`).
 *              `<glob>`      limited to actions with a word matching the glob (`read:orders`, `email:send`, `read:*`).
 * Roles in `acts_for` allow nothing unless an entry grants it (default deny).
 */

const data = raw as unknown as GeneratedData;
const DATA: DataClass[] = ['pii', 'phi', 'financial-data', 'credentials'];

const split = (e: string) => {
  const i = e.indexOf(':');
  return i < 0 ? [e, ''] as const : [e.slice(0, i), e.slice(i + 1)] as const;
};

const wordHit = (g: string, a: Action) => {
  const re = glob(g);
  return words(actionText(a)).split(' ').some((w) => re.test(w) || re.test(`${w}s`) || re.test(w.replace(/s$/, '')));
};

/** The entry's target names this action, whatever the qualifier says. */
export function targets(entry: string, a: Action): boolean {
  const [t] = split(entry);
  return (a.effects as string[]).includes(t) || glob(t).test(a.name) ||
    (a.operationId !== undefined && glob(t).test(a.operationId)) || wordHit(t, a);
}

function holds(q: string, a: Action, limits: Manifest['limits']): boolean {
  if (!q) return true;
  const n = /^<=(\d+(?:\.\d+)?)$/.exec(q);
  if (n) {
    const cap = capOf({ actions: [], data, files: [], manifest: { agent: { name: '' }, limits } } as CheckContext, a);
    return cap !== undefined && cap <= Number(n[1]);
  }
  const own = /^own(?:-(.+))?$/.exec(q);
  if (own) return !own[1] || wordHit(own[1], a);
  return wordHit(q, a);
}

export const grants = (entry: string, a: Action, limits?: Manifest['limits']) =>
  targets(entry, a) && holds(split(entry)[1], a, limits);

/** Spec decision 4: allowed when any entry's target and qualifier both hold. */
export const allows = (role: RoleSpec | undefined, a: Action, limits?: Manifest['limits']) =>
  (role?.allow ?? []).some((e) => grants(e, a, limits));

/** An `own` entry of an acted-for role (any role when `acts_for` is empty) grants the action. */
export function ownScoped(m: Manifest | undefined, a: Action): boolean {
  if (!m?.roles) return false;
  const roles = m.agent.acts_for?.length ? m.agent.acts_for : Object.keys(m.roles);
  return roles.some((r) => (m.roles![r]?.allow ?? []).some((e) => /^own(-|$)/.test(split(e)[1]) && grants(e, a, m.limits)));
}

/** Worth a finding when exceeded: a non-read effect or a sensitive data class. Plain reads are amber only. */
export const significant = (a: Action) => a.effects.some((e) => e !== 'read') || a.data.length > 0;

export function buildMatrix(actions: Action[], manifest?: Manifest): Matrix {
  const roles = manifest?.agent.acts_for ?? [];
  if (roles.length) {
    return {
      mode: 'roles',
      columns: ['agent', ...roles],
      rows: actions.map((a) => ({
        actionId: a.id, label: a.label,
        cells: ['yes', ...roles.map((r) =>
          allows(manifest!.roles?.[r], a, manifest!.limits) ? 'allowed' as const : significant(a) ? 'exceeds' as const : 'exceeds-minor' as const)],
      })),
    };
  }
  const columns = [...ALL, ...DATA].filter((c) => actions.some((a) => has(a, c)));
  return {
    mode: 'effects', columns,
    rows: actions.map((a) => ({ actionId: a.id, label: a.label, cells: columns.map((c) => (has(a, c) ? 'yes' as const : '' as const)) })),
  };
}
