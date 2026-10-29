import { grant, listedOut, significant, targets, type Miss } from '../scope.ts';
import type { Action, Check, CheckContext, Hit } from '../types.ts';
import { applySeverity, has } from './util.ts';

const missing = (ctx: CheckContext, r: string) => !ctx.manifest?.roles?.[r];
const noEntry = (rs: string[]) => (rs.length ? ` (no roles entry for ${rs.join(', ')})` : '');

/** Why each action is out of scope: an `out_of_scope` effect it has, or a significant one no acted-for role targets at all. */
function outOfScope(ctx: CheckContext): Map<Action, string> {
  const m = ctx.manifest;
  const out = new Map<Action, string>();
  if (!m) return out;
  const roles = m.agent.acts_for ?? [];
  const entries = roles.flatMap((r) => m.roles?.[r]?.allow ?? []);
  const gap = noEntry(roles.filter((r) => missing(ctx, r)));
  for (const a of ctx.actions) {
    const listed = listedOut(m, a);
    if (listed.length) out.set(a, `${a.name} has ${listed.join(', ')}, which the manifest lists in out_of_scope`);
    else if (roles.length && significant(a) && !entries.some((e) => targets(e, a))) {
      const what = [...a.effects.filter((e) => e !== 'read'), ...a.data].join(', ');
      out.set(a, `${a.name} (${what}) is not granted to any role the agent acts for (${roles.join(', ')})${gap}`);
    }
  }
  return out;
}

export const outOfScopeAction: Check = (ctx) =>
  [...outOfScope(ctx)].map(([a, detail]) => ({ file: a.file, loc: a.loc, action: a.name, detail }));

const KEY = ['money', 'identity-admin', 'phi', 'delete'];
// I1: the role has an entry for the action but its qualifier fails, so adding the entry again is the wrong advice.
const CAP_FIX = 'The role allows this action only up to a cap. Give the action a cap at or below it: a `maximum` on its amount '
  + 'parameter, or `limits.<action>.max_amount` in the manifest. Or check the role server-side before each action.';
const WORD_FIX = "The role's entry names this action, but its qualifier doesn't match it. Narrow the action to what the "
  + 'qualifier allows, or check the role server-side before each action.';

/** Per acted-for role, significant actions it cannot do (granted to another role, else out-of-scope-action reports them). One finding per role, severity and file. */
export const exceedsRole: Check = (ctx, rule) => {
  const m = ctx.manifest;
  const oos = outOfScope(ctx);
  const candidates = ctx.actions.filter((a) => significant(a) && !oos.has(a));
  const groups = new Map<string, Hit & { role: string; misses: Miss[] }>();
  for (const r of m?.agent.acts_for ?? []) {
    const spec = m!.roles?.[r];
    for (const a of candidates) {
      const g = grant(spec, a, m!.limits);
      if (typeof g === 'string') continue;
      const severity = applySeverity(rule.severity, false, !KEY.some((k) => has(a, k)));
      const key = `${r}|${severity}|${a.file}`;
      const h = groups.get(key) ?? { file: a.file, loc: a.loc, actions: [], severity, role: r, misses: [] };
      if (!h.actions!.includes(a.name)) { h.actions!.push(a.name); if (g) h.misses.push(g); }
      groups.set(key, h);
    }
  }
  return [...groups.values()].map(({ role, misses, ...h }) => ({
    ...h,
    detail: `Acting for ${role}, the agent can also ${h.actions!.join(', ')}, which the ${role} role does not allow${noEntry(missing(ctx, role) ? [role] : [])}`
      + misses.map((x) => `; ${role} allows \`${x.entry}\`, but ${x.why}`).join(''),
    ...(misses.length && { fix: misses.some((x) => x.kind === 'cap') ? CAP_FIX : WORD_FIX }),
  }));
};
