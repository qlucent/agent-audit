import { allows, listedOut, significant, targets } from '../scope.ts';
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

/** Per acted-for role, significant actions it cannot do (granted to another role, else out-of-scope-action reports them). One finding per role, severity and file. */
export const exceedsRole: Check = (ctx, rule) => {
  const m = ctx.manifest;
  const oos = outOfScope(ctx);
  const candidates = ctx.actions.filter((a) => significant(a) && !oos.has(a));
  const groups = new Map<string, Hit & { role: string }>();
  for (const r of m?.agent.acts_for ?? []) {
    const spec = m!.roles?.[r];
    for (const a of candidates) {
      if (allows(spec, a, m!.limits)) continue;
      const severity = applySeverity(rule.severity, false, !KEY.some((k) => has(a, k)));
      const key = `${r}|${severity}|${a.file}`;
      const h = groups.get(key) ?? { file: a.file, loc: a.loc, actions: [], severity, role: r };
      if (!h.actions!.includes(a.name)) h.actions!.push(a.name);
      groups.set(key, h);
    }
  }
  return [...groups.values()].map(({ role, ...h }) => ({
    ...h,
    detail: `Acting for ${role}, the agent can also ${h.actions!.join(', ')}, which the ${role} role does not allow${noEntry(missing(ctx, role) ? [role] : [])}`,
  }));
};
