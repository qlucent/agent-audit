import { allows, significant, targets } from '../scope.ts';
import type { Action, Check, CheckContext, Hit } from '../types.ts';
import { applySeverity, has } from './util.ts';

/** Why the action is out of scope: an `out_of_scope` effect it has, or a significant one no acted-for role targets at all. */
function outOfScope(ctx: CheckContext, a: Action): string | undefined {
  const m = ctx.manifest;
  if (!m) return undefined;
  const listed = (m.out_of_scope ?? []).filter((x) => has(a, x));
  if (listed.length) return `${a.name} has ${listed.join(', ')}, which the manifest lists in out_of_scope`;
  const roles = m.agent.acts_for ?? [];
  if (roles.length && significant(a) && !roles.some((r) => (m.roles?.[r]?.allow ?? []).some((e) => targets(e, a)))) {
    const what = [...a.effects.filter((e) => e !== 'read'), ...a.data].join(', ');
    return `${a.name} (${what}) is not granted to any role the agent acts for (${roles.join(', ')})`;
  }
  return undefined;
}

export const outOfScopeAction: Check = (ctx) => ctx.actions.flatMap((a) => {
  const detail = outOfScope(ctx, a);
  return detail ? [{ file: a.file, loc: a.loc, action: a.name, detail }] : [];
});

const KEY = ['money', 'identity-admin', 'phi', 'delete'];

/** Per acted-for role, significant actions it cannot do (granted to another role, else out-of-scope-action reports them). One finding per role, severity and file. */
export const exceedsRole: Check = (ctx, rule) => {
  const m = ctx.manifest;
  const groups = new Map<string, Hit & { role: string }>();
  for (const r of m?.agent.acts_for ?? []) {
    for (const a of ctx.actions) {
      if (!significant(a) || allows(m!.roles?.[r], a, m!.limits) || outOfScope(ctx, a)) continue;
      const severity = applySeverity(rule.severity, false, !KEY.some((k) => has(a, k)));
      const key = `${r}|${severity}|${a.file}`;
      const h = groups.get(key) ?? { file: a.file, loc: a.loc, actions: [], severity, role: r };
      if (!h.actions!.includes(a.name)) h.actions!.push(a.name);
      groups.set(key, h);
    }
  }
  return [...groups.values()].map(({ role, ...h }) => ({
    ...h, detail: `Acting for ${role}, the agent can also ${h.actions!.join(', ')}, which the ${role} role does not allow`,
  }));
};
