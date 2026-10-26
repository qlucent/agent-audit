import { glob, words } from '../classify.ts';
import type { Action, Check, CheckContext } from '../types.ts';
import { applySeverity, paramMatcher } from './util.ts';

const SENSITIVE = ['phi', 'pii', 'financial-data'] as const;

/**
 * Spec decision 4, `own` qualifier only (the full allow grammar comes with the scope matrix): an entry
 * `<target>:own` or `<target>:own-<noun glob>` binds the action to the requester when the target is one of its
 * effects or a glob on its name, and the noun glob (if any) matches a word of the name, singular or plural.
 */
export function ownScoped(ctx: CheckContext, a: Action): boolean {
  const m = ctx.manifest;
  if (!m?.roles) return false;
  const roles = m.agent.acts_for?.length ? m.agent.acts_for : Object.keys(m.roles);
  const ws = words(a.name).split(' ');
  return roles.some((r) => (m.roles![r]?.allow ?? []).some((entry) => {
    const [target, q] = [entry.slice(0, entry.indexOf(':')), entry.slice(entry.indexOf(':') + 1)];
    if (!entry.includes(':') || !/^own(-|$)/.test(q)) return false;
    if (!(a.effects as string[]).includes(target) && !glob(target).test(a.name)) return false;
    const noun = q.slice(4);
    if (!noun) return true;
    const g = glob(noun);
    return ws.some((w) => g.test(w) || g.test(`${w}s`) || g.test(w.replace(/s$/, '')));
  }));
}

/** Read/write of a sensitive record chosen by a record-id param, with nothing binding it to the requester. */
export const unscopedRecordAccess: Check = (ctx, rule) => {
  const isId = paramMatcher(ctx.data.lexicon['record-ids']);
  return ctx.actions.flatMap((a) => {
    const cls = SENSITIVE.filter((c) => a.data.includes(c));
    const id = a.params.find(isId);
    if (!cls.length || !id || !(a.effects.includes('read') || a.effects.includes('write')) || ownScoped(ctx, a)) return [];
    return [{
      file: a.file, loc: id.loc ?? a.loc, action: a.name, field: id.name,
      severity: applySeverity(rule.severity, cls.includes('phi'), !ctx.manifest),
      detail: `${a.name} takes any "${id.name}" (${cls.join(', ')}) and nothing ties it to the requester`,
    }];
  });
};
