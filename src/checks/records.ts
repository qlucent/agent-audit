import { ownScoped } from '../scope.ts';
import type { Check } from '../types.ts';
import { applySeverity, paramMatcher } from './util.ts';

const SENSITIVE = ['phi', 'pii', 'financial-data'] as const;

/** Read/write of a sensitive record chosen by a record-id param, with nothing binding it to the requester (low when a role declares it own-only). */
export const unscopedRecordAccess: Check = (ctx, rule) => {
  const isId = paramMatcher(ctx.data.lexicon['record-ids']);
  return ctx.actions.flatMap((a) => {
    const cls = SENSITIVE.filter((c) => a.data.includes(c));
    const id = a.params.find(isId);
    if (!cls.length || !id || !(a.effects.includes('read') || a.effects.includes('write'))) return [];
    // R19: `own` is the builder's word; the spec still takes any id, so it stays visible at low.
    if (ownScoped(ctx.manifest, a)) return [{
      file: a.file, loc: id.loc ?? a.loc, action: a.name, field: id.name, severity: 'low' as const,
      detail: `${a.name}: declared own-only; make sure the server binds ${id.name} to the signed-in user (the spec accepts any value)`,
    }];
    return [{
      file: a.file, loc: id.loc ?? a.loc, action: a.name, field: id.name,
      severity: applySeverity(rule.severity, cls.includes('phi'), !ctx.manifest),
      detail: `${a.name} takes any "${id.name}" (${cls.join(', ')}) and nothing ties it to the requester`,
    }];
  });
};
