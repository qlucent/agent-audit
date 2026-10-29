import { ownScoped } from '../scope.ts';
import type { Check } from '../types.ts';
import { applySeverity, paramMatcher } from './util.ts';

const SENSITIVE = ['phi', 'pii', 'financial-data'] as const;

/** Read/write of a sensitive record chosen by a record-id param, with nothing binding it to the requester. */
export const unscopedRecordAccess: Check = (ctx, rule) => {
  const isId = paramMatcher(ctx.data.lexicon['record-ids']);
  return ctx.actions.flatMap((a) => {
    const cls = SENSITIVE.filter((c) => a.data.includes(c));
    const id = a.params.find(isId);
    if (!cls.length || !id || !(a.effects.includes('read') || a.effects.includes('write')) || ownScoped(ctx.manifest, a)) return [];
    return [{
      file: a.file, loc: id.loc ?? a.loc, action: a.name, field: id.name,
      severity: applySeverity(rule.severity, cls.includes('phi'), !ctx.manifest),
      detail: `${a.name} takes any "${id.name}" (${cls.join(', ')}) and nothing ties it to the requester`,
    }];
  });
};
