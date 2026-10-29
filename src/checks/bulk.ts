import type { Check } from '../types.ts';
import { reportedAt } from './iam.ts';
import { paramMatcher } from './util.ts';

const SENSITIVE = ['pii', 'phi', 'financial-data', 'credentials'] as const;

/** bulk effect on sensitive data, or with no limit-like param that has a schema `maximum`. */
export const bulkExport: Check = (ctx) => {
  const isLimit = paramMatcher(ctx.data.lexicon.limits);
  return ctx.actions.flatMap((a) => {
    if (!a.effects.includes('bulk') || reportedAt(a)) return [];
    const cls = SENSITIVE.filter((c) => a.data.includes(c));
    const capped = a.params.some((p) => isLimit(p) && p.maximum !== undefined);
    if (!cls.length && capped) return [];
    return [{
      file: a.file, loc: a.loc, action: a.name,
      detail: cls.length ? `${a.name} reads in bulk and touches ${cls.join(', ')}` : `${a.name} reads in bulk with no capped limit param`,
    }];
  });
};
