import type { Action, Check, CheckContext, Param } from '../types.ts';
import { applySeverity, approved, has, limitFor, nameMatcher, paramMatcher, actionText } from './util.ts';

const MONEY_DOMAINS = ['fintech', 'ecommerce', 'finance-ops'];
const NO_APPROVAL = 'no approval step is declared';

const amounts = (ctx: CheckContext, a: Action): Param[] => {
  const isAmount = paramMatcher(ctx.data.lexicon.amounts);
  return a.params.filter((p) => isAmount(p) && (p.type === undefined || p.type === 'number' || p.type === 'integer'));
};

/** Effective cap: the lower of the amount params' schema `maximum` (all must have one) and `limits.max_amount`. */
export function capOf(ctx: CheckContext, a: Action): number | undefined {
  const ps = amounts(ctx, a);
  const schema = ps.length && ps.every((p) => p.maximum !== undefined) ? Math.min(...ps.map((p) => p.maximum!)) : undefined;
  const limit = limitFor(ctx, a);
  return schema === undefined ? limit : limit === undefined ? schema : Math.min(schema, limit);
}

/** Money action with an amount-like param that has no `maximum` and no manifest limit. Schema evidence: no-manifest does not lower it. */
export const moneyNoCap: Check = (ctx, rule) => {
  const up = MONEY_DOMAINS.includes(ctx.domain ?? '');
  return ctx.actions.flatMap((a) => {
    if (!has(a, 'money') || limitFor(ctx, a) !== undefined) return [];
    const open = amounts(ctx, a).filter((p) => p.maximum === undefined);
    if (!open.length) return [];
    return [{
      file: a.file, loc: open[0]!.loc ?? a.loc, action: a.name, field: open[0]!.name,
      severity: applySeverity(rule.severity, up, false),
      detail: `${a.name} moves money and "${open[0]!.name}" has no maximum or manifest limit`,
    }];
  });
};

/** Money action not covered by a manifest approval. One step lower when capped or when there is no manifest. */
export const moneyNoApproval: Check = (ctx, rule) =>
  ctx.actions.filter((a) => has(a, 'money') && !approved(ctx, a)).map((a) => ({
    file: a.file, loc: a.loc, action: a.name,
    severity: applySeverity(rule.severity, false, !ctx.manifest || capOf(ctx, a) !== undefined),
    detail: ctx.manifest ? `${a.name} moves money and is not listed in approvals` : `${a.name} moves money and ${NO_APPROVAL}`,
  }));

/** Buys, charges or subscribes on the user's behalf without an approval. */
export const purchaseWithoutConsent: Check = (ctx, rule) => {
  const buys = nameMatcher(ctx.data.lexicon.purchases);
  return ctx.actions.filter((a) => buys(actionText(a)) && !approved(ctx, a)).map((a) => ({
    file: a.file, loc: a.loc, action: a.name,
    severity: applySeverity(rule.severity, false, !ctx.manifest),
    detail: ctx.manifest ? `${a.name} buys or charges for the user and is not listed in approvals` : `${a.name} buys or charges for the user and ${NO_APPROVAL}`,
  }));
};
