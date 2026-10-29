import type { Check } from '../types.ts';
import { applySeverity, nameMatcher } from './util.ts';
import { reportedElsewhere } from './iam.ts';

/** identity-admin effect. Critical when the purpose or acts_for roles look L1/support/customer-facing, or it is out of scope. */
export const identityAdminAction: Check = (ctx, rule) => {
  const m = ctx.manifest;
  const front = nameMatcher(ctx.data.lexicon.frontline);
  const l1 = !!m && [m.agent.purpose ?? '', ...(m.agent.acts_for ?? [])].some((t) => t && front(t));
  const up = l1 || !!m?.out_of_scope?.includes('identity-admin');
  return ctx.actions.filter((a) => a.effects.includes('identity-admin') && !reportedElsewhere(a)).map((a) => ({
    file: a.file, loc: a.loc, action: a.name,
    severity: applySeverity(rule.severity, up, false),
    detail: `${a.name} can change users, roles or credentials${l1 ? ' and this agent is customer-facing or L1' : up ? ', which the manifest marks out of scope' : ''}`,
  }));
};
