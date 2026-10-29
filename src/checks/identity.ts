import type { Action, Check } from '../types.ts';
import { ORDER, applySeverity, nameMatcher } from './util.ts';
import { reportedAt } from './iam.ts';

/** identity-admin effect. Critical when the purpose or acts_for roles look L1/support/customer-facing, or it is out of scope. */
export const identityAdminAction: Check = (ctx, rule) => {
  const m = ctx.manifest;
  const front = nameMatcher(ctx.data.lexicon.frontline);
  const l1 = !!m && [m.agent.purpose ?? '', ...(m.agent.acts_for ?? [])].some((t) => t && front(t));
  const up = l1 || !!m?.out_of_scope?.includes('identity-admin');
  const severity = applySeverity(rule.severity, up, false);
  // One finding per IAM statement or broad scope, unless this one is more severe (the L1 / out-of-scope critical).
  const kept = (a: Action) => { const r = reportedAt(a); return !r || ORDER.indexOf(severity) < ORDER.indexOf(r); };
  return ctx.actions.filter((a) => a.effects.includes('identity-admin') && kept(a)).map((a) => ({
    file: a.file, loc: a.loc, action: a.name, severity,
    detail: `${a.name} can change users, roles or credentials${l1 ? ' and this agent is customer-facing or L1' : up ? ', which the manifest marks out of scope' : ''}`,
  }));
};
