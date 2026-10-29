import type { Check } from '../types.ts';
import { applySeverity } from './util.ts';

/** Scope the catalogue marks broad. High when it can send as the user, administer identities or run code. */
export const broadOauthScope: Check = (ctx, rule) =>
  ctx.actions.filter((a) => a.kind === 'scope' && a.broad).map((a) => ({
    file: a.file, loc: a.loc, action: a.name,
    severity: applySeverity(rule.severity, a.effects.some((e) => e === 'external-send' || e === 'identity-admin' || e === 'code-exec'), false),
    detail: `${a.name}: ${a.label}`,
  }));
