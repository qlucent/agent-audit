import type { Action, Check, Severity } from '../types.ts';
import { applySeverity } from './util.ts';

const sendsOrAdmin = (a: Action) => a.effects.some((e) => e === 'external-send' || e === 'identity-admin' || e === 'code-exec');
/** broad-oauth-scope's severity for a broad scope (base medium, as in rules/broad-oauth-scope.yaml). */
export const broadScopeSeverity = (a: Action, base: Severity = 'medium') => applySeverity(base, sendsOrAdmin(a), false);

/** Scope the catalogue marks broad. High when it can send as the user, administer identities or run code. */
export const broadOauthScope: Check = (ctx, rule) =>
  ctx.actions.filter((a) => a.kind === 'scope' && a.broad).map((a) => ({
    file: a.file, loc: a.loc, action: a.name,
    severity: broadScopeSeverity(a, rule.severity),
    detail: `${a.name}: ${a.label}`,
  }));
