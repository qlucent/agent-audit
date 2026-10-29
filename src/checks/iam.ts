import { glob } from '../classify.ts';
import type { Action, Check, Severity } from '../types.ts';
import { broadScopeSeverity } from './oauth.ts';

const ESCALATE = ['iam:PassRole', 'sts:AssumeRole'];

/**
 * iam-wildcard severity for an IAM action, or undefined: `*` (or NotAction) critical on Resource `*`, else high;
 * high for PassRole/AssumeRole or write/delete on Resource `*`.
 */
export function iamWildcard(a: Action): Severity | undefined {
  if (a.kind !== 'iam') return undefined;
  const anyRes = a.resource?.includes('*') ?? false;
  if (a.notAction || a.name === '*' || a.name === '*:*') return anyRes ? 'critical' : 'high';
  if (!anyRes) return undefined;
  const g = glob(a.name);
  if (ESCALATE.some((x) => g.test(x)) || a.effects.includes('write') || a.effects.includes('delete')) return 'high';
  return undefined;
}

/**
 * Severity at which iam-wildcard (IAM grant) or broad-oauth-scope (broad scope) already reports this action. Effect
 * rules (identity, code, bulk) leave it to that one finding unless theirs is higher.
 */
export const reportedAt = (a: Action): Severity | undefined =>
  a.kind === 'scope' ? (a.broad ? broadScopeSeverity(a) : undefined) : iamWildcard(a);

export const iamWildcardCheck: Check = (ctx) =>
  ctx.actions.flatMap((a) => {
    const severity = iamWildcard(a);
    if (!severity) return [];
    const res = (a.resource?.length ? a.resource.join(', ') : 'no Resource') +
      (a.condition ? ' (the statement has Conditions: check they actually narrow it)' : '');
    return [{
      file: a.file, loc: a.loc, action: a.name, severity,
      detail: a.notAction
        ? `Allow with NotAction grants every action except ${a.notAction.join(', ')} on ${res}`
        : `Allow ${a.name} on ${res}`,
    }];
  });
