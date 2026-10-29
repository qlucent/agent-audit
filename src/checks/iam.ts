import { glob } from '../classify.ts';
import type { Action, Check, Severity } from '../types.ts';

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
 * A wildcard IAM grant iam-wildcard already reports, or a broad scope broad-oauth-scope reports: effect rules
 * (identity, code, bulk) leave it to that one finding.
 */
export const reportedElsewhere = (a: Action) =>
  (a.kind === 'scope' && !!a.broad) || (a.kind === 'iam' && (!!a.notAction || a.name.includes('*')) && iamWildcard(a) !== undefined);

export const iamWildcardCheck: Check = (ctx) =>
  ctx.actions.flatMap((a) => {
    const severity = iamWildcard(a);
    if (!severity) return [];
    const res = a.resource?.length ? a.resource.join(', ') : 'no Resource';
    return [{
      file: a.file, loc: a.loc, action: a.name, severity,
      detail: a.notAction
        ? `Allow with NotAction grants every action except ${a.notAction.join(', ')} on ${res}`
        : `Allow ${a.name} on ${res}`,
    }];
  });
