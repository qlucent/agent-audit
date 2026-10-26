import type { Action } from '../types.ts';
import { action, isObj, type Doc } from './json.ts';

const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined ? [] : [v]);

/** AWS IAM policy: one action per Allow statement action pattern. Deny statements grant nothing. */
export function parse(doc: Doc, file: string): Action[] | null {
  const v = doc.value;
  if (!isObj(v) || !('Version' in v) || !('Statement' in v)) return null;
  const many = Array.isArray(v.Statement);
  const stmts = list(v.Statement);
  const valid = (s: unknown): s is Record<string, any> =>
    isObj(s) && (s.Effect === 'Allow' || s.Effect === 'Deny') && ('Action' in s || 'NotAction' in s);
  if (!stmts.every(valid)) return null;
  const out: Action[] = [];
  stmts.forEach((s, i) => {
    // ponytail: Allow + NotAction ("everything except") is skipped; add when a rule needs it.
    if (!valid(s) || s.Effect !== 'Allow' || !('Action' in s)) return;
    const sp = many ? ['Statement', i] : ['Statement'];
    const arr = Array.isArray(s.Action);
    list(s.Action).forEach((pattern, j) => {
      if (typeof pattern !== 'string') return;
      out.push(
        action(file, doc.loc(arr ? [...sp, 'Action', j] : [...sp, 'Action'], false), {
          name: pattern,
          kind: 'iam',
          ...(typeof s.Sid === 'string' && { description: s.Sid }),
          resource: list(s.Resource).filter((r): r is string => typeof r === 'string'),
          ...(isObj(s.Condition) && { condition: s.Condition }),
        }),
      );
    });
  });
  return out;
}
