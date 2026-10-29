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
    if (!valid(s) || s.Effect !== 'Allow') return;
    const sp = many ? ['Statement', i] : ['Statement'];
    const common = {
      kind: 'iam' as const,
      ...(typeof s.Sid === 'string' && { description: s.Sid }),
      resource: list(s.Resource).filter((r): r is string => typeof r === 'string'),
      ...(isObj(s.Condition) && { condition: s.Condition }),
    };
    if (!('Action' in s)) {
      // Allow + NotAction grants every action except the listed ones: one broad action for the statement.
      const notAction = list(s.NotAction).filter((x): x is string => typeof x === 'string');
      out.push(action(file, doc.loc([...sp, 'NotAction']), { name: `NotAction ${notAction.join(', ')}`, notAction, ...common }));
      return;
    }
    const arr = Array.isArray(s.Action);
    list(s.Action).forEach((pattern, j) => {
      if (typeof pattern !== 'string') return;
      out.push(
        action(file, doc.loc(arr ? [...sp, 'Action', j] : [...sp, 'Action'], false), {
          name: pattern,
          ...common,
        }),
      );
    });
  });
  return out;
}
