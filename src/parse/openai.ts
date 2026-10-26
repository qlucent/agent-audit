import type { Action } from '../types.ts';
import { action, isObj, schemaParams, toolList, type Doc } from './json.ts';

/** OpenAI tools: `{type:"function", function:{name,…}}` (Chat Completions) or flat `{type:"function", name,…}` (Responses API). */
export function parse(doc: Doc, file: string): Action[] | null {
  const found = toolList(doc.value);
  if (!found) return null;
  const [items, base] = found;
  const fn = (t: any) => (isObj(t.function) ? t.function : t);
  if (!items.every((t) => isObj(t) && t.type === 'function' && typeof fn(t).name === 'string')) return null;
  return items.map((t, i) => {
    const f = fn(t);
    const p = [...base, i, ...(isObj(t.function) ? ['function'] : [])];
    return action(file, doc.loc([...p, 'name']), {
      name: f.name,
      kind: 'tool',
      ...(typeof f.description === 'string' && { description: f.description }),
      params: schemaParams(doc, f.parameters, [...p, 'parameters']),
    });
  });
}
