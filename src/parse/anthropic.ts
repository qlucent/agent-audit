import type { Action } from '../types.ts';
import { action, isObj, schemaParams, toolList, type Doc } from './json.ts';

/** Anthropic tools: `{name, description, input_schema}` items, as an array or `{tools:[…]}`. */
export function parse(doc: Doc, file: string): Action[] | null {
  const found = toolList(doc.value);
  if (!found) return null;
  const [items, base] = found;
  if (!items.every((t) => isObj(t) && typeof t.name === 'string' && isObj(t.input_schema) && !('inputSchema' in t))) return null;
  return items.map((t, i) =>
    action(file, doc.loc([...base, i, 'name']), {
      name: t.name,
      kind: 'tool',
      ...(typeof t.description === 'string' && { description: t.description }),
      params: schemaParams(doc, t.input_schema, [...base, i, 'input_schema']),
    }),
  );
}
