import type { Action } from '../types.ts';
import { action, isObj, schemaParams, toolList, type Doc } from './json.ts';

/** MCP `tools/list` result: `{tools:[{name, inputSchema, annotations?}]}`, optionally inside `{result:…}`. */
export function parse(doc: Doc, file: string): Action[] | null {
  const found = toolList(doc.value);
  if (!found) return null;
  const [items, base] = found;
  if (!items.every((t) => isObj(t) && typeof t.name === 'string' && isObj(t.inputSchema))) return null;
  return items.map((t, i) => {
    const raw = isObj(t.annotations) ? t.annotations : {};
    const annotations: Record<string, boolean> = Object.fromEntries(
      Object.entries(raw).filter((e): e is [string, boolean] => typeof e[1] === 'boolean'),
    );
    return action(file, doc.loc([...base, i, 'name']), {
      name: t.name,
      kind: 'tool',
      ...(typeof t.description === 'string' && { description: t.description }),
      ...(Object.keys(annotations).length && { annotations }),
      params: schemaParams(doc, t.inputSchema, [...base, i, 'inputSchema']),
    });
  });
}
