import type { Action, Param } from '../types.ts';
import { action, deref, humanise, isObj, param, schemaParams, type Doc, type Path } from './json.ts';

const METHODS = ['get', 'put', 'post', 'delete', 'patch', 'head', 'options', 'trace'];

const scopesOf = (security: unknown): string[] =>
  Array.isArray(security)
    ? [...new Set(security.flatMap((req) => (isObj(req) ? Object.values(req).flat() : [])).filter((s): s is string => typeof s === 'string'))]
    : [];

/** OpenAPI 3.x: one action per operation, named `METHOD /path`. */
export function parse(doc: Doc, file: string): Action[] | null {
  const v = doc.value;
  if (!isObj(v) || !/^3(\.|$)/.test(String(v.openapi)) || !isObj(v.paths)) return null;
  const out: Action[] = [];
  for (const route of Object.keys(v.paths)) {
    const [pathItem, ip] = deref(doc, v.paths[route], ['paths', route]);
    if (!isObj(pathItem)) continue;
    for (const m of METHODS) {
      const op = pathItem[m];
      if (!isObj(op)) continue;
      const opPath = [...ip, m];
      // Operation parameters override path-level ones with the same name and location.
      const byKey = new Map<string, Param>();
      const addParams = (list: unknown, p: Path) => {
        if (!Array.isArray(list)) return;
        list.forEach((raw, i) => {
          const [prm, pp] = deref(doc, raw, [...p, i]);
          // External or missing $ref: keep a placeholder named after the ref, type unknown.
          if (isObj(raw) && typeof raw.$ref === 'string' && (!isObj(prm) || '$ref' in prm)) {
            const name = raw.$ref.split(/[/#]/).filter(Boolean).at(-1) ?? raw.$ref;
            byKey.set(`ref:${raw.$ref}`, { name, loc: doc.loc([...p, i, '$ref']) });
            return;
          }
          if (!isObj(prm) || typeof prm.name !== 'string') return;
          const [schema] = deref(doc, prm.schema, [...pp, 'schema']);
          byKey.set(`${prm.in}:${prm.name}`, param(prm.name, schema, doc.loc([...pp, 'name'])));
        });
      };
      addParams(pathItem.parameters, [...ip, 'parameters']);
      addParams(op.parameters, [...opPath, 'parameters']);
      const params = [...byKey.values()];
      const [body, bp] = deref(doc, op.requestBody, [...opPath, 'requestBody']);
      if (isObj(body) && isObj(body.content)) {
        const type = 'application/json' in body.content ? 'application/json' : Object.keys(body.content)[0];
        if (type) params.push(...schemaParams(doc, body.content[type]?.schema, [...bp, 'content', type, 'schema']));
      }
      const name = `${m.toUpperCase()} ${route}`;
      const operationId = typeof op.operationId === 'string' ? op.operationId : undefined;
      const summary = typeof op.summary === 'string' ? op.summary : undefined;
      const description = summary ?? (typeof op.description === 'string' ? op.description : undefined);
      out.push(
        action(file, doc.loc(opPath), {
          name,
          kind: 'endpoint',
          method: m.toUpperCase(),
          label: operationId ? humanise(operationId) : (summary ?? name),
          ...(operationId && { operationId }),
          ...(description && { description }),
          scopes: scopesOf(op.security ?? v.security),
          params,
        }),
      );
    }
  }
  return out;
}
