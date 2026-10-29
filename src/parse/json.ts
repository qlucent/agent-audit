// One view over JSON(C) and YAML: the plain value plus 1-based locations by path.
import { findNodeAtLocation, getNodeValue, parseTree, printParseErrorCode, type ParseError as JsonError } from 'jsonc-parser';
import { LineCounter, isAlias, isMap, isScalar, isSeq, parseDocument, type Node as YNode } from 'yaml';
import type { Action, Loc, Param } from '../types.ts';
import type { Tree } from '../secrets.ts';

export type Path = (string | number)[];
export type ParseError = { message: string; line: number; column: number };
export interface Doc {
  value: unknown;
  json: boolean;
  /** The parsed tree, kept for redaction so a file is parsed once. */
  tree: Tree;
  /** Location of the key when the path ends in an object key (`key` false: of the value), else of the element. */
  loc(path: Path, key?: boolean): Loc;
}

export const isObj = (v: unknown): v is Record<string, any> => typeof v === 'object' && v !== null && !Array.isArray(v);
export const get = (v: unknown, path: Path): any => path.reduce<any>((o, k) => (o == null ? undefined : o[k]), v);

export const looksJson = (name: string, text: string) => !/\.ya?ml$/i.test(name) && /^\s*[[{/]/.test(text);

export function parseText(name: string, raw: string): { doc?: Doc; error?: ParseError } {
  // A leading BOM becomes a space, as in mcp-audit, so offsets match its locations.
  const text = raw.replace(/^﻿/, ' ');
  const lc = new LineCounter();
  const at = (offset: number, length: number): Loc => {
    const { line, col } = lc.linePos(offset);
    return { line, column: col, offset, length };
  };
  if (looksJson(name, text)) {
    lc.addNewLine(0);
    for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) lc.addNewLine(i + 1);
    const errors: JsonError[] = [];
    const tree = parseTree(text, errors, { allowTrailingComma: true, disallowComments: false });
    const e = errors[0];
    if (e || !tree) {
      const { line, column } = at(e?.offset ?? 0, 0);
      return { error: { message: e ? printParseErrorCode(e.error) : 'Empty file', line, column } };
    }
    const loc = (path: Path, key = true): Loc => {
      for (let p = path; ; p = p.slice(0, -1)) {
        const n = findNodeAtLocation(tree, p);
        if (!n) continue;
        const k = key && p === path && typeof p.at(-1) === 'string' && n.parent?.type === 'property' ? n.parent.children![0]! : n;
        return at(k.offset, k.length);
      }
    };
    return { doc: { value: getNodeValue(tree), json: true, loc, tree: { json: tree } } };
  }
  const yd = parseDocument(text, { lineCounter: lc, uniqueKeys: false });
  const ye = yd.errors[0];
  if (ye) {
    const [pos] = ye.linePos ?? [{ line: 1, col: 1 }];
    return { error: { message: ye.message.split('\n')[0]!.replace(/ at line \d+, column \d+:?$/, ''), line: pos.line, column: pos.col } };
  }
  const loc = (path: Path, key = true): Loc => {
    for (let p = path; ; p = p.slice(0, -1)) {
      let n: unknown = yd.contents;
      for (let i = 0; i < p.length && n; i++) {
        if (isAlias(n)) n = n.resolve(yd);
        if (isMap(n)) {
          const pair = n.items.find((x) => String(isScalar(x.key) ? x.key.value : x.key) === String(p[i]));
          n = pair && (key && i === p.length - 1 ? pair.key : pair.value);
        } else n = isSeq(n) ? n.items[p[i] as number] : undefined;
      }
      const r = (n as YNode | undefined)?.range;
      if (r) return at(r[0], r[1] - r[0]);
      if (!p.length) return at(0, 0);
    }
  };
  return { doc: { value: yd.toJS({ maxAliasCount: 100 }), json: false, loc, tree: { yaml: yd } } };
}

/** Resolve a local `$ref` (`#/a/b`); returns the target and its path for locations. */
export function deref(doc: Doc, value: unknown, path: Path): [any, Path] {
  for (let i = 0; i < 10 && isObj(value) && typeof value.$ref === 'string' && value.$ref.startsWith('#/'); i++) {
    path = value.$ref.slice(2).split('/').map((s: string) => decodeURIComponent(s).replaceAll('~1', '/').replaceAll('~0', '~'));
    value = get(doc.value, path);
  }
  return [value, path];
}

const firstType = (t: unknown) => (Array.isArray(t) ? t.find((x) => x !== 'null') : t);
const num = (v: unknown) => (typeof v === 'number' ? v : undefined);

export function param(name: string, schema: any, loc: Loc): Param {
  const p: Param = { name, loc };
  const type = firstType(schema?.type);
  if (typeof type === 'string') p.type = type;
  const max = num(schema?.maximum) ?? num(schema?.exclusiveMaximum);
  if (max !== undefined) p.maximum = max;
  return p;
}

/** Params from a JSON Schema's properties; nested objects (and arrays of objects) become dotted names. */
export function schemaParams(doc: Doc, schema: unknown, path: Path, prefix = '', depth = 0): Param[] {
  const [s, sp] = deref(doc, schema, path);
  if (!isObj(s) || depth > 4) return [];
  const out: Param[] = [];
  if (isObj(s.properties)) {
    for (const k of Object.keys(s.properties)) {
      const [ps, pp] = deref(doc, s.properties[k], [...sp, 'properties', k]);
      out.push(param(prefix + k, ps, doc.loc([...sp, 'properties', k])));
      out.push(...schemaParams(doc, ps, pp, `${prefix}${k}.`, depth + 1));
    }
  }
  if (s.type === 'array' && s.items) out.push(...schemaParams(doc, s.items, [...sp, 'items'], prefix.replace(/\.$/, '[].'), depth + 1));
  return out;
}

/** `issue_refund` / `createRefund` → "Issue refund" / "Create refund". */
export const humanise = (s: string) => {
  const w = s.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').trim().toLowerCase();
  return w.charAt(0).toUpperCase() + w.slice(1);
};

export function action(file: string, loc: Loc, a: Pick<Action, 'name' | 'kind'> & Partial<Action>): Action {
  return { id: `${file}:${loc.line}:${loc.column}`, label: a.name, file, loc, params: [], effects: [], data: [], evidence: [], ...a };
}

/** A non-empty tool list at `[]`, `tools` or `result.tools`, with its path. */
export function toolList(v: unknown): [any[], Path] | null {
  for (const p of [[], ['tools'], ['result', 'tools']] as Path[]) {
    const l = get(v, p);
    if (Array.isArray(l)) return l.length ? [l, p] : null;
  }
  return null;
}
