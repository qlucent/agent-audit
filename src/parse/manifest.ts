import data from '../generated/data.json' with { type: 'json' };
import type { Manifest } from '../types.ts';
import { isObj, type Doc, type ParseError, type Path } from './json.ts';

interface Schema {
  type?: string;
  required?: string[];
  properties?: Record<string, Schema>;
  additionalProperties?: boolean | Schema;
  items?: Schema;
  enum?: unknown[];
  minLength?: number;
}

const typeOk = (t: string, v: unknown) =>
  t === 'object' ? isObj(v) : t === 'array' ? Array.isArray(v) : t === 'integer' ? Number.isInteger(v) : typeof v === t;

// ponytail: interprets only the keywords manifest.schema.json uses (runtime has no ajv); extend alongside the schema.
function validate(s: Schema, v: unknown, path: Path): [Path, string] | null {
  if (s.type && !typeOk(s.type, v)) return [path, `must be ${s.type}`];
  if (s.enum && !s.enum.includes(v)) return [path, `must be one of: ${s.enum.join(', ')}`];
  if (s.minLength !== undefined && typeof v === 'string' && v.length < s.minLength) return [path, 'must not be empty'];
  if (Array.isArray(v) && s.items) {
    for (let i = 0; i < v.length; i++) {
      const e = validate(s.items, v[i], [...path, i]);
      if (e) return e;
    }
  }
  if (isObj(v)) {
    for (const k of s.required ?? []) if (!(k in v)) return [path, `must have property ${k}`];
    for (const [k, val] of Object.entries(v)) {
      const sub = s.properties?.[k] ?? s.additionalProperties;
      if (sub === false) return [[...path, k], 'is not allowed'];
      if (isObj(sub)) {
        const e = validate(sub as Schema, val, [...path, k]);
        if (e) return e;
      }
    }
  }
  return null;
}

/** A top-level `agent:` object (not e.g. Claude Code's `agent` string setting) is a manifest; it must validate against schemas/manifest.schema.json. */
export function parse(doc: Doc): { manifest?: Manifest; error?: ParseError } | null {
  const v = doc.value;
  if (!isObj(v) || !isObj(v.agent)) return null;
  const e = validate((data as { manifestSchema: Schema }).manifestSchema, v, []);
  if (!e) return { manifest: v as Manifest };
  const { line, column } = doc.loc(e[0], false);
  return { error: { message: `Invalid manifest: /${e[0].join('/')} ${e[1]}`, line, column } };
}
