// Secret-looking values, found the way @qlucent/mcp-audit finds them (its provider patterns, secret-like key names,
// URL credentials, private keys) and shown through its exported `mask`. mcp-audit 0.1.0 exports only `mask`, so the
// detection is ported here (R21: structural, over the parsed tree, like mcp-audit's `redact()`).
// ponytail: import mcp-audit's detector instead once it exports one.
import { createScanner, parseTree, type Node, type ParseError } from 'jsonc-parser';
import { isAlias, isMap, isScalar, isSeq, parseDocument, type Scalar } from 'yaml';
import { mask } from '@qlucent/mcp-audit';
import { looksJson } from './parse/json.ts';

export const HIDDEN = '••••••';

const PROVIDERS = [
  /(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/,
  /(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])/,
  /(?<![A-Za-z0-9])xox[bpar]-[A-Za-z0-9-]{10,}/,
  /(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}/,
  /(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{20,}/,
  /(?<![A-Za-z0-9])[sr]k_live_[A-Za-z0-9]{20,}/,
  /(?<![A-Za-z0-9])AIza[A-Za-z0-9_-]{35}/,
];
const TOKEN_SRC = PROVIDERS.map((r) => r.source).join('|');
const TOKEN = new RegExp(TOKEN_SRC, 'g');
const IS_TOKEN = new RegExp(TOKEN_SRC);
const PEM = /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[^]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)/g;
const URL_RE = /[a-z][a-z0-9+.-]*:\/\/[^\s"'`<>]+/gi;
// URL userinfo (`user:pass@`, `token@`; a bare `git@` user is not a credential) and query values.
const USERINFO = /^([a-z][a-z0-9+.-]*:\/\/)(?!git@[^/?#\s@]*(?:[/?#\s]|$))([^/?#\s]+)@/i;
const QUERY = /([?&][^=&#\s]*=)([^&#\s]+)/g;
// A pair: `name=value`, `name: value`, `"any:key/name": value`; a `:` after a bare name needs a space, so ARNs,
// URLs and `service:Action` names are never pairs. The value is a quoted string or one bare word.
const PAIR = /(?<![\w.-])(?:"([^"\n]+)"|'([^'\n]+)'|(-{0,2}[A-Za-z_][\w.-]*))(?:[ \t]*=[ \t]*|(?<=["'])[ \t]*:[ \t]*|[ \t]*:[ \t]+)(?:(?:bearer|basic|token)[ \t]+)?("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|[^\s"'`,;&|<>{}[\]()]+)/gi;
const REFERENCE = [/^\$\{[^}]*\}$/, /^\$[A-Za-z_][A-Za-z0-9_]*$/, /^\{\{[^}]*\}\}$/];

const SECRET_TOKENS = new Set(['token', 'secret', 'key', 'apikey', 'password', 'passwd', 'pwd', 'pat', 'auth', 'authorization', 'credential', 'credentials', 'bearer', 'pw']);
const NON_SECRET_LAST = new Set(['file', 'path', 'dir', 'url', 'uri', 'env', 'sock', 'socket', 'name', 'mode', 'type', 'arn', 'id', 'region', 'endpoint',
  'format', 'length', 'min', 'max', 'method', 'scheme']);
// Spec structure inside a secret-named subtree (an OpenAPI security scheme, a schema property): not the secret itself.
const STRUCTURE = new Set(['type', 'format', 'in', 'name', 'scheme', 'bearerFormat', 'description', 'summary', 'title', 'required', 'nullable',
  'minLength', 'maxLength', 'minimum', 'maximum', 'pattern', '$ref', 'tokenUrl', 'authorizationUrl', 'refreshUrl', 'openIdConnectUrl']);

const words = (key: string) => key.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
/** mcp-audit's rule: a key-name word is a secret word and the last word is not a pointer to one (`TOKEN_FILE`). Keys
 * split on any non-alphanumeric and camelCase, so `aws:PrincipalTag/token` is secret-like. */
export function secretLikeKey(key: string): boolean {
  const w = words(key);
  return w.some((x) => SECRET_TOKENS.has(x)) && !NON_SECRET_LAST.has(w[w.length - 1]!);
}

function entropy(s: string): number {
  const n = new Map<string, number>();
  for (const c of s) n.set(c, (n.get(c) ?? 0) + 1);
  let h = 0;
  for (const c of n.values()) h -= (c / s.length) * Math.log2(c / s.length);
  return h;
}
/** Raw values the final pass also hides wherever they turn up: secret-shaped only (M1), so a name never matches. */
const keep = (raws: string[], v: string) => {
  if (IS_TOKEN.test(v) || (v.length >= 16 && /\d/.test(v) && /[A-Za-z]/.test(v) && !/\s/.test(v) && entropy(v) >= 3.5)) raws.push(v);
};

const linesMask = (v: string) => v.split('\n').map((l) => HIDDEN + (l.endsWith('\r') ? '\r' : '')).join('\n');
/** A URL with its userinfo and query values hidden. */
const redactUrl = (u: string, raws: string[]) => u
  .replace(USERINFO, (_, pre: string, v: string) => { keep(raws, v); return `${pre}${HIDDEN}@`; })
  .replace(QUERY, (_, pre: string, v: string) => { keep(raws, v); return pre + HIDDEN; });

function pairs(s: string, raws: string[]): string {
  return s.replace(PAIR, (m, dq?: string, sq?: string, bare?: string, raw = '') => {
    const quoted = /^["']/.test(raw) ? raw[0]! : '';
    const inner = quoted ? raw.slice(1, -1) : raw;
    const head = m.slice(0, m.length - raw.length);
    // Not a secret name: a quoted value may still hold pairs of its own (C1).
    if (!secretLikeKey((dq ?? sq ?? bare ?? '').replace(/^-+/, ''))) return quoted ? head + quoted + pairs(inner, raws) + quoted : m;
    if (!inner || inner.includes('•') || REFERENCE.some((r) => r.test(inner))) return m;
    keep(raws, inner);
    return head + quoted + mask(inner) + quoted;
  });
}

/** Free text (a string value, a comment) with private keys, provider tokens, URL credentials and secret-named pairs
 * hidden. Line breaks are kept. */
export function redactFree(s: string, raws: string[] = []): string {
  let o = s.includes('-----BEGIN') ? s.replace(PEM, linesMask) : s;
  o = o.replace(TOKEN, (m) => { raws.push(m); return mask(m); });
  if (o.includes('://')) o = o.replace(URL_RE, (u) => {
    const tail = /[).,;:!?]+$/.exec(u)?.[0] ?? ''; // `(see https://x/y?v=1).` keeps its `).` (M2)
    return redactUrl(u.slice(0, u.length - tail.length), raws) + tail;
  });
  return pairs(o, raws);
}

type Edit = { offset: number; length: number; to: string };
/** Whether a child of `key` is masked whole: under a secret-named key, unless the key is spec structure. */
const forceUnder = (force: boolean, key: string) => !STRUCTURE.has(key) && (force || secretLikeKey(key));

function walkJson(text: string, edits: Edit[], raws: string[]): boolean {
  const errors: ParseError[] = [];
  const tree = parseTree(text, errors, { allowTrailingComma: true, disallowComments: false });
  if (errors.length || !tree) return false;
  const scan = createScanner(text, false);
  for (let t = scan.scan(); t !== 17 /* EOF */; t = scan.scan()) {
    if (t !== 12 && t !== 13 /* line, block comment; SyntaxKind is a const enum */) continue;
    const c = scan.getTokenValue(), to = redactFree(c, raws);
    if (to !== c) edits.push({ offset: scan.getTokenOffset(), length: scan.getTokenLength(), to });
  }
  const scalar = (n: Node, force: boolean) => {
    if (force) {
      const v = n.type === 'string' ? String(n.value) : text.slice(n.offset, n.offset + n.length);
      if (n.type !== 'null') { keep(raws, v); edits.push({ offset: n.offset, length: n.length, to: JSON.stringify(mask(v)) }); }
    } else if (n.type === 'string') {
      const v = String(n.value), r = redactFree(v, raws);
      if (r !== v) edits.push({ offset: n.offset, length: n.length, to: JSON.stringify(r) });
    }
  };
  const walk = (n: Node | undefined, force: boolean): void => {
    if (!n) return;
    if (n.type === 'object') for (const p of n.children ?? []) {
      const [k, v] = p.children ?? [];
      if (k) scalar(k, false);
      walk(v, forceUnder(force, String(k?.value ?? '')));
    }
    else if (n.type === 'array') for (const c of n.children ?? []) walk(c, force);
    else scalar(n, force);
  };
  walk(tree, false);
  return true;
}

const indentMask = (l: string) => (/\S/.test(l) ? l.replace(/\S.*?(\r?)$/, `${HIDDEN}$1`) : l);

function walkYaml(text: string, edits: Edit[], raws: string[]): boolean {
  const doc = parseDocument(text, { uniqueKeys: false });
  if (doc.errors.length) return false;
  const blocks: [number, number][] = [];
  const render = (n: Scalar, v: string) =>
    n.type === 'QUOTE_DOUBLE' ? JSON.stringify(v) : n.type === 'QUOTE_SINGLE' ? `'${v.replaceAll("'", "''")}'` : v;
  const scalar = (n: Scalar, force: boolean) => {
    const [s, e] = n.range ?? [0, 0];
    if (e <= s) return;
    const src = text.slice(s, e);
    let to: string | undefined;
    if (n.type === 'BLOCK_LITERAL' || n.type === 'BLOCK_FOLDED') {
      blocks.push([s, e]);
      // Keep the `|` / `>-` header line; mask or scan the body, line by line, so the line count holds (C2).
      const nl = src.indexOf('\n');
      if (nl < 0) return;
      const body = src.slice(nl + 1);
      if (force) for (const l of body.split('\n')) if (l.trim()) keep(raws, l.trim());
      to = src.slice(0, nl + 1) + (force ? body.split('\n').map(indentMask).join('\n') : redactFree(body, raws));
    } else if (src.includes('\n')) {
      if (force) keep(raws, String(n.value));
      to = force ? src.split('\n').map(indentMask).join('\n') : redactFree(src, raws);
    } else if (force) {
      keep(raws, String(n.value));
      to = render(n, mask(String(n.value)));
    } else if (typeof n.value === 'string') {
      const r = redactFree(n.value, raws);
      if (r !== n.value) to = render(n, r);
    }
    if (to !== undefined && to !== src) edits.push({ offset: s, length: e - s, to });
  };
  const walk = (n: unknown, force: boolean): void => {
    if (!n || isAlias(n)) return;
    if (isMap(n)) for (const p of n.items) {
      if (isScalar(p.key)) scalar(p.key, false);
      walk(p.value, forceUnder(force, isScalar(p.key) ? String(p.key.value) : ''));
    }
    else if (isSeq(n)) for (const c of n.items) walk(c, force);
    else if (isScalar(n)) scalar(n, force);
  };
  walk(doc.contents, false);
  // Whole-line `#` comments outside block scalars.
  for (let at = 0; at < text.length;) {
    const end = text.indexOf('\n', at) < 0 ? text.length : text.indexOf('\n', at);
    const line = text.slice(at, end);
    if (/^\s*#/.test(line) && !blocks.some(([s, e]) => at >= s && at < e)) {
      const to = redactFree(line, raws);
      if (to !== line) edits.push({ offset: at, length: line.length, to });
    }
    at = end + 1;
  }
  return true;
}

/**
 * The file text with every secret-looking value masked, line count kept: every scalar under a secret-named key, and
 * in every other string (and comment) any provider token, private key, URL credential or secret-named pair. Walks the
 * parsed tree (JSONC or YAML, as the parser reads it); a file that doesn't parse is scanned as free text. Excerpts
 * are cut from this text.
 */
export function redactFile(name: string, raw: string): { text: string; raws: string[] } {
  const text = raw.replace(/^﻿/, ' ');
  const raws: string[] = [];
  const edits: Edit[] = [];
  const parsed = looksJson(name, text) ? walkJson(text, edits, raws) : walkYaml(text, edits, raws);
  if (!parsed) return { text: redactFree(text, raws), raws };
  edits.sort((a, b) => a.offset - b.offset);
  let out = '', pos = 0;
  for (const e of edits) {
    if (e.offset < pos) continue;
    out += text.slice(pos, e.offset) + e.to;
    pos = e.offset + e.length;
  }
  return { text: out + text.slice(pos), raws };
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** The final pass over every result string: `redactFree`, plus the secret-shaped raw values, as whole words. */
export function scrubber(raws: string[]): (s: string) => string {
  const known = [...new Set(raws)].sort((a, b) => b.length - a.length);
  // Provider tokens anywhere, even glued to a word; other raws only as whole words.
  const tokens = known.filter((r) => IS_TOKEN.test(r)), others = known.filter((r) => !IS_TOKEN.test(r));
  const re = (l: string[], word: boolean) => (l.length ? new RegExp(word ? `(?<![\\w-])(?:${l.map(escape).join('|')})(?![\\w-])` : l.map(escape).join('|'), 'g') : undefined);
  const t = re(tokens, false), o = re(others, true);
  return (s) => {
    if (t) s = s.replace(t, mask);
    if (o) s = s.replace(o, mask);
    return redactFree(s);
  };
}

/** A deep copy of `v` with every string, keys included, passed through `f`. */
export function scrubDeep<T>(v: T, f: (s: string) => string): T {
  if (typeof v === 'string') return f(v) as T;
  if (Array.isArray(v)) return v.map((x) => scrubDeep(x, f)) as T;
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [f(k), scrubDeep(x, f)])) as T;
  return v;
}

/** A copy of a spec object (an IAM Condition) with every scalar under a secret-named key masked. */
export function maskUnderSecretKeys<T>(v: T, force = false): T {
  if (Array.isArray(v)) return v.map((x) => maskUnderSecretKeys(x, force)) as T;
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, maskUnderSecretKeys(x, forceUnder(force, k))])) as T;
  return (force && (typeof v === 'string' || typeof v === 'number') ? mask(String(v)) : v) as T;
}
