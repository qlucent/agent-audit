// Secret-looking values, found the way @qlucent/mcp-audit finds them (its provider patterns, secret-like key names,
// URL credentials, private keys) and shown through its exported `mask`. mcp-audit 0.1.0 exports only `mask`, so the
// detection is ported here (R21: structural, over the parsed tree, like mcp-audit's `redact()`).
// ponytail: import mcp-audit's detector instead once it exports one.
import { createScanner, parseTree, type Node, type ParseError } from 'jsonc-parser';
import { isAlias, isMap, isScalar, isSeq, parseDocument, type Document, type Scalar } from 'yaml';
import { mask } from '@qlucent/mcp-audit';
import { bomless, looksJson } from './parse/json.ts';

export const HIDDEN = '••••••';

// Unanchored inside words (`AllowAKIA…` in a Sid, R4), bounded so they stay linear. Only the generic `sk-` keeps a
// word boundary, since `task-`/`disk-` names would match it.
const PROVIDERS = [
  /(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})/,
  /(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])/,
  /xox[bpar]-[A-Za-z0-9-]{10,255}/,
  /sk-ant-[A-Za-z0-9_-]{20,255}/,
  /(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{20,255}/,
  /[sr]k_live_[A-Za-z0-9]{20,255}/,
  /AIza[A-Za-z0-9_-]{35}/,
];
const TOKEN_SRC = PROVIDERS.map((r) => r.source).join('|');
const TOKEN = new RegExp(TOKEN_SRC, 'g');
const IS_TOKEN = new RegExp(TOKEN_SRC);
const PEM = /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[^]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)/g;
const JWT = /eyJ[\w-]+\.[\w-]+\.[\w-]+/g;
const URL_RE = /[a-z][a-z0-9+.-]*:\/\/[^\s"'`<>]+/gi;
// URL userinfo (`user:pass@`, `token@`; a bare `git@` user is not a credential) and query values.
const USERINFO = /^([a-z][a-z0-9+.-]*:\/\/)(?!git@[^/?#\s@]*(?:[/?#\s]|$))([^/?#\s]+)@/i;
const QUERY = /([?&][^=&#\s]*=)([^&#\s]+)/g;
// Credentials in prose with no `name:` key (N3): `Bearer x`, `Basic x`, `Authorization x`, `--token x`, `-u user:x`,
// `token 9f8e…`. The value is captured last; the `tokenish` check keeps prose words.
const BEARER = /\b((?:Bearer|Basic)[ \t]+)([A-Za-z0-9._~+/-]{12,}=*)/gi;
const AUTH_BARE = /\b(Authorization[ \t]+)(?!Bearer\b|Basic\b)([A-Za-z0-9._~+/-]{12,}=*)/gi;
const FLAG = /(?<![\w-])(--?(?:password|passwd|pass|token|secret|api-?key|access-token|auth-token|client-secret)[ \t]+)([^\s"'`-][^\s"'`]*)/gi;
const CURL_USER = /(?<![\w-])((?:-u|--user)[ \t]+[^\s:"'`]+:)([^\s"'`@]+)/g;
const WORD = /(?<![\w.-])((?:token|password|passwd|pwd|secret|api[_-]?key|apikey)[ \t]+)((?=[^\s"'`,;&|<>]*\d)(?=[^\s"'`,;&|<>]*[A-Za-z])[^\s"'`,;&|<>]{8,})/gi;
// A pair: `name=value`, `name: value`, `"any:key/name": value`; a `:` after a bare name needs a space, so ARNs,
// URLs and `service:Action` names are never pairs. The value is a quoted string or one bare word.
const PAIR = /(?<![\w.-])(?:"([^"\n]+)"|'([^'\n]+)'|(-{0,2}[A-Za-z_][\w.-]*))(?:[ \t]*=[ \t]*|(?<=["'])[ \t]*:[ \t]*|[ \t]*:[ \t]+)(?:(?:bearer|basic|token)[ \t]+)?("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|[^\s"'`,;&|<>{}[\]()]+)/gi;
const REFERENCE = [/^\$\{[^}]*\}$/, /^\$[A-Za-z_][A-Za-z0-9_]*$/, /^\{\{[^}]*\}\}$/];

const SECRET_TOKENS = new Set(['token', 'secret', 'key', 'apikey', 'password', 'passwd', 'pwd', 'pat', 'auth', 'authorization', 'credential', 'credentials', 'bearer', 'pw']);
const NON_SECRET_LAST = new Set(['file', 'path', 'dir', 'url', 'uri', 'env', 'sock', 'socket', 'name', 'mode', 'type', 'arn', 'id', 'region', 'endpoint',
  'format', 'length', 'min', 'max', 'method', 'scheme', 'version', 'policy', 'status', 'ttl']);
// Spec structure inside a secret-named subtree (a security scheme, a schema property): never the secret itself.
const STRUCTURE = new Set(['type', 'format', 'in', 'name', 'scheme', 'bearerFormat', 'description', 'summary', 'title', 'required', 'nullable',
  'minLength', 'maxLength', 'minimum', 'maximum', 'pattern', '$ref', 'tokenUrl', 'authorizationUrl', 'refreshUrl', 'openIdConnectUrl',
  'operationId', 'enum', 'writeOnly', 'readOnly', 'deprecated', 'scopes']);
// Maps whose keys are names (paths, components), not properties holding a value: their keys never force (N5).
const NAME_MAPS = new Set(['paths', 'schemas', 'securitySchemes', 'parameters', 'requestBodies', 'responses', 'definitions', '$defs', 'flows',
  'properties', 'patternProperties']);
// Under a secret-named schema property only its own values are the secret (R5); enum members only when secret-shaped (R3).
const SCHEMA_VALUES = new Set(['example', 'examples', 'default', 'const', 'x-example', 'x-examples']);
const PROPERTY_MAPS = new Set(['properties', 'patternProperties']);
// Free text, never output verbatim (R22): these keys' string values, and every string under an `x-*` key.
const FREE_TEXT = new Set(['description', 'summary', 'title', 'purpose']);
export const HIDDEN_TEXT = '(description hidden)';
// An OpenAPI parameter or header carrying a credential, and a security scheme: these children hold its value (N1).
const VALUE_KEYS = new Set(['example', 'examples', 'content', 'schema', 'default', 'x-example', 'x-examples']);
const CREDENTIAL_HEADER = /^(?:authorization|proxy-authorization|cookie|set-cookie)$/i;
// Secret-sounding names that carry a client-chosen id, not a credential.
const NOT_CREDENTIAL = /^idempotency[-_]?key$/i;

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
const shaped = (v: string) => IS_TOKEN.test(v) || (v.length >= 16 && /\d/.test(v) && /[A-Za-z]/.test(v) && !/\s/.test(v) && entropy(v) >= 3.5);
const keep = (raws: string[], v: string) => { if (shaped(v)) raws.push(v); };
/** Looks like a credential rather than a prose word: a digit, base64 padding/slashes, or inner capitals. */
const tokenish = (v: string) => /\d/.test(v) || /[+/=]/.test(v) || (/[A-Z]/.test(v.slice(1)) && /[a-z]/.test(v));
/** A bare one-word value after a secret name in prose: `Token: returned by` keeps `returned` (N5). */
const secretWord = (v: string) => /\d/.test(v) || v.length >= 16 || (v.length >= 8 && tokenish(v));

const linesMask = (v: string) => v.split('\n').map((l) => HIDDEN + (l.endsWith('\r') ? '\r' : '')).join('\n');
/** A URL with its userinfo and query values hidden. */
const redactUrl = (u: string, raws: string[]) => u
  .replace(USERINFO, (_, pre: string, v: string) => { keep(raws, v); return `${pre}${HIDDEN}@`; })
  .replace(QUERY, (_, pre: string, v: string) => { keep(raws, v); return pre + HIDDEN; });

function pairs(s: string, raws: string[]): string {
  const re = new RegExp(PAIR.source, 'gi');
  let out = '', pos = 0;
  for (let m; (m = re.exec(s));) {
    const [whole, dq, sq, bare, raw = ''] = m;
    const end = m.index + whole.length, at = end - raw.length;
    const quoted = /^["']/.test(raw) ? raw[0]! : '';
    const inner = quoted ? raw.slice(1, -1) : raw;
    if (!secretLikeKey((dq ?? sq ?? bare ?? '').replace(/^-+/, ''))) {
      // Not a secret name. A quoted value may hold pairs of its own (C1); a bare one may start the next pair, so
      // the scan goes on from it instead of past it (`Note: api_key=x`, N2).
      if (quoted) { out += s.slice(pos, at) + quoted + pairs(inner, raws) + quoted; pos = end; } else re.lastIndex = at;
      continue;
    }
    if (!inner || inner.includes('•') || REFERENCE.some((r) => r.test(inner)) || (!quoted && !secretWord(inner))) { re.lastIndex = at; continue; }
    keep(raws, inner);
    out += s.slice(pos, at) + quoted + mask(inner) + quoted;
    pos = end;
  }
  return out + s.slice(pos);
}

/** `re` with its last group (the value) masked when `ok` holds. */
const hideValue = (s: string, re: RegExp, raws: string[], ok: (v: string) => boolean = () => true) =>
  s.replace(re, (m: string, pre: string, v: string) => (v.includes('•') || !ok(v) ? m : (keep(raws, v), pre + mask(v))));

/** Free text (a string value, a comment) with private keys, provider tokens, JWTs, URL credentials, bearer and basic
 * credentials, credential flags and secret-named pairs hidden. Line breaks are kept. */
export function redactFree(s: string, raws: string[] = []): string {
  // Fast path: every pattern needs a separator, a space or 20+ characters (tokens are 20+).
  if (s.length < 20 && !/[=:\s]/.test(s)) return s;
  let o = s.includes('-----BEGIN') ? s.replace(PEM, linesMask) : s;
  o = o.replace(TOKEN, (m) => { raws.push(m); return mask(m); });
  if (o.includes('eyJ')) o = o.replace(JWT, (m) => { raws.push(m); return mask(m); });
  if (o.includes('://')) o = o.replace(URL_RE, (u) => {
    const tail = /[).,;:!?]+$/.exec(u)?.[0] ?? ''; // `(see https://x/y?v=1).` keeps its `).` (M2)
    return redactUrl(u.slice(0, u.length - tail.length), raws) + tail;
  });
  o = hideValue(o, BEARER, raws, tokenish);
  o = hideValue(o, AUTH_BARE, raws, tokenish);
  if (o.includes('-')) o = hideValue(hideValue(o, FLAG, raws), CURL_USER, raws);
  o = hideValue(o, WORD, raws);
  return pairs(o, raws);
}

/** A parsed file, as the parser left it: reused so a large YAML file is not parsed twice (N7). */
export interface Tree { yaml?: Document; json?: Node }

type Edit = { offset: number; length: number; to: string; force: boolean };
/** Whether a child of `key` is masked whole: under a secret-named key, unless the key is spec structure. */
const forceUnder = (force: boolean, key: string) => !STRUCTURE.has(key) && (force || secretLikeKey(key));

/** The format-specific half of the tree walk. */
interface Adapter<N> {
  kind(n: N): 'map' | 'seq' | 'scalar' | 'alias' | undefined;
  entries(n: N): [key: string, keyNode: N | undefined, value: N | undefined][];
  items(n: N): N[];
  resolve(n: N): N | undefined;
  /** String value of a scalar child, for the parameter / security-scheme checks. */
  str(n: N | undefined): string | undefined;
  scalar(n: N, mode: Mode): void;
}
/** How a scalar is shown: masked whole, masked when secret-shaped, hidden as free text, or scanned. */
type Mode = 'mask' | 'shape' | 'hide' | 'scan';
/** Masking state of a subtree: `true` everything (minus structure), `schema` a secret-named schema property's own
 * values only, `shape` secret-shaped values only (enum members). */
type Force = boolean | 'schema' | 'shape';

function walkTree<N extends object>(root: N | undefined, a: Adapter<N>): void {
  const seen = new Set<string>();
  let ids = 0;
  const id = new WeakMap<N, number>();
  const walk = (n: N | undefined, force: Force, hide: boolean, parent: string): void => {
    if (!n) return;
    const k = a.kind(n);
    if (k === 'alias') {
      // An alias under a secret key masks its anchor too (N4); each target is walked once per mode.
      const t = a.resolve(n);
      if (!t) return;
      if (!id.has(t)) id.set(t, ids++);
      const key = `${id.get(t)}:${force}:${hide}`;
      if (!seen.has(key)) { seen.add(key); walk(t, force, hide, parent); }
    } else if (k === 'map') {
      const es = a.entries(n);
      const get = (x: string) => a.str(es.find(([key]) => key === x)?.[2]);
      const where = get('in')?.toLowerCase(), name = get('name') ?? '', type = get('type');
      const holdsCredential = (where === 'header' || where === 'query' || where === 'cookie') && ((secretLikeKey(name) && !NOT_CREDENTIAL.test(name)) || CREDENTIAL_HEADER.test(name));
      const scheme = (type === 'apiKey' || type === 'http' || type === 'oauth2' || type === 'openIdConnect') && es.some(([key]) => key === 'scheme' || key === 'in' || key === 'flows');
      const names = NAME_MAPS.has(parent);
      for (const [key, kn, v] of es) {
        if (kn) a.scalar(kn, 'scan');
        const child: Force = (holdsCredential || scheme) && VALUE_KEYS.has(key) ? true
          : key === 'enum' && !names ? (force ? 'shape' : false)
          : force === 'schema' ? (SCHEMA_VALUES.has(key) || forceUnder(false, key))
          : PROPERTY_MAPS.has(parent) ? (force === true ? !STRUCTURE.has(key) : secretLikeKey(key) ? 'schema' : false)
          : names ? force === true && !STRUCTURE.has(key)
          : forceUnder(force === true, key);
        // R22: free text (and anything under an `x-*` extension) is never shown; a key under a name map is a name.
        walk(v, child, hide || key.startsWith('x-') || (FREE_TEXT.has(key) && !names), key);
      }
    } else if (k === 'seq') for (const c of a.items(n)) walk(c, force, hide, '');
    else if (k === 'scalar') a.scalar(n, hide ? 'hide' : force === 'shape' ? 'shape' : force ? 'mask' : 'scan');
  };
  walk(root, false, false, '');
}

/** Under a secret key, a non-string scalar is masked only when long enough to be one (a PIN, not `90` or `true`). */
const maskable = (v: unknown) => typeof v === 'string' || (typeof v === 'number' && String(v).length >= 6);

function walkJson(text: string, tree: Node | undefined, edits: Edit[], raws: string[]): boolean {
  if (!tree) {
    const errors: ParseError[] = [];
    tree = parseTree(text, errors, { allowTrailingComma: true, disallowComments: false });
    if (errors.length || !tree) return false;
  }
  const scan = createScanner(text, false);
  for (let t = scan.scan(); t !== 17 /* EOF */; t = scan.scan()) {
    if (t !== 12 && t !== 13 /* line, block comment; SyntaxKind is a const enum */) continue;
    const c = scan.getTokenValue(), to = redactFree(c, raws);
    if (to !== c) edits.push({ offset: scan.getTokenOffset(), length: scan.getTokenLength(), to, force: false });
  }
  walkTree<Node>(tree, {
    kind: (n) => (n.type === 'object' ? 'map' : n.type === 'array' ? 'seq' : n.type === 'property' ? undefined : 'scalar'),
    entries: (n) => (n.children ?? []).map((p) => [String(p.children?.[0]?.value ?? ''), p.children?.[0], p.children?.[1]]),
    items: (n) => n.children ?? [],
    resolve: () => undefined,
    str: (n) => (n?.type === 'string' ? String(n.value) : undefined),
    scalar: (n, mode) => {
      if (mode === 'hide' && n.type === 'string') edits.push({ offset: n.offset, length: n.length, to: JSON.stringify(HIDDEN_TEXT), force: true });
      else if ((mode === 'mask' || mode === 'hide') && maskable(n.value) || (mode === 'shape' && n.type === 'string' && shaped(String(n.value)))) {
        const v = String(n.value);
        keep(raws, v);
        edits.push({ offset: n.offset, length: n.length, to: JSON.stringify(mask(v)), force: true });
      } else if (n.type === 'string') {
        const v = String(n.value), r = redactFree(v, raws);
        if (r !== v) edits.push({ offset: n.offset, length: n.length, to: JSON.stringify(r), force: false });
      }
    },
  });
  return true;
}

const indentMask = (l: string) => (/\S/.test(l) ? l.replace(/\S.*?(\r?)$/, `${HIDDEN}$1`) : l);

function walkYaml(text: string, doc: Document | undefined, edits: Edit[], raws: string[]): boolean {
  doc ??= parseDocument(text, { uniqueKeys: false });
  if (doc.errors.length) return false;
  const blocks: [number, number][] = [];
  const render = (n: Scalar, v: string) =>
    n.type === 'QUOTE_DOUBLE' ? JSON.stringify(v) : n.type === 'QUOTE_SINGLE' ? `'${v.replaceAll("'", "''")}'` : v;
  const scalar = (n: Scalar, mode: Mode) => {
    const [s, e] = n.range ?? [0, 0];
    if (e <= s) return;
    const block = n.type === 'BLOCK_LITERAL' || n.type === 'BLOCK_FOLDED';
    if (block) blocks.push([s, e]);
    const src = text.slice(s, e);
    const hide = mode === 'hide' && typeof n.value === 'string';
    if (hide) {
      // R22: one marker line per original line; a block keeps its `|` / `>-` header.
      const nl = src.indexOf('\n');
      const to = !src.includes('\n') ? JSON.stringify(HIDDEN_TEXT)
        : block ? src.slice(0, nl + 1) + src.slice(nl + 1).split('\n').map((l) => (/\S/.test(l) ? l.replace(/\S.*?(\r?)$/, `${HIDDEN_TEXT}$1`) : l)).join('\n')
        : [JSON.stringify(HIDDEN_TEXT) + (src.slice(0, nl).endsWith('\r') ? '\r' : ''), ...src.split('\n').slice(1).map((l) => l.replace(/\S.*?(\r?)$/, '$1'))].join('\n');
      edits.push({ offset: s, length: e - s, to, force: true });
      return;
    }
    const force = (mode === 'mask' || mode === 'hide') && maskable(n.value) || (mode === 'shape' && typeof n.value === 'string' && shaped(n.value));
    // An anchored value can be aliased anywhere (a description), so its raw is hidden there too whatever its shape.
    if (force && n.anchor) raws.push(String(n.value));
    let to: string | undefined;
    if (block) {
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
    if (to !== undefined && to !== src) edits.push({ offset: s, length: e - s, to, force });
  };
  walkTree<object>(doc.contents ?? undefined, {
    kind: (n) => (isAlias(n) ? 'alias' : isMap(n) ? 'map' : isSeq(n) ? 'seq' : isScalar(n) ? 'scalar' : undefined),
    entries: (n) => (isMap(n) ? n.items.map((p) => [isScalar(p.key) ? String(p.key.value) : '', isScalar(p.key) ? p.key : undefined, (p.value ?? undefined) as object | undefined]) : []),
    items: (n) => (isSeq(n) ? (n.items as object[]) : []),
    resolve: (n) => (isAlias(n) ? (n.resolve(doc) as object | undefined) : undefined),
    str: (n) => (n && isScalar(n) && typeof n.value === 'string' ? n.value : undefined),
    scalar: (n, mode) => scalar(n as Scalar, mode),
  });
  // Whole-line `#` comments outside block scalars.
  for (let at = 0; at < text.length;) {
    const nl = text.indexOf('\n', at), end = nl < 0 ? text.length : nl;
    if (text[at] === '#' || /^[ \t]*#/.test(text.slice(at, Math.min(end, at + 256)))) {
      const line = text.slice(at, end);
      if (!blocks.some(([s, e]) => at >= s && at < e)) {
        const to = redactFree(line, raws);
        if (to !== line) edits.push({ offset: at, length: line.length, to, force: false });
      }
    }
    at = end + 1;
  }
  return true;
}

/**
 * The file text with every secret-looking value masked, line count kept: every scalar under a secret-named key or in
 * a credential parameter's example, and in every other string (and comment) any provider token, private key, URL
 * credential, bearer credential or secret-named pair. Walks the parsed tree (`tree` from the parser if given, else it
 * parses; `null`: the file is known not to parse); a file that doesn't parse is scanned as free text. Excerpts are cut
 * from this text.
 */
export function redactFile(name: string, raw: string, tree?: Tree | null): { text: string; raws: string[] } {
  const text = bomless(name, raw);
  const raws: string[] = [];
  const edits: Edit[] = [];
  const json = tree ? tree.json !== undefined : looksJson(name, text);
  const parsed = tree === null ? false : json ? walkJson(text, tree?.json, edits, raws) : walkYaml(text, tree?.yaml, edits, raws);
  if (!parsed) return { text: redactFree(text, raws), raws };
  // A forced mask wins over a free-text edit of the same node (an anchor reached again through an alias).
  edits.sort((a, b) => a.offset - b.offset || Number(b.force) - Number(a.force));
  let out = '', pos = 0;
  for (const e of edits) {
    if (e.offset < pos) continue;
    out += text.slice(pos, e.offset) + e.to;
    pos = e.offset + e.length;
  }
  return { text: out + text.slice(pos), raws };
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** The final pass over every result string: `redactFree`, plus the raw values found in the files. */
export function scrubber(raws: string[]): (s: string) => string {
  const known = [...new Set(raws)].filter((r) => r.length >= 4).sort((a, b) => b.length - a.length);
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
  return (force && maskable(v) ? mask(String(v)) : v) as T;
}
