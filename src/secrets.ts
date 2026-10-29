// Secret-looking values, found the way @qlucent/mcp-audit finds them (its provider patterns, secret-like key names,
// URL credentials, private keys) and shown through its exported `mask`. mcp-audit 0.1.0 exports only `mask`, so the
// detection is ported here. ponytail: import mcp-audit's detector instead once it exports one.
import { mask } from '@qlucent/mcp-audit';

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
const TOKEN = new RegExp(PROVIDERS.map((r) => r.source).join('|'), 'g');
const PEM = /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[^]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)/g;
// URL userinfo (`user:pass@`, `token@`; a bare `git@` user is not a credential) and query values.
const URL_RE = /[a-z][a-z0-9+.-]*:\/\/[^\s"'`<>]+/gi;
const USERINFO = /^([a-z][a-z0-9+.-]*:\/\/)(?!git@[^/?#\s@]*(?:[/?#\s]|$))([^/?#\s]+)@/i;
const QUERY = /([?&][^=&#\s]*=)([^&#\s]+)/g;
// `key: value`, `"key": "value"`, `key=value` on one line; the value is a quoted string or one bare word.
const PAIR = /(?<![\w.-])(["']?)(-{0,2}[A-Za-z_][\w.-]*)\1[ \t]*[=:][ \t]*(?:(?:bearer|basic|token)[ \t]+)?("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|[^\s"'`,;&|<>{}[\]]+)/gi;
const REFERENCE = [/^\$\{[^}]*\}$/, /^\$[A-Za-z_][A-Za-z0-9_]*$/, /^\{\{[^}]*\}\}$/];

const SECRET_TOKENS = new Set(['token', 'secret', 'key', 'apikey', 'password', 'passwd', 'pwd', 'pat', 'auth', 'authorization', 'credential', 'credentials', 'bearer', 'pw']);
const NON_SECRET_LAST = new Set(['file', 'path', 'dir', 'url', 'uri', 'env', 'sock', 'socket', 'name', 'mode', 'type', 'arn', 'id', 'region', 'endpoint']);

/** mcp-audit's rule: a key-name word is a secret word and the last word is not a pointer to one (`TOKEN_FILE`). */
export function secretLikeKey(key: string): boolean {
  const w = key.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  return w.some((x) => SECRET_TOKENS.has(x)) && !NON_SECRET_LAST.has(w[w.length - 1]!);
}

/** A URL with its userinfo and query values hidden. */
const redactUrl = (u: string, raws: string[]) => u
  .replace(USERINFO, (_, pre: string, v: string) => { keep(raws, v); return `${pre}${HIDDEN}@`; })
  .replace(QUERY, (_, pre: string, v: string) => { keep(raws, v); return pre + HIDDEN; });

const linesMask = (v: string) => v.split('\n').map((l) => HIDDEN + (l.endsWith('\r') ? '\r' : '')).join('\n');
// Raw values worth hiding wherever else they turn up: long enough and not a plain word.
const keep = (raws: string[], v: string) => { if (v.length >= 8 && /\d/.test(v) && !/\s/.test(v) && !v.includes('•')) raws.push(v); };

/** Text with every secret-looking value masked; line breaks are kept, so line numbers still match. */
export function redactText(text: string): { text: string; raws: string[] } {
  const raws: string[] = [];
  let out = text.includes('-----BEGIN') ? text.replace(PEM, linesMask) : text;
  out = out.replace(TOKEN, (m) => { raws.push(m); return mask(m); });
  if (out.includes('://')) out = out.replace(URL_RE, (u) => redactUrl(u, raws));
  out = out.replace(PAIR, (m, q: string, name: string, raw: string) => {
    if (!secretLikeKey(name.replace(/^-+/, ''))) return m;
    const quoted = /^["']/.test(raw) ? raw[0]! : '';
    const v = quoted ? raw.slice(1, -1) : raw;
    if (!v || v.includes('•') || REFERENCE.some((r) => r.test(v))) return m;
    keep(raws, v);
    return m.slice(0, m.length - raw.length) + quoted + mask(v) + quoted;
  });
  return { text: out, raws };
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** A scrubber for any string: private keys, provider tokens, URL credentials and the given raw values masked. */
export function scrubber(raws: string[]): (s: string) => string {
  const known = [...new Set(raws)].sort((a, b) => b.length - a.length);
  const re = known.length ? new RegExp(known.map(escape).join('|'), 'g') : undefined;
  return (s) => {
    let o = s.includes('-----BEGIN') ? s.replace(PEM, linesMask) : s;
    o = o.replace(TOKEN, mask);
    if (re) o = o.replace(re, mask);
    if (o.includes('://')) o = o.replace(URL_RE, (u) => redactUrl(u, []));
    return o;
  };
}

/** A deep copy of `v` with every string, keys included, passed through `f`. */
export function scrubDeep<T>(v: T, f: (s: string) => string): T {
  if (typeof v === 'string') return f(v) as T;
  if (Array.isArray(v)) return v.map((x) => scrubDeep(x, f)) as T;
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [f(k), scrubDeep(x, f)])) as T;
  return v;
}
