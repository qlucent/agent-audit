// Fills effects, data classes and evidence from data files only: lexicon/*.yaml, catalog/scopes.yaml, catalog/aws-iam.yaml.
import bundled from './generated/data.json' with { type: 'json' };
import { humanise } from './parse/json.ts';
import type { Action, DataClass, Domain, Effect, Evidence, GeneratedData, LexEntry, Manifest } from './types.ts';

const DEFAULT = bundled as unknown as GeneratedData;
export const ALL: Effect[] = ['read', 'write', 'delete', 'money', 'external-send', 'identity-admin', 'code-exec', 'bulk'];
const METHOD: Record<string, Effect> = { GET: 'read', HEAD: 'read', POST: 'write', PUT: 'write', PATCH: 'write', DELETE: 'delete' };

/** `issue_refund`, `issueRefund`, `GET /v1/refunds/{id}` → "issue refund", "get v1 refunds id". */
export const words = (s: string) =>
  s
    .replace(/([A-Z])(?=[A-Z][a-z])/g, '$1 ')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();

const any = (ps: string[] | undefined, wrap: (p: string) => string) => (ps?.length ? new RegExp(ps.map(wrap).join('|'), 'i') : undefined);
const wordRe = (ps?: string[]) => any(ps, (p) => `\\b(?:${p})\\b`);
const wholeRe = (ps?: string[]) => any(ps, (p) => `^(?:${p})$`);

interface Compiled {
  tag: Effect | DataClass | Domain | undefined;
  name?: RegExp; desc?: RegExp; param?: RegExp; not?: RegExp; verb?: RegExp; noun?: RegExp; nounWhole?: RegExp; verbFirst?: RegExp;
  methods: string[]; context?: DataClass;
}
const compile = (entries: LexEntry[] = []): Compiled[] =>
  entries.map((e) => ({
    tag: e.effect ?? e.data ?? e.domain,
    name: wordRe(e.name_patterns),
    desc: wordRe(e.description_patterns),
    param: wholeRe(e.param_patterns),
    not: wordRe(e.not_patterns),
    verb: e.verbs && new RegExp(wordRe(e.verbs)!.source, 'gi'),
    noun: e.nouns && new RegExp(wordRe(e.nouns)!.source, 'gi'),
    nounWhole: wholeRe(e.nouns),
    verbFirst: any(e.verbs, (p) => `^(?:${p})\\b`),
    methods: e.method_verbs ?? [],
    context: e.context,
  }));

type Span = [start: number, end: number, text: string];
const spans = (re: RegExp, s: string): Span[] => [...s.matchAll(re)].map((m) => [m.index, m.index + m[0].length, m[0]]);
const PREP = / (to|from|for|in|on|of|as|with)\b/y;
/** Phrases scanned for verb x noun are capped: no real action name is this long, and the scan is O(verbs x nouns). */
const MAX_PHRASE = 512;
const MAX_NAME = 2048;
/**
 * Ruling R6: the noun must be the verb's object. Matches "verb … noun" with the noun last or followed only by a
 * to/from/for/in/on/of/as/with clause, or "noun … verb" with the verb last (staffMemberCreate, users … deactivate).
 */
const verbNoun = (text: string, verbs: Span[], nouns: Span[]) => {
  const after = (i: number) => ((PREP.lastIndex = i), i === text.length || PREP.test(text));
  for (const v of verbs)
    for (const n of nouns) {
      if (v[1] <= n[0] && after(n[1])) return [v[2], n[2]] as const;
      if (n[1] <= v[0] && v[1] === text.length) return [v[2], n[2]] as const;
    }
  return undefined;
};

/** Shell-style glob, case-insensitive. Over 256 chars (no real IAM action or tool name) it matches nothing: a 100k-char
 * glob would exceed the regex size limit. */
export const glob = (g: string) => g.length > 256 ? /(?!)/ : new RegExp(`^${g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`, 'i');

/**
 * Manifest `actions:` (R7): declared effects/data replace the classifier's for every action whose name matches the glob
 * (all matching globs are merged). An action with no effect, none declared, and not read-only by method or annotation
 * is marked unclassified for review.
 */
export function classify(actions: Action[], data: GeneratedData = DEFAULT, manifest?: Manifest): Action[] {
  const declared = Object.entries(manifest?.actions ?? {}).map(([g, d]) => ({ g, re: glob(g), ...d }));
  return classifyLexicon(actions, data).map((a) => {
    const hits = declared.filter((d) => d.re.test(a.name));
    for (const [key, tags] of [['effects', hits.filter((d) => d.effects)], ['data', hits.filter((d) => d.data)]] as const) {
      if (!tags.length) continue;
      const list = [...new Set(tags.flatMap((d) => d[key]!))];
      a = {
        ...a,
        [key]: list,
        evidence: [
          ...a.evidence.filter((e) => ALL.includes(e.effect as Effect) !== (key === 'effects')),
          ...tags.flatMap((d) => d[key]!.map((t) => ({ effect: t, why: `declared in manifest actions."${d.g}"`, via: 'declared' as const }))),
        ],
      };
    }
    if (!a.effects.length && !hits.some((d) => d.effects)) a.unclassified = true;
    return a;
  });
}

function classifyLexicon(actions: Action[], data: GeneratedData): Action[] {
  const lex = [...compile(data.lexicon.effects), ...compile(data.lexicon['data-classes'])];
  const dest = compile(data.lexicon.destinations);
  const scopes = new Map(data.scopes.map((s) => [s.scope, s]));
  const iam = data.iam.map((e) => ({ ...e, re: glob(e.pattern), lower: e.pattern.toLowerCase() }));

  // Context entries (e.g. FHIR Condition -> phi) need the class elsewhere in the batch: one more pass when it is there.
  const first = actions.map((a) => one(a, new Set()));
  const present = new Set(first.flatMap((a) => a.data));
  return lex.some((e) => e.context && present.has(e.context)) ? actions.map((a) => one(a, present)) : first;

  function one(a0: Action, ctx: Set<DataClass>): Action {
    const a: Action = { ...a0, effects: [], data: [], evidence: [] };
    const add = (tag: Effect | DataClass, why: string, via: Evidence['via']) => {
      const list = ALL.includes(tag as Effect) ? (a.effects as string[]) : (a.data as string[]);
      if (!list.includes(tag)) list.push(tag);
      if (!a.evidence.some((e) => e.effect === tag && e.why === why)) a.evidence.push({ effect: tag, why, via });
    };
    // One catalogue evidence entry per effect or data class: the first entry that grants it.
    const fromCatalog = (label: string, effects: Effect[], d: DataClass[] = []) => {
      for (const t of [...effects, ...d]) if (!a.evidence.some((e) => e.effect === t && e.via === 'catalog')) add(t, `catalogue: ${label}`, 'catalog');
    };

    if (a.kind === 'scope') {
      const s = scopes.get(a.name) ?? scopes.get(a.name.replace(/^https:\/\/graph\.microsoft\.com\//, ''));
      if (s) {
        a.label = s.label;
        if (s.broad) a.broad = true;
        fromCatalog(s.label, s.effects, s.data);
      }
      return a;
    }
    if (a.kind === 'iam' && a.notAction) {
      // Everything except the listed patterns: every catalogue entry they do not cover (`*` itself left out).
      const not = a.notAction.map(glob);
      a.label = `Every action except ${a.notAction.join(', ')}`;
      for (const e of iam) if (e.pattern !== '*' && !not.some((n) => n.test(e.pattern))) fromCatalog(`not excluded by NotAction, e.g. ${e.label}`, e.effects, e.data);
      return a;
    }
    if (a.kind === 'iam') {
      const name = a.name.toLowerCase();
      const pre = glob(a.name);
      const svc = name.includes(':') ? name.split(':')[0] : undefined;
      for (const e of iam) {
        // Policy action covers the entry (a generic `*:Verb*` entry is read in the policy's service, so `ec2:*` covers
        // `*:Delete*`), or a service-prefixed entry covers the policy action.
        const covered = pre.test(e.pattern) || (svc !== undefined && e.pattern.startsWith('*:') && pre.test(`${svc}:${e.pattern.slice(2)}`));
        if (e.lower === name || covered || (e.pattern.includes(':') && e.re.test(a.name))) {
          if (e.lower === name) a.label = e.label;
          fromCatalog(e.label, e.effects, e.data);
        }
      }
      return a;
    }
    // mcp-server effects come from mcp-audit's mixes (spec decision 3, checks/mcp.ts), set before classify.
    if (a.kind === 'mcp-server') return { ...a0 };

    if (a.kind === 'tool' && a.label === a.name) a.label = humanise(a.name);
    // Endpoints: method, operationId and path (file extensions dropped) together, e.g. "post create user rest api 3 user".
    const path = a.name.replace(/^\S+\s/, '').replace(/\.(json|xml|ya?ml)(?=\/|$)/gi, '');
    const name = a.kind === 'endpoint' ? words(`${a.method ?? ''} ${a.operationId ?? ''} ${path}`.slice(0, MAX_NAME)) : words(a.name.slice(0, MAX_NAME));
    // Verb x noun phrases: the tool name; for endpoints the operationId and the path without {params} and $ref.
    const segs = path.split('/').filter((x) => x && !/^[{$]/.test(x)).map(words).filter(Boolean);
    const phrases = (a.kind === 'endpoint' ? [words(a.operationId ?? ''), segs.join(' ')].filter(Boolean) : [name]).map((t) => t.slice(0, MAX_PHRASE));
    // ponytail: only the first 10k chars of a description are read; real descriptions are far shorter.
    const desc = a.description ? words(a.description.slice(0, 10_000)) : '';
    const leaves = a.params.map((p) => ({ p, w: words(p.name.split('.').at(-1)!) }));

    if (a.method && METHOD[a.method]) add(METHOD[a.method]!, `HTTP ${a.method}`, 'method');
    for (const e of lex) {
      if (!e.tag || (e.context && !ctx.has(e.context))) continue;
      const tag = e.tag as Effect | DataClass;
      const also = e.context ? ` (with ${e.context} elsewhere in this agent)` : '';
      // not_patterns cancel name and description hits only; a param name is strong evidence on its own.
      if (!e.not?.test(name)) {
        const n = e.name?.exec(name);
        if (n) add(tag, `name contains "${n[0]}"${also}`, 'name');
        if (e.verb && e.noun) {
          const vn = phrases.map((t) => verbNoun(t, spans(e.verb!, t), spans(e.noun!, t))).find(Boolean);
          if (vn) add(tag, `name contains "${vn[0]}" + "${vn[1]}"${also}`, 'name');
          else if (a.kind === 'endpoint' && a.method && e.methods.includes(a.method as never)) {
            // The method is the verb; the noun is the last resource segment (a trailing action segment is skipped).
            const res = segs.length > 1 && e.verbFirst!.test(segs.at(-1)!) ? segs.at(-2) : segs.at(-1);
            if (res && e.nounWhole!.test(res)) add(tag, `HTTP ${a.method} on "${res}"${also}`, 'method');
          }
        }
        const d = desc && !e.not?.test(desc) ? e.desc?.exec(desc) : null;
        if (d) add(tag, `description mentions "${d[0]}"`, 'description');
      }
      for (const { p, w } of leaves) if (e.param?.test(w)) add(tag, `param "${p.name}"`, 'param');
    }

    const hints = a.annotations ?? {};
    // Hints are self-declared by the server: they add effects, never remove them (ruling R4).
    if (hints.readOnlyHint) {
      for (const x of a.evidence.filter((v) => v.effect !== 'read' && v.effect !== 'bulk' && ALL.includes(v.effect as Effect)))
        add(x.effect, `MCP readOnlyHint claims read-only, but ${x.why}`, 'annotation');
      add('read', 'MCP readOnlyHint', 'annotation');
    }
    if (hints.destructiveHint) add('delete', 'MCP destructiveHint', 'annotation');
    if (hints.openWorldHint) {
      const to = leaves.find(({ w }) => dest.some((e) => e.param?.test(w)));
      if (to) add('external-send', `MCP openWorldHint with destination param "${to.p.name}"`, 'annotation');
    }
    return a;
  }
}

/** Spec decision 6: manifest `domain`, else a lexicon match on `purpose`. Action names never set the domain. */
export function detectDomain(manifest?: Manifest, data: GeneratedData = DEFAULT): Domain | undefined {
  if (!manifest) return undefined;
  if (manifest.agent.domain) return manifest.agent.domain;
  const purpose = words(manifest.agent.purpose ?? '');
  return purpose ? (compile(data.lexicon.domains).find((e) => e.name?.test(purpose))?.tag as Domain | undefined) : undefined;
}
