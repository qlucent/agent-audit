import type { Action } from '../types.ts';
import { action, isObj, type Doc } from './json.ts';

// Known scope shapes (public docs): Google, Microsoft Graph, Slack/GitHub `a:b`, OIDC and bare GitHub scopes.
const FORMS = [
  /^https:\/\/www\.googleapis\.com\/auth\/[\w.\-/]+$/,
  /^(https:\/\/graph\.microsoft\.com\/)?[A-Z][A-Za-z]*(\.[A-Z][A-Za-z]*)+$/,
  /^[a-z]+(\.[a-z]+)*:[a-z_]+(\.[a-z_]+)*$/,
  /^(openid|email|profile|offline_access|repo|public_repo|gist|notifications|user|workflow|delete_repo|project|codespace|security_events)$/,
];

/** A list of strings (or `{scopes:[…]}`) where every entry is a known scope form. */
export function parse(doc: Doc, file: string): Action[] | null {
  const v = doc.value;
  const items = isObj(v) ? v.scopes : v;
  if (!Array.isArray(items) || !items.length) return null;
  if (!items.every((s) => typeof s === 'string' && FORMS.some((re) => re.test(s)))) return null;
  const base = isObj(v) ? ['scopes'] : [];
  return items.map((s: string, i) => action(file, doc.loc([...base, i]), { name: s, kind: 'scope' }));
}
