import { glob, words } from '../classify.ts';
import type { Action, CheckContext, LexEntry, Param, Severity } from '../types.ts';

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

/** Spec decision 6: at most one step up and one step down from the base; both together cancel. */
export function applySeverity(base: Severity, up: boolean, down: boolean): Severity {
  const i = ORDER.indexOf(base) - (up ? 1 : 0) + (down ? 1 : 0);
  return ORDER[Math.min(ORDER.length - 1, Math.max(0, i))]!;
}

const re = (ps: string[], wrap: (p: string) => string) => (ps.length ? new RegExp(ps.map(wrap).join('|'), 'i') : undefined);

/** Name-pattern lexicon (word boundary, minus not_patterns) over the words of `text`. */
export function nameMatcher(entries: LexEntry[] = []) {
  const c = entries.map((e) => ({ name: re(e.name_patterns ?? [], (p) => `\\b(?:${p})\\b`), not: re(e.not_patterns ?? [], (p) => `\\b(?:${p})\\b`) }));
  return (text: string) => {
    const t = words(text.slice(0, 2048));
    return c.some((e) => e.name?.test(t) && !e.not?.test(t));
  };
}

/** Param-pattern lexicon: whole match on a param's leaf name. */
export function paramMatcher(entries: LexEntry[] = []) {
  const r = re(entries.flatMap((e) => e.param_patterns ?? []), (p) => `^(?:${p})$`);
  return (p: Param) => !!r?.test(words(p.name.split('.').at(-1)!.slice(0, 256)));
}

/** The name, plus the operationId for endpoints. */
export const actionText = (a: Action) => (a.operationId ? `${a.name} ${a.operationId}` : a.name);

const globHit = (globs: string[] | undefined, a: Action) =>
  (globs ?? []).some((g) => glob(g).test(a.name) || (a.operationId !== undefined && glob(g).test(a.operationId)));

/** Matched by a manifest `approvals` glob. */
export const approved = (ctx: CheckContext, a: Action) => globHit(ctx.manifest?.approvals, a);

/** Lowest `limits.<glob>.max_amount` that applies to the action. */
export function limitFor(ctx: CheckContext, a: Action): number | undefined {
  const caps = Object.entries(ctx.manifest?.limits ?? {})
    .filter(([g, l]) => typeof l.max_amount === 'number' && globHit([g], a))
    .map(([, l]) => l.max_amount!);
  return caps.length ? Math.min(...caps) : undefined;
}

/** R10: approvals belong to the calls an agent makes, not to the scopes or IAM grants behind them. */
export const approvable = (a: Action) => a.kind !== 'scope' && a.kind !== 'iam';

export const has = (a: Action, x: string) => (a.effects as string[]).includes(x) || (a.data as string[]).includes(x);
