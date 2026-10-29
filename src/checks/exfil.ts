import type { Action, Check, DataClass } from '../types.ts';
import { applySeverity, paramMatcher } from './util.ts';

const SENSITIVE: DataClass[] = ['pii', 'phi', 'financial-data', 'credentials'];

/**
 * Spec decision 2: an external send with a free destination (destination param, MCP openWorldHint, or a catalogued
 * or declared send) plus an action with strong evidence of sensitive data (param, explicit description, declared).
 * One finding per agent.
 */
export const externalSendSensitive: Check = (ctx, rule) => {
  const isDest = paramMatcher(ctx.data.lexicon.destinations);
  const strong = (a: Action) => SENSITIVE.filter((c) => a.evidence.some((e) => e.effect === c && ['param', 'description', 'declared'].includes(e.via)));
  const sends = ctx.actions.filter((a) => a.effects.includes('external-send') && (a.params.some(isDest) ||
    a.evidence.some((e) => e.effect === 'external-send' && ['annotation', 'catalog', 'declared'].includes(e.via))));
  const reads = ctx.actions.filter((a) => strong(a).length);
  if (!sends.length || !reads.length) return [];
  const cls = [...new Set(reads.flatMap(strong))];
  const up = cls.includes('phi') || cls.includes('credentials') || ctx.domain === 'healthcare' || ctx.domain === 'fintech';
  const s = sends[0]!;
  return [{
    file: s.file, loc: s.loc, action: s.name,
    actions: [...new Set([...sends, ...reads].map((a) => a.name))],
    severity: applySeverity(rule.severity, up, false),
    detail: `${sends.map((a) => a.name).join(', ')} can send data out and ${reads.map((a) => a.name).join(', ')} reads ${cls.join(', ')}`,
  }];
};
