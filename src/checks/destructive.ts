import type { Check, Hit } from '../types.ts';
import { applySeverity, approved } from './util.ts';

/** delete effect (MCP destructiveHint included, via classify) without an approval. High if bulk, one lower without a manifest. */
export const destructiveNoApproval: Check = (ctx, rule) =>
  ctx.actions.filter((a) => a.effects.includes('delete') && !approved(ctx, a)).map((a) => ({
    file: a.file, loc: a.loc, action: a.name,
    severity: applySeverity(rule.severity, a.effects.includes('bulk'), !ctx.manifest),
    detail: `${a.name} deletes${a.effects.includes('bulk') ? ' in bulk' : ''} and ${ctx.manifest ? 'is not listed in approvals' : 'no approval step is declared'}`,
  }));

/** R7: actions with no recognised effect, one finding per file. */
export const unclassifiedAction: Check = (ctx) => {
  const byFile = new Map<string, Hit>();
  for (const a of ctx.actions.filter((x) => x.unclassified)) {
    const h = byFile.get(a.file);
    if (h) h.actions!.push(a.name);
    else byFile.set(a.file, { file: a.file, loc: a.loc, actions: [a.name] });
  }
  return [...byFile.values()].map((h) => ({
    ...h, detail: `${h.actions!.length} action${h.actions!.length === 1 ? '' : 's'} with no recognised effect: ${h.actions!.join(', ')}`,
  }));
};
