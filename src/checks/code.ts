import type { Check } from '../types.ts';
import { reportedElsewhere } from './iam.ts';

/** code-exec effect: shell, eval, raw SQL, deploy. Schema evidence, so no-manifest does not lower it. */
export const codeExecAction: Check = (ctx) =>
  ctx.actions.filter((a) => a.effects.includes('code-exec') && !reportedElsewhere(a)).map((a) => ({
    file: a.file, loc: a.loc, action: a.name,
    detail: `${a.name} can run code or commands (${a.evidence.find((e) => e.effect === 'code-exec')?.why ?? 'code-exec'})`,
  }));
