import type { Check } from '../types.ts';

/** No manifest: one note so the builder knows the scope check did not run. */
export const noManifest: Check = (ctx) => {
  const a = ctx.actions[0];
  if (ctx.manifest || !a) return [];
  const bad = ctx.files.find((f) => f.format === 'manifest' && f.error);
  if (bad) return [{
    file: bad.file, loc: { line: bad.error!.line, column: bad.error!.column, offset: 0, length: 0 },
    detail: `The agent manifest ${bad.file} is invalid (${bad.error!.message}, line ${bad.error!.line}), so roles, approvals and limits were not checked`,
  }];
  return [{ file: a.file, loc: { line: 1, column: 1, offset: 0, length: 0 }, detail: 'No agent manifest was given, so roles, approvals and limits were not checked' }];
};
