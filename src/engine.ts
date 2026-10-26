import { computeVerdict } from '@qlucent/mcp-audit';
import raw from './generated/data.json' with { type: 'json' };
import { parseInputs } from './parse/index.ts';
import { classify, detectDomain } from './classify.ts';
import { checks } from './checks/index.ts';
import type { AuditResult, CheckContext, Finding, Fixture, GeneratedData, Rule, Severity } from './types.ts';

export { applySeverity } from './checks/util.ts';

const data = raw as unknown as GeneratedData;
export const rules = data.rules as (Rule & { fixtures: { fail: Fixture[]; pass: Fixture[] } })[];
const ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

/** Several inputs describe one agent. Excerpts come with the reporters; until then `excerpt` is empty. */
export function audit(inputs: { name: string; text: string }[]): AuditResult {
  const parsed = parseInputs(inputs);
  const { manifest } = parsed;
  const actions = classify(parsed.actions, data, manifest);
  const ctx: CheckContext = { actions, manifest, domain: detectDomain(manifest, data), data };

  const findings: Finding[] = rules.flatMap((rule) =>
    (checks[rule.check]?.(ctx, rule) ?? []).map((h) => ({
      ruleId: rule.id,
      severity: h.severity ?? rule.severity,
      title: rule.title,
      detail: h.detail,
      file: h.file,
      line: h.loc.line,
      column: h.loc.column,
      // Same Finding shape as mcp-audit: its `server`/`servers` carry the action name(s) here.
      server: h.action,
      servers: h.actions,
      field: h.field,
      evidence: h.value,
      excerpt: [],
      why: rule.why,
      fix: rule.fix,
      helpUri: `https://qlucent.com/tools/agent-audit/rules/${rule.id}`,
    })),
  );
  findings.sort((a, b) =>
    ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity) || a.file.localeCompare(b.file) || a.line - b.line);

  const { files } = parsed;
  const why = files.map((f) => !f.error ? `${f.file} isn't recognised as an agent spec`
    : f.actions ? `Only part of ${f.file} could be read (parse error at line ${f.error.line})`
    : `${f.file} couldn't be parsed`).join('; ');
  const recognised = files.some((f) => f.format !== null && !f.error);
  const verdict = computeVerdict(findings, rules.length, recognised, `Couldn't check any input: ${why}`);
  const broken = files.filter((f) => f.error).length;
  if (verdict.level !== 'unrecognised' && broken) verdict.text += ` (${broken} file${broken === 1 ? '' : 's'} couldn't be fully parsed)`;
  return { files, actions, manifest, findings, verdict, matrix: { columns: [], rows: [] }, rulesChecked: rules.length };
}
