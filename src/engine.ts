import { computeVerdict } from '@qlucent/mcp-audit';
import raw from './generated/data.json' with { type: 'json' };
import { parseInputs } from './parse/index.ts';
import { classify, detectDomain } from './classify.ts';
import { checks } from './checks/index.ts';
import { mcpEffects, mcpFindings } from './checks/mcp.ts';
import { buildMatrix } from './scope.ts';
import { excerpt } from './excerpt.ts';
import { maskUnderSecretKeys, redactFile, redactFree, scrubber, scrubDeep } from './secrets.ts';
import { humanise } from './parse/json.ts';
import type { AuditResult, CheckContext, FileSummary, Finding, Fixture, GeneratedData, Hit, Rule, Severity, Verdict } from './types.ts';

export { applySeverity } from './checks/util.ts';

const data = raw as unknown as GeneratedData;
export const rules = data.rules as (Rule & { fixtures: { fail: Fixture[]; pass: Fixture[] } })[];
const ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

/** Several inputs describe one agent. Every secret-looking value in the result is masked (Review Focus 4). */
export function audit(inputs: { name: string; text: string }[]): AuditResult {
  const parsed = parseInputs(inputs);
  const { manifest } = parsed;
  const actions = classify(mcpEffects(parsed.actions, parsed.mcpFiles), data, manifest);
  const ctx: CheckContext = { actions, manifest, domain: detectDomain(manifest, data), data, files: parsed.files };

  // Decision 5 lists an action defined in two files twice; its findings show once unless the copies differ.
  const dup = (h: Hit) => actions.find((a) => a.file === h.file && a.name === h.action)?.duplicateOf !== undefined;
  const findings: Finding[] = rules.flatMap((rule) => {
    const hits = checks[rule.check]?.(ctx, rule) ?? [];
    const firsts = new Set(hits.filter((h) => h.action && !dup(h)).map((h) => `${h.action}|${h.severity ?? rule.severity}`));
    return hits.filter((h) => !(h.action && dup(h) && firsts.has(`${h.action}|${h.severity ?? rule.severity}`))).map((h) => ({
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
      excerpt: [] as Finding['excerpt'],
      why: rule.why,
      fix: rule.fix,
      helpUri: `https://qlucent.com/tools/agent-audit/rules/${rule.id}`,
    }));
  });
  findings.push(...mcpFindings(parsed.mcpFiles));
  findings.sort((a, b) =>
    ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity) || a.file.localeCompare(b.file) || a.line - b.line);

  const { files } = parsed;
  // Excerpts are the redacted source lines. None for a file that failed to parse (masking can't be trusted where the
  // structure is unknown) or for an MCP config: mcp-audit's own findings carry its stricter-masked excerpts there.
  const redacted = new Map(inputs.map((i, n) => [i.name, redactFile(i.name, i.text, parsed.trees[n])]));
  const lines = new Map<string, string[]>();
  const noExcerpt = new Set(files.filter((f) => f.error || f.format === 'mcp-config').map((f) => f.file));
  for (const f of findings) {
    if (f.ruleId.startsWith('mcp/') || noExcerpt.has(f.file) || !redacted.has(f.file)) continue;
    if (!lines.has(f.file)) lines.set(f.file, redacted.get(f.file)!.text.split('\n'));
    f.excerpt = excerpt(lines.get(f.file)!, f.line, f.column);
  }
  const verdict = verdictFor(findings, files);
  const shown = actions.map((a) => {
    const id = a.operationId ?? a.name;
    // A label built from a name holding a token (lowercased, split) would slip past the final pass: rebuild it (N6).
    const label = redactFree(id) !== id ? humanise(redactFree(id)) : a.label;
    return { ...a, label, ...(a.condition && { condition: maskUnderSecretKeys(a.condition) }) };
  });
  const result = { files, actions: shown, manifest, findings, verdict, matrix: buildMatrix(shown, manifest), rulesChecked: rules.length };
  return scrubDeep(result, scrubber([...redacted.values()].flatMap((r) => r.raws)));
}

/** mcp-audit's verdict wording. Only files that yield actions count as checked: a manifest alone audits nothing. */
export function verdictFor(findings: Finding[], files: FileSummary[]): Verdict {
  const why = files.map((f) => f.format === 'manifest' && !f.error
    ? `${f.file} is a manifest; add the agent's tool definitions, OpenAPI, scopes or IAM policy`
    : !f.error ? `${f.file} isn't recognised as an agent spec`
    : f.actions ? `Only part of ${f.file} could be read (parse error at line ${f.error.line}); none of the ${rules.length} rules matched the part that was read`
    : `${f.file} couldn't be parsed`).join('; ');
  const partly = files.some((f) => f.error && f.actions);
  const recognised = files.some((f) => f.format !== null && f.format !== 'manifest' && !f.error);
  const verdict = computeVerdict(findings, rules.length, recognised, partly ? why : `Couldn't check any input: ${why}`);
  const broken = files.filter((f) => f.error).length;
  if (verdict.level !== 'unrecognised' && broken) verdict.text += ` (${broken} file${broken === 1 ? '' : 's'} couldn't be fully parsed)`;
  return verdict;
}
