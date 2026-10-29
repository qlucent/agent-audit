import type { AuditResult, Severity } from '../types.ts';

const level: Record<Severity, string> = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };

/** SARIF wants a URI: `file:///C:/…` for a Windows absolute path, else the path with `/` separators, percent-encoded. */
export const uri = (file: string): string => {
  const p = encodeURI(file.replaceAll('\\', '/')).replace(/[?#]/g, encodeURIComponent);
  return /^[A-Za-z]:\//.test(p) ? `file:///${p}` : p;
};

/** SARIF 2.1.0. The action name(s) of a finding go in its `properties` (`action` / `actions`). */
export function toSarif(result: AuditResult, toolVersion?: string): object {
  const ids = [...new Set(result.findings.map((f) => f.ruleId))];
  const rules = ids.map((id) => {
    const f = result.findings.find((x) => x.ruleId === id)!;
    return {
      id,
      name: id,
      shortDescription: { text: f.title },
      fullDescription: { text: f.why },
      help: { text: f.fix },
      helpUri: f.helpUri,
      defaultConfiguration: { level: level[f.severity] },
    };
  });
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'qlucent-agent-audit', ...(toolVersion && { version: toolVersion }),
          informationUri: 'https://qlucent.com/tools/agent-audit', rules,
        },
      },
      results: result.findings.map((f) => {
        const hit = f.excerpt.find((l) => l.hit);
        const props = f.server ? { action: f.server } : f.servers?.length ? { actions: f.servers } : undefined;
        return {
          ruleId: f.ruleId,
          ruleIndex: ids.indexOf(f.ruleId),
          level: level[f.severity],
          message: { text: f.detail ? `${f.title}: ${f.detail}` : f.title },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: uri(f.file) },
              region: { startLine: f.line, startColumn: f.column, ...(hit ? { snippet: { text: hit.text } } : {}) },
            },
          }],
          ...(props && { properties: props }),
        };
      }),
    }],
  };
}
