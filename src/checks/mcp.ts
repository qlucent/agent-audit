import { audit as mcpAudit, normalize, parseFile, type Cap } from '@qlucent/mcp-audit';
import type { Action, Effect, Finding } from '../types.ts';

/** Spec decision 3: mcp-audit's findings, passed through under `mcp/<id>` with their own helpUri. */
export const mcpFindings = (files: { name: string; text: string }[]): Finding[] =>
  files.flatMap((f) => mcpAudit([f]).findings.map((x) => ({ ...x, ruleId: `mcp/${x.ruleId}` })));

const CAP: Partial<Record<Cap, Effect | 'pii'>> = { outbound: 'external-send', code_exec: 'code-exec', writes: 'write', private_data: 'pii' };
// Two copies of a catalogued untrusted-input + outbound server: with them in the config every catalogued server shows
// up in mcp-audit's mixes, so a lone server still gets its caps.
const PROBE = { command: 'uvx', args: ['mcp-server-fetch'] };

/** Effects of `mcp-server` actions from mcp-audit's `mixes[].nodes[].caps`; servers with none are left unclassified. */
export function mcpEffects(actions: Action[], files: { name: string; text: string }[]): Action[] {
  const caps = new Map<string, { label: string; caps: Cap[] }>();
  for (const f of files) {
    const servers = normalize([parseFile(f)]).servers;
    const mcpServers = Object.fromEntries(servers.map((s, i) => [`s${i}`, s.url ? { type: s.transport === 'sse' ? 'sse' : 'http', url: s.url } : { command: s.command, args: s.args }]));
    const probe = { name: '.mcp.json', text: JSON.stringify({ mcpServers: { ...mcpServers, probe_a: PROBE, probe_b: PROBE } }) };
    for (const n of mcpAudit([probe]).mixes.flatMap((m) => m.nodes)) {
      const s = servers[Number(n.server.slice(1))];
      if (n.server.startsWith('s') && s) caps.set(`${f.name}\0${s.loc.offset}`, n);
    }
  }
  return actions.map((a) => {
    if (a.kind !== 'mcp-server') return a;
    const n = caps.get(`${a.file}\0${a.loc.offset}`);
    if (!n) return a;
    const tags = [...new Set(n.caps.map((c) => CAP[c]).filter((t) => t !== undefined))];
    return {
      ...a, label: n.label,
      effects: tags.filter((t) => t !== 'pii') as Effect[],
      data: tags.includes('pii') ? ['pii'] : [],
      evidence: tags.map((t) => ({ effect: t, why: `mcp-audit catalogue: ${n.label} (${n.caps.filter((c) => CAP[c] === t).join(', ')})`, via: 'catalog' as const })),
    };
  });
}
