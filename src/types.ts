import type { Finding, Severity, Verdict, Loc } from '@qlucent/mcp-audit';

export type { Finding, Severity, Verdict, Loc };

export type Effect = 'read' | 'write' | 'delete' | 'money' | 'external-send' | 'identity-admin' | 'code-exec' | 'bulk';
export type DataClass = 'pii' | 'phi' | 'financial-data' | 'credentials';
export type Format =
  | 'manifest'
  | 'aws-iam'
  | 'openapi'
  | 'mcp-config'
  | 'mcp-tools'
  | 'anthropic-tools'
  | 'openai-tools'
  | 'oauth-scopes';
export type Domain = 'fintech' | 'healthcare' | 'helpdesk' | 'hr' | 'finance-ops' | 'ecommerce' | 'devops' | 'it-admin' | 'general';

export interface Param { name: string; type?: string; maximum?: number; loc?: Loc }

export interface Action {
  id: string;
  name: string;
  label: string;
  kind: 'tool' | 'endpoint' | 'mcp-server' | 'scope' | 'iam';
  file: string;
  loc: Loc;
  params: Param[];
  description?: string;
  annotations?: Record<string, boolean>;
  method?: string;
  effects: Effect[];
  data: DataClass[];
  evidence: { effect: Effect | DataClass; why: string }[];
  /** Index of the earlier action with the same name in another file. */
  duplicateOf?: number;
}

export interface Manifest {
  agent: { name: string; purpose?: string; domain?: Domain; acts_for?: string[] };
  roles?: Record<string, { allow: string[] }>;
  approvals?: string[];
  limits?: Record<string, { max_amount?: number; currency?: string; per_day?: number }>;
  out_of_scope?: string[];
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  check: string;
  why: string;
  fix: string;
  references: string[];
}

export interface Hit {
  file: string; loc: Loc; action?: string; actions?: string[];
  field?: string; value?: string; detail?: string; severity?: Severity;
}

export interface FileSummary {
  file: string; format: Format | null; actions: number;
  error?: { message: string; line: number; column: number }; unrecognised?: true;
}

export interface AuditResult {
  files: FileSummary[];
  actions: Action[];
  manifest?: Manifest;
  findings: Finding[];
  verdict: Verdict;
  /** Scope matrix model; shape is defined with the matrix task. */
  matrix: unknown;
  rulesChecked: number;
}
