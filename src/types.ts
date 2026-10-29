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
  /** OpenAPI operationId. */
  operationId?: string;
  /** OAuth scopes an OpenAPI operation requires. */
  scopes?: string[];
  /** IAM statement Resource (normalised to a list) and Condition. */
  resource?: string[];
  condition?: Record<string, unknown>;
  /** IAM Allow + NotAction: the statement grants every action except these. */
  notAction?: string[];
  effects: Effect[];
  data: DataClass[];
  evidence: Evidence[];
  /** OAuth scope the catalogue marks broad. */
  broad?: true;
  /** Index of the earlier action with the same name in another file. */
  duplicateOf?: number;
  /** Not read-only by method or annotation, no effect found and none declared: listed for review (R7). */
  unclassified?: true;
}

export interface Evidence {
  effect: Effect | DataClass;
  why: string;
  via: 'name' | 'description' | 'param' | 'method' | 'annotation' | 'catalog' | 'declared';
}

/** Lexicon entry (lexicon/*.yaml). Patterns are regex sources, matched case-insensitively on words split from snake/camel/kebab. */
export interface LexEntry {
  effect?: Effect;
  data?: DataClass;
  domain?: Domain;
  /** Word-boundary match on the action name (or manifest purpose, for domains). */
  name_patterns?: string[];
  description_patterns?: string[];
  /** Whole-name match on a parameter's leaf name. */
  param_patterns?: string[];
  /** Composite match: a verb and a noun as separate words, either order, anything between. */
  verbs?: string[];
  nouns?: string[];
  /** For endpoints, these HTTP methods also count as the verb. */
  method_verbs?: ('POST' | 'PUT' | 'PATCH' | 'DELETE')[];
  /** Applies only when another action in the batch already has this data class (e.g. FHIR Condition needs phi). */
  context?: DataClass;
  /** Any match on the name (or description, for description hits) cancels the entry. */
  not_patterns?: string[];
}
export interface ScopeEntry { scope: string; label: string; effects: Effect[]; data?: DataClass[]; broad?: boolean }
export interface IamEntry { pattern: string; label: string; effects: Effect[]; data?: DataClass[] }
export interface GeneratedData {
  rules: unknown[];
  lexicon: Record<string, LexEntry[]>;
  scopes: ScopeEntry[];
  iam: IamEntry[];
  manifestSchema: unknown;
}

export interface Manifest {
  agent: { name: string; purpose?: string; domain?: Domain; acts_for?: string[] };
  roles?: Record<string, { allow: string[] }>;
  approvals?: string[];
  limits?: Record<string, { max_amount?: number; currency?: string; per_day?: number }>;
  out_of_scope?: string[];
  /** Action-name glob -> declared effects/data; these replace the classifier's (R7). */
  actions?: Record<string, { effects?: Effect[]; data?: DataClass[] }>;
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

export interface CheckContext { actions: Action[]; manifest?: Manifest; domain?: Domain; data: GeneratedData; files: FileSummary[] }
export type Check = (ctx: CheckContext, rule: Rule) => Hit[];
export interface Fixture { file?: string; config: unknown; manifest?: unknown }
