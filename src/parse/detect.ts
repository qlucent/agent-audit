import type { Action, Format, Manifest } from '../types.ts';
import { parseText, type ParseError } from './json.ts';
import * as manifest from './manifest.ts';
import * as iam from './iam.ts';
import * as openapi from './openapi.ts';
import * as mcpConfig from './mcp-config.ts';
import * as mcpTools from './mcp-tools.ts';
import * as anthropic from './anthropic.ts';
import * as openai from './openai.ts';
import * as oauth from './oauth.ts';

export interface Detected {
  format: Format | null;
  actions: Action[];
  manifest?: Manifest;
  error?: ParseError;
}

/** Spec decision 8: the first full match wins; a partial or unknown shape is unrecognised (format null, no error). */
export function detect(input: { name: string; text: string }): Detected {
  const { doc, error } = parseText(input.name, input.text);
  if (!doc) return { format: null, actions: [], ...(error && { error }) };
  const m = manifest.parse(doc);
  if (m) return { format: 'manifest', actions: [], ...m };
  const order: [Format, () => Action[] | null][] = [
    ['aws-iam', () => iam.parse(doc, input.name)],
    ['openapi', () => openapi.parse(doc, input.name)],
    ['mcp-config', () => (doc.json ? mcpConfig.parse(input) : null)],
    ['mcp-tools', () => mcpTools.parse(doc, input.name)],
    ['anthropic-tools', () => anthropic.parse(doc, input.name)],
    ['openai-tools', () => openai.parse(doc, input.name)],
    ['oauth-scopes', () => oauth.parse(doc, input.name)],
  ];
  for (const [format, run] of order) {
    const actions = run();
    if (actions) return { format, actions };
  }
  return { format: null, actions: [] };
}
