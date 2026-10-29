import type { Action, Format, Manifest } from '../types.ts';
import type { Tree } from '../secrets.ts';
import { parseText, type Doc, type ParseError } from './json.ts';
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
  /** The parsed tree, for redaction. */
  tree?: Tree;
}

/** Spec decision 8: the first full match wins; a partial or unknown shape is unrecognised (format null, no error). */
export function detect(input: { name: string; text: string }): Detected {
  try {
    return run(input);
  } catch {
    // e.g. RangeError from very deep nesting: this file fails, the rest of the batch still parses.
    return { format: null, actions: [], error: { message: 'Could not parse (nesting too deep?)', line: 1, column: 1 } };
  }
}

function run(input: { name: string; text: string }): Detected {
  const { doc, error } = parseText(input.name, input.text);
  if (!doc) return { format: null, actions: [], ...(error && { error }) };
  return { ...match(input, doc), tree: doc.tree };
}

function match(input: { name: string; text: string }, doc: Doc): Detected {
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
  // An MCP config with no servers (e.g. matched only by filename) yields to a later format that matches.
  let emptyMcp: Detected | undefined;
  for (const [format, parse] of order) {
    const actions = parse();
    if (format === 'mcp-config' && actions?.length === 0) emptyMcp = { format, actions };
    else if (actions) return { format, actions };
  }
  return emptyMcp ?? { format: null, actions: [] };
}
