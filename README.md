# agent-audit

**Live page: https://qlucent.com/tools/agent-audit?utm_source=github**

Audit what an AI agent is allowed to do before you ship it. Give it the agent's tool definitions, OpenAPI spec, MCP config, OAuth scopes, AWS IAM policy and an optional manifest. They are audited together as one agent. You get a verdict, an inventory of every action in plain words, findings with the exact file and line, and a scope matrix that shows where the agent can do more than the people it acts for.

Everything runs on your machine. No uploads, no network calls, no AI model. Secrets are masked in every output, and free-text fields (descriptions, summaries, titles) and comments are never reproduced, because they are where pasted secrets and injected instructions hide.

> Running agents in production? [Qlucent assesses agent permissions and data boundaries.](https://qlucent.com/#services)

Try a bundled sample from a clone of this repo (the samples also ship in the npm package, under `samples/`):

```sh
npx @qlucent/agent-audit samples/fintech-refund-bot/tools.json samples/fintech-refund-bot/agent.yaml
```

## Supported formats

JSON, JSONC and YAML. The format is detected per file. A file that matches nothing, or matches two formats only partly, is reported as unrecognised and never guessed.

| Format | What it looks like | Yields |
|---|---|---|
| Agent manifest | top-level `agent:` | declared intent (see below) |
| AWS IAM policy | `Version` + `Statement` | one action per Allow action pattern, with resource |
| OpenAPI 3.x | `openapi: 3.*` + `paths` | one action per operation |
| MCP client config | `claude_desktop_config.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, Claude Code `settings.json` | one action per server, plus [mcp-audit](https://github.com/qlucent/mcp-audit) findings as `mcp/*` |
| MCP `tools/list` dump | `{ "tools": [{ "name", "inputSchema" }] }` (also `{ "result": { "tools": [...] } }`) | one action per tool; `readOnlyHint`, `destructiveHint` and `openWorldHint` are read |
| Anthropic tools | `{ "name", "input_schema" }` items | one action per tool |
| OpenAI tools | `{ "type": "function", "function": {...} }` (also the flat Responses API form) | one action per function |
| OAuth scopes | an array of known scope strings, or `{ "scopes": [...] }` | one action per scope |

### Exporting tool schemas

Dump the list you already give the model.

- **OpenAI SDK:** write out the `tools` array you pass to `chat.completions.create` or `responses.create`, for example `json.dump(tools, open("tools.json", "w"), indent=2)`.
- **Anthropic SDK:** the same for the `tools` array you pass to `messages.create`.
- **MCP SDK:** call `tools/list` and save the result, for example `JSON.stringify(await client.listTools(), null, 2)`. The MCP Inspector can show the same list.

## What the audit looks for

| Rule | Fires when | Severity |
|---|---|---|
| `money-no-cap` | a money action has an amount param with no `maximum` and no manifest limit | high; critical in fintech, ecommerce, finance-ops |
| `money-no-approval` | a money action is not in the manifest `approvals` | high; medium with a cap or no manifest |
| `purchase-without-consent` | an action buys, subscribes or charges on the user's behalf | high |
| `unscoped-record-access` | an action takes any patient, customer or account id and nothing ties it to the requester | high; critical for health data |
| `identity-admin-action` | an action resets MFA or passwords, or changes users or roles | high; critical for L1, support or customer-facing agents |
| `destructive-no-approval` | a delete with no approval | medium; high for a bulk delete |
| `external-send-sensitive` | the agent can send data to a free destination and also reads sensitive data | medium; high for health data and credentials |
| `code-exec-action` | shell, eval, raw SQL or deploy | high |
| `bulk-export` | an export or list-all action on sensitive data | medium |
| `broad-oauth-scope` | a scope that covers all of a user's or tenant's data, or admin or send rights | medium; high for send and admin |
| `iam-wildcard` | an IAM Allow with `*` actions or resources, or `iam:PassRole` on `*` | high; critical for `*` on `*` |
| `out-of-scope-action` | an action has an effect the manifest lists in `out_of_scope`, or no role allows it | high |
| `exceeds-role` | the agent can do something a role it acts for cannot | high for money, identity, health data and delete; else medium |
| `unclassified-action` | an action is not read-only and the classifier could not tell what it does | low |
| `no-manifest` | no manifest was given | low |
| `mcp/*` | findings from mcp-audit on MCP configs | as mcp-audit |

Without a manifest the audit cannot see approvals that may exist in your code, so the approval rules fire one level lower and say "no approval step is declared". Severity stays conservative: a false alarm costs more trust than a miss.

## What the classifier can and cannot do

The classifier decides what each action does (read, write, delete, money, external-send, identity-admin, code-exec, bulk) and which data it touches (pii, phi, financial-data, credentials). It uses keyword lists, the HTTP method, MCP annotations and a catalogue of public OAuth scopes and AWS IAM actions. **It is not an AI model.**

- It works from names and parameter names. On action names it has not seen, it misses things: in two independent tests on unseen API names it placed roughly 70 to 80 percent of names it had never seen.
- It errs toward misses rather than false alarms. `refund_policy_lookup` is a read, not money, and `list_password_rules` is not an identity action.
- Known misses: amounts typed as strings (PayPal `amount.value`) get no `money-no-cap`; a bare `{customer}` path param is not treated as a record id; `POST /v1/subscriptions` is a write, not a purchase; `disable_account` is unclassified.
- A server's own `readOnlyHint` never removes an effect the names show. The report notes the contradiction instead.
- **Declare effects in the manifest `actions:` block.** Declared effects replace the classifier's and are labelled "declared" in the report.
- The `unclassified-action` finding is the "review these actions" list: every action that is not read-only and that the classifier could not place. Go through it.

The audit checks what the spec declares, not what your agent's code does. A clean result is not proof of safety.

## Agent manifest

The manifest says what the agent is for, who it acts for, what each of them may do, and what needs a human. It turns the audit from "what can this agent do" into "what can it do that it should not". Put it in a YAML or JSON file with a top-level `agent:` and pass it with the other files. It is validated against [`schemas/manifest.schema.json`](schemas/manifest.schema.json). An invalid manifest is reported with the path and line, and roles, approvals and limits are then not checked.

```yaml
agent:
  name: Support refund bot
  purpose: L1 customer support for a payments app; issues refunds   # free text; also used to detect the domain
  domain: fintech            # optional: fintech | healthcare | helpdesk | hr | finance-ops | ecommerce | devops | it-admin | general
  acts_for: [customer, support-agent]     # the roles the agent acts on behalf of
roles:
  customer:
    allow: ["read:own", "*refund*:<=50"]
  support-agent:
    allow: ["read", "*refund*:<=200", "send_email"]
approvals: [issue_refund, delete_*]       # action-name globs that need a human approval step
limits:
  issue_refund: { max_amount: 200, currency: USD, per_day: 20 }   # max_amount counts as the cap
out_of_scope: [identity-admin, delete]    # effects this agent must never have
actions:                                  # declare what an action does when the classifier cannot tell
  frobnicate_widget: { effects: [write] }
  lookup_member: { data: [pii] }
```

| Field | Meaning |
|---|---|
| `agent.name` | required |
| `agent.purpose` | free text. L1, support or helpdesk wording raises identity findings. It is never printed back. |
| `agent.domain` | sets the domain directly. Otherwise it is detected from `purpose` only, never from action names. A domain raises some severities by one step. |
| `agent.acts_for` | roles the agent acts for. They become the matrix columns. `agent` is a reserved name. |
| `roles.<role>.allow` | what that role may do (grammar below). A role in `acts_for` with no entry is allowed nothing. |
| `approvals` | action-name globs (`*` and `?`, case-insensitive) that need a human approval step. Matched against the action name or operationId. |
| `limits.<glob>` | `max_amount`, `currency`, `per_day`. The lowest matching `max_amount`, and the schema `maximum`, give the action's cap. |
| `out_of_scope` | effects (`read`, `write`, `delete`, `money`, `external-send`, `identity-admin`, `code-exec`, `bulk`) or data classes the agent must never have. |
| `actions.<glob>` | `effects:` and/or `data:` lists (data classes are `pii`, `phi`, `financial-data`, `credentials`). They replace the classifier's for matching actions. |

### The allow grammar

An entry is `<target>[:<qualifier>]`: no spaces, at most one `:`.

**Target** is either:
- an **effect name**: `read`, `write`, `delete`, `money`, `external-send`, `identity-admin`, `code-exec` or `bulk`. It grants an action with that effect, but only if every high-risk effect the action has is that one. High-risk means money, identity-admin, code-exec, delete and external-send. So `write` never grants a refund, and `money` does not grant an action that also sends email.
- a **glob over the full action name or operationId** (`*` and `?`, case-insensitive), such as `*refund*`, `delete_*` or `send_email`. It grants the whole action, whatever its effects. A bare word is not matched inside a name: write `*refund*`, not `refund`.

**Qualifier** narrows the entry. With none, the target alone grants.
- `<=N`: the action must have a cap and it must be at most N. An uncapped action fails.
- `own`: you declare the action is limited to the signed-in requester. The audit cannot verify that. If the action takes a free record id such as `patient_id`, the matrix shows `declared`, and `unscoped-record-access` stays as a low finding reminding you to bind the id to the signed-in user on the server.
- `own-<glob>`: the same, only for actions with a matching word in the name, such as `own-orders`.
- `<glob>`: only actions with a matching word in the name, such as `read:orders`. `-s` and `-es` plurals match.

| Entry | Grants |
|---|---|
| `read` | actions that only read |
| `read:orders` | read actions with an "order" word in the name |
| `read:own` | reads, declared own-only |
| `*refund*:<=50` | refund actions capped at 50 or lower |
| `money:<=50` | money actions capped at 50 or lower, unless they also send, delete, run code or change identities |
| `send_email` | exactly `send_email` |
| `delete_*` | every action named `delete_...` |

Roles in `acts_for` are default deny. See [`samples/`](samples) for four complete examples.

## CLI

```sh
npx @qlucent/agent-audit <files...> [--format table|md|sarif] [--output <file>] [--fail-on <level>]
```

| Flag | Meaning |
|---|---|
| `--format` | `table` (default; findings only), `md` (Markdown with inventory and matrix) or `sarif` (SARIF 2.1.0) |
| `--output <file>` | write the report to a file instead of stdout |
| `--fail-on <level>` | `critical`, `high` (default), `medium`, `low` or `none` |
| `--help`, `--version` | |

There is no auto-discovery: name every file. Exit codes: `0` nothing at or above `--fail-on`; `1` a finding at or above it; `2` usage error, no readable files, a parse error in any file, or nothing auditable. These match mcp-audit.

### GitHub Actions

```yaml
name: agent-audit
on: [pull_request]
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-node@v5
        with:
          node-version: 24
      - run: npx @qlucent/agent-audit@0.1.0 agent/tools.json agent/openapi.yaml agent/agent.yaml --fail-on high
      # For code scanning, add --format sarif --output agent-audit.sarif
      # and upload it with github/codeql-action/upload-sarif.
```

## Library

```ts
import { audit, toMarkdown, toSarif } from '@qlucent/agent-audit';
import fs from 'node:fs';

const result = audit([
  { name: 'tools.json', text: fs.readFileSync('tools.json', 'utf8') },
  { name: 'agent.yaml', text: fs.readFileSync('agent.yaml', 'utf8') },
]);
console.log(result.verdict.text, result.findings.length);
fs.writeFileSync('report.md', toMarkdown(result));
```

`audit(inputs)` returns `{ files, actions, manifest, findings, verdict, matrix, rulesChecked }`. `toTable`, `toMarkdown` and `toSarif` render it. The library makes no network calls.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report a wrong classification or a false positive with the [issue templates](https://github.com/qlucent/agent-audit/issues/new/choose).

## Licence

Apache-2.0. See [LICENSE](LICENSE).
