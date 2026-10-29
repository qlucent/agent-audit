# Contributing

Thanks for helping. Before you open a PR:

1. `npm run typecheck && npm run build && npm test` must pass (Node >= 22.23.4).
2. The library and CLI must not make network requests.
3. Keep dependencies minimal and pinned to exact versions. Say why you need any new dependency in the PR.
4. Use conventional commit messages (`feat:`, `fix:`, `docs:` and so on).
5. Use public knowledge only. Never add material from a private or employer environment.
6. Fixtures use obviously fake values (`ghp_EXAMPLE...`, `AKIAEXAMPLE...`).

Severity stays conservative. A false positive costs more than a miss.

## Adding a rule

Add `rules/<id>.yaml`. `schemas/rule.schema.json` checks it and `npm run data` compiles it. Fields: `id` (matches the file name), `title`, `severity` (`critical`, `high`, `medium`, `low`), `applies_to`, `why`, `fix`, `references` (public `http(s)` URLs), `fixtures`, and exactly one of `match` or `check`.

Rules here use `check`: write the function in `src/checks/`, register it in `src/checks/index.ts`, and add its name to `KNOWN_CHECKS` in `src/checks/names.ts`. Use `applySeverity` (in `src/checks/util.ts`) for domain bumps and no-manifest step-downs: at most one step each way, and they cancel.

**Fixtures** are required: at least one under `fixtures.fail` (the rule must fire) and one under `fixtures.pass` (it must not). A fixture is `{ config, manifest? }`: `config` is the parsed spec and `manifest` is an optional manifest object, passed as a second file. Cover the with-manifest and no-manifest cases where they differ. `npm test` runs every fixture.

## Lexicon entries

Classification is data in `lexicon/*.yaml` (format: `schemas/lexicon.schema.json`). Names are split into lowercase words first (`issueRefund`, `issue_refund` and `issue-refund` all become `issue refund`). Patterns are word-boundary and case-insensitive.

- Use `verbs` + `nouns` entries where you can. A noun fires only when it is the verb's object.
- Add `not_patterns` for look-alikes (`refund_policy_lookup` is not money).
- Keep patterns tight and linear (no repeated groups). A test times every pattern on a 10k-character input.
- Add cases to `test/fixtures/classify-corpus.json`: names that must get an effect and names that must not. The corpus gate requires zero false positives for money, identity-admin, code-exec and health data.

## Scope and IAM catalogue entries

`catalog/scopes.yaml` (OAuth scopes) and `catalog/aws-iam.yaml` (AWS IAM actions) map public identifiers to effects and data classes. Use the provider's public documentation only, cite the source in the file's header comment, and leave out anything unclear. Mark a scope `broad: true` only when it covers all of a user's or tenant's data or gives admin or send rights. An IAM entry's effects must hold for every action its pattern matches, so there are no summary entries such as `s3:*`. The classify tests enforce this.

## Manifest allow grammar

Documented in the README under [Agent manifest](README.md#agent-manifest) and enforced by `schemas/manifest.schema.json` and `src/scope.ts`. Any change to it needs the schema, tests in `test/scope.test.ts` and the README updated together.

## Samples

`samples/<name>/` holds realistic fake specs in a mix of formats. `test/samples.test.ts` pins the findings each one must produce, and the read-only sample must never come out "not ready".

## Reporting a false positive

Open a [false positive issue](https://github.com/qlucent/agent-audit/issues/new?template=false-positive.md). Give the rule id, the action name, the smallest spec that triggers it (fake values only) and why it is safe.
