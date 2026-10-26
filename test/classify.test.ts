import { test } from 'node:test';
import assert from 'node:assert/strict';
import raw from '../src/generated/data.json' with { type: 'json' };
import { classify, detectDomain, words } from '../src/classify.ts';
import { action } from '../src/parse/json.ts';
import type { Action, GeneratedData } from '../src/types.ts';

const data = raw as unknown as GeneratedData;
const loc = { line: 1, column: 1, offset: 0, length: 0 };
const one = (a: Partial<Action> & Pick<Action, 'name'>) => classify([action('t.json', loc, { kind: 'tool', ...a })], data)[0]!;
const tool = (name: string, params: string[] = [], extra: Partial<Action> = {}) =>
  one({ name, params: params.map((p) => ({ name: p, type: 'string' })), ...extra });
const has = (a: Action, ...xs: string[]) => {
  for (const x of xs) assert.ok([...a.effects, ...a.data].includes(x as never), `${a.name}: expected ${x}, got ${[...a.effects, ...a.data]}`);
};
const lacks = (a: Action, ...xs: string[]) => {
  for (const x of xs) assert.ok(![...a.effects, ...a.data].includes(x as never), `${a.name}: did not expect ${x}`);
};

test('money: refunds and payment intents', () => {
  const r = tool('issue_refund', ['order_id', 'amount']);
  has(r, 'money');
  assert.match(r.evidence.find((e) => e.effect === 'money')!.why, /refund/);
  assert.equal(r.label, 'Issue refund');
  has(tool('create_payment_intent'), 'money');
  has(tool('issueRefund'), 'money');
});

test('benign names with trigger words are not money / credentials / identity-admin', () => {
  for (const n of ['refund_policy_lookup', 'get_payment_status']) {
    const a = tool(n);
    has(a, 'read');
    lacks(a, 'money');
  }
  lacks(tool('list_password_rules'), 'credentials', 'identity-admin');
  lacks(tool('get_deployment_status'), 'code-exec');
  lacks(tool('search', ['query']), 'code-exec');
  lacks(tool('transfer_ticket'), 'money');
  lacks(tool('send_payment_reminder'), 'money');
  has(tool('send_payment_reminder'), 'external-send');
  lacks(tool('send_payment'), 'external-send');
  has(tool('send_payment'), 'money');
});

test('identity-admin', () => {
  has(tool('reset_user_mfa'), 'identity-admin');
  has(tool('assign_role'), 'identity-admin');
  has(tool('disable_user'), 'identity-admin');
});

test('data classes from names and params', () => {
  const p = tool('get_patient_record', ['patient_id']);
  has(p, 'read', 'phi');
  assert.ok(p.evidence.some((e) => e.effect === 'phi' && e.via === 'param'));
  const e = tool('export_all_customers');
  has(e, 'bulk', 'pii');
  has(tool('update_profile', ['ssn']), 'pii');
  has(tool('save_card', ['card_number']), 'financial-data');
  has(tool('connect_service', ['api_key']), 'credentials');
  lacks(tool('lookup', ['country_code']), 'pii', 'phi', 'financial-data', 'credentials');
  // Name not_patterns do not cancel param evidence.
  has(tool('reset_password', ['api_key']), 'credentials');
  has(tool('change_password', ['new_password']), 'credentials');
});

test('external-send and code-exec', () => {
  has(tool('send_email', ['to', 'body']), 'external-send');
  has(tool('run_sql', ['query']), 'code-exec');
  has(tool('execute_shell_command'), 'code-exec');
  lacks(tool('get_email_template'), 'external-send');
});

test('unknown names stay unclassified', () => {
  const a = tool('frobnicate');
  assert.deepEqual([a.effects, a.data, a.evidence], [[], [], []]);
});

test('HTTP methods', () => {
  const ep = (method: string, path: string, operationId?: string) =>
    one({ name: `${method} ${path}`, kind: 'endpoint', method, ...(operationId && { operationId }) });
  has(ep('GET', '/orders'), 'read');
  has(ep('HEAD', '/orders'), 'read');
  for (const m of ['POST', 'PUT', 'PATCH']) has(ep(m, '/orders'), 'write');
  has(ep('DELETE', '/orders/{id}'), 'delete');
  has(ep('POST', '/v1/refunds'), 'write', 'money');
  lacks(ep('GET', '/v1/refunds'), 'money');
  has(ep('POST', '/x', 'createRefund'), 'money');
});

test('MCP annotations', () => {
  // Ruling R4: a hint never removes effects; a contradiction is recorded as evidence.
  const ro = tool('update_notes', [], { annotations: { readOnlyHint: true } });
  has(ro, 'read', 'write');
  assert.ok(ro.evidence.some((e) => e.effect === 'write' && e.via === 'annotation' && /readOnlyHint claims read-only/.test(e.why)));
  const pure = tool('get_notes', [], { annotations: { readOnlyHint: true } });
  assert.deepEqual([pure.effects, pure.data], [['read'], []]);
  has(tool('purge_cache', [], { annotations: { destructiveHint: true } }), 'delete');
  has(tool('frobnicate', [], { annotations: { readOnlyHint: true, destructiveHint: true } }), 'read', 'delete');
  has(tool('frobnicate', ['url'], { annotations: { openWorldHint: true } }), 'external-send');
  lacks(tool('frobnicate', ['id'], { annotations: { openWorldHint: true } }), 'external-send');
});

test('OAuth scope catalogue', () => {
  const s = (name: string) => one({ name, kind: 'scope' });
  const drive = s('https://www.googleapis.com/auth/drive');
  has(drive, 'read', 'write', 'delete');
  assert.equal(drive.broad, true);
  assert.notEqual(drive.label, drive.name);
  assert.notEqual(s('https://www.googleapis.com/auth/drive.file').broad, true);
  has(s('Mail.Send'), 'external-send');
  has(s('https://graph.microsoft.com/Mail.Send'), 'external-send');
  has(s('chat:write'), 'external-send');
  assert.equal(s('repo').broad, true);
  assert.deepEqual(s('unknown:scope').effects, []);
});

test('AWS IAM catalogue', () => {
  const i = (name: string) => one({ name, kind: 'iam', resource: ['*'] });
  has(i('s3:DeleteObject'), 'delete');
  has(i('iam:CreateUser'), 'identity-admin');
  lacks(i('iam:GetUser'), 'identity-admin');
  has(i('iam:GetUser'), 'read');
  has(i('IAM:createuser'), 'identity-admin');
  has(i('iam:*'), 'identity-admin');
  has(i('s3:*'), 'read', 'write', 'delete');
  has(i('s3:Get*'), 'read');
  lacks(i('s3:Get*'), 'delete');
  const all = i('*');
  has(all, 'read', 'write', 'delete', 'money', 'external-send', 'identity-admin', 'code-exec', 'bulk');
  has(i('secretsmanager:GetSecretValue'), 'read', 'credentials');
  has(i('ec2:*'), 'read', 'write', 'delete');
  has(i('secretsmanager:*'), 'write', 'delete', 'credentials');
  lacks(i('ec2:Describe*'), 'write', 'delete');
  lacks(i('s3:*'), 'money');
  for (const n of ['sts:AssumeRole', 'sts:AssumeRoleWithWebIdentity', 'sts:AssumeRoleWithSAML', 'sts:*']) has(i(n), 'identity-admin');
  lacks(i('sts:GetCallerIdentity'), 'identity-admin');
});

test('IAM catalogue has no summary entries and wildcard entries never add effects', () => {
  const lower = (p: string) => p.toLowerCase();
  // IAM catalogue patterns only contain word characters, ':', '-' and '*'.
  const re = (p: string) => new RegExp(`^${lower(p).replace(/\*/g, '.*')}$`);
  for (const e of data.iam) assert.doesNotMatch(e.pattern, /^[^:*]+:\*$/, `summary entry ${e.pattern}`);
  for (const e of data.iam.filter((x) => x.pattern.includes('*') && x.pattern.includes(':'))) {
    for (const f of data.iam.filter((x) => x !== e && re(e.pattern).test(lower(x.pattern)))) {
      for (const t of [...e.effects, ...(e.data ?? [])])
        assert.ok([...f.effects, ...(f.data ?? [])].includes(t as never), `${e.pattern} adds ${t} to ${f.pattern}`);
    }
  }
});

test('detectDomain: manifest domain, else purpose lexicon', () => {
  assert.equal(detectDomain({ agent: { name: 'x', purpose: 'L1 helpdesk for employees' } }, data), 'helpdesk');
  assert.equal(detectDomain({ agent: { name: 'x', purpose: 'L1 helpdesk', domain: 'fintech' } }, data), 'fintech');
  assert.equal(detectDomain({ agent: { name: 'x', purpose: 'Answers patient questions for a clinic' } }, data), 'healthcare');
  assert.equal(detectDomain({ agent: { name: 'x', purpose: 'Writes haiku' } }, data), undefined);
  assert.equal(detectDomain(undefined, data), undefined);
});

test('every lexicon pattern runs in under 50 ms on a 10k-char input', () => {
  const inputs = [
    'a '.repeat(5000),
    'add user to '.repeat(834),
    words('get_'.repeat(2500)),
    'x'.repeat(10000),
    ('reset ' + 'user '.repeat(20)).repeat(80),
  ];
  for (const [file, entries] of Object.entries(data.lexicon)) {
    for (const e of entries) {
      for (const k of ['name_patterns', 'description_patterns', 'param_patterns', 'not_patterns', 'verbs', 'nouns'] as const) {
        for (const p of e[k] ?? []) {
          // Linear by construction: a quantifier may follow a group only as `?` (at most once).
          assert.doesNotMatch(p, /\)[*+{]/, `${file} ${k} /${p}/ repeats a group`);
          for (const wrap of [`\\b(?:${p})\\b`, `^(?:${p})$`]) {
            const r = new RegExp(wrap, 'i');
            for (const s of inputs) {
              const t = performance.now();
              r.test(s.slice(0, 10000));
              const ms = performance.now() - t;
              assert.ok(ms < 50, `${file} ${k} /${p}/ took ${ms.toFixed(1)} ms`);
            }
          }
        }
      }
    }
  }
});

test('verbs x nouns entries: either order, separate words, method verbs, not_patterns', () => {
  const d: GeneratedData = {
    ...data,
    lexicon: {
      effects: [{ effect: 'identity-admin', verbs: ['add|grant'], nouns: ['users?|client grants?'], method_verbs: ['POST'], not_patterns: ['notes?'] }],
      'data-classes': [],
    },
  };
  const c = (name: string, extra: Partial<Action> = {}) => classify([action('t', loc, { kind: 'tool', name, ...extra })], d)[0]!;
  assert.deepEqual(c('add_user').effects, ['identity-admin']);
  assert.match(c('add_user').evidence[0]!.why, /"add" \+ "user"/);
  assert.deepEqual(c('users_bulk_add').effects, ['identity-admin']);
  assert.deepEqual(c('add_guest_to_portal_users').effects, ['identity-admin']);
  assert.deepEqual(c('add_user_note').effects, []);
  assert.deepEqual(c('add_item').effects, []);
  assert.deepEqual(c('users').effects, []);
  // "grant" inside the noun "client grant" is not also the verb.
  assert.deepEqual(c('client_grant').effects, []);
  assert.deepEqual(c('add_client_grant').effects, ['identity-admin']);
  const ep = (method: string, path: string) => c(`${method} ${path}`, { kind: 'endpoint', method });
  assert.deepEqual(ep('POST', '/api/v2/users.json').effects, ['write', 'identity-admin']);
  assert.deepEqual(ep('GET', '/api/v2/users.json').effects, ['read']);
});

test('context entries apply only when the batch already has that class', () => {
  const d: GeneratedData = {
    ...data,
    lexicon: {
      effects: [],
      'data-classes': [
        { data: 'phi', name_patterns: ['patients?'] },
        { data: 'phi', name_patterns: ['procedures?'], context: 'phi' },
      ],
    },
  };
  const t = (name: string) => action('t', loc, { kind: 'tool', name });
  assert.deepEqual(classify([t('get_procedure')], d)[0]!.data, []);
  const both = classify([t('get_procedure'), t('get_patient')], d);
  assert.deepEqual(both[0]!.data, ['phi']);
  assert.equal(both[0]!.evidence[0]!.why, 'name contains "procedure" (with phi elsewhere in this agent)');
});
