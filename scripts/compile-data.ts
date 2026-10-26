// Compiles rules/*.yaml, lexicon/*.yaml, catalog/*.yaml into src/generated/data.json.
// Usage: node scripts/compile-data.ts [dataDir] [outFile]   (defaults: repo root, src/generated/data.json)
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ajv } from 'ajv';
import { parse } from 'yaml';

const repo = fileURLToPath(new URL('../', import.meta.url));
const dataDir = process.argv[2] ?? repo;
const outFile = process.argv[3] ?? join(repo, 'src/generated/data.json');
const readJson = (p: string) => JSON.parse(readFileSync(join(repo, p), 'utf8'));
const ajv = new Ajv({ allErrors: true, strict: false });
const v = Object.fromEntries(
  ['rule', 'manifest', 'lexicon', 'scopes', 'iam'].map((n) => [n, ajv.compile(readJson(`schemas/${n}.schema.json`))]),
);

const errors: string[] = [];
const check = (name: keyof typeof v, file: string, data: unknown) => {
  if (v[name](data)) return true;
  for (const e of v[name].errors ?? []) errors.push(`${file}: ${e.instancePath || '/'} ${e.message}`);
  return false;
};
const load = (file: string) => {
  try {
    return parse(readFileSync(join(dataDir, file), 'utf8'));
  } catch (e) {
    errors.push(`${file}: ${(e as Error).message}`);
  }
};
const yamls = (dir: string) => {
  try {
    return readdirSync(join(dataDir, dir)).filter((f) => f.endsWith('.yaml')).sort();
  } catch {
    return [];
  }
};

const rules: unknown[] = [];
for (const name of yamls('rules')) {
  const file = `rules/${name}`;
  const rule = load(file);
  if (rule === undefined || !check('rule', file, rule)) continue;
  if ((rule as { id: string }).id !== basename(name, '.yaml')) errors.push(`${file}: id must equal the filename`);
  rules.push(rule);
}

const lexicon: Record<string, unknown> = {};
for (const name of yamls('lexicon')) {
  const file = `lexicon/${name}`;
  const d = load(file);
  if (d === undefined || !check('lexicon', file, d)) continue;
  d.forEach((entry: Record<string, unknown>, i: number) => {
    for (const k of ['name_patterns', 'description_patterns', 'param_patterns', 'not_patterns'])
      for (const p of (entry[k] as string[] | undefined) ?? []) {
        try {
          new RegExp(p);
        } catch (e) {
          errors.push(`${file}: /${i}/${k} ${(e as Error).message}`);
        }
      }
  });
  lexicon[basename(name, '.yaml')] = d;
}

const catalog = (name: 'scopes' | 'iam', file: string) => {
  const d = yamls('catalog').includes(basename(file)) ? load(file) : [];
  return d !== undefined && check(name, file, d) ? d : [];
};
const scopes = catalog('scopes', 'catalog/scopes.yaml');
const iam = catalog('iam', 'catalog/aws-iam.yaml');

if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}
mkdirSync(dirname(outFile), { recursive: true });
writeFileSync(outFile, JSON.stringify({ rules, lexicon, scopes, iam, manifestSchema: readJson('schemas/manifest.schema.json') }, null, 2) + '\n');
console.log(`compiled ${rules.length} rules, ${Object.keys(lexicon).length} lexicon files`);
