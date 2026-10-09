#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';

// Development safety checks only. No external API, package install or deployment.
const files = [
  'worker_updated.js',
  'worker_updated_v2.js',
  'worker_updated_v3.js',
  ...readdirSync('scripts')
    .filter((f) => f.endsWith('.mjs'))
    .map((f) => `scripts/${f}`),
];
for (const file of files) execFileSync(process.execPath, ['--check', file], { stdio: 'inherit' });
execFileSync(process.execPath, ['--test', 'scripts/preflight-readonly.test.mjs'], {
  stdio: 'inherit',
});
execFileSync('git', ['diff', '--check'], { stdio: 'inherit' });

// git diff doesn't include untracked initialization files; also check them without staging.
const fresh = [
  'AGENTS.md',
  '.gitignore',
  '.env.readonly.example',
  'package.json',
  ...files.filter((f) => f.startsWith('scripts/')),
  ...readdirSync('docs')
    .filter((f) => f.endsWith('.md'))
    .map((f) => `docs/${f}`),
  'docs/workflows/preflight-readonly.yml.example',
];
for (const file of fresh) {
  const text = readFileSync(file, 'utf8');
  if (!text.endsWith('\n') || text.split('\n').some((line) => /[\t ]+$/.test(line)))
    throw new Error(`Whitespace issue: ${file}`);
}
// Preserve the original six legacy materials after the README rewrite.
// The old README now lives in the archive; both copies of every old Worker stay frozen.
for (const [original, file] of [
  ['README.md', 'archive/legacy-workers/README.v3.md'],
  ['CODEX_HANDOFF.md', 'CODEX_HANDOFF.md'],
  ['LICENSE', 'LICENSE'],
  ...['worker_updated.js', 'worker_updated_v2.js', 'worker_updated_v3.js'].flatMap((file) => [
    [file, file],
    [file, `archive/legacy-workers/${file}`],
  ]),
]) {
  const baseline = execFileSync('git', [
    'show',
    `4eb246fb41d5f15fd8262cfda84cbe930fa37b3c:${original}`,
  ]);
  if (!baseline.equals(readFileSync(file))) throw new Error(`Legacy content changed: ${file}`);
}
console.log('Development safety checks passed; legacy originals and archive copies are unchanged.');
