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
// Prove tracked legacy material was not edited, deleted, staged or given different content.
for (const file of [
  'README.md',
  'CODEX_HANDOFF.md',
  'LICENSE',
  'worker_updated.js',
  'worker_updated_v2.js',
  'worker_updated_v3.js',
]) {
  const baseline = execFileSync('git', [
    'show',
    `4eb246fb41d5f15fd8262cfda84cbe930fa37b3c:${file}`,
  ]);
  if (!baseline.equals(readFileSync(file))) throw new Error(`Legacy content changed: ${file}`);
}
console.log('Development safety checks passed; all six legacy files are byte-for-byte unchanged.');
