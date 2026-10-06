import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { migrationTriggerMetadata } from '../scripts/record-migration-trigger.mjs';

const env = {
  GITHUB_ACTIONS: 'true',
  GITHUB_REPOSITORY: 'jacklilyhello/cloudflare-workers-shortlink',
  GITHUB_REF: 'refs/heads/main',
  GITHUB_EVENT_NAME: 'schedule',
  GITHUB_RUN_ID: '12345678901',
  GITHUB_SHA: 'a'.repeat(40),
  TRIGGER_SCHEDULE: '47,17 * * * *',
};
const now = () => new Date('2026-10-06T04:10:00Z');
const expected = {
  event: 'schedule',
  ref: 'refs/heads/main',
  run_id: '12345678901',
  sha: 'a'.repeat(40),
  observed_at_utc: '2026-10-06T04:10:00.000Z',
  schedule: '47,17 * * * *',
};

test('scheduled trigger records only bounded identity, exact cron and observation time', () => {
  assert.deepEqual(migrationTriggerMetadata(env, now), expected);
  const reordered = '17,47 * * * *';
  assert.equal(
    migrationTriggerMetadata({ ...env, TRIGGER_SCHEDULE: reordered }, now).schedule,
    reordered,
    'preserve actual trigger expression without inferring registration or delivery delay',
  );
});

test('manual trigger remains manual and never borrows a supplied cron expression', () => {
  assert.deepEqual(
    migrationTriggerMetadata({ ...env, GITHUB_EVENT_NAME: 'workflow_dispatch' }, now),
    { ...expected, event: 'workflow_dispatch', schedule: null },
  );
});

test('missing or invalid context redacts every externally supplied identity field', () => {
  for (const override of [
    { GITHUB_ACTIONS: 'false' },
    { GITHUB_REPOSITORY: 'other/project' },
    { GITHUB_REF: 'refs/heads/codex/example' },
    { GITHUB_EVENT_NAME: 'push' },
    { GITHUB_RUN_ID: undefined },
    { GITHUB_RUN_ID: '0' },
    { GITHUB_RUN_ID: '1'.repeat(21) },
    { GITHUB_RUN_ID: '123\n' },
    { GITHUB_SHA: 'a'.repeat(39) },
    { GITHUB_SHA: `${'a'.repeat(40)}\n` },
    { GITHUB_SHA: 'private-fixture-credential' },
  ])
    assert.deepEqual(migrationTriggerMetadata({ ...env, ...override }, now), {
      event: null,
      ref: null,
      run_id: null,
      sha: null,
      observed_at_utc: expected.observed_at_utc,
      schedule: null,
    });
});

test('absent, oversized or unsafe cron values are omitted without exposing the input', () => {
  for (const cron of [
    undefined,
    '',
    '47,17 * * * *\n',
    '47,17 * * * *\r',
    '47,17\t* * * *',
    '47,17 * * * *\n::error::fixture',
    '$(echo fixture) * * * *',
    'private-fixture-credential',
    `${'1'.repeat(20)} ${'1'.repeat(20)} ${'1'.repeat(20)} ${'1'.repeat(20)} ${'1'.repeat(20)}`,
    '47,17 * * *',
    '47,17 * * * * *',
  ]) {
    const actual = migrationTriggerMetadata({ ...env, TRIGGER_SCHEDULE: cron }, now);
    assert.deepEqual(actual, { ...expected, schedule: null });
  }
});

test('unselected environment fields and event file contents are never read or emitted', () => {
  const supplied = { ...env };
  for (const key of ['CLOUDFLARE_API_TOKEN', 'GITHUB_TOKEN', 'GITHUB_EVENT_PATH'])
    Object.defineProperty(supplied, key, {
      get() {
        throw new Error('unselected field read');
      },
    });
  assert.deepEqual(migrationTriggerMetadata(supplied, now), expected);
});

test('standalone CLI emits one JSON line and omits credentials', () => {
  const result = spawnSync(process.execPath, ['scripts/record-migration-trigger.mjs'], {
    env: {
      ...env,
      CLOUDFLARE_API_TOKEN: 'fixture-deployment-credential',
      GITHUB_TOKEN: 'fixture-github-credential',
      GITHUB_EVENT_PATH: '/not-a-readable-event-fixture',
    },
    encoding: 'utf8',
  });
  assert.equal(result.status, 0);
  assert.equal(result.stderr, '');
  assert.equal(result.stdout.trim().split('\n').length, 1);
  const actual = JSON.parse(result.stdout);
  assert.match(actual.observed_at_utc, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  assert.deepEqual(actual, { ...expected, observed_at_utc: actual.observed_at_utc });
  assert.doesNotMatch(result.stdout, /credential|EVENT_PATH|readable-event/);
});

test('workflow records before dependency install and keeps secrets confined to data sync', () => {
  const yaml = readFileSync('.github/workflows/migrate-legacy-auto.yml', 'utf8');
  const diagnostic = yaml.slice(
    yaml.indexOf('      - name: Record bounded migration trigger'),
    yaml.indexOf('      - run: npm ci'),
  );
  assert.match(diagnostic, /continue-on-error: true/);
  assert.match(diagnostic, /TRIGGER_SCHEDULE: \$\{\{ github\.event\.schedule \}\}/);
  assert.match(diagnostic, /run: node scripts\/record-migration-trigger\.mjs/);
  assert.doesNotMatch(diagnostic, /secrets\.|CLOUDFLARE_API_TOKEN|\brun:.*\$\{\{/);
  assert.ok(yaml.indexOf('actions/setup-node@') < yaml.indexOf(diagnostic));
  assert.ok(yaml.indexOf(diagnostic) < yaml.indexOf('      - run: npm ci'));
  assert.match(yaml, /cron: '47,17 \* \* \* \*'/);
  assert.match(yaml, /cancel-in-progress: false/);
  assert.equal((yaml.match(/secrets\./g) || []).length, 1);
  assert.ok(yaml.indexOf('secrets.CLOUDFLARE_API_TOKEN') > yaml.indexOf('Run fixed-source'));
  assert.doesNotMatch(
    yaml,
    /scripts\/deploy|upload-artifact|\n  (push|pull_request|workflow_run):/,
  );
});
