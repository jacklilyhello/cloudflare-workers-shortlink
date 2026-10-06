import { pathToFileURL } from 'node:url';

function fullMatch(value, pattern) {
  return typeof value === 'string' && pattern.exec(value)?.[0] === value;
}

export function migrationTriggerMetadata(env, now = () => new Date()) {
  const valid =
    env.GITHUB_ACTIONS === 'true' &&
    env.GITHUB_REPOSITORY === 'jacklilyhello/cloudflare-workers-shortlink' &&
    env.GITHUB_REF === 'refs/heads/main' &&
    ['schedule', 'workflow_dispatch'].includes(env.GITHUB_EVENT_NAME) &&
    fullMatch(env.GITHUB_RUN_ID, /^[1-9][0-9]{0,19}$/) &&
    fullMatch(env.GITHUB_SHA, /^[a-f0-9]{40}$/);
  const scheduled =
    valid &&
    env.GITHUB_EVENT_NAME === 'schedule' &&
    typeof env.TRIGGER_SCHEDULE === 'string' &&
    env.TRIGGER_SCHEDULE.length <= 100 &&
    fullMatch(env.TRIGGER_SCHEDULE, /^[0-9*/,-]{1,20}(?: [0-9*/,-]{1,20}){4}$/);
  return {
    event: valid ? env.GITHUB_EVENT_NAME : null,
    ref: valid ? 'refs/heads/main' : null,
    run_id: valid ? env.GITHUB_RUN_ID : null,
    sha: valid ? env.GITHUB_SHA : null,
    observed_at_utc: now().toISOString(),
    schedule: scheduled ? env.TRIGGER_SCHEDULE : null,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  console.log(JSON.stringify(migrationTriggerMetadata(process.env)));
