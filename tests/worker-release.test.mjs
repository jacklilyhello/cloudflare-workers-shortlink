import assert from 'node:assert/strict';
import test from 'node:test';
import { ACCOUNT, EXPECTED } from '../scripts/cf-client.mjs';
import {
  activeWorkerVersion,
  rollbackWorkerRelease,
  verifyWorkerReleaseVersion,
} from '../scripts/worker-release.mjs';

const script = `${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}`;
const deployments = `${script}/deployments`;
const previous = '11111111-1111-4111-8111-111111111111';
const current = '22222222-2222-4222-8222-222222222222';
const currentDeployment = '33333333-3333-4333-8333-333333333333';
const restoredDeployment = '44444444-4444-4444-8444-444444444444';
const sha = 'a'.repeat(40);
const etag = 'b'.repeat(64);

function deployment(id, versionId, percentage = 100) {
  return { id, versions: [{ version_id: versionId, percentage }] };
}

function fixture() {
  const journal = [{ step: 'worker-upload', state: 'intent', sha, previous_version_id: previous }];
  const prior = deployment(restoredDeployment, previous);
  const published = deployment(currentDeployment, current);
  const version = {
    id: current,
    annotations: { 'workers/tag': sha },
    resources: {
      script: { etag },
      script_runtime: { exports: { ShortlinkService: { type: 'worker' } } },
    },
  };
  const calls = [];
  const state = { active: published, mutate: () => (state.active = prior) };
  const client = {
    async request(path, options) {
      calls.push({ path, options });
      if (path === deployments && !options)
        return { result: { deployments: [state.active, prior] } };
      if (path === `${script}/versions/${previous}`) return { result: { id: previous } };
      if (path === `${script}/versions/${current}`) return { result: version };
      assert.equal(path, deployments);
      assert.equal(options?.method, 'POST');
      state.mutate();
      return { result: {} };
    },
  };
  const writes = () => calls.filter(({ options }) => options?.method === 'POST');
  const rollback = () =>
    rollbackWorkerRelease(client, { journal }, { sha, baselineVersion: previous });
  return { client, journal, prior, state, version, writes, rollback };
}

test('reads the first active deployment and requires one version receiving all traffic', async () => {
  const { client, state } = fixture();
  assert.deepEqual(await activeWorkerVersion(client), {
    deployment_id: currentDeployment,
    version_id: current,
    percentage: 100,
  });
  state.active.versions[0].percentage = 90;
  state.active.versions.push({ version_id: previous, percentage: 10 });
  await assert.rejects(activeWorkerVersion(client), {
    code: 'WORKER_ACTIVE_DEPLOYMENT_UNVERIFIED',
  });
  state.active.versions = [{ version_id: current, percentage: 99 }];
  await assert.rejects(activeWorkerVersion(client), {
    code: 'WORKER_ACTIVE_DEPLOYMENT_UNVERIFIED',
  });
});

test('binds version readback to the reviewed SHA and named RPC export', async () => {
  const { client, version } = fixture();
  assert.deepEqual(await verifyWorkerReleaseVersion(client, current, sha), {
    version_id: current,
    sha,
    entrypoint: 'ShortlinkService',
    script_etag: etag,
  });
  await assert.rejects(verifyWorkerReleaseVersion(client, current, 'c'.repeat(40)), {
    code: 'WORKER_RELEASE_TAG_MISMATCH',
  });
  delete version.resources.script_runtime;
  await assert.rejects(verifyWorkerReleaseVersion(client, current, sha), {
    code: 'WORKER_RELEASE_ENTRYPOINT_MISSING',
  });
  version.resources.script.named_handlers = [{ name: 'ShortlinkService', handlers: [] }];
  assert.equal(
    (await verifyWorkerReleaseVersion(client, current, sha)).entrypoint,
    'ShortlinkService',
  );
});

test('rolls back only to the journal-pinned version and verifies independent readback', async () => {
  const { rollback, writes } = fixture();
  assert.deepEqual(await rollback(), {
    rolled_back: true,
    already_active: false,
    deployment_id: restoredDeployment,
    version_id: previous,
    percentage: 100,
  });
  assert.deepEqual(writes(), [
    {
      path: deployments,
      options: {
        method: 'POST',
        json: {
          strategy: 'percentage',
          versions: [{ version_id: previous, percentage: 100 }],
          annotations: { 'workers/message': `Restore the version before ${sha}` },
        },
      },
    },
  ]);
  assert.equal((await rollback()).already_active, true);
  assert.equal(writes().length, 1);
});

test('refuses conflicting baseline evidence and unrelated active versions', async () => {
  const { journal, rollback, version, writes } = fixture();
  journal.push({ ...journal[0], previous_version_id: current });
  await assert.rejects(rollback(), { code: 'WORKER_ROLLBACK_BASELINE_UNVERIFIED' });
  journal.pop();
  version.annotations['workers/tag'] = 'c'.repeat(40);
  await assert.rejects(rollback(), { code: 'WORKER_RELEASE_TAG_MISMATCH' });
  assert.equal(writes().length, 0);
});

test('refuses rollback if the active deployment changes before the write', async () => {
  const { client, prior, rollback, state, writes } = fixture();
  const read = client.request.bind(client);
  client.request = async (path, options) => {
    const response = await read(path, options);
    if (path === `${script}/versions/${current}`) state.active = prior;
    return response;
  };
  await assert.rejects(rollback(), { code: 'WORKER_ROLLBACK_DEPLOYMENT_CHANGED' });
  assert.equal(writes().length, 0);
});

test('reads back an ambiguous rollback without retrying the write', async () => {
  const { prior, rollback, state, writes } = fixture();
  state.mutate = () => {
    state.active = prior;
    throw new Error('synthetic lost response');
  };
  assert.equal((await rollback()).version_id, previous);
  assert.equal(writes().length, 1);
});

test('fails a successful response that did not restore the pinned version', async () => {
  const { rollback, state, writes } = fixture();
  state.mutate = () => {};
  await assert.rejects(rollback(), { code: 'WORKER_ROLLBACK_READBACK_MISMATCH' });
  assert.equal(writes().length, 1);
});
