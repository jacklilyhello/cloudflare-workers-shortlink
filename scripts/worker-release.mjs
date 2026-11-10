import { ACCOUNT, EXPECTED, ensure } from './cf-client.mjs';

const SCRIPT = `${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}`;
const DEPLOYMENTS = `${SCRIPT}/deployments`;
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const COMMIT = /^[a-f0-9]{40}$/;
const ENTRYPOINT = 'ShortlinkService';

const isUUID = (value) => typeof value === 'string' && UUID.test(value);
const isCommit = (value) => typeof value === 'string' && COMMIT.test(value);

export async function activeWorkerVersion(client) {
  const { result } = await client.request(DEPLOYMENTS);
  // Cloudflare lists the deployment serving traffic first.
  const active = Array.isArray(result?.deployments) ? result.deployments[0] : null;
  ensure(
    isUUID(active?.id) && Array.isArray(active.versions) && active.versions.length === 1,
    'WORKER_ACTIVE_DEPLOYMENT_UNVERIFIED',
  );
  const version = active.versions[0];
  ensure(
    isUUID(version?.version_id) && version.percentage === 100,
    'WORKER_ACTIVE_DEPLOYMENT_UNVERIFIED',
  );
  return { deployment_id: active.id, version_id: version.version_id, percentage: 100 };
}

async function readVersion(client, versionId) {
  ensure(isUUID(versionId), 'WORKER_VERSION_ID_INVALID');
  const { result } = await client.request(`${SCRIPT}/versions/${versionId}`);
  ensure(result?.id === versionId, 'WORKER_VERSION_READBACK_MISMATCH');
  return result;
}

function verifyReleaseTag(version, sha) {
  ensure(version.annotations?.['workers/tag'] === sha, 'WORKER_RELEASE_TAG_MISMATCH');
}

export async function verifyWorkerReleaseVersion(client, versionId, sha) {
  ensure(isCommit(sha), 'RELEASE_SHA_INVALID');
  const version = await readVersion(client, versionId);
  verifyReleaseTag(version, sha);
  const script = version.resources?.script;
  const namedHandlers = script?.named_handlers;
  const runtimeExport = version.resources?.script_runtime?.exports?.[ENTRYPOINT];
  ensure(
    (runtimeExport?.type === 'worker' &&
      (runtimeExport.state === undefined || runtimeExport.state === 'created')) ||
      (Array.isArray(namedHandlers) &&
        namedHandlers.some((handler) => handler?.name === ENTRYPOINT)),
    'WORKER_RELEASE_ENTRYPOINT_MISSING',
  );
  const etag = script?.etag;
  return {
    version_id: versionId,
    sha,
    entrypoint: ENTRYPOINT,
    script_etag: typeof etag === 'string' && /^[a-f0-9]{64}$/i.test(etag) ? etag : null,
  };
}

export async function rollbackWorkerRelease(client, manifest, { sha, baselineVersion }) {
  ensure(isCommit(sha) && isUUID(baselineVersion), 'WORKER_ROLLBACK_INPUT_INVALID');
  ensure(Array.isArray(manifest?.journal), 'WORKER_ROLLBACK_BASELINE_UNVERIFIED');
  const intents = manifest.journal.filter(
    (entry) => entry?.step === 'worker-upload' && entry.state === 'intent' && entry.sha === sha,
  );
  ensure(
    intents.length > 0 && intents.every((intent) => intent.previous_version_id === baselineVersion),
    'WORKER_ROLLBACK_BASELINE_UNVERIFIED',
  );
  await readVersion(client, baselineVersion);
  const active = await activeWorkerVersion(client);
  if (active.version_id === baselineVersion)
    return { rolled_back: false, already_active: true, ...active };
  verifyReleaseTag(await readVersion(client, active.version_id), sha);
  const current = await activeWorkerVersion(client);
  ensure(
    current.deployment_id === active.deployment_id && current.version_id === active.version_id,
    'WORKER_ROLLBACK_DEPLOYMENT_CHANGED',
  );
  try {
    await client.request(DEPLOYMENTS, {
      method: 'POST',
      json: {
        strategy: 'percentage',
        versions: [{ version_id: baselineVersion, percentage: 100 }],
        annotations: { 'workers/message': `Restore the version before ${sha}` },
      },
    });
  } catch (error) {
    // A failed response can follow a successful write. Reconcile before another attempt.
    const observed = await activeWorkerVersion(client);
    if (observed.version_id === baselineVersion)
      return { rolled_back: true, already_active: false, ...observed };
    throw error;
  }
  const restored = await activeWorkerVersion(client);
  ensure(restored.version_id === baselineVersion, 'WORKER_ROLLBACK_READBACK_MISMATCH');
  return { rolled_back: true, already_active: false, ...restored };
}
