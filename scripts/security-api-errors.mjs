import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
const target = {
  schema: 1,
  phase: 'http_custom_errors',
  kind: 'zone',
  ruleset_id: '41af06544ea4466e94deabb33e7f1e9d',
  rule_id: '4ded32ebdd7a4c99bf8b579c60ca5ab3',
  original_definition_sha256: '857c3c18ad33a772fdda027ab7e2fc5a4808b2de18601524a75627e9f0a027b3',
  original_entrypoint_sha256: '57945782cb0262dd33dde308a3e19d60acc08b3a6baa04f7b8381827810709d1',
};
import {
  ACCOUNT,
  ADMIN_ZONE,
  EXPECTED,
  REPOSITORY,
  DeliveryError,
  ensure,
  createCFClient,
  requireAction,
  verifyAccount,
  safeError,
} from './cf-client.mjs';
import {
  objectPath,
  readManifest,
  saveManifest,
  privateSnapshot,
  validateManifest,
  verifyD1Owner,
} from './deploy-resources.mjs';
import {
  API_MATCH,
  GUARD_REF,
  SKIP_REF,
  inspectSecurity,
  verifySecurity,
} from './security-bootstrap.mjs';

const KEY = 'custom-error-api-checkpoint';
const PHASE = 'http_custom_errors';
const CHECKPOINT_MAX_BYTES = 256 * 1024;
const CONFIRM = {
  apply: 'apply reviewed exact shortlink-new API error exception',
  rollback: 'restore reviewed exact shortlink-new API error exception',
};
const RECORD_KEYS = new Set([
  'schema',
  'checkpoint_key',
  'checkpoint_sha256',
  'ruleset_id',
  'rule_id',
  'original_expression_sha256',
  'expected_expression_sha256',
  'status',
]);
const DEFINITION_KEYS = new Set([
  'action',
  'action_parameters',
  'description',
  'enabled',
  'expression',
  'ref',
]);
const RULE_KEYS = new Set([...DEFINITION_KEYS, 'id', 'version', 'last_updated']);
const copy = (value) => JSON.parse(JSON.stringify(value));
const sorted = (value) =>
  Array.isArray(value)
    ? value.map(sorted)
    : value && typeof value === 'object'
      ? Object.fromEntries(
          Object.keys(value)
            .sort()
            .map((key) => [key, sorted(value[key])]),
        )
      : value;
export const digest = (value) =>
  createHash('sha256')
    .update(JSON.stringify(sorted(value)))
    .digest('hex');
const expressionDigest = (value) => createHash('sha256').update(value).digest('hex');
const stripVolatile = (value) =>
  Object.fromEntries(
    Object.entries(value).filter(([key]) => !['version', 'last_updated'].includes(key)),
  );
export const entryDigest = (entry) =>
  digest({
    ...stripVolatile(entry),
    rules: entry.rules.map(stripVolatile),
  });
export const exactException = (expression) => `(${expression}) and not ${API_MATCH}`;

function validateTarget(t) {
  ensure(
    t?.schema === 1 &&
      t.phase === PHASE &&
      t.kind === 'zone' &&
      /^[a-f0-9]{32}$/.test(t.ruleset_id) &&
      /^[a-f0-9]{32}$/.test(t.rule_id) &&
      /^[a-f0-9]{64}$/.test(t.original_definition_sha256) &&
      /^[a-f0-9]{64}$/.test(t.original_entrypoint_sha256),
    'CUSTOM_ERROR_TARGET_INVALID',
  );
}
function definition(rule) {
  ensure(
    rule &&
      Object.keys(rule).every((key) => RULE_KEYS.has(key)) &&
      rule.action === 'serve_error' &&
      rule.enabled === true &&
      typeof rule.description === 'string' &&
      typeof rule.ref === 'string' &&
      typeof rule.expression === 'string' &&
      rule.expression.length > 0 &&
      rule.action_parameters &&
      !Array.isArray(rule.action_parameters) &&
      Object.keys(rule.action_parameters).sort().join(',') ===
        'asset_name,content_type,status_code' &&
      typeof rule.action_parameters.asset_name === 'string' &&
      rule.action_parameters.asset_name.length > 0 &&
      rule.action_parameters.content_type === 'text/html' &&
      rule.action_parameters.status_code === 403,
    'CUSTOM_ERROR_RULE_SHAPE_UNREVIEWED',
  );
  // PATCH replaces the definition. Preserve every reviewed writable field, including nested data.
  return copy(Object.fromEntries(Object.entries(rule).filter(([key]) => DEFINITION_KEYS.has(key))));
}
function validateEntry(entry, t) {
  ensure(
    entry?.id === t.ruleset_id &&
      entry.kind === 'zone' &&
      entry.phase === PHASE &&
      Array.isArray(entry.rules) &&
      entry.rules.every((rule) => rule && /^[a-f0-9]{32}$/.test(rule.id)) &&
      new Set(entry.rules.map((rule) => rule.id)).size === entry.rules.length,
    'CUSTOM_ERROR_ENTRYPOINT_METADATA_MISMATCH',
  );
  const matches = entry.rules.filter((rule) => rule.id === t.rule_id);
  ensure(matches.length === 1, 'CUSTOM_ERROR_REVIEWED_RULE_MISSING');
  definition(matches[0]);
  return matches[0];
}
async function readEntry(client, t) {
  const response = await client.request(`${ADMIN_ZONE}/rulesets/${t.ruleset_id}`);
  validateEntry(response.result, t);
  return response.result;
}

export async function proveProjectSecurity(client, manifest) {
  validateManifest(manifest);
  ensure(manifest.d1, 'RESOURCE_BOOTSTRAP_REQUIRED');
  ensure(manifest.security?.status === 'ready', 'PROJECT_SECURITY_NOT_READY');
  await verifySecurity(client, manifest);
  const snapshot = await inspectSecurity(client, manifest);
  for (const ref of [GUARD_REF, SKIP_REF]) {
    const owned = manifest.security.rules?.[ref];
    const matches = snapshot.entry?.rules.filter((rule) => rule.ref === ref) || [];
    const actual = matches[0];
    ensure(
      typeof owned === 'string' &&
        /^[a-f\d]{32}$/i.test(owned) &&
        matches.length === 1 &&
        actual &&
        owned === actual.id &&
        manifest.security.ruleset_id === snapshot.entry.id,
      'PROJECT_WAF_ID_OWNERSHIP_UNPROVEN',
    );
  }
  const worker = (
    await client.request(`${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}/settings`)
  ).result;
  const bindings = worker?.bindings;
  const named = (name) =>
    Array.isArray(bindings) ? bindings.filter((binding) => binding && binding.name === name) : [];
  const ownerBindings = named('RESOURCE_OWNER_ID');
  ensure(
    ownerBindings.length === 1 &&
      ownerBindings[0].type === 'plain_text' &&
      ownerBindings[0].text === manifest.owner_id,
    'PROJECT_WORKER_OWNER_UNPROVEN',
  );
  const databaseBindings = named('DB');
  const database = databaseBindings[0];
  ensure(
    databaseBindings.length === 1 &&
      database.type === 'd1' &&
      (database.id || database.database_id) === manifest.d1.id &&
      (database.id === undefined || database.id === manifest.d1.id) &&
      (database.database_id === undefined || database.database_id === manifest.d1.id),
    'PROJECT_WORKER_D1_DRIFT',
  );
  const backupBindings = named('BACKUPS');
  ensure(
    backupBindings.length === 1 &&
      backupBindings[0].type === 'r2_bucket' &&
      backupBindings[0].bucket_name === manifest.bucket,
    'PROJECT_WORKER_R2_DRIFT',
  );
}

function makeCheckpoint(manifest, entry, t, now) {
  const rule = validateEntry(entry, t);
  ensure(
    digest(stripVolatile(rule)) === t.original_definition_sha256 &&
      entryDigest(entry) === t.original_entrypoint_sha256,
    'CUSTOM_ERROR_ORIGINAL_DRIFT',
  );
  const data = {
    schema: 1,
    project: REPOSITORY,
    account: EXPECTED.CLOUDFLARE_ACCOUNT_ID,
    owner_id: manifest.owner_id,
    worker: EXPECTED.WORKER_NAME,
    environment: 'test',
    zone_id: EXPECTED.CF_ZONE_ID_LILY_LAT,
    phase: PHASE,
    kind: 'zone',
    ruleset_id: t.ruleset_id,
    rule_id: t.rule_id,
    original_entrypoint: copy(entry),
    expected_expression: exactException(rule.expression),
    created_at: now().toISOString(),
  };
  const checkpoint = { ...data, sha256: digest(data) };
  ensure(
    Buffer.byteLength(JSON.stringify(checkpoint)) <= CHECKPOINT_MAX_BYTES,
    'CUSTOM_ERROR_CHECKPOINT_EXCEEDS_READ_LIMIT',
  );
  return checkpoint;
}
function validateCheckpoint(checkpoint, manifest, t) {
  ensure(
    checkpoint &&
      checkpoint.schema === 1 &&
      checkpoint.project === REPOSITORY &&
      checkpoint.account === EXPECTED.CLOUDFLARE_ACCOUNT_ID &&
      checkpoint.owner_id === manifest.owner_id &&
      checkpoint.worker === EXPECTED.WORKER_NAME &&
      checkpoint.environment === 'test' &&
      checkpoint.zone_id === EXPECTED.CF_ZONE_ID_LILY_LAT &&
      checkpoint.phase === PHASE &&
      checkpoint.kind === 'zone' &&
      checkpoint.ruleset_id === t.ruleset_id &&
      checkpoint.rule_id === t.rule_id &&
      typeof checkpoint.created_at === 'string',
    'CUSTOM_ERROR_CHECKPOINT_OWNERSHIP_UNPROVEN',
  );
  const { sha256, ...data } = checkpoint;
  ensure(sha256 === digest(data), 'CUSTOM_ERROR_CHECKPOINT_INVALID');
  const original = validateEntry(checkpoint.original_entrypoint, t);
  ensure(
    digest(stripVolatile(original)) === t.original_definition_sha256 &&
      entryDigest(checkpoint.original_entrypoint) === t.original_entrypoint_sha256 &&
      checkpoint.expected_expression === exactException(original.expression),
    'CUSTOM_ERROR_CHECKPOINT_TARGET_DRIFT',
  );
  const expected = copy(checkpoint.original_entrypoint);
  expected.rules.find((rule) => rule.id === t.rule_id).expression = checkpoint.expected_expression;
  return { original: checkpoint.original_entrypoint, expected };
}
function checkpointRecord(checkpoint, status) {
  const original = checkpoint.original_entrypoint.rules.find(
    (rule) => rule.id === checkpoint.rule_id,
  );
  return {
    schema: 1,
    checkpoint_key: KEY,
    checkpoint_sha256: checkpoint.sha256,
    ruleset_id: checkpoint.ruleset_id,
    rule_id: checkpoint.rule_id,
    original_expression_sha256: expressionDigest(original.expression),
    expected_expression_sha256: expressionDigest(checkpoint.expected_expression),
    status,
  };
}
function checkRecord(record, checkpoint) {
  if (!record) return;
  ensure(
    Object.keys(record).every((key) => RECORD_KEYS.has(key)) &&
      ['planned', 'applied', 'rolled_back'].includes(record.status) &&
      digest({ ...record, status: 'planned' }) === digest(checkpointRecord(checkpoint, 'planned')),
    'CUSTOM_ERROR_MANIFEST_CHECKPOINT_DRIFT',
  );
}
async function readCheckpoint(client, manifest, t) {
  const path = objectPath(`delivery/${manifest.owner_id}/${KEY}.json`);
  const raw = await client.optional(path, { raw: true, maxBytes: CHECKPOINT_MAX_BYTES });
  if (raw === null) return null;
  let checkpoint;
  try {
    checkpoint = JSON.parse(raw);
  } catch {
    ensure(false, 'CUSTOM_ERROR_CHECKPOINT_INVALID');
  }
  validateCheckpoint(checkpoint, manifest, t);
  return checkpoint;
}
async function dryRun(client, t, rule, before) {
  // Official PATCH dry_run validates authorization and syntax without persisting a version:
  // https://developers.cloudflare.com/api/resources/rulesets/subresources/rules/methods/edit/
  let response;
  try {
    response = await client.request(
      `${ADMIN_ZONE}/rulesets/${t.ruleset_id}/rules/${t.rule_id}?dry_run=true`,
      { method: 'PATCH', json: definition(rule) },
    );
  } catch (error) {
    if (error instanceof DeliveryError && error.status === 403) {
      const wrapped = new DeliveryError(
        'CUSTOM_ERROR_DRY_RUN_PERMISSION_DENIED',
        403,
        error.cfCodes,
        'ZONE_RULESETS',
        error.responseContext,
      );
      wrapped.requestMethod = 'PATCH';
      throw wrapped;
    }
    throw error;
  }
  ensure(response.result === null, 'CUSTOM_ERROR_DRY_RUN_RESPONSE_INVALID');
  const after = await readEntry(client, t);
  // Check volatile version fields too: any unexpected dry-run publication or concurrent change stops here.
  ensure(digest(after) === digest(before), 'CUSTOM_ERROR_DRY_RUN_OR_CONCURRENT_DRIFT');
}

export async function changeCustomErrorRule(
  client,
  manifest,
  {
    operation = 'apply',
    reviewedTarget = target,
    prove = proveProjectSecurity,
    now = () => new Date(),
  } = {},
) {
  ensure(['apply', 'rollback'].includes(operation), 'CUSTOM_ERROR_OPERATION_INVALID');
  validateTarget(reviewedTarget);
  validateManifest(manifest);
  ensure(manifest.d1, 'RESOURCE_BOOTSTRAP_REQUIRED');
  await prove(client, manifest); // Every write is gated by verified existing project resources.
  let checkpoint = await readCheckpoint(client, manifest, reviewedTarget);
  let current = await readEntry(client, reviewedTarget);
  let checkedDryRun = false;
  if (!checkpoint) {
    ensure(
      operation === 'apply' && !manifest.security?.custom_error_api,
      'CUSTOM_ERROR_EXISTING_CHECKPOINT_REQUIRED',
    );
    checkpoint = makeCheckpoint(manifest, current, reviewedTarget, now);
    const { expected } = validateCheckpoint(checkpoint, manifest, reviewedTarget);
    await dryRun(
      client,
      reviewedTarget,
      expected.rules.find((rule) => rule.id === reviewedTarget.rule_id),
      current,
    );
    checkedDryRun = true;
    await privateSnapshot(client, manifest, KEY, checkpoint, { preserveExisting: true });
    // Do not silently reuse a different immutable snapshot after an interrupted save.
    const persisted = await readCheckpoint(client, manifest, reviewedTarget);
    ensure(persisted?.sha256 === checkpoint.sha256, 'CUSTOM_ERROR_CHECKPOINT_SAVE_UNPROVEN');
    checkpoint = persisted;
  }
  checkRecord(manifest.security?.custom_error_api, checkpoint);
  const { original, expected } = validateCheckpoint(checkpoint, manifest, reviewedTarget);
  const destination = operation === 'apply' ? expected : original;
  const source = operation === 'apply' ? original : expected;
  const destinationDigest = entryDigest(destination);
  const currentDigest = entryDigest(current);
  ensure(
    currentDigest === entryDigest(source) || currentDigest === destinationDigest,
    'CUSTOM_ERROR_CURRENT_DRIFT',
  );
  let changed = false;
  if (currentDigest !== destinationDigest) {
    if (!checkedDryRun)
      await dryRun(
        client,
        reviewedTarget,
        destination.rules.find((rule) => rule.id === reviewedTarget.rule_id),
        current,
      );
    manifest.security.custom_error_api = checkpointRecord(checkpoint, 'planned');
    await saveManifest(client, manifest);
    await prove(client, manifest);
    current = await readEntry(client, reviewedTarget); // Fresh fingerprint immediately before PATCH.
    ensure(entryDigest(current) === entryDigest(source), 'CUSTOM_ERROR_PREWRITE_DRIFT');
    // No position, no whole-ruleset replacement, and no security-product or Access changes.
    await client.request(
      `${ADMIN_ZONE}/rulesets/${reviewedTarget.ruleset_id}/rules/${reviewedTarget.rule_id}`,
      {
        method: 'PATCH',
        json: definition(destination.rules.find((rule) => rule.id === reviewedTarget.rule_id)),
      },
    );
    changed = true;
  }
  const after = await readEntry(client, reviewedTarget);
  ensure(entryDigest(after) === destinationDigest, 'CUSTOM_ERROR_POSTWRITE_DRIFT');
  await prove(client, manifest);
  manifest.security.custom_error_api = checkpointRecord(
    checkpoint,
    operation === 'apply' ? 'applied' : 'rolled_back',
  );
  await saveManifest(client, manifest);
  return {
    operation,
    changed,
    recovered_without_rule_write: !changed,
    scope: 'link-admin.lily.lat and normalized exact /api/shorten',
    target_expression_only: true,
    other_rules_and_order_unchanged: true,
    original_checkpoint_retained: true,
  };
}

export async function main(env = process.env) {
  const operation = env.CUSTOM_ERROR_OPERATION || 'apply';
  ensure(Object.hasOwn(CONFIRM, operation), 'CUSTOM_ERROR_OPERATION_INVALID');
  requireAction(env, CONFIRM[operation]);
  const client = createCFClient(env.CLOUDFLARE_API_TOKEN, { allowWrites: true });
  await verifyAccount(client);
  const manifest = await readManifest(client);
  ensure(manifest?.d1, 'RESOURCE_BOOTSTRAP_REQUIRED');
  await verifyD1Owner(client, manifest);
  console.log(JSON.stringify(await changeCustomErrorRule(client, manifest, { operation })));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await main();
  } catch (error) {
    console.error(JSON.stringify(safeError(error)));
    process.exitCode = 1;
  }
}
