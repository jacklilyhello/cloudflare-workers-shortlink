#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import {
  ACCOUNT,
  ADMIN_ZONE,
  EXPECTED,
  ensure,
  createCFClient,
  requireAction,
  verifyAccount,
  safeError,
  listAll,
} from './cf-client.mjs';
import {
  readManifest,
  saveManifest,
  privateSnapshot,
  objectPath,
  validateManifest,
  verifyD1Owner,
} from './deploy-resources.mjs';
import {
  API_MATCH,
  GUARD_MATCH,
  GUARD_REF,
  SKIP_REF,
  DENY_REF,
  inspectSecurity,
  verifySecurity,
  productionPolicyReady,
  unrelatedRulesUnchanged,
  apiIPCondition,
  TEST_ALL_IP_CONDITION,
  TEST_ALL_IP_CHECKPOINT_KEY,
  verifyAccess,
} from './security-bootstrap.mjs';
import { proveProjectSecurity, digest } from './security-api-errors.mjs';
import { PRODUCTION_IP_CONDITION, verifyIPCondition } from './security-ip-policy.mjs';
import {
  DISPLAY_NAMES,
  ownerMarker,
  ownedRule,
  POLICY_NAMES,
  POLICY_CHECKPOINT_KEY,
  PREVIOUS_ADMIN_EMAILS,
  readPolicyOwnership,
} from './security-ownership.mjs';

export const CONFIRMATIONS = {
  'restrict-ip': 'restrict exact shortlink-new API to reviewed IP',
  'allow-test-all-ip': 'allow exact shortlink-new API all IPv4 and IPv6 for testing',
  rename: 'rename owned shortlink-new security display labels',
  'update-admin-policies': 'update owned shortlink-new administrator emails and policy labels',
  verify: 'verify owned shortlink-new security configuration',
};
export const REVIEWED_IP_CONDITION = PRODUCTION_IP_CONDITION;
export const PRODUCTION_IP_CHECKPOINT_KEY = 'production-restricted-api-before-v1';
const REFS = new Set([GUARD_REF, SKIP_REF, DENY_REF]);
const copy = (v) => structuredClone(v);
const sha = (v) => createHash('sha256').update(v).digest('hex');
const strip = (value, fields = []) =>
  Object.fromEntries(
    Object.entries(value).filter(
      ([key]) => !['version', 'last_updated', 'updated_at', ...fields].includes(key),
    ),
  );
const ruleDefinition = (rule) => {
  const allowed = new Set([
    'id',
    'version',
    'last_updated',
    'ref',
    'description',
    'action',
    'action_parameters',
    'expression',
    'enabled',
    'logging',
  ]);
  ensure(
    Object.keys(rule).every((key) => allowed.has(key)),
    'WAF_RULE_SHAPE_UNREVIEWED',
  );
  return copy(strip(rule, ['id']));
};
const APP_READONLY = new Set(['id', 'uid', 'aud', 'created_at', 'updated_at']);
const APP_WRITABLE = new Set([
  'type',
  'name',
  'domain',
  'self_hosted_domains',
  'destinations',
  'app_launcher_visible',
  'allowed_idps',
  'tags',
  'auto_redirect_to_identity',
  'policies',
  'session_duration',
  'enable_binding_cookie',
  'http_only_cookie_attribute',
  'allow_authenticate_via_warp',
  'options_preflight_bypass',
  'eager_redirect_cookie_setting',
]);
export function accessRenameBody(app, name) {
  ensure(
    Object.keys(app).every((key) => APP_READONLY.has(key) || APP_WRITABLE.has(key)),
    'ACCESS_RENAME_FIELDS_UNREVIEWED',
  );
  // Reference existing policy IDs rather than recreating or editing them via the application PUT.
  ensure(
    Array.isArray(app.policies) && app.policies.every((p) => typeof p.id === 'string'),
    'ACCESS_POLICY_IDS_UNPROVEN',
  );
  return {
    ...copy(Object.fromEntries(Object.entries(app).filter(([key]) => APP_WRITABLE.has(key)))),
    name,
    policies: app.policies.map((p) => ({ id: p.id })),
  };
}
async function entry(client, manifest) {
  const value = (await client.request(`${ADMIN_ZONE}/rulesets/${manifest.security.ruleset_id}`))
    .result;
  ensure(
    value.id === manifest.security.ruleset_id &&
      value.kind === 'zone' &&
      value.phase === 'http_request_firewall_custom' &&
      Array.isArray(value.rules),
    'PROJECT_RULESET_DRIFT',
  );
  ensure(
    new Set(value.rules.map((r) => r.id)).size === value.rules.length &&
      new Set(value.rules.map((r) => r.ref)).size === value.rules.length,
    'PROJECT_RULE_IDS_DUPLICATED',
  );
  return value;
}
export async function verifyCustomErrorException(client, manifest) {
  const record = manifest.security?.custom_error_api;
  ensure(
    record?.status === 'applied' &&
      /^[a-f0-9]{32}$/.test(record.ruleset_id) &&
      /^[a-f0-9]{32}$/.test(record.rule_id),
    'CUSTOM_ERROR_API_EXCEPTION_REQUIRED',
  );
  const current = (await client.request(`${ADMIN_ZONE}/rulesets/${record.ruleset_id}`)).result;
  const rules = current?.rules?.filter((r) => r.id === record.rule_id) || [];
  ensure(
    current.kind === 'zone' &&
      current.phase === 'http_custom_errors' &&
      rules.length === 1 &&
      rules[0].action === 'serve_error' &&
      rules[0].enabled === true &&
      sha(rules[0].expression) === record.expected_expression_sha256,
    'CUSTOM_ERROR_API_EXCEPTION_DRIFT',
  );
}
async function checkpoint(client, manifest, key, build) {
  const path = objectPath(`delivery/${manifest.owner_id}/${key}.json`);
  let raw = await client.optional(path, { raw: true });
  if (raw === null) {
    const data = {
      schema: 1,
      owner_id: manifest.owner_id,
      account: EXPECTED.CLOUDFLARE_ACCOUNT_ID,
      worker: EXPECTED.WORKER_NAME,
      ...(await build()),
    };
    await privateSnapshot(
      client,
      manifest,
      key,
      { ...data, sha256: digest(data) },
      { preserveExisting: true },
    );
    raw = await client.request(path, { raw: true });
  }
  let saved;
  try {
    saved = JSON.parse(raw);
  } catch {
    ensure(false, 'SECURITY_CHECKPOINT_INVALID');
  }
  const { sha256, ...data } = saved;
  ensure(
    saved.schema === 1 &&
      saved.owner_id === manifest.owner_id &&
      saved.account === EXPECTED.CLOUDFLARE_ACCOUNT_ID &&
      saved.worker === EXPECTED.WORKER_NAME &&
      sha256 === digest(data),
    'SECURITY_CHECKPOINT_OWNERSHIP_UNPROVEN',
  );
  return saved;
}
function own(entrypoint, ref, manifest) {
  const found = entrypoint.rules.filter((r) => r.ref === ref);
  ensure(
    found.length === 1 && manifest.security.rules[ref] === found[0].id,
    'PROJECT_WAF_ID_OWNERSHIP_UNPROVEN',
  );
  return found[0];
}
async function readOwnedAccess(client, manifest) {
  const apps = {};
  for (const [key, owned] of Object.entries(manifest.security.apps)) {
    const path = `${ACCOUNT}/access/apps/${owned.id}`;
    const [app, policies] = await Promise.all([
      client.request(path),
      listAll(client, `${path}/policies`),
    ]);
    apps[key] = { app: app.result, policies };
  }
  return apps;
}
// Keep every existing policy setting; only the two expressly authorized fields change.
// Unknown response fields are retained rather than silently dropped on this legacy endpoint.
export function accessPolicyUpdateBody(policy, name, include) {
  return {
    ...copy(strip(policy, ['id', 'uid', 'account_id', 'app_id', 'created_at'])),
    name,
    include: copy(include),
  };
}
function policyTarget(original, key) {
  return {
    ...copy(original),
    name: POLICY_NAMES[key],
    include:
      key === 'api'
        ? copy(original.include)
        : EXPECTED.ADMIN_EMAILS.split(',').map((email) => ({ email: { email } })),
  };
}
function unchangedAccessApplication(current, original) {
  return digest(strip(current, ['policies'])) === digest(strip(original, ['policies']));
}
const policyChanges = (saved) =>
  Object.keys(POLICY_NAMES).map((key) => ({
    object: key,
    before: saved.apps[key].policies[0].name,
    after: POLICY_NAMES[key],
    policy_id_preserved: true,
    app_id_aud_and_other_fields_preserved: true,
    administrator_emails_changed: key !== 'api',
  }));
async function verifyPolicyTransition(client, manifest, saved) {
  await proveProjectSecurity(client, manifest, { policyTransition: true });
  await verifyCustomErrorException(client, manifest);
  const current = await readOwnedAccess(client, manifest);
  for (const key of Object.keys(POLICY_NAMES)) {
    const original = saved.apps[key],
      actual = current[key],
      policy = actual?.policies?.[0],
      target = policyTarget(original.policies[0], key);
    ensure(
      actual.policies.length === 1 &&
        unchangedAccessApplication(actual.app, original.app) &&
        actual.app.policies?.length === 1 &&
        actual.app.policies[0].id === policy?.id &&
        (!actual.app.policies[0].name || actual.app.policies[0].name === policy.name) &&
        policy.id === original.policies[0].id &&
        digest(strip(policy, ['name', 'include'])) ===
          digest(strip(original.policies[0], ['name', 'include'])) &&
        [original.policies[0].name, target.name].includes(policy.name) &&
        [digest(original.policies[0].include), digest(target.include)].includes(
          digest(policy.include),
        ),
      'ACCESS_POLICY_UPDATE_DRIFT',
    );
  }
  ensure(
    digest(await entry(client, manifest)) === digest(saved.before),
    'ACCESS_POLICY_WAF_CHANGED',
  );
  ensure(
    digest(
      (
        await client.request(
          `${ADMIN_ZONE}/rulesets/${manifest.security.custom_error_api.ruleset_id}`,
        )
      ).result,
    ) === digest(saved.custom_errors),
    'ACCESS_POLICY_CUSTOM_ERRORS_CHANGED',
  );
  return current;
}
export async function updateAdminPolicies(client, manifest, { env } = {}) {
  requireAction(env || {}, CONFIRMATIONS['update-admin-policies']);
  ensure(
    env.SECURITY_OPERATION === 'update-admin-policies' &&
      ['test', 'production'].includes(env.APP_ENV) &&
      /^\d+$/.test(env.GITHUB_RUN_ID || ''),
    'ACCESS_POLICY_MANUAL_DISPATCH_REQUIRED',
  );
  validateManifest(manifest);
  ensure(manifest.security?.display_names?.status === 'complete', 'ACCESS_DISPLAY_NAMES_REQUIRED');
  if (manifest.security.access_policies?.status === 'complete') {
    const saved = await readPolicyOwnership(client, manifest);
    const current = await verifyPolicyTransition(client, manifest, saved);
    await verifySecurity(client, manifest);
    // Recover a missing final receipt after a lost manifest/snapshot response, without touching policies.
    await privateSnapshot(
      client,
      manifest,
      'access-admin-policies-after-v1',
      {
        changes: policyChanges(saved),
        policies: current,
        administrator_count: 3,
      },
      { preserveExisting: true },
    );
    return {
      changed: false,
      administrator_count: 3,
      policy_labels: POLICY_NAMES,
      identities_preserved: true,
    };
  }
  const saved = await checkpoint(client, manifest, POLICY_CHECKPOINT_KEY, async () => {
    await proveProjectSecurity(client, manifest, { policyTransition: true });
    await verifyCustomErrorException(client, manifest);
    const labels = await checkpoint(client, manifest, 'security-labels-before', () => {
      ensure(false, 'ACCESS_POLICY_EXISTING_ID_CHECKPOINT_REQUIRED');
    });
    ensure(
      labels.sha256 === manifest.security.display_names.checkpoint_sha256,
      'ACCESS_POLICY_EXISTING_ID_CHECKPOINT_DRIFT',
    );
    const apps = await readOwnedAccess(client, manifest);
    for (const key of Object.keys(POLICY_NAMES)) {
      ensure(
        apps[key]?.policies?.length === 1 &&
          apps[key].policies[0].name?.startsWith(ownerMarker(manifest.owner_id)) &&
          apps[key].policies[0].reusable !== true &&
          labels.apps?.[key]?.id === apps[key].app.id &&
          labels.apps[key].aud === apps[key].app.aud &&
          labels.apps[key].policies?.length === 1 &&
          labels.apps[key].policies[0].id === apps[key].policies[0].id &&
          typeof apps[key].policies[0].id === 'string' &&
          apps[key].policies[0].id.length > 0 &&
          apps[key].app.policies?.length === 1 &&
          apps[key].app.policies[0].id === apps[key].policies[0].id,
        'ACCESS_POLICY_INITIAL_OWNERSHIP_UNPROVEN',
      );
    }
    ensure(
      new Set(Object.values(apps).map((item) => item.policies[0].id)).size === 3,
      'ACCESS_POLICIES_MUST_STAY_INDEPENDENT',
    );
    return {
      authorization: 'manual-admin-policy-update',
      dispatch_run_id: env.GITHUB_RUN_ID,
      previous_admin_emails: PREVIOUS_ADMIN_EMAILS,
      admin_emails: EXPECTED.ADMIN_EMAILS,
      existing_identity_checkpoint_sha256: labels.sha256,
      policy_names: copy(POLICY_NAMES),
      apps,
      before: await entry(client, manifest),
      custom_errors: (
        await client.request(
          `${ADMIN_ZONE}/rulesets/${manifest.security.custom_error_api.ruleset_id}`,
        )
      ).result,
    };
  });
  ensure(
    saved.authorization === 'manual-admin-policy-update' &&
      /^\d+$/.test(saved.dispatch_run_id || '') &&
      saved.previous_admin_emails === PREVIOUS_ADMIN_EMAILS &&
      saved.admin_emails === EXPECTED.ADMIN_EMAILS &&
      saved.existing_identity_checkpoint_sha256 ===
        manifest.security.display_names.checkpoint_sha256 &&
      digest(saved.policy_names) === digest(POLICY_NAMES) &&
      (!manifest.security.access_policies?.checkpoint_sha256 ||
        manifest.security.access_policies.checkpoint_sha256 === saved.sha256),
    'ACCESS_POLICY_UPDATE_CHECKPOINT_DRIFT',
  );
  manifest.security.access_policies = {
    schema: 1,
    owner_id: manifest.owner_id,
    status: 'planned',
    checkpoint_key: POLICY_CHECKPOINT_KEY,
    checkpoint_sha256: saved.sha256,
    dispatch_run_id: saved.dispatch_run_id,
    apps: Object.fromEntries(
      Object.keys(POLICY_NAMES).map((key) => [
        key,
        {
          app_id: saved.apps[key].app.id,
          aud: saved.apps[key].app.aud,
          policy_id: saved.apps[key].policies[0].id,
        },
      ]),
    ),
  };
  // Before any write, prove the immutable baseline still names these exact applications and policies.
  await readPolicyOwnership(client, manifest);
  await verifyPolicyTransition(client, manifest, saved);
  await saveManifest(client, manifest);
  for (const key of Object.keys(POLICY_NAMES)) {
    const current = await verifyPolicyTransition(client, manifest, saved),
      original = saved.apps[key].policies[0],
      target = policyTarget(original, key),
      policy = current[key].policies[0];
    const path = `${ACCOUNT}/access/apps/${saved.apps[key].app.id}/policies/${original.id}`;
    if (digest(strip(policy)) !== digest(strip(target)))
      await client.request(path, {
        method: 'PUT',
        json: accessPolicyUpdateBody(policy, target.name, target.include),
      });
    const after = await verifyPolicyTransition(client, manifest, saved);
    ensure(
      digest(strip(after[key].policies[0])) === digest(strip(target)),
      'ACCESS_POLICY_UPDATE_POSTWRITE_DRIFT',
    );
  }
  const changes = policyChanges(saved);
  manifest.security.access_policies.status = 'complete';
  await saveManifest(client, manifest);
  await verifySecurity(client, manifest);
  await privateSnapshot(
    client,
    manifest,
    'access-admin-policies-after-v1',
    { changes, policies: await readOwnedAccess(client, manifest), administrator_count: 3 },
    { preserveExisting: true },
  );
  return {
    changed: true,
    changes,
    administrator_count: 3,
    independent_policies_preserved: true,
    waf_custom_errors_and_other_services_preserved: true,
  };
}
function verifyTransitionCapabilities(current, manifest) {
  const guard = own(current, GUARD_REF, manifest);
  const skip = own(current, SKIP_REF, manifest);
  ensure(
    guard.action === 'block' &&
      guard.enabled !== false &&
      guard.expression === GUARD_MATCH &&
      ownedRule(guard, manifest) &&
      current.rules.indexOf(guard) < current.rules.indexOf(skip),
    'WAF_PATH_GUARD_DRIFT',
  );
  ensure(
    skip.action === 'skip' && skip.enabled !== false && ownedRule(skip, manifest),
    'WAF_SKIP_DRIFT',
  );
  const canonical = (parameters) =>
    digest(
      Object.fromEntries(
        Object.entries(parameters || {}).map(([key, value]) => [
          key,
          Array.isArray(value) ? [...value].sort() : value,
        ]),
      ),
    );
  ensure(
    manifest.security.skip_parameters &&
      canonical(skip.action_parameters) === canonical(manifest.security.skip_parameters),
    'WAF_SKIP_CAPABILITIES_DRIFT',
  );
}
async function temporaryTransition(client, manifest, saved) {
  const snapshot = await inspectSecurity(client, manifest);
  await verifyAccess(client, manifest, snapshot);
  verifyTransitionCapabilities(snapshot.entry, manifest);
  const bindings = (
    await client.request(`${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}/settings`)
  ).result?.bindings;
  ensure(Array.isArray(bindings), 'TEST_ALL_API_WORKER_OWNER_UNPROVEN');
  const binding = (name) => bindings.filter((item) => item?.name === name);
  ensure(
    binding('RESOURCE_OWNER_ID').length === 1 &&
      binding('RESOURCE_OWNER_ID')[0].type === 'plain_text' &&
      binding('RESOURCE_OWNER_ID')[0].text === manifest.owner_id &&
      binding('DB').length === 1 &&
      binding('DB')[0].type === 'd1' &&
      (binding('DB')[0].id || binding('DB')[0].database_id) === manifest.d1.id &&
      (!binding('DB')[0].id || binding('DB')[0].id === manifest.d1.id) &&
      (!binding('DB')[0].database_id || binding('DB')[0].database_id === manifest.d1.id) &&
      binding('BACKUPS').length === 1 &&
      binding('BACKUPS')[0].type === 'r2_bucket' &&
      binding('BACKUPS')[0].bucket_name === manifest.bucket,
    'TEST_ALL_API_WORKER_OWNER_UNPROVEN',
  );
  ensure(
    digest(await readOwnedAccess(client, manifest)) === digest(saved.apps),
    'TEST_ALL_API_ACCESS_CHANGED',
  );
  const customErrors = (
    await client.request(`${ADMIN_ZONE}/rulesets/${manifest.security.custom_error_api.ruleset_id}`)
  ).result;
  ensure(
    digest(customErrors) === digest(saved.custom_errors),
    'TEST_ALL_API_CUSTOM_ERRORS_CHANGED',
  );
  await verifyCustomErrorException(client, manifest);
  const current = snapshot.entry;
  ensure(
    new Set(current.rules.map((rule) => rule.id)).size === current.rules.length &&
      new Set(current.rules.map((rule) => rule.ref)).size === current.rules.length,
    'PROJECT_RULE_IDS_DUPLICATED',
  );
  ensure(
    current?.id === saved.before.id &&
      digest(current.rules.map((rule) => rule.id)) ===
        digest(saved.before.rules.map((rule) => rule.id)) &&
      unrelatedRulesUnchanged(saved.before.rules, current.rules, REFS),
    'TEST_ALL_API_RULESET_CHANGED',
  );
  const skipTarget = `${API_MATCH} and (${TEST_ALL_IP_CONDITION})`;
  const denyTarget = `${API_MATCH} and not (${TEST_ALL_IP_CONDITION})`;
  for (const ref of REFS) {
    const rule = own(current, ref, manifest);
    const original = saved.before.rules.find((item) => item.ref === ref);
    ensure(
      original?.id === rule.id &&
        saved.rule_ids[ref] === rule.id &&
        digest(strip(rule, ['expression'])) === digest(strip(original, ['expression'])) &&
        [
          original.expression,
          ref === SKIP_REF ? skipTarget : ref === DENY_REF ? denyTarget : original.expression,
        ].includes(rule.expression),
      'TEST_ALL_API_RULE_DRIFT',
    );
  }
  const skip = own(current, SKIP_REF, manifest),
    deny = own(current, DENY_REF, manifest);
  ensure(
    current.rules.indexOf(deny) < current.rules.indexOf(skip) &&
      (deny.expression !== denyTarget || skip.expression === skipTarget),
    'TEST_ALL_API_TRANSITION_UNSAFE',
  );
  return current;
}
export async function allowTestAllIP(client, manifest, { env, prove = proveProjectSecurity } = {}) {
  requireAction(env || {}, CONFIRMATIONS['allow-test-all-ip']);
  ensure(
    env.SECURITY_OPERATION === 'allow-test-all-ip' &&
      env.APP_ENV === 'test' &&
      /^\d+$/.test(env.GITHUB_RUN_ID || ''),
    'TEST_ALL_API_MANUAL_DISPATCH_REQUIRED',
  );
  validateManifest(manifest);
  ensure(
    manifest.environment !== 'production' &&
      !manifest.security?.production_restricted_ip &&
      !manifest.production_cutover,
    'PRODUCTION_TEST_ALL_IP_OPERATION_FORBIDDEN',
  );
  ensure(
    manifest.security?.restricted_ip?.status === 'complete' &&
      manifest.security.display_names?.status === 'complete',
    'TEST_ALL_API_OWNED_RESTRICTED_RULES_REQUIRED',
  );
  if (manifest.security.temporary_all_ip?.status === 'complete') {
    await prove(client, manifest);
    await verifyCustomErrorException(client, manifest);
    return { changed: false, operator_policy_preserved: true };
  }
  const saved = await checkpoint(client, manifest, TEST_ALL_IP_CHECKPOINT_KEY, async () => {
    await prove(client, manifest);
    await verifyCustomErrorException(client, manifest);
    const before = await entry(client, manifest);
    verifyTransitionCapabilities(before, manifest);
    ensure(
      apiIPCondition(own(before, SKIP_REF, manifest).expression) === REVIEWED_IP_CONDITION,
      'TEST_ALL_API_SOURCE_POLICY_CHANGED',
    );
    for (const ref of REFS) own(before, ref, manifest);
    return {
      environment: 'test',
      authorization: 'manual-test-all-ipv4-ipv6',
      dispatch_run_id: env.GITHUB_RUN_ID,
      condition: TEST_ALL_IP_CONDITION,
      rule_ids: Object.fromEntries([...REFS].map((ref) => [ref, manifest.security.rules[ref]])),
      before,
      apps: await readOwnedAccess(client, manifest),
      custom_errors: (
        await client.request(
          `${ADMIN_ZONE}/rulesets/${manifest.security.custom_error_api.ruleset_id}`,
        )
      ).result,
    };
  });
  ensure(
    saved.environment === 'test' &&
      saved.authorization === 'manual-test-all-ipv4-ipv6' &&
      /^\d+$/.test(saved.dispatch_run_id || '') &&
      saved.condition === TEST_ALL_IP_CONDITION &&
      saved.before?.id === manifest.security.ruleset_id &&
      apiIPCondition(saved.before.rules.find((rule) => rule.ref === SKIP_REF)?.expression) ===
        REVIEWED_IP_CONDITION &&
      [...REFS].every((ref) => saved.rule_ids?.[ref] === manifest.security.rules[ref]) &&
      (!manifest.security.temporary_all_ip?.checkpoint_sha256 ||
        manifest.security.temporary_all_ip.checkpoint_sha256 === saved.sha256),
    'TEST_ALL_API_CHECKPOINT_DRIFT',
  );
  productionPolicyReady(saved.before.rules, manifest.owner_id, manifest);
  manifest.security.temporary_all_ip = {
    schema: 1,
    owner_id: manifest.owner_id,
    status: 'planned',
    checkpoint_key: TEST_ALL_IP_CHECKPOINT_KEY,
    checkpoint_sha256: saved.sha256,
    dispatch_run_id: saved.dispatch_run_id,
  };
  await saveManifest(client, manifest);
  // Widen Skip first while the original complementary Block still enforces the old list.
  // Only the second PATCH opens the exact API to both IP families.
  for (const [ref, expression] of [
    [SKIP_REF, `${API_MATCH} and (${TEST_ALL_IP_CONDITION})`],
    [DENY_REF, `${API_MATCH} and not (${TEST_ALL_IP_CONDITION})`],
  ]) {
    const current = await temporaryTransition(client, manifest, saved);
    const rule = own(current, ref, manifest);
    if (rule.expression !== expression)
      await client.request(`${ADMIN_ZONE}/rulesets/${current.id}/rules/${rule.id}`, {
        method: 'PATCH',
        json: { ...ruleDefinition(rule), expression },
      });
  }
  const after = await temporaryTransition(client, manifest, saved);
  productionPolicyReady(after.rules, manifest.owner_id, manifest);
  manifest.security.temporary_all_ip.status = 'complete';
  await saveManifest(client, manifest);
  await prove(client, manifest);
  await verifyCustomErrorException(client, manifest);
  await privateSnapshot(
    client,
    manifest,
    'test-all-api-after',
    {
      dispatch_run_id: saved.dispatch_run_id,
      own_rules: after.rules.filter((rule) => REFS.has(rule.ref)),
      unrelated_digest: digest(
        after.rules.filter((rule) => !REFS.has(rule.ref)).map((rule) => strip(rule)),
      ),
    },
    { preserveExisting: true },
  );
  return {
    changed: true,
    exact_entry_only: true,
    ipv4_and_ipv6_testing: true,
    existing_ids_names_order_parameters_preserved: true,
    custom_errors_and_access_preserved: true,
  };
}
async function productionRestrictionTransition(client, manifest, saved) {
  const snapshot = await inspectSecurity(client, manifest);
  await verifyAccess(client, manifest, snapshot);
  verifyTransitionCapabilities(snapshot.entry, manifest);
  await verifyCustomErrorException(client, manifest);
  const bindings = (
    await client.request(`${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}/settings`)
  ).result?.bindings;
  const named = (name) =>
    Array.isArray(bindings) ? bindings.filter((binding) => binding?.name === name) : [];
  const owner = named('RESOURCE_OWNER_ID'),
    database = named('DB'),
    backups = named('BACKUPS');
  ensure(
    owner.length === 1 &&
      owner[0].type === 'plain_text' &&
      owner[0].text === manifest.owner_id &&
      database.length === 1 &&
      database[0].type === 'd1' &&
      (database[0].id || database[0].database_id) === manifest.d1.id &&
      (!database[0].id || database[0].id === manifest.d1.id) &&
      (!database[0].database_id || database[0].database_id === manifest.d1.id) &&
      backups.length === 1 &&
      backups[0].type === 'r2_bucket' &&
      backups[0].bucket_name === manifest.bucket,
    'PRODUCTION_IP_WORKER_OWNER_UNPROVEN',
  );
  ensure(
    digest(await readOwnedAccess(client, manifest)) === digest(saved.apps) &&
      digest(
        (
          await client.request(
            `${ADMIN_ZONE}/rulesets/${manifest.security.custom_error_api.ruleset_id}`,
          )
        ).result,
      ) === digest(saved.custom_errors),
    'PRODUCTION_IP_ACCESS_OR_CUSTOM_ERRORS_CHANGED',
  );
  const current = snapshot.entry;
  const originalIds = saved.before.rules.map((rule) => rule.id);
  ensure(
    new Set(current.rules.map((rule) => rule.id)).size === current.rules.length &&
      new Set(current.rules.map((rule) => rule.ref)).size === current.rules.length,
    'PROJECT_RULE_IDS_DUPLICATED',
  );
  const newDeny = !saved.before.rules.some((rule) => rule.ref === DENY_REF);
  ensure(
    current.id === saved.before.id &&
      digest(
        current.rules.filter((rule) => !(newDeny && rule.ref === DENY_REF)).map((rule) => rule.id),
      ) === digest(originalIds) &&
      unrelatedRulesUnchanged(saved.before.rules, current.rules, REFS),
    'PRODUCTION_IP_RULESET_CHANGED',
  );
  for (const ref of [GUARD_REF, SKIP_REF, ...(newDeny ? [] : [DENY_REF])]) {
    const actual = own(current, ref, manifest);
    const original = saved.before.rules.find((rule) => rule.ref === ref);
    const target =
      ref === SKIP_REF
        ? `${API_MATCH} and (${PRODUCTION_IP_CONDITION})`
        : ref === DENY_REF
          ? `${API_MATCH} and not (${PRODUCTION_IP_CONDITION})`
          : original.expression;
    ensure(
      actual.id === saved.rule_ids[ref] &&
        digest(strip(actual, ['expression'])) === digest(strip(original, ['expression'])) &&
        [original.expression, target].includes(actual.expression),
      'PRODUCTION_IP_RULE_DRIFT',
    );
  }
  const deny = current.rules.find((rule) => rule.ref === DENY_REF);
  if (newDeny && deny) {
    ensure(
      deny.action === 'block' &&
        deny.enabled === true &&
        !deny.action_parameters &&
        deny.description === `${ownerMarker(manifest.owner_id)}deny-api-outside-allowlist` &&
        deny.expression === `${API_MATCH} and not (${PRODUCTION_IP_CONDITION})` &&
        (!manifest.security.rules[DENY_REF] || manifest.security.rules[DENY_REF] === deny.id),
      'PRODUCTION_IP_DENY_RECOVERY_UNPROVEN',
    );
  }
  if (deny)
    ensure(
      current.rules.indexOf(deny) < current.rules.indexOf(own(current, SKIP_REF, manifest)),
      'WAF_DENY_ORDER_UNSAFE',
    );
  return current;
}
async function restrictProductionAPI(client, manifest, { env, prove }) {
  requireAction(env || {}, CONFIRMATIONS['restrict-ip']);
  ensure(
    env.APP_ENV === 'production' &&
      env.SECURITY_OPERATION === 'restrict-ip' &&
      /^\d+$/.test(env.GITHUB_RUN_ID || ''),
    'PRODUCTION_IP_MANUAL_DISPATCH_REQUIRED',
  );
  const saved = await checkpoint(client, manifest, PRODUCTION_IP_CHECKPOINT_KEY, async () => {
    // Validate the actual source policy and its historical authorization before capturing it.
    // APP_ENV upgrades do not rewrite the immutable test authorization checkpoint.
    await prove(client, manifest, { production: false, ipTransition: true });
    await verifyCustomErrorException(client, manifest);
    const before = await entry(client, manifest);
    verifyTransitionCapabilities(before, manifest);
    for (const ref of [GUARD_REF, SKIP_REF]) own(before, ref, manifest);
    if (before.rules.some((rule) => rule.ref === DENY_REF)) own(before, DENY_REF, manifest);
    const target = before.rules.map((rule) =>
      rule.ref === SKIP_REF
        ? { ...rule, expression: `${API_MATCH} and (${PRODUCTION_IP_CONDITION})` }
        : rule.ref === DENY_REF
          ? { ...rule, expression: `${API_MATCH} and not (${PRODUCTION_IP_CONDITION})` }
          : rule,
    );
    if (before.rules.some((rule) => rule.ref === DENY_REF))
      productionPolicyReady(target, manifest.owner_id, manifest);
    return {
      environment: 'production',
      authorization: 'manual-production-two-ip-restriction',
      dispatch_run_id: env?.GITHUB_RUN_ID || null,
      condition: PRODUCTION_IP_CONDITION,
      rule_ids: Object.fromEntries(
        [...REFS]
          .filter((ref) => manifest.security.rules[ref])
          .map((ref) => [ref, manifest.security.rules[ref]]),
      ),
      before,
      apps: await readOwnedAccess(client, manifest),
      custom_errors: (
        await client.request(
          `${ADMIN_ZONE}/rulesets/${manifest.security.custom_error_api.ruleset_id}`,
        )
      ).result,
    };
  });
  const record = manifest.security.production_restricted_ip;
  ensure(
    saved.environment === 'production' &&
      saved.authorization === 'manual-production-two-ip-restriction' &&
      saved.condition === PRODUCTION_IP_CONDITION &&
      saved.before.id === manifest.security.ruleset_id &&
      (!record ||
        (record.schema === 1 &&
          ['planned', 'complete'].includes(record.status) &&
          record.owner_id === manifest.owner_id &&
          record.checkpoint_key === PRODUCTION_IP_CHECKPOINT_KEY &&
          record.checkpoint_sha256 === saved.sha256 &&
          record.dispatch_run_id === saved.dispatch_run_id &&
          record.condition === PRODUCTION_IP_CONDITION)),
    'PRODUCTION_IP_CHECKPOINT_DRIFT',
  );
  let current = await productionRestrictionTransition(client, manifest, saved);
  const targetSkip = `${API_MATCH} and (${PRODUCTION_IP_CONDITION})`;
  const targetDeny = `${API_MATCH} and not (${PRODUCTION_IP_CONDITION})`;
  const wasComplete = record?.status === 'complete';
  let changed = false;
  if (!wasComplete) {
    manifest.security.production_restricted_ip = {
      schema: 1,
      owner_id: manifest.owner_id,
      status: 'planned',
      checkpoint_key: PRODUCTION_IP_CHECKPOINT_KEY,
      checkpoint_sha256: saved.sha256,
      dispatch_run_id: saved.dispatch_run_id,
      condition: PRODUCTION_IP_CONDITION,
    };
    await saveManifest(client, manifest);
  }
  // Constrain the complementary Block first. A crash can deny too much temporarily,
  // but cannot open an outsider request while Skip still carries the former condition.
  let deny = current.rules.find((rule) => rule.ref === DENY_REF);
  if (!deny) {
    const skip = own(current, SKIP_REF, manifest);
    const planned = {
      id: 'planned-production-deny',
      ref: DENY_REF,
      description: `${ownerMarker(manifest.owner_id)}deny-api-outside-allowlist`,
      action: 'block',
      expression: targetDeny,
      enabled: true,
    };
    productionPolicyReady(
      current.rules.flatMap((rule) =>
        rule.ref === SKIP_REF ? [planned, { ...rule, expression: targetSkip }] : [rule],
      ),
      manifest.owner_id,
      {
        ...manifest,
        security: {
          ...manifest.security,
          rules: { ...manifest.security.rules, [DENY_REF]: planned.id },
        },
      },
    );
    await client.request(`${ADMIN_ZONE}/rulesets/${current.id}/rules`, {
      method: 'POST',
      json: { ...ruleDefinition(planned), position: { before: skip.id } },
    });
    changed = true;
    current = await productionRestrictionTransition(client, manifest, saved);
    deny = current.rules.find((rule) => rule.ref === DENY_REF);
  }
  if (!manifest.security.rules[DENY_REF]) {
    manifest.security.rules[DENY_REF] = deny.id;
    await saveManifest(client, manifest);
  }
  for (const [ref, expression] of [
    [DENY_REF, targetDeny],
    [SKIP_REF, targetSkip],
  ]) {
    current = await productionRestrictionTransition(client, manifest, saved);
    const rule = own(current, ref, manifest);
    if (rule.expression !== expression) {
      ensure(!wasComplete, 'PRODUCTION_IP_COMPLETED_POLICY_DRIFT');
      await client.request(`${ADMIN_ZONE}/rulesets/${current.id}/rules/${rule.id}`, {
        method: 'PATCH',
        json: { ...ruleDefinition(rule), expression },
      });
      changed = true;
    }
  }
  const after = await productionRestrictionTransition(client, manifest, saved);
  productionPolicyReady(after.rules, manifest.owner_id, manifest);
  const ipReadback = await verifyIPCondition(
    client,
    apiIPCondition(own(after, SKIP_REF, manifest).expression),
    { exactProduction: true },
  );
  const security = await verifySecurity(client, manifest, { production: true });
  if (!wasComplete) {
    manifest.security.production_restricted_ip.status = 'complete';
    await saveManifest(client, manifest);
  }
  await privateSnapshot(
    client,
    manifest,
    'production-restricted-api-after-v1',
    {
      checkpoint_sha256: saved.sha256,
      own_rules: after.rules.filter((rule) => REFS.has(rule.ref)),
      unrelated_digest: digest(
        after.rules.filter((rule) => !REFS.has(rule.ref)).map((rule) => strip(rule)),
      ),
      ip_readback: ipReadback,
      security,
    },
    { preserveExisting: true },
  );
  return {
    changed,
    exact_entry_only: true,
    complement_before_skip: true,
    existing_ids_names_order_parameters_preserved: true,
    custom_errors_and_access_preserved: true,
    ip_readback: ipReadback,
  };
}
export async function restrictAPI(
  client,
  manifest,
  {
    prove = proveProjectSecurity,
    env,
    production = env?.APP_ENV === 'production' ||
      manifest.environment === 'production' ||
      !!manifest.security?.production_restricted_ip,
  } = {},
) {
  validateManifest(manifest);
  if (production) return restrictProductionAPI(client, manifest, { env, prove });
  if (manifest.security?.restricted_ip?.status === 'complete') {
    await verifySecurity(client, manifest);
    await verifyCustomErrorException(client, manifest);
    return { changed: false, operator_policy_preserved: true };
  }
  await prove(client, manifest);
  await verifyCustomErrorException(client, manifest);
  // The immutable checkpoint allows reconciliation before verification if a create response was lost.
  const saved = await checkpoint(client, manifest, 'restricted-api-before', async () => {
    await prove(client, manifest);
    await verifyCustomErrorException(client, manifest);
    const before = await entry(client, manifest);
    ensure(!before.rules.some((r) => r.ref === DENY_REF), 'EXISTING_DENY_REVIEW_REQUIRED');
    const skip = own(before, SKIP_REF, manifest);
    ensure(skip.expression === API_MATCH, 'EXISTING_OPERATOR_IP_POLICY_PRESERVED');
    return { before };
  });
  ensure(saved.before.id === manifest.security.ruleset_id, 'SECURITY_CHECKPOINT_RULESET_DRIFT');
  ensure(
    !manifest.security.restricted_ip?.checkpoint_sha256 ||
      manifest.security.restricted_ip.checkpoint_sha256 === saved.sha256,
    'SECURITY_CHECKPOINT_MANIFEST_DRIFT',
  );
  for (const ref of [GUARD_REF, SKIP_REF])
    ensure(
      saved.before.rules.find((r) => r.ref === ref)?.id === manifest.security.rules[ref],
      'SECURITY_CHECKPOINT_RULE_ID_DRIFT',
    );
  manifest.security.restricted_ip = {
    schema: 1,
    status: 'planned',
    checkpoint_sha256: saved.sha256,
  };
  await saveManifest(client, manifest);
  let current = await entry(client, manifest);
  ensure(
    unrelatedRulesUnchanged(saved.before.rules, current.rules, REFS),
    'UNRELATED_WAF_RULES_CHANGED',
  );
  const originalSkip = saved.before.rules.find((r) => r.ref === SKIP_REF);
  const targetExpression = `${API_MATCH} and (${REVIEWED_IP_CONDITION})`;
  const denyExpression = `${API_MATCH} and not (${REVIEWED_IP_CONDITION})`;
  let deny = current.rules.find((r) => r.ref === DENY_REF);
  if (!deny) {
    const skip = own(current, SKIP_REF, manifest);
    ensure(digest(strip(skip)) === digest(strip(originalSkip)), 'WAF_SKIP_PREWRITE_DRIFT');
    const plannedDeny = {
      id: 'planned-deny',
      ref: DENY_REF,
      description: `${ownerMarker(manifest.owner_id)}deny-api-outside-allowlist`,
      action: 'block',
      expression: denyExpression,
      enabled: true,
    };
    const proposed = current.rules.flatMap((rule) =>
      rule.ref === SKIP_REF ? [plannedDeny, { ...rule, expression: targetExpression }] : [rule],
    );
    productionPolicyReady(proposed, manifest.owner_id, {
      ...manifest,
      security: {
        ...manifest.security,
        rules: { ...manifest.security.rules, [DENY_REF]: plannedDeny.id },
      },
    });
    await client.request(`${ADMIN_ZONE}/rulesets/${current.id}/rules`, {
      method: 'POST',
      json: {
        ref: DENY_REF,
        description: `${ownerMarker(manifest.owner_id)}deny-api-outside-allowlist`,
        action: 'block',
        expression: denyExpression,
        enabled: true,
        position: { before: skip.id },
      },
    });
    current = await entry(client, manifest);
    deny = current.rules.find((r) => r.ref === DENY_REF);
  }
  ensure(
    deny?.description === `${ownerMarker(manifest.owner_id)}deny-api-outside-allowlist` &&
      deny.action === 'block' &&
      deny.enabled === true &&
      deny.expression === denyExpression &&
      !deny.action_parameters,
    'WAF_DENY_RECOVERY_UNPROVEN',
  );
  ensure(
    !manifest.security.rules[DENY_REF] || manifest.security.rules[DENY_REF] === deny.id,
    'PROJECT_WAF_ID_OWNERSHIP_UNPROVEN',
  );
  manifest.security.rules[DENY_REF] = deny.id;
  await saveManifest(client, manifest);
  current = await entry(client, manifest);
  deny = own(current, DENY_REF, manifest);
  ensure(
    unrelatedRulesUnchanged(saved.before.rules, current.rules, REFS),
    'UNRELATED_WAF_RULES_CHANGED',
  );
  const skip = own(current, SKIP_REF, manifest);
  ensure(
    digest(strip(skip, ['expression'])) === digest(strip(originalSkip, ['expression'])) &&
      [API_MATCH, targetExpression].includes(skip.expression),
    'WAF_SKIP_PREWRITE_DRIFT',
  );
  ensure(current.rules.indexOf(deny) < current.rules.indexOf(skip), 'WAF_DENY_ORDER_UNSAFE');
  // Before narrowing Skip, the complement already blocks outsiders. Never create a temporary gap.
  productionPolicyReady(
    current.rules.map((r) => (r.ref === SKIP_REF ? { ...r, expression: targetExpression } : r)),
    manifest.owner_id,
    manifest,
  );
  if (skip.expression !== targetExpression)
    await client.request(`${ADMIN_ZONE}/rulesets/${current.id}/rules/${skip.id}`, {
      method: 'PATCH',
      json: { ...ruleDefinition(skip), expression: targetExpression },
    });
  const after = await entry(client, manifest);
  ensure(
    unrelatedRulesUnchanged(saved.before.rules, after.rules, REFS),
    'UNRELATED_WAF_RULES_CHANGED',
  );
  productionPolicyReady(after.rules, manifest.owner_id, manifest);
  await verifyCustomErrorException(client, manifest);
  manifest.security.restricted_ip.status = 'complete';
  await saveManifest(client, manifest);
  await verifySecurity(client, manifest);
  await privateSnapshot(client, manifest, 'restricted-api-after', {
    own_rules: after.rules.filter((r) => REFS.has(r.ref)),
    unrelated_digest: digest(after.rules.filter((r) => !REFS.has(r.ref)).map((r) => strip(r))),
  });
  return {
    changed: true,
    exact_entry_only: true,
    complement_before_skip: true,
    custom_errors_preserved: true,
  };
}
export async function renameSecurity(client, manifest, { prove = proveProjectSecurity } = {}) {
  ensure(
    manifest.security?.restricted_ip?.status === 'complete',
    'RESTRICTED_API_POLICY_REQUIRED_BEFORE_RENAME',
  );
  if (manifest.security.display_names?.status === 'complete') {
    await verifySecurity(client, manifest);
    await verifyCustomErrorException(client, manifest);
    return { changed: false, verified_display_names: DISPLAY_NAMES };
  }
  await prove(client, manifest);
  const saved = await checkpoint(client, manifest, 'security-labels-before', async () => {
    await prove(client, manifest);
    const apps = {};
    for (const [key, owned] of Object.entries(manifest.security.apps))
      apps[key] = (await client.request(`${ACCOUNT}/access/apps/${owned.id}`)).result;
    return { apps, before: await entry(client, manifest) };
  });
  ensure(
    !manifest.security.display_names?.checkpoint_sha256 ||
      manifest.security.display_names.checkpoint_sha256 === saved.sha256,
    'SECURITY_CHECKPOINT_MANIFEST_DRIFT',
  );
  manifest.security.display_names = {
    schema: 1,
    owner_id: manifest.owner_id,
    status: 'planned',
    ...copy(DISPLAY_NAMES),
    checkpoint_sha256: saved.sha256,
  };
  await saveManifest(client, manifest);
  const changes = [];
  for (const [key, name] of Object.entries(DISPLAY_NAMES.apps)) {
    const original = saved.apps[key];
    ensure(original?.id === manifest.security.apps[key]?.id, 'ACCESS_RENAME_ID_DRIFT');
    const path = `${ACCOUNT}/access/apps/${original.id}`;
    const current = (await client.request(path)).result;
    ensure(
      digest(strip(current, ['name'])) === digest(strip(original, ['name'])) &&
        [original.name, name].includes(current.name),
      'ACCESS_RENAME_PREWRITE_DRIFT',
    );
    if (current.name !== name)
      await client.request(path, { method: 'PUT', json: accessRenameBody(current, name) });
    const after = (await client.request(path)).result;
    ensure(
      after.name === name && digest(strip(after, ['name'])) === digest(strip(original, ['name'])),
      'ACCESS_RENAME_POSTWRITE_DRIFT',
    );
    changes.push({
      object: key,
      before: original.name,
      after: name,
      id_preserved: true,
      aud_and_configuration_preserved: true,
    });
  }
  for (const [ref, name] of Object.entries(DISPLAY_NAMES.rules)) {
    const original = saved.before.rules.find((r) => r.ref === ref);
    const before = await entry(client, manifest);
    const rule = own(before, ref, manifest);
    ensure(
      original?.id === rule.id &&
        digest(strip(rule, ['description'])) === digest(strip(original, ['description'])) &&
        [original.description, name].includes(rule.description),
      'WAF_RENAME_PREWRITE_DRIFT',
    );
    ensure(
      unrelatedRulesUnchanged(saved.before.rules, before.rules, REFS),
      'UNRELATED_WAF_RULES_CHANGED',
    );
    if (rule.description !== name)
      await client.request(`${ADMIN_ZONE}/rulesets/${before.id}/rules/${rule.id}`, {
        method: 'PATCH',
        json: { ...ruleDefinition(rule), description: name },
      });
    const after = await entry(client, manifest);
    const renamed = own(after, ref, manifest);
    ensure(
      renamed.description === name &&
        digest(strip(renamed, ['description'])) === digest(strip(original, ['description'])) &&
        digest(after.rules.map((r) => r.id)) === digest(saved.before.rules.map((r) => r.id)) &&
        unrelatedRulesUnchanged(saved.before.rules, after.rules, REFS),
      'WAF_RENAME_POSTWRITE_DRIFT',
    );
    changes.push({
      object: ref,
      before: original.description,
      after: name,
      id_and_order_preserved: true,
    });
  }
  await verifySecurity(client, manifest);
  await verifyCustomErrorException(client, manifest);
  manifest.security.display_names.status = 'complete';
  await saveManifest(client, manifest);
  await verifySecurity(client, manifest);
  await privateSnapshot(client, manifest, 'security-labels-after', { changes });
  return { changes, no_identity_rotation: true, other_services_preserved: true };
}
export async function main(env = process.env) {
  const operation = env.SECURITY_OPERATION;
  ensure(Object.hasOwn(CONFIRMATIONS, operation), 'SECURITY_OPERATION_INVALID');
  requireAction(env, CONFIRMATIONS[operation]);
  // D1 ownership is a fixed SELECT sent through the POST-only query API even in verify mode.
  const client = createCFClient(env.CLOUDFLARE_API_TOKEN, { allowWrites: true });
  await verifyAccount(client);
  const manifest = await readManifest(client);
  await verifyD1Owner(client, manifest);
  const result =
    operation === 'update-admin-policies'
      ? await updateAdminPolicies(client, manifest, { env })
      : operation === 'allow-test-all-ip'
        ? await allowTestAllIP(client, manifest, { env })
        : operation === 'restrict-ip'
          ? await restrictAPI(client, manifest, { env })
          : operation === 'rename'
            ? await renameSecurity(client, manifest)
            : await verifySecurity(client, manifest);
  if (operation === 'verify') await verifyCustomErrorException(client, manifest);
  console.log(JSON.stringify({ operation, result }));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await main();
  } catch (e) {
    console.error(JSON.stringify(safeError(e)));
    process.exitCode = 1;
  }
}
