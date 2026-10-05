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
  GUARD_REF,
  SKIP_REF,
  DENY_REF,
  inspectSecurity,
  verifySecurity,
  productionPolicyReady,
  unrelatedRulesUnchanged,
} from './security-bootstrap.mjs';
import { proveProjectSecurity, digest } from './security-api-errors.mjs';
import { DISPLAY_NAMES, ownerMarker } from './security-ownership.mjs';

export const CONFIRMATIONS = {
  'restrict-ip': 'restrict exact shortlink-new API to reviewed IP',
  rename: 'rename owned shortlink-new security display labels',
  verify: 'verify owned shortlink-new security configuration',
};
export const REVIEWED_IP_CONDITION = 'ip.src in {87.83.110.180}';
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
export async function restrictAPI(client, manifest, { prove = proveProjectSecurity } = {}) {
  validateManifest(manifest);
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
    operation === 'restrict-ip'
      ? await restrictAPI(client, manifest)
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
