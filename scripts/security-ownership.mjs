import { createHash } from 'node:crypto';
import { EXPECTED, ensure } from './cf-client.mjs';
import { objectPath } from './deploy-resources.mjs';

// Display labels are never the source of ownership. Recorded IDs and stable refs stay authoritative.
export const DISPLAY_NAMES = Object.freeze({
  apps: {
    admin: '短链管理后台',
    api: '短链 API 入口',
    children: '短链 API 子路径保护',
  },
  rules: {
    shortlink_new_api_path_guard: '短链 API 路径保护',
    shortlink_new_api_skip: '短链 API 白名单放行',
    shortlink_new_api_deny_outside_allowlist: '短链 API 非白名单拦截',
  },
});
export const POLICY_NAMES = Object.freeze({
  admin: '短链后台管理员',
  api: '短链 API 免登录',
  children: '短链 API 子路径管理员',
});
export const POLICY_CHECKPOINT_KEY = 'access-admin-policies-before-v1';
export const PREVIOUS_ADMIN_EMAILS = 'lilyyaloveyou@gmail.com,admin@888888.mom';
const digest = (value) => {
  const sorted = (item) =>
    Array.isArray(item)
      ? item.map(sorted)
      : item && typeof item === 'object'
        ? Object.fromEntries(
            Object.keys(item)
              .sort()
              .map((key) => [key, sorted(item[key])]),
          )
        : item;
  return createHash('sha256')
    .update(JSON.stringify(sorted(value)))
    .digest('hex');
};
export async function readPolicyOwnership(client, manifest) {
  const record = manifest.security?.access_policies;
  if (!record) {
    const labels = manifest.security?.display_names;
    if (!labels) return null; // Only a cold bootstrap has no earlier policy identity checkpoint.
    ensure(
      labels.owner_id === manifest.owner_id && /^[a-f\d]{64}$/.test(labels.checkpoint_sha256 || ''),
      'ACCESS_POLICY_LEGACY_ID_CHECKPOINT_REQUIRED',
    );
    const raw = await client.request(
      objectPath(`delivery/${manifest.owner_id}/security-labels-before.json`),
      { raw: true, maxBytes: 256 * 1024 },
    );
    let original;
    try {
      original = JSON.parse(raw);
    } catch {
      ensure(false, 'ACCESS_POLICY_LEGACY_ID_CHECKPOINT_INVALID');
    }
    ensure(
      original && typeof original === 'object' && !Array.isArray(original),
      'ACCESS_POLICY_LEGACY_ID_CHECKPOINT_INVALID',
    );
    const { sha256, ...data } = original;
    ensure(
      sha256 === labels.checkpoint_sha256 &&
        sha256 === digest(data) &&
        original.schema === 1 &&
        original.owner_id === manifest.owner_id &&
        original.account === EXPECTED.CLOUDFLARE_ACCOUNT_ID &&
        original.worker === EXPECTED.WORKER_NAME,
      'ACCESS_POLICY_LEGACY_ID_CHECKPOINT_INVALID',
    );
    for (const key of Object.keys(POLICY_NAMES)) {
      const app = original.apps?.[key],
        owned = manifest.security.apps?.[key];
      ensure(
        app?.id === owned?.id &&
          app?.aud === owned?.aud &&
          app.policies?.length === 1 &&
          typeof app.policies[0].id === 'string' &&
          app.policies[0].id.length > 0 &&
          app.policies[0].reusable !== true &&
          app.policies[0].name?.startsWith(ownerMarker(manifest.owner_id)),
        'ACCESS_POLICY_LEGACY_ID_CHECKPOINT_INVALID',
      );
    }
    ensure(
      new Set(Object.values(original.apps).map((app) => app.policies[0].id)).size === 3,
      'ACCESS_POLICY_LEGACY_ID_CHECKPOINT_INVALID',
    );
    return {
      ...original,
      legacy_identity_only: true,
      apps: Object.fromEntries(
        Object.entries(original.apps).map(([key, app]) => [key, { app, policies: app.policies }]),
      ),
    };
  }
  ensure(
    record.schema === 1 &&
      record.owner_id === manifest.owner_id &&
      ['planned', 'complete'].includes(record.status) &&
      record.checkpoint_key === POLICY_CHECKPOINT_KEY &&
      /^[a-f\d]{64}$/.test(record.checkpoint_sha256 || '') &&
      /^\d+$/.test(record.dispatch_run_id || '') &&
      Object.keys(record.apps || {})
        .sort()
        .join(',') === 'admin,api,children' &&
      Object.values(record.apps).every(
        (item) => item && typeof item.policy_id === 'string' && item.policy_id.length > 0,
      ),
    'ACCESS_POLICY_OWNERSHIP_RECORD_INVALID',
  );
  const raw = await client.request(
    objectPath(`delivery/${manifest.owner_id}/${POLICY_CHECKPOINT_KEY}.json`),
    { raw: true, maxBytes: 256 * 1024 },
  );
  let saved;
  try {
    saved = JSON.parse(raw);
  } catch {
    ensure(false, 'ACCESS_POLICY_OWNERSHIP_CHECKPOINT_INVALID');
  }
  ensure(
    saved && typeof saved === 'object' && !Array.isArray(saved),
    'ACCESS_POLICY_OWNERSHIP_CHECKPOINT_INVALID',
  );
  const { sha256, ...data } = saved;
  ensure(
    sha256 === record.checkpoint_sha256 &&
      sha256 === digest(data) &&
      saved.schema === 1 &&
      saved.owner_id === manifest.owner_id &&
      saved.account === EXPECTED.CLOUDFLARE_ACCOUNT_ID &&
      saved.worker === EXPECTED.WORKER_NAME &&
      saved.authorization === 'manual-admin-policy-update' &&
      saved.admin_emails === EXPECTED.ADMIN_EMAILS &&
      saved.previous_admin_emails === PREVIOUS_ADMIN_EMAILS &&
      digest(saved.policy_names) === digest(POLICY_NAMES) &&
      saved.existing_identity_checkpoint_sha256 ===
        manifest.security.display_names?.checkpoint_sha256 &&
      saved.dispatch_run_id === record.dispatch_run_id &&
      new Set(Object.values(record.apps || {}).map((item) => item.policy_id)).size === 3,
    'ACCESS_POLICY_OWNERSHIP_CHECKPOINT_INVALID',
  );
  for (const key of Object.keys(POLICY_NAMES)) {
    const app = saved.apps?.[key]?.app,
      policies = saved.apps?.[key]?.policies,
      owned = record.apps?.[key];
    ensure(
      policies?.length === 1 &&
        owned?.app_id === app?.id &&
        owned.app_id === manifest.security.apps?.[key]?.id &&
        owned.aud === app?.aud &&
        owned.aud === manifest.security.apps?.[key]?.aud &&
        owned.policy_id === policies[0].id &&
        policies[0].name?.startsWith(ownerMarker(manifest.owner_id)),
      'ACCESS_POLICY_OWNERSHIP_CHECKPOINT_INVALID',
    );
  }
  return saved;
}
export function ownedPolicy(policy, manifest, key, saved = null, { transition = false } = {}) {
  if (!policy || !manifest.security?.apps?.[key]?.id) return false;
  const record = manifest.security.access_policies;
  const fixed = (value) =>
    Object.fromEntries(
      Object.entries(value).filter(
        ([field]) => !['name', 'include', 'updated_at', 'version', 'last_updated'].includes(field),
      ),
    );
  if (!record)
    return saved?.legacy_identity_only === true
      ? saved.apps[key].app.id === manifest.security.apps[key].id &&
          policy.id === saved.apps[key].policies[0].id &&
          policy.reusable !== true &&
          digest(fixed(policy)) === digest(fixed(saved.apps[key].policies[0])) &&
          policy.name === saved.apps[key].policies[0].name
      : !manifest.security.display_names &&
          policy.reusable !== true &&
          policy.name?.startsWith(ownerMarker(manifest.owner_id)) === true;
  const owned = record.apps?.[key];
  return (
    !!saved &&
    owned?.app_id === manifest.security.apps[key].id &&
    owned.policy_id === policy.id &&
    policy.reusable !== true &&
    digest(fixed(policy)) === digest(fixed(saved.apps[key].policies[0])) &&
    (policy.name === POLICY_NAMES[key] ||
      (transition &&
        record.status === 'planned' &&
        policy.name === saved.apps[key].policies[0].name))
  );
}
export const ownerMarker = (owner) => `shortlink-new:${owner}:`;
export function ownedRule(rule, manifest) {
  if (!rule || !manifest) return false;
  const id = manifest.security?.rules?.[rule.ref];
  if (typeof id !== 'string' || id !== rule.id) return false;
  const labels = manifest.security?.display_names;
  if (labels?.owner_id === manifest.owner_id && labels.rules?.[rule.ref] === rule.description)
    return true;
  // During a checkpointed rename, both the original and intended labels remain valid.
  return (
    labels?.status !== 'complete' &&
    String(rule.description || '').startsWith(ownerMarker(manifest.owner_id))
  );
}
export function ownedAppName(app, manifest, key, originalName) {
  if (app?.id !== manifest.security?.apps?.[key]?.id) return false;
  const labels = manifest.security?.display_names;
  return (
    (labels?.owner_id === manifest.owner_id && labels.apps?.[key] === app.name) ||
    (labels?.status !== 'complete' && app.name === originalName)
  );
}
