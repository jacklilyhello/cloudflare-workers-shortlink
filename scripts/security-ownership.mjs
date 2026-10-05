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
