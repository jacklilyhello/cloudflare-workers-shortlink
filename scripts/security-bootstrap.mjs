import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import {
  ACCOUNT,
  ADMIN_ZONE,
  EXPECTED,
  DeliveryError,
  ensure,
  fail,
  listAll,
  createCFClient,
  requireAction,
  verifyAccount,
  safeError,
} from './cf-client.mjs';
import {
  readManifest,
  saveManifest,
  privateSnapshot,
  hostPatternMatches,
  verifyD1Owner,
} from './deploy-resources.mjs';
import { verifyIPCondition } from './security-ip-policy.mjs';
import { readZoneEntrypoint, validateRulesetCatalog } from './ruleset-metadata.mjs';

export const API_MATCH =
  '(http.host eq "link-admin.lily.lat" and http.request.uri.path eq "/api/shorten")';
export const GUARD_MATCH =
  '(http.host eq "link-admin.lily.lat" and starts_with(http.request.uri.path, "/api/shorten") and http.request.uri.path ne "/api/shorten")';
export const GUARD_REF = 'shortlink_new_api_path_guard';
export const SKIP_REF = 'shortlink_new_api_skip';
export const DENY_REF = 'shortlink_new_api_deny_outside_allowlist';
const PHASE = 'http_request_firewall_custom';
const marker = (owner) => `shortlink-new:${owner}:`;
const digest = (data) => createHash('sha256').update(JSON.stringify(data)).digest('hex');
const stripVolatile = (rule) =>
  Object.fromEntries(
    Object.entries(rule).filter(([k]) => !['version', 'last_updated'].includes(k)),
  );
export function unrelatedRulesUnchanged(before, after, ownRefs) {
  return (
    digest(before.filter((r) => !ownRefs.has(r.ref)).map(stripVolatile)) ===
    digest(after.filter((r) => !ownRefs.has(r.ref)).map(stripVolatile))
  );
}
export function accessAppTouchesHost(app, host) {
  const patterns = [
    app.domain,
    ...(app.self_hosted_domains || []),
    ...(app.destinations || []).map((d) => d.uri || d.hostname || ''),
    ...(app.destinations || []).flatMap((d) =>
      (d.overrides || []).map((o) => o.path_pattern || ''),
    ),
  ].filter(Boolean);
  // A Worker destination might bypass normal hostname matching; ambiguous targets fail closed.
  if ((app.destinations || []).some((d) => d.worker_id || (d.type && d.type !== 'public')))
    return true;
  return patterns.some((p) => hostPatternMatches(p, host));
}
export function validateAccessPolicy(policies, bypass = false) {
  ensure(policies.length === 1, 'ACCESS_POLICY_COUNT_UNSAFE');
  const p = policies[0];
  ensure(
    p.decision === (bypass ? 'bypass' : 'allow') &&
      !(p.exclude || []).length &&
      !(p.require || []).length,
    'ACCESS_POLICY_UNSAFE',
  );
  if (bypass)
    ensure(
      p.include?.length === 1 &&
        Object.keys(p.include[0]).length === 1 &&
        p.include[0].everyone &&
        Object.keys(p.include[0].everyone).length === 0,
      'ACCESS_BYPASS_UNSAFE',
    );
  else {
    const emails = (p.include || []).map((r) =>
      Object.keys(r).length === 1 ? r.email?.email : undefined,
    );
    ensure(
      emails.length === 2 &&
        [...emails].sort().join(',') === EXPECTED.ADMIN_EMAILS.split(',').sort().join(','),
      'ACCESS_EMAILS_UNSAFE',
    );
  }
}
const compact = (s) => String(s).replace(/\s+/g, ' ').trim();
export function apiIPCondition(expression) {
  const value = compact(expression);
  const base = compact(API_MATCH);
  if (value === base) return null;
  ensure(value.startsWith(`${base} and (`) && value.endsWith(')'), 'WAF_SKIP_SCOPE_UNSAFE');
  const condition = value.slice(base.length + 6, -1);
  ensure(
    /^ip\.src in \$[A-Za-z][A-Za-z0-9_]*$/.test(condition) ||
      /^ip\.src in \{[0-9a-fA-F:.\/ ]+\}$/.test(condition),
    'WAF_IP_CONDITION_REVIEW_REQUIRED',
  );
  return condition;
}
export function productionPolicyReady(rules, owner) {
  const skip = rules.find((r) => r.ref === SKIP_REF);
  const deny = rules.find((r) => r.ref === DENY_REF);
  ensure(
    skip?.enabled !== false &&
      skip.action === 'skip' &&
      skip.description?.startsWith(marker(owner)),
    'OWNED_SKIP_REQUIRED',
  );
  const condition = apiIPCondition(skip.expression);
  ensure(condition, 'PRODUCTION_TEMPORARY_ALL_IP_FORBIDDEN');
  ensure(
    deny?.enabled !== false &&
      deny.action === 'block' &&
      deny.description?.startsWith(marker(owner)) &&
      compact(deny.expression) === `${compact(API_MATCH)} and not (${condition})` &&
      rules.indexOf(deny) < rules.indexOf(skip),
    'PRODUCTION_DENY_OUTSIDE_ALLOWLIST_REQUIRED',
  );
  ensure(
    !rules.slice(0, rules.indexOf(deny)).some((rule) => {
      if (rule.enabled === false || rule.action !== 'skip') return false;
      const parameters = rule.action_parameters || {};
      if (parameters.ruleset === 'current' || (parameters.phases || []).includes(PHASE))
        return true;
      if (parameters.rules === undefined) return false;
      // Do not infer an earlier Skip's expression cannot match the API. Unknown rule selectors also stop release.
      if (
        !parameters.rules ||
        typeof parameters.rules !== 'object' ||
        Array.isArray(parameters.rules)
      )
        return true;
      return Object.values(parameters.rules).some(
        (ids) =>
          !Array.isArray(ids) || ids.some((id) => [deny.id, deny.ref, '*', 'all'].includes(id)),
      );
    }),
    'PRODUCTION_EARLIER_SKIP_CAN_BYPASS_DENY',
  );
  return true;
}
export async function inspectSecurity(client, manifest) {
  const [organization, idps, apps, bot, settings, zoneRulesets, accountRulesets] =
    await Promise.all([
      client.request(`${ACCOUNT}/access/organizations`),
      listAll(client, `${ACCOUNT}/access/identity_providers`),
      listAll(client, `${ACCOUNT}/access/apps`),
      client.request(`${ADMIN_ZONE}/bot_management`),
      client.request(`${ADMIN_ZONE}/settings`),
      listAll(client, `${ADMIN_ZONE}/rulesets`),
      listAll(client, `${ACCOUNT}/rulesets`),
    ]);
  ensure(
    organization.result.auth_domain === EXPECTED.CF_ACCESS_TEAM_DOMAIN,
    'ACCESS_ORGANIZATION_MISMATCH',
  );
  const otp = idps.filter((i) => i.type === 'onetimepin');
  ensure(otp.length === 1 && otp[0].id, 'EXISTING_OTP_PROVIDER_REQUIRED');
  ensure(
    bot.result.fight_mode !== true && bot.result.stale_zone_configuration?.fight_mode !== true,
    'BOT_FIGHT_MODE_NOT_PRECISELY_SKIPPABLE',
  );
  const ownIds = new Set(Object.values(manifest?.security?.apps || {}).map((a) => a.id));
  const ownNames = manifest
    ? new Set(
        ['admin', 'machine', 'machine-children-guard'].map(
          (n) => `${marker(manifest.owner_id)}${n}`,
        ),
      )
    : new Set();
  ensure(
    apps
      .filter((a) => accessAppTouchesHost(a, EXPECTED.ADMIN_HOSTNAME))
      .every((a) => ownIds.has(a.id) || ownNames.has(a.name)),
    'EXISTING_OR_BROAD_ACCESS_CONFLICT',
  );
  const accountDetails = [];
  for (const r of validateRulesetCatalog(accountRulesets).filter(
    (r) => r.kind === 'root' && r.phase === PHASE,
  )) {
    const p = await client.request(`${ACCOUNT}/rulesets/${r.id}`);
    ensure(
      p.result?.id === r.id &&
        p.result.kind === r.kind &&
        p.result.phase === r.phase &&
        Array.isArray(p.result.rules),
      'ACCOUNT_RULESET_DETAIL_METADATA_MISMATCH',
    );
    accountDetails.push(p.result);
    ensure(
      !(p.result.rules || []).some((rule) => rule.enabled !== false),
      'ACCOUNT_CUSTOM_RULES_REVIEW_REQUIRED',
    );
  }
  const detail = [];
  // The zone catalog also contains deployable definitions. Only kind=zone entrypoints describe
  // this zone's actual execution; managed/custom catalog presence is not an enabled phase.
  for (const r of validateRulesetCatalog(zoneRulesets).filter((r) => r.kind === 'zone'))
    detail.push(await readZoneEntrypoint(client, r));
  const entrypoints = detail.filter((r) => r.kind === 'zone' && r.phase === PHASE);
  ensure(entrypoints.length <= 1, 'MULTIPLE_CUSTOM_RULESET_ENTRYPOINTS');
  const entry = entrypoints[0] || null;
  for (const rule of entry?.rules || []) {
    if ([GUARD_REF, SKIP_REF, DENY_REF].includes(rule.ref))
      ensure(
        manifest && rule.description?.startsWith(marker(manifest.owner_id)),
        'SAME_NAMED_WAF_RULE_UNOWNED',
      );
  }
  return {
    otp: otp[0],
    apps,
    bot: bot.result,
    settings: settings.result,
    rulesets: detail,
    accountRulesets: accountDetails,
    entry,
  };
}
function intendedApps(manifest, otp) {
  const include = EXPECTED.ADMIN_EMAILS.split(',').map((email) => ({ email: { email } }));
  const policy = (suffix) => ({
    name: `${marker(manifest.owner_id)}${suffix}`,
    decision: 'allow',
    precedence: 1,
    include,
    exclude: [],
    require: [],
  });
  const common = {
    type: 'self_hosted',
    session_duration: '12h',
    allow_authenticate_via_warp: false,
    allowed_idps: [otp.id],
    auto_redirect_to_identity: true,
    app_launcher_visible: false,
  };
  return {
    admin: {
      ...common,
      name: `${marker(manifest.owner_id)}admin`,
      domain: EXPECTED.ADMIN_HOSTNAME,
      policies: [policy('two-email-otp')],
    },
    api: {
      ...common,
      name: `${marker(manifest.owner_id)}machine`,
      domain: `${EXPECTED.ADMIN_HOSTNAME}/api/shorten`,
      policies: [
        {
          name: `${marker(manifest.owner_id)}machine-bypass`,
          decision: 'bypass',
          precedence: 1,
          include: [{ everyone: {} }],
          exclude: [],
          require: [],
        },
      ],
    },
    children: {
      ...common,
      name: `${marker(manifest.owner_id)}machine-children-guard`,
      domain: `${EXPECTED.ADMIN_HOSTNAME}/api/shorten/*`,
      policies: [policy('children-two-email-otp')],
    },
  };
}
export async function verifyAccess(client, manifest, snapshot) {
  ensure(manifest.security?.apps, 'ACCESS_BOOTSTRAP_REQUIRED');
  for (const [key, intended] of Object.entries(intendedApps(manifest, snapshot.otp))) {
    const owned = manifest.security.apps[key];
    ensure(owned?.id, 'ACCESS_BOOTSTRAP_REQUIRED');
    const app = snapshot.apps.find((a) => a.id === owned.id);
    ensure(
      app &&
        app.name === intended.name &&
        app.domain === intended.domain &&
        app.type === 'self_hosted' &&
        app.allow_authenticate_via_warp === false &&
        app.allowed_idps?.length === 1 &&
        app.allowed_idps[0] === snapshot.otp.id &&
        !(app.self_hosted_domains || []).some((d) => d !== intended.domain) &&
        !(app.destinations || []).some(
          (d) => d.uri !== intended.domain || (d.overrides || []).length,
        ),
      'ACCESS_APPLICATION_DRIFT',
    );
    const policies = await listAll(client, `${ACCOUNT}/access/apps/${app.id}/policies`);
    validateAccessPolicy(policies, key === 'api');
    ensure(
      policies.every((p) => p.name?.startsWith(marker(manifest.owner_id))),
      'ACCESS_POLICY_OWNERSHIP_UNPROVEN',
    );
    if (key === 'admin')
      ensure(app.aud === owned.aud && /^[a-f\d]{64}$/i.test(app.aud), 'ACCESS_AUD_DRIFT');
  }
}
export async function verifySecurity(client, manifest, { production = false } = {}) {
  const snapshot = await inspectSecurity(client, manifest);
  await verifyAccess(client, manifest, snapshot);
  const rules = snapshot.entry?.rules || [];
  const guard = rules.find((r) => r.ref === GUARD_REF);
  const skip = rules.find((r) => r.ref === SKIP_REF);
  ensure(
    guard?.action === 'block' &&
      guard.enabled !== false &&
      guard.expression === GUARD_MATCH &&
      guard.description?.startsWith(marker(manifest.owner_id)),
    'WAF_PATH_GUARD_DRIFT',
  );
  ensure(
    skip?.action === 'skip' &&
      skip.enabled !== false &&
      skip.description?.startsWith(marker(manifest.owner_id)),
    'WAF_SKIP_DRIFT',
  );
  ensure(manifest.security.skip_parameters, 'WAF_SKIP_CAPABILITIES_UNRECORDED');
  const canonical = (parameters) =>
    JSON.stringify(
      Object.fromEntries(
        Object.entries(parameters || {})
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([key, value]) => [key, Array.isArray(value) ? [...value].sort() : value]),
      ),
    );
  ensure(
    canonical(skip.action_parameters) === canonical(manifest.security.skip_parameters),
    'WAF_SKIP_CAPABILITIES_DRIFT',
  );
  apiIPCondition(skip.expression); // Allows operator narrowing; never writes it back to all IPs.
  ensure(rules.indexOf(guard) < rules.indexOf(skip), 'WAF_GUARD_ORDER_UNSAFE');
  if (production) {
    productionPolicyReady(rules, manifest.owner_id);
    await verifyIPCondition(client, apiIPCondition(skip.expression));
  }
  return {
    admin_aud: manifest.security.apps.admin.aud,
    ip_policy: apiIPCondition(skip.expression)
      ? 'operator-restricted'
      : 'temporary-test-all-ipv4-ipv6',
    path_guard: true,
    access_root_and_children: true,
  };
}
export async function bootstrapSecurity(client, manifest) {
  const before = await inspectSecurity(client, manifest);
  // Already-created applications and rules are verified and preserved; this never reopens a narrowed policy.
  manifest.security ||= { apps: {}, rules: {}, status: 'creating' };
  if (!manifest.security.before_saved) {
    await privateSnapshot(client, manifest, 'security-before', before, { preserveExisting: true });
    manifest.security.before_saved = true;
    await saveManifest(client, manifest);
  }
  const intended = intendedApps(manifest, before.otp);
  for (const [key, body] of Object.entries(intended)) {
    if (manifest.security.apps[key]) continue;
    // Reconcile only a uniquely owner-named object after an ambiguous earlier create.
    const apps = await listAll(client, `${ACCOUNT}/access/apps`);
    const recoverable = apps.filter((a) => a.name === body.name && a.domain === body.domain);
    ensure(recoverable.length <= 1, 'ACCESS_OWNER_MARKER_DUPLICATED');
    let app = recoverable[0];
    if (!app)
      app = (await client.request(`${ACCOUNT}/access/apps`, { method: 'POST', json: body })).result;
    ensure(
      app.id && app.name === body.name && app.domain === body.domain,
      'ACCESS_CREATE_RESULT_INVALID',
    );
    manifest.security.apps[key] = { id: app.id, aud: app.aud };
    await saveManifest(client, manifest);
  }
  let entry = before.entry;
  if (!entry) {
    const result = await client.request(`${ADMIN_ZONE}/rulesets`, {
      method: 'POST',
      json: {
        name: 'shortlink-new custom security entrypoint',
        description: `${marker(manifest.owner_id)}entrypoint`,
        kind: 'zone',
        phase: PHASE,
        rules: [],
      },
    });
    entry = result.result;
    manifest.security.created_entrypoint = entry.id;
    await saveManifest(client, manifest);
  }
  // Skip only products present in the pre-change settings/rulesets. Never disable zone-wide products.
  const phases = [];
  for (const phase of ['http_ratelimit', 'http_request_sbfm', 'http_request_firewall_managed'])
    if (
      before.rulesets.some(
        (r) => r.phase === phase && (r.rules || []).some((x) => x.enabled !== false),
      ) ||
      (phase === 'http_request_sbfm' &&
        Object.entries(before.bot).some(
          ([k, v]) => k.startsWith('sbfm_') && ['block', 'managed_challenge'].includes(v),
        ))
    )
      phases.push(phase);
  const products = [];
  for (const [setting, product] of [
    ['browser_check', 'bic'],
    ['security_level', 'securityLevel'],
    ['hotlink_protection', 'hot'],
  ])
    if (
      before.settings.some(
        (s) =>
          s.id === setting && !['off', false, null, undefined, 'essentially_off'].includes(s.value),
      )
    )
      products.push(product);
  const bodies = [
    {
      ref: GUARD_REF,
      description: `${marker(manifest.owner_id)}reject-api-subpaths`,
      action: 'block',
      expression: GUARD_MATCH,
      enabled: true,
      position: { before: '' },
    },
    {
      ref: SKIP_REF,
      description: `${marker(manifest.owner_id)}temporary-test-api-all-ip`,
      action: 'skip',
      expression: API_MATCH,
      enabled: true,
      action_parameters: {
        ruleset: 'current',
        ...(phases.length ? { phases } : {}),
        ...(products.length ? { products } : {}),
      },
      logging: { enabled: true },
    },
  ];
  manifest.security.skip_parameters ||= bodies[1].action_parameters;
  await saveManifest(client, manifest);
  for (const body of bodies) {
    const current = (await client.request(`${ADMIN_ZONE}/rulesets/${entry.id}`)).result;
    const existing = (current.rules || []).find((r) => r.ref === body.ref);
    if (existing) {
      ensure(
        existing.description?.startsWith(marker(manifest.owner_id)),
        'SAME_NAMED_WAF_RULE_UNOWNED',
      );
      manifest.security.rules[body.ref] = existing.id;
      await saveManifest(client, manifest);
      continue;
    }
    if (body.ref === SKIP_REF) body.position = { after: manifest.security.rules[GUARD_REF] };
    const result = await client.request(`${ADMIN_ZONE}/rulesets/${entry.id}/rules`, {
      method: 'POST',
      json: body,
    });
    const made = result.result.rules?.find((r) => r.ref === body.ref);
    ensure(made?.id, 'WAF_CREATE_RESULT_INVALID');
    manifest.security.rules[body.ref] = made.id;
    await saveManifest(client, manifest);
  }
  const afterRules =
    (await client.request(`${ADMIN_ZONE}/rulesets/${entry.id}`)).result.rules || [];
  ensure(
    unrelatedRulesUnchanged(
      before.entry?.rules || [],
      afterRules,
      new Set([GUARD_REF, SKIP_REF, DENY_REF]),
    ),
    'UNRELATED_WAF_RULES_CHANGED',
  );
  manifest.security.ruleset_id = entry.id;
  manifest.security.status = 'ready';
  await saveManifest(client, manifest);
  const result = await verifySecurity(client, manifest);
  await privateSnapshot(client, manifest, 'security-after', {
    own_rules: afterRules.filter((r) => [GUARD_REF, SKIP_REF].includes(r.ref)),
    unrelated_rules_digest: digest(
      afterRules.filter((r) => ![GUARD_REF, SKIP_REF, DENY_REF].includes(r.ref)).map(stripVolatile),
    ),
    result,
  });
  return result;
}
export async function main(env = process.env) {
  requireAction(env, 'configure shortlink-new test API security');
  const client = createCFClient(env.CLOUDFLARE_API_TOKEN, { allowWrites: true });
  await verifyAccount(client);
  const manifest = await readManifest(client);
  ensure(manifest?.d1, 'RESOURCE_BOOTSTRAP_REQUIRED');
  await verifyD1Owner(client, manifest);
  const result = await bootstrapSecurity(client, manifest);
  console.log(
    JSON.stringify({
      security: result,
      scope: 'link-admin.lily.lat and exact /api/shorten; API child guard only',
    }),
  );
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await main();
  } catch (e) {
    console.error(JSON.stringify(safeError(e)));
    process.exitCode = 1;
  }
}
