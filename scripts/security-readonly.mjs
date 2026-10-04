#!/usr/bin/env node
// Fixed-project GETs only. The user-confirmed token must be process-mapped to the explicit readonly source.
import { pathToFileURL } from 'node:url';
import { loadCredential } from './preflight-readonly.mjs';
import {
  ACCOUNT,
  ADMIN_ZONE,
  EXPECTED,
  createCFClient,
  listAll,
  ensure,
  safeError,
} from './cf-client.mjs';
import { accessAppTouchesHost, API_MATCH } from './security-bootstrap.mjs';

export async function main(env = process.env, fetcher = fetch) {
  const credential = loadCredential(env);
  if (!credential)
    return {
      result: 'PENDING',
      detail: 'No explicit readonly source; no Cloudflare requests issued.',
    };
  const client = createCFClient(credential.token, { fetcher, allowWrites: false });
  const checks = [];
  const run = async (item, work) => {
    try {
      const detail = await work();
      checks.push({ item, result: 'PASS', detail, time: new Date().toISOString() });
      return detail;
    } catch (e) {
      checks.push({
        item,
        result: /PAGINATION|INCOMPLETE/.test(e.code || '') ? 'PARTIAL' : safeError(e).code,
        ...safeError(e),
        time: new Date().toISOString(),
      });
      return null;
    }
  };
  const verified = await run('token.active', async () => {
    const p = await client.request(`${ACCOUNT}/tokens/verify`);
    ensure(p.result?.status === 'active', 'READONLY_TOKEN_INACTIVE');
    return { active: true, permissions_proven: false };
  });
  if (!verified) return { result: 'PENDING', checks };
  const zone = await run('zone.account', async () => {
    const p = await client.request(ADMIN_ZONE);
    ensure(
      p.result.name === 'lily.lat' && p.result.account?.id === EXPECTED.CLOUDFLARE_ACCOUNT_ID,
      'ZONE_ACCOUNT_MISMATCH',
    );
    return { zone: 'lily.lat', fixed_account: true };
  });
  if (!zone) return { result: 'PENDING', checks };
  await run('access.organization', async () => {
    const p = await client.request(`${ACCOUNT}/access/organizations`);
    return { fixed_team_matches: p.result.auth_domain === EXPECTED.CF_ACCESS_TEAM_DOMAIN };
  });
  await run('access.otp', async () => {
    const p = await listAll(client, `${ACCOUNT}/access/identity_providers`);
    return {
      otp_count: p.filter((i) => i.type === 'onetimepin').length,
      complete: true,
      provider_configs_withheld: true,
    };
  });
  await run('access.applications.and.policies', async () => {
    const apps = await listAll(client, `${ACCOUNT}/access/apps`);
    const related = apps.filter((a) => accessAppTouchesHost(a, EXPECTED.ADMIN_HOSTNAME));
    const summaries = [];
    for (const app of related) {
      const policies = await listAll(client, `${ACCOUNT}/access/apps/${app.id}/policies`);
      const emails = policies.flatMap((p) =>
        (p.include || []).map((r) => r.email?.email).filter(Boolean),
      );
      const complexSelectors = policies
        .flatMap((p) => [...(p.include || []), ...(p.exclude || []), ...(p.require || [])])
        .filter((r) => !r.email && !r.everyone).length;
      summaries.push({
        exact_admin_host: app.domain === EXPECTED.ADMIN_HOSTNAME,
        exact_machine_path: app.domain === `${EXPECTED.ADMIN_HOSTNAME}/api/shorten`,
        api_children_path: app.domain === `${EXPECTED.ADMIN_HOSTNAME}/api/shorten/*`,
        wildcard_or_multiple_destinations:
          String(app.domain || '').includes('*') || (app.destinations || []).length > 1,
        aud_present: typeof app.aud === 'string' && /^[a-f\d]{64}$/i.test(app.aud),
        policy_count: policies.length,
        decisions: policies.map((p) => p.decision),
        expected_admin_emails_only:
          emails.length === 2 &&
          [...emails].sort().join(',') === EXPECTED.ADMIN_EMAILS.split(',').sort().join(','),
        everyone_selector_count: policies.flatMap((p) => p.include || []).filter((r) => r.everyone)
          .length,
        complex_selector_count: complexSelectors,
        allowed_idps_count: app.allowed_idps?.length ?? null,
        warp_authentication: app.allow_authenticate_via_warp === true,
      });
    }
    return {
      all_application_count: apps.length,
      related_application_count: related.length,
      complete: true,
      related: summaries,
      names_ids_and_unrelated_configuration_withheld: true,
    };
  });
  await run('zone.bot_management', async () => {
    const p = await client.request(`${ADMIN_ZONE}/bot_management`);
    return {
      bot_fight_mode:
        p.result.fight_mode === true || p.result.stale_zone_configuration?.fight_mode === true,
      precisely_skippable: !(
        p.result.fight_mode === true || p.result.stale_zone_configuration?.fight_mode === true
      ),
      sbfm_definitely_automated: p.result.sbfm_definitely_automated ?? 'not_observed',
      sbfm_likely_automated: p.result.sbfm_likely_automated ?? 'not_observed',
    };
  });
  await run('zone.security_settings', async () => {
    const p = await client.request(`${ADMIN_ZONE}/settings`);
    return Object.fromEntries(
      (p.result || [])
        .filter((s) =>
          [
            'browser_check',
            'security_level',
            'challenge_ttl',
            'hotlink_protection',
            'waf',
          ].includes(s.id),
        )
        .map((s) => [s.id, { value: s.value, editable: s.editable }]),
    );
  });
  for (const [scope, path] of [
    ['zone', ADMIN_ZONE],
    ['account', ACCOUNT],
  ]) {
    await run(`${scope}.rulesets.complete`, async () => {
      const metadata = await listAll(client, `${path}/rulesets`);
      const relevant = metadata.filter((r) =>
        [
          'http_request_firewall_custom',
          'http_request_firewall_managed',
          'http_ratelimit',
          'http_request_sbfm',
        ].includes(r.phase),
      );
      const rows = [];
      for (const r of relevant) {
        const p = await client.request(`${path}/rulesets/${r.id}`);
        const rules = p.result.rules || [];
        rows.push({
          phase: r.phase,
          kind: r.kind,
          rule_count: rules.length,
          ...(r.kind === 'managed'
            ? { enabled_rule_count: rules.filter((x) => x.enabled !== false).length }
            : {
                enabled_actions_in_order: rules
                  .filter((x) => x.enabled !== false)
                  .map((x) => x.action),
              }),
          project_rule_count: rules.filter((x) => String(x.ref || '').startsWith('shortlink_new_'))
            .length,
          exact_api_expression_count: rules.filter((x) => x.expression === API_MATCH).length,
          potentially_host_related_expression_count: rules.filter((x) =>
            String(x.expression || '').includes(EXPECTED.ADMIN_HOSTNAME),
          ).length,
          rules_configuration_withheld: true,
        });
      }
      return {
        ruleset_count: metadata.length,
        relevant: rows,
        complete: true,
        limit:
          '100 pages, Rulesets 50 items/page with cursors.after, other lists 100; 8MiB each response; limits fail PARTIAL',
      };
    });
  }
  return {
    schema: 1,
    source: credential.source,
    scope: 'fixed account, lily.lat, link-admin.lily.lat',
    result: checks.every((c) => c.result === 'PASS') ? 'READ_COMPLETED_REVIEW_REQUIRED' : 'PENDING',
    checks,
    unverified:
      'No Access login, WAF hit, write permission, runtime API or shared Turnstile validation; no configuration changed.',
  };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const r = await main();
    console.log(JSON.stringify(r, null, 2));
    process.exitCode = r.result === 'READ_COMPLETED_REVIEW_REQUIRED' ? 0 : 2;
  } catch (e) {
    console.error(JSON.stringify(safeError(e)));
    process.exitCode = 2;
  }
}
