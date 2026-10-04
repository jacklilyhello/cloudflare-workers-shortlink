import { ADMIN_ZONE, DeliveryError, ensure } from './cf-client.mjs';

const PHASES = new Set([
  'ddos_l4',
  'ddos_l7',
  'http_config_settings',
  'http_custom_errors',
  'http_log_custom_fields',
  'http_ratelimit',
  'http_request_cache_settings',
  'http_request_cloud_connector',
  'http_request_dynamic_redirect',
  'http_request_firewall_custom',
  'http_request_firewall_managed',
  'http_request_late_transform',
  'http_request_origin',
  'http_request_redirect',
  'http_request_sanitize',
  'http_request_sbfm',
  'http_request_snippets',
  'http_request_transform',
  'http_response_cache_settings',
  'http_response_compression',
  'http_response_firewall_managed',
  'http_response_headers_transform',
  'magic_transit',
  'magic_transit_ids_managed',
  'magic_transit_managed',
  'magic_transit_ratelimit',
]);
const KINDS = new Set(['managed', 'custom', 'root', 'zone']);
const READ_ERRORS = new Set([
  'AUTH_FAILED',
  'PERMISSION_DENIED',
  'NOT_FOUND',
  'RATE_LIMITED',
  'CF_API_ERROR',
  'CF_API_CHALLENGE',
  'NETWORK_OR_REDIRECT_BLOCKED',
  'AUTHENTICATED_REDIRECT_BLOCKED',
  'NON_JSON_RESPONSE',
  'INVALID_CF_RESPONSE',
  'RESPONSE_TOO_LARGE',
  'RESPONSE_BODY_MISSING',
  'RULESET_DETAIL_METADATA_MISMATCH',
]);
const validMetadata = (r) =>
  r &&
  typeof r === 'object' &&
  !Array.isArray(r) &&
  typeof r.id === 'string' &&
  /^[a-f\d]{32}$/i.test(r.id) &&
  KINDS.has(r.kind) &&
  PHASES.has(r.phase);

export function validateRulesetCatalog(metadata) {
  ensure(Array.isArray(metadata), 'RULESET_CATALOG_INVALID');
  const ids = new Set();
  const entryPhases = new Set();
  for (const r of metadata) {
    ensure(validMetadata(r) && !ids.has(r.id.toLowerCase()), 'RULESET_CATALOG_INVALID');
    ids.add(r.id.toLowerCase());
    if (r.kind === 'zone') {
      ensure(!entryPhases.has(r.phase), 'MULTIPLE_RULESET_PHASE_ENTRYPOINTS');
      entryPhases.add(r.phase);
    }
  }
  return metadata;
}

export function rulesetContext(metadata) {
  ensure(validMetadata(metadata) && metadata.kind === 'zone', 'RULESET_CATALOG_INVALID');
  return { ruleset_kind: metadata.kind, ruleset_phase: metadata.phase };
}

export async function readZoneEntrypoint(client, metadata) {
  const context = rulesetContext(metadata);
  try {
    const response = await client.request(`${ADMIN_ZONE}/rulesets/${metadata.id}`);
    const detail = response.result;
    ensure(
      detail &&
        typeof detail === 'object' &&
        !Array.isArray(detail) &&
        detail.id === metadata.id &&
        detail.kind === metadata.kind &&
        detail.phase === metadata.phase &&
        Array.isArray(detail.rules),
      'RULESET_DETAIL_METADATA_MISMATCH',
    );
    return detail;
  } catch (error) {
    // Codes contain only fixed enum labels. Never include a raw ID, name, expression or API body.
    const reason =
      error instanceof DeliveryError && READ_ERRORS.has(error.code) ? error.code : 'READ_FAILED';
    const wrapped = new DeliveryError(
      `RULESET_DETAIL_${context.ruleset_kind.toUpperCase()}_${context.ruleset_phase.toUpperCase()}_${reason}`,
      error instanceof DeliveryError ? error.status : null,
      error instanceof DeliveryError ? error.cfCodes : [],
      'ZONE_RULESETS',
    );
    wrapped.requestMethod = 'GET';
    throw wrapped;
  }
}
