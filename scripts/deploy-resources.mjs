import { createHash, randomUUID } from 'node:crypto';
import {
  ACCOUNT,
  PUBLIC_ZONE,
  ADMIN_ZONE,
  EXPECTED,
  REPOSITORY,
  BUCKET,
  DATABASE,
  OWNER_KEY,
  DeliveryError,
  ensure,
  fail,
  listAll,
} from './cf-client.mjs';

const UUID = /^[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12}$/i;
export const objectPath = (key) =>
  `${ACCOUNT}/r2/buckets/${BUCKET}/objects/${key.split('/').map(encodeURIComponent).join('/')}`;
export async function readManifest(client) {
  const payload = await client.optional(objectPath(OWNER_KEY), { raw: true, maxBytes: 256 * 1024 });
  if (payload === null) return null;
  let manifest;
  try {
    manifest = JSON.parse(payload);
  } catch {
    fail('OWNERSHIP_MANIFEST_INVALID');
  }
  validateManifest(manifest);
  return manifest;
}
export function validateManifest(m) {
  ensure(
    m?.schema === 1 &&
      m.project === REPOSITORY &&
      m.account === EXPECTED.CLOUDFLARE_ACCOUNT_ID &&
      m.worker === EXPECTED.WORKER_NAME &&
      m.environment === 'test' &&
      m.bucket === BUCKET &&
      UUID.test(m.owner_id),
    'RESOURCE_OWNERSHIP_UNPROVEN',
  );
  if (m.d1) ensure(m.d1.name === DATABASE && UUID.test(m.d1.id), 'D1_OWNERSHIP_UNPROVEN');
  for (const domain of Object.keys(m.domains || {}))
    ensure(
      [EXPECTED.PUBLIC_HOSTNAME, EXPECTED.ADMIN_HOSTNAME].includes(domain),
      'FOREIGN_DOMAIN_IN_MANIFEST',
    );
}
export async function saveManifest(client, manifest) {
  validateManifest(manifest);
  manifest.updated_at = new Date().toISOString();
  await client.request(objectPath(OWNER_KEY), {
    method: 'PUT',
    body: JSON.stringify(manifest),
    contentType: 'application/json',
  });
}
export async function privateSnapshot(client, manifest, key, data) {
  ensure(/^[a-z0-9-]+$/.test(key), 'SNAPSHOT_KEY_INVALID');
  await client.request(objectPath(`delivery/${manifest.owner_id}/${key}.json`), {
    method: 'PUT',
    body: JSON.stringify(data),
    contentType: 'application/json',
  });
}
export async function query(client, id, sql, params = []) {
  ensure(UUID.test(id), 'D1_ID_INVALID');
  const payload = await client.request(`${ACCOUNT}/d1/database/${id}/query`, {
    method: 'POST',
    json: { sql, params },
  });
  ensure(
    Array.isArray(payload.result) &&
      payload.result.length > 0 &&
      payload.result.every((r) => r.success === true),
    'D1_QUERY_FAILED',
  );
  return payload.result;
}
export async function verifyD1Owner(client, manifest) {
  validateManifest(manifest);
  ensure(manifest.d1, 'BOOTSTRAP_REQUIRED');
  const meta = await client.request(`${ACCOUNT}/d1/database/${manifest.d1.id}`);
  ensure(meta.result.name === DATABASE && meta.result.uuid === manifest.d1.id, 'D1_RESOURCE_DRIFT');
  const rows = await query(
    client,
    manifest.d1.id,
    'SELECT project, owner_id, account_id, worker FROM delivery_ownership WHERE singleton = 1',
  );
  const owner = rows[0].results?.[0];
  ensure(
    owner?.project === REPOSITORY &&
      owner.owner_id === manifest.owner_id &&
      owner.account_id === EXPECTED.CLOUDFLARE_ACCOUNT_ID &&
      owner.worker === EXPECTED.WORKER_NAME,
    'D1_OWNERSHIP_UNPROVEN',
  );
}
const ownerMatches = (owner, manifest) =>
  owner?.project === REPOSITORY &&
  owner.owner_id === manifest.owner_id &&
  owner.account_id === EXPECTED.CLOUDFLARE_ACCOUNT_ID &&
  owner.worker === EXPECTED.WORKER_NAME;
export async function reconcileD1(client, manifest, database) {
  ensure(
    manifest &&
      database?.name === DATABASE &&
      UUID.test(database.uuid) &&
      manifest.journal?.some((j) => j.step === 'create-d1' && j.state === 'intent'),
    'EXISTING_D1_UNOWNED',
  );
  // Only the fixed marker table is read; intent/name alone never authorizes a write to this database.
  const rows = await query(
    client,
    database.uuid,
    'SELECT project, owner_id, account_id, worker FROM delivery_ownership WHERE singleton = 1',
  );
  ensure(ownerMatches(rows[0].results?.[0], manifest), 'EXISTING_D1_UNOWNED');
  manifest.d1 = { name: DATABASE, id: database.uuid };
  await saveManifest(client, manifest);
}
export function hostPatternMatches(pattern, host) {
  const p = String(pattern)
    .replace(/^https?:\/\//i, '')
    .split('/')[0]
    .toLowerCase();
  const escaped = p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i').test(host);
}
export async function inspectHost(client, host, manifest, { recover = false } = {}) {
  ensure(
    [EXPECTED.PUBLIC_HOSTNAME, EXPECTED.ADMIN_HOSTNAME].includes(host),
    'UNAUTHORIZED_HOSTNAME',
  );
  const zone = host === EXPECTED.PUBLIC_HOSTNAME ? PUBLIC_ZONE : ADMIN_ZONE;
  const [dns, routes, domains] = await Promise.all([
    listAll(client, `${zone}/dns_records`),
    listAll(client, `${zone}/workers/routes`),
    listAll(client, `${ACCOUNT}/workers/domains`),
  ]);
  const custom = domains.filter((d) => d.hostname === host);
  let owned = manifest?.domains?.[host];
  const intent = manifest?.domain_intents?.[host];
  const intentProven =
    intent?.owner_id === manifest?.owner_id &&
    intent?.service === EXPECTED.WORKER_NAME &&
    intent?.zone_id === zone.split('/').at(-1);
  ensure(custom.length <= 1, 'DUPLICATE_CUSTOM_DOMAIN');
  if (custom.length && !owned && recover && intentProven && manifest.worker_created) {
    await verifyD1Owner(client, manifest);
    await inspectWorker(client, manifest);
    ensure(
      custom[0].service === EXPECTED.WORKER_NAME && custom[0].zone_id === zone.split('/').at(-1),
      'EXISTING_DOMAIN_UNOWNED',
    );
    owned = manifest.domains[host] = { id: custom[0].id, zone_id: custom[0].zone_id };
    await saveManifest(client, manifest);
  }
  if (custom.length)
    ensure(
      owned &&
        custom[0].id === owned.id &&
        custom[0].service === EXPECTED.WORKER_NAME &&
        custom[0].zone_id === zone.split('/').at(-1),
      'EXISTING_DOMAIN_UNOWNED',
    );
  else ensure(!owned, 'OWNED_DOMAIN_MISSING');
  const matchingRoutes = routes.filter((r) => hostPatternMatches(r.pattern, host));
  ensure(matchingRoutes.length === 0, 'BROAD_OR_EXISTING_WORKER_ROUTE_CONFLICT');
  const exactDNS = dns.filter((d) => d.name === host);
  // Existing custom domains' managed DNS is accepted only with recorded domain ownership.
  if (exactDNS.length) {
    ensure(
      custom.length === 1 &&
        owned &&
        exactDNS.every(
          (d) =>
            d.proxied === true &&
            ((d.type === 'AAAA' && d.content === '100::') ||
              (d.type === 'CNAME' &&
                manifest?.workers_hostname &&
                d.content === manifest.workers_hostname)),
        ),
      'EXISTING_DNS_CONFLICT',
    );
    const signature = createHash('sha256')
      .update(
        JSON.stringify(
          exactDNS
            .map((d) => ({
              id: d.id,
              type: d.type,
              content: d.content,
              proxied: d.proxied,
              meta: d.meta || {},
            }))
            .sort((a, b) => String(a.id).localeCompare(String(b.id))),
        ),
      )
      .digest('hex');
    if (!owned.dns_signature && recover && intentProven) {
      await verifyD1Owner(client, manifest);
      await inspectWorker(client, manifest);
      owned.dns_signature = signature;
      await saveManifest(client, manifest);
    }
    ensure(owned.dns_signature === signature, 'OWNED_DNS_DRIFT_OR_UNPROVEN');
  } else ensure(!custom.length, 'CUSTOM_DOMAIN_MANAGED_DNS_MISSING');
  const wildcardDNS = dns.filter(
    (d) => String(d.name).startsWith('*.') && host.endsWith(String(d.name).slice(1)),
  );
  ensure(wildcardDNS.length === 0, 'WILDCARD_DNS_CONFLICT_REVIEW_REQUIRED');
  return { custom: custom[0] || null };
}
export function workerOwnerMatches(settings, manifest) {
  const b = settings?.bindings || [];
  return (
    b.some(
      (x) =>
        x.name === 'RESOURCE_OWNER_ID' && x.type === 'plain_text' && x.text === manifest.owner_id,
    ) &&
    b.some((x) => x.name === 'DB' && x.type === 'd1' && x.id === manifest.d1?.id) &&
    b.some((x) => x.name === 'BACKUPS' && x.type === 'r2_bucket' && x.bucket_name === BUCKET)
  );
}
export async function inspectWorker(client, manifest) {
  const response = await client.optional(
    `${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}/settings`,
  );
  if (response)
    ensure(manifest && workerOwnerMatches(response.result, manifest), 'EXISTING_WORKER_UNOWNED');
  else ensure(!manifest?.worker_created, 'OWNED_WORKER_MISSING');
  return response;
}
export async function requireBootstrapComplete(client, manifest) {
  ensure(
    manifest?.security?.status === 'ready' &&
      manifest.worker_created === true &&
      manifest.journal?.some(
        (step) => step.step === 'worker-upload' && step.state === 'complete',
      ) &&
      [
        [EXPECTED.PUBLIC_HOSTNAME, EXPECTED.CF_ZONE_ID_GFW_MOM],
        [EXPECTED.ADMIN_HOSTNAME, EXPECTED.CF_ZONE_ID_LILY_LAT],
      ].every(([host, zone]) => {
        const domain = manifest.domains?.[host];
        return (
          domain?.id && domain.zone_id === zone && /^[a-f\d]{64}$/i.test(domain.dns_signature || '')
        );
      }),
    'BOOTSTRAP_RECOVERY_REQUIRED',
  );
  await verifyD1Owner(client, manifest);
  const rows = await query(
    client,
    manifest.d1.id,
    'SELECT hostname, bound FROM domains WHERE hostname = ?',
    [EXPECTED.PUBLIC_HOSTNAME],
  );
  ensure(
    rows[0].results?.[0]?.hostname === EXPECTED.PUBLIC_HOSTNAME && rows[0].results[0].bound === 1,
    'BOOTSTRAP_RECOVERY_REQUIRED',
  );
  // enabled is deliberately not checked: an administrator-disabled domain remains disabled.
}
export async function prepareResources(client, { bootstrap = false } = {}) {
  const buckets = await listAll(client, `${ACCOUNT}/r2/buckets?name_contains=${BUCKET}`, {
    select: (p) => p.result?.buckets,
  });
  const exists = buckets.some((b) => b.name === BUCKET);
  let manifest = exists ? await readManifest(client) : null;
  if (exists) ensure(manifest, 'EXISTING_R2_BUCKET_UNOWNED');
  if (!bootstrap) {
    ensure(manifest?.d1 && manifest.security && manifest.worker_created, 'BOOTSTRAP_REQUIRED');
    await requireBootstrapComplete(client, manifest);
  }
  // All first-pass conflicts are detected before any creation.
  const databases = await listAll(client, `${ACCOUNT}/d1/database?name=${DATABASE}`);
  const db = databases.find((d) => d.name === DATABASE);
  if (db && bootstrap && !manifest?.d1) await reconcileD1(client, manifest, db);
  if (db) ensure(manifest?.d1?.id === db.uuid, 'EXISTING_D1_UNOWNED');
  else ensure(!manifest?.d1, 'OWNED_D1_MISSING');
  await inspectWorker(client, manifest);
  await inspectHost(client, EXPECTED.PUBLIC_HOSTNAME, manifest, { recover: bootstrap });
  await inspectHost(client, EXPECTED.ADMIN_HOSTNAME, manifest, { recover: bootstrap });
  if (!manifest) {
    ensure(bootstrap, 'BOOTSTRAP_REQUIRED');
    await client.request(`${ACCOUNT}/r2/buckets`, {
      method: 'POST',
      json: { name: BUCKET, locationHint: 'apac' },
    });
    manifest = {
      schema: 1,
      project: REPOSITORY,
      account: EXPECTED.CLOUDFLARE_ACCOUNT_ID,
      worker: EXPECTED.WORKER_NAME,
      environment: 'test',
      bucket: BUCKET,
      owner_id: randomUUID(),
      created_at: new Date().toISOString(),
      domains: {},
      journal: [],
    };
    // Immediate durable marker, before D1/Access/WAF/Worker work. Ambiguous initial PUT fails closed.
    await saveManifest(client, manifest);
  }
  if (!db) {
    ensure(bootstrap, 'BOOTSTRAP_REQUIRED');
    manifest.journal.push({ step: 'create-d1', state: 'intent', time: new Date().toISOString() });
    await saveManifest(client, manifest);
    const created = await client.request(`${ACCOUNT}/d1/database`, {
      method: 'POST',
      json: { name: DATABASE, primary_location_hint: 'apac' },
    });
    ensure(UUID.test(created.result.uuid), 'D1_CREATE_RESULT_INVALID');
    manifest.d1 = { name: DATABASE, id: created.result.uuid };
    // The create response authorizes only its exact returned ID. Write its owner marker before manifest checkpoint,
    // so a failed R2 checkpoint can be recovered by reading the marker, never by the name/intent alone.
    await query(
      client,
      manifest.d1.id,
      'CREATE TABLE IF NOT EXISTS delivery_ownership (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), project TEXT NOT NULL, owner_id TEXT NOT NULL, account_id TEXT NOT NULL, worker TEXT NOT NULL, created_at TEXT NOT NULL)',
    );
    await query(
      client,
      manifest.d1.id,
      'INSERT INTO delivery_ownership (singleton,project,owner_id,account_id,worker,created_at) VALUES (1,?,?,?,?,?) ON CONFLICT(singleton) DO NOTHING',
      [
        REPOSITORY,
        manifest.owner_id,
        EXPECTED.CLOUDFLARE_ACCOUNT_ID,
        EXPECTED.WORKER_NAME,
        manifest.created_at,
      ],
    );
    manifest.journal.push({ step: 'create-d1', state: 'complete', time: new Date().toISOString() });
    await saveManifest(client, manifest);
  }
  await verifyD1Owner(client, manifest);
  return manifest;
}
export async function attachDomains(client, manifest) {
  for (const [hostname, zone] of [
    [EXPECTED.PUBLIC_HOSTNAME, PUBLIC_ZONE],
    [EXPECTED.ADMIN_HOSTNAME, ADMIN_ZONE],
  ]) {
    const { custom } = await inspectHost(client, hostname, manifest, { recover: true });
    if (custom) continue;
    manifest.domain_intents ||= {};
    manifest.domain_intents[hostname] = {
      zone_id: zone.split('/').at(-1),
      service: EXPECTED.WORKER_NAME,
      owner_id: manifest.owner_id,
    };
    await saveManifest(client, manifest);
    const attached = await client.request(`${ACCOUNT}/workers/domains`, {
      method: 'PUT',
      json: {
        hostname,
        service: EXPECTED.WORKER_NAME,
        zone_id: zone.split('/').at(-1),
      },
    });
    ensure(
      attached.result.hostname === hostname && attached.result.service === EXPECTED.WORKER_NAME,
      'CUSTOM_DOMAIN_RESULT_MISMATCH',
    );
    manifest.domains[hostname] = { id: attached.result.id, zone_id: zone.split('/').at(-1) };
    await saveManifest(client, manifest);
    await inspectHost(client, hostname, manifest, { recover: true });
  }
}
