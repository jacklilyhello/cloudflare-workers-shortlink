import { basicAuditIdentity } from './audit-identity';
import type { AuditRow, Env } from './types';

const TOKEN_ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;

export async function auditIdentities(env: Env, rows: AuditRow[]) {
  const ids = [...new Set(rows.map((row) => row.actor).filter((actor) => TOKEN_ID.test(actor)))];
  const tokens = new Map<string, string>();
  const creators = new Map<string, string>();
  if (ids.length) {
    const placeholders = ids.map(() => '?').join(',');
    // Include revoked/expired tokens and creation records outside this audit page.
    // Resolve creators in one scan, rather than scanning the audit table for every row.
    const [tokenRows, creationRows] = await env.DB.batch<Record<string, unknown>>([
      env.DB.prepare(`SELECT id,label FROM tokens WHERE id IN (${placeholders})`).bind(...ids),
      env.DB.prepare(
        `SELECT entity_id,MIN(actor) AS created_by FROM audit
         WHERE action='token.create' AND entity_id IN (${placeholders})
         GROUP BY entity_id HAVING COUNT(DISTINCT actor)=1`,
      ).bind(...ids),
    ]);
    for (const row of tokenRows.results) {
      if (typeof row.id === 'string' && typeof row.label === 'string')
        tokens.set(row.id, row.label);
    }
    for (const row of creationRows.results) {
      if (
        typeof row.entity_id === 'string' &&
        typeof row.created_by === 'string' &&
        basicAuditIdentity(row.created_by).type === 'admin'
      )
        creators.set(row.entity_id, row.created_by);
    }
  }
  return rows.map((row) => {
    const identity = basicAuditIdentity(row.actor);
    if (
      identity.type === 'unknown' &&
      TOKEN_ID.test(row.actor) &&
      (tokens.has(row.actor) || creators.has(row.actor) || row.action === 'link.create')
    ) {
      identity.type = 'business_token';
      identity.name = tokens.get(row.actor) ?? null;
      identity.token_id = row.actor;
      identity.created_by = creators.get(row.actor) ?? null;
    }
    return { ...row, actor_identity: identity };
  });
}
