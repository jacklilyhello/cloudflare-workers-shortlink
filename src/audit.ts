import { basicAuditIdentity, type AuditFilterOptions } from './audit-identity';
import type { AuditRow, Env } from './types';

const TOKEN_ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;

export async function auditFilterOptions(env: Env): Promise<AuditFilterOptions> {
  const [actors, actions] = await env.DB.batch<Record<string, unknown>>([
    env.DB.prepare(
      `SELECT a.actor,t.label AS token_label,
       MAX(CASE WHEN a.action='link.create' THEN 1 ELSE 0 END) AS has_link_create
       FROM audit a LEFT JOIN tokens t ON t.id=a.actor
       GROUP BY a.actor,t.label ORDER BY a.actor LIMIT 201`,
    ),
    env.DB.prepare('SELECT DISTINCT action FROM audit ORDER BY action LIMIT 101'),
  ]);
  return {
    actors: actors.results.slice(0, 200).map((row) => {
      const actor = row.actor as string;
      const identity = basicAuditIdentity(actor);
      if (
        identity.type === 'unknown' &&
        TOKEN_ID.test(actor) &&
        (typeof row.token_label === 'string' || row.has_link_create === 1)
      ) {
        identity.type = 'business_token';
        identity.name = typeof row.token_label === 'string' ? row.token_label : null;
        identity.token_id = actor;
      }
      return { actor, actor_identity: identity };
    }),
    actions: actions.results.slice(0, 100).map((row) => row.action as string),
    actors_truncated: actors.results.length > 200,
    actions_truncated: actions.results.length > 100,
  };
}

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
