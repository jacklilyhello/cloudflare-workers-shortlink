export interface AuditActorIdentity {
  type: 'admin' | 'business_token' | 'anonymous' | 'system' | 'unknown';
  name: string | null;
  token_id: string | null;
  created_by: string | null;
}

// Interpret only actor formats emitted by this application; unknown identifiers stay unknown.
export function basicAuditIdentity(actor: unknown): AuditActorIdentity {
  const identity: AuditActorIdentity = {
    type: 'unknown',
    name: null,
    token_id: null,
    created_by: null,
  };
  if (actor === 'system:scheduled' || actor === 'system:production-migration') {
    identity.type = 'system';
    identity.name = actor === 'system:scheduled' ? '定时任务' : '生产迁移备份';
  } else if (actor === 'anonymous') {
    identity.type = 'anonymous';
  } else if (typeof actor === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(actor)) {
    identity.type = 'admin';
    identity.name = actor;
  }
  return identity;
}
