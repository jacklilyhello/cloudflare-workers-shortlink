export interface AuditActorIdentity {
  type: 'admin' | 'business_token' | 'anonymous' | 'system' | 'unknown';
  name: string | null;
  token_id: string | null;
  created_by: string | null;
}
