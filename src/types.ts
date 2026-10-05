export interface Env {
  DB: D1Database;
  BACKUPS?: R2Bucket;
  ASSETS?: Fetcher;
  APP_ENV: string;
  PUBLIC_HOSTNAME: string;
  ADMIN_HOSTNAME: string;
  WORKERS_DEV_HOSTNAME?: string;
  TURNSTILE_SITE_KEY: string;
  TURNSTILE_SECRET_KEY: string;
  CF_ACCESS_TEAM_DOMAIN?: string;
  CF_ACCESS_AUD?: string;
  ADMIN_EMAILS: string;
  CLOUDFLARE_ACCOUNT_ID?: string;
  WORKER_NAME?: string;
  D1_DATABASE_ID?: string;
  RESOURCE_OWNER_ID?: string;
  DOMAIN_BINDING_READ_TOKEN?: string;
}

export interface LinkRow {
  id: string;
  domain: string;
  slug: string;
  url: string;
  created_at: number | null;
  expires_at: number | null;
  enabled: number;
  confirm_enabled: number;
  confirm_text: string;
  query_mode: 'merge' | 'preserve';
  source: 'machine' | 'anonymous' | 'migration' | 'admin';
  creator: string;
  token_id: string | null;
  idempotency_key: string | null;
  request_hash: string | null;
}

export interface TokenRow {
  id: string;
  label: string;
  digest: string;
  created_at: number;
  expires_at: number | null;
  revoked_at: number | null;
  rate_per_minute: number;
}

export interface DomainRow {
  hostname: string;
  enabled: number;
  bound: number;
  created_at: number;
  binding_state: 'unbound' | 'pending' | 'verified' | 'failed';
  last_verified_at: number | null;
  last_checked_at: number | null;
  binding_error: string | null;
}
