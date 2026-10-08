import { readFile } from 'node:fs/promises';
import ts from 'typescript';
import { ACCOUNT, ensure } from './cf-client.mjs';
import { privateSnapshot, query, verifyD1Owner } from './deploy-resources.mjs';
import { verifyFinalMigrationBackup } from './deploy-upgrade-guard.mjs';

// Use the same reviewed atomic snapshot builder as scheduled/admin backups.
// Only the provider adapter changes; the retained job/rows and R2 object format
// remain owned by the existing Worker backup executor.
async function snapshotBuilder() {
  const source = await readFile(new URL('../src/maintenance.ts', import.meta.url), 'utf8');
  const result = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
    reportDiagnostics: true,
  });
  ensure(
    !(result.diagnostics || []).some((row) => row.category === ts.DiagnosticCategory.Error),
    'BACKUP_SOURCE_COMPILATION_FAILED',
  );
  const module = await import(
    `data:text/javascript;base64,${Buffer.from(result.outputText).toString('base64')}`
  );
  ensure(typeof module.startBackup === 'function', 'BACKUP_SOURCE_EXPORT_MISSING');
  return module.startBackup;
}
function d1Adapter(client, id) {
  const call = async (body) => {
    const result = await client.request(`${ACCOUNT}/d1/database/${id}/query`, {
      method: 'POST',
      json: body,
    });
    ensure(
      Array.isArray(result.result) &&
        result.result.length > 0 &&
        result.result.every((row) => row.success === true),
      'D1_QUERY_FAILED',
    );
    return result.result;
  };
  return {
    prepare(sql) {
      const statement = {
        sql,
        params: [],
        bind(...params) {
          this.params = params;
          return this;
        },
        async all() {
          return (await call({ sql: this.sql, params: this.params }))[0];
        },
        async first() {
          return (await this.all()).results?.[0] ?? null;
        },
        async run() {
          return this.all();
        },
      };
      return statement;
    },
    async batch(statements) {
      // Cloudflare's REST batch executes the complete list atomically. No
      // row-by-row snapshot or SQL interpolation can split the captured state.
      return call({ batch: statements.map(({ sql, params }) => ({ sql, params })) });
    },
  };
}
export async function ensureProductionBackup(
  client,
  manifest,
  { finalResult, now = Date.now } = {},
) {
  await verifyD1Owner(client, manifest);
  ensure(
    finalResult?.final_scan_complete && finalResult.lease_released,
    'FINAL_MIGRATION_COMPLETE_PROOF_REQUIRED',
  );
  const complete = (
    await query(
      client,
      manifest.d1.id,
      "SELECT id FROM backup_jobs WHERE status='complete' AND retired_at IS NULL AND created_at>=? ORDER BY completed_at DESC,id DESC LIMIT 1",
      [finalResult.completed_at],
    )
  )[0].results?.[0];
  if (complete)
    return {
      state: 'complete',
      ...(await verifyFinalMigrationBackup(client, manifest, {
        finalResult,
        backupId: complete.id,
        now,
      })),
    };
  const active = (
    await query(
      client,
      manifest.d1.id,
      "SELECT id,created_at,status,lease_until,retry_at,last_error_code FROM backup_jobs WHERE status IN ('pending','uploading') ORDER BY created_at,id LIMIT 1",
    )
  )[0].results?.[0];
  if (active)
    return {
      state:
        active.created_at >= finalResult.completed_at
          ? 'pending_final_backup'
          : 'waiting_existing_backup',
      backup_id: active.id,
      created_at: active.created_at,
      status: active.status,
      lease_active: active.lease_until > now(),
      retry_at: active.retry_at,
      error_code: active.last_error_code,
      final_snapshot: active.created_at >= finalResult.completed_at,
      next_action:
        'read back after the existing Worker scheduled maintenance advances the retained job',
    };
  const failed = (
    await query(
      client,
      manifest.d1.id,
      "SELECT id,created_at,last_error_code,retry_at FROM backup_jobs WHERE status='failed' AND created_at>=? ORDER BY created_at DESC,id DESC LIMIT 1",
      [finalResult.completed_at],
    )
  )[0].results?.[0];
  if (failed)
    return {
      state: 'failed_final_backup',
      backup_id: failed.id,
      created_at: failed.created_at,
      status: 'failed',
      error_code: /^[A-Z_]{1,120}$/.test(failed.last_error_code || '')
        ? failed.last_error_code
        : 'BACKUP_FAILED',
      retry_at: failed.retry_at,
      final_snapshot: true,
      writes_performed: false,
      next_action: 'review this failed retained backup job before any authorized repair or retry',
    };
  const startBackup = await snapshotBuilder();
  const backupId = await startBackup(
    { DB: d1Adapter(client, manifest.d1.id), BACKUPS: {} },
    'system:production-migration',
  );
  const job = (
    await query(client, manifest.d1.id, 'SELECT id,created_at,status FROM backup_jobs WHERE id=?', [
      backupId,
    ])
  )[0].results?.[0];
  ensure(
    job && ['pending', 'uploading', 'complete'].includes(job.status),
    'FINAL_BACKUP_JOB_READBACK_FAILED',
  );
  const saved = {
    owner_id: manifest.owner_id,
    database_id: manifest.d1.id,
    backup_id: job.id,
    created_at: job.created_at,
    final_run_id: finalResult.run_id,
    final_completed_at: finalResult.completed_at,
    atomic_snapshot_builder: 'src/maintenance.ts startBackup',
    recorded_at: now(),
  };
  await privateSnapshot(
    client,
    manifest,
    `final-migration-backup-job-${finalResult.run_id}`,
    saved,
    { preserveExisting: true },
  );
  return {
    state:
      job.created_at >= finalResult.completed_at
        ? 'pending_final_backup'
        : 'waiting_existing_backup',
    backup_id: job.id,
    created_at: job.created_at,
    status: job.status,
    final_snapshot: job.created_at >= finalResult.completed_at,
    next_action:
      'read back after the existing Worker scheduled maintenance advances the retained job',
  };
}
