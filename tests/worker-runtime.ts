import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { build } from 'vite';

export async function bundleWorker(): Promise<string> {
  const built = await build({
    configFile: false,
    root: fileURLToPath(new URL('..', import.meta.url)),
    logLevel: 'silent',
    build: {
      write: false,
      minify: false,
      target: 'es2022',
      rollupOptions: { external: ['cloudflare:workers'] },
      lib: {
        entry: fileURLToPath(new URL('../src/index.ts', import.meta.url)),
        formats: ['es'],
        fileName: 'worker',
      },
    },
  });
  const builds = Array.isArray(built) ? built : [built];
  const chunks = builds.flatMap((result) =>
    'output' in result ? result.output.filter((output) => output.type === 'chunk') : [],
  );
  if (chunks.length !== 1) throw new Error('Expected one Worker bundle');
  return chunks[0].code;
}

export async function migrateTestDatabase(db: D1Database): Promise<void> {
  for (const file of (await readdir(new URL('../migrations/', import.meta.url)))
    .filter((name) => name.endsWith('.sql'))
    .sort()) {
    const sql = await readFile(new URL(`../migrations/${file}`, import.meta.url), 'utf8');
    await db.batch(
      sql
        .split(';')
        .filter((statement) => statement.trim())
        .map((statement) => db.prepare(statement)),
    );
  }
}
