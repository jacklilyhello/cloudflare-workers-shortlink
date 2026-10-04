const encoder = new TextEncoder();
const RESERVED = new Set([
  'api',
  'admin',
  'login',
  'logout',
  'assets',
  'static',
  'robots',
  'favicon',
  'health',
  'config',
  '_internal',
]);
const LEGACY_RESERVED = new Set([
  ...RESERVED,
  'robots.txt',
  'favicon.ico',
  'status.css',
  'index.html',
]);

export function isNewSlug(value) {
  return (
    typeof value === 'string' &&
    /^[A-Za-z0-9_-]{1,64}$/.test(value) &&
    !RESERVED.has(value.toLowerCase())
  );
}

// Preserve the exact legacy key, including spaces and normalization form.
export function isSafeLegacySlug(value) {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    encoder.encode(value).byteLength <= 512 &&
    /^[\p{L}\p{M}\p{N}._ '\uFF08\uFF09-]+$/u.test(value) &&
    !/[\p{C}\p{Default_Ignorable_Code_Point}]/u.test(value) &&
    value !== '.' &&
    value !== '..' &&
    !LEGACY_RESERVED.has(value.toLowerCase()) &&
    !value.startsWith('SYS_CONFIG_')
  );
}

export function decodeLegacyPath(pathname) {
  if (typeof pathname !== 'string' || !pathname.startsWith('/')) return null;
  const segment = pathname.slice(1);
  if (!segment || segment.includes('/') || encoder.encode(segment).byteLength > 1536) return null;
  if (isNewSlug(segment)) return { slug: segment, requiresMigration: false };
  try {
    const slug = decodeURIComponent(segment);
    return isSafeLegacySlug(slug) ? { slug, requiresMigration: true } : null;
  } catch {
    return null;
  }
}

export function encodeLegacySlug(slug) {
  return encodeURIComponent(slug).replace(/'/g, '%27');
}
