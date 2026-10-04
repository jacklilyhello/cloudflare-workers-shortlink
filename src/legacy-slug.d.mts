export function isNewSlug(value: unknown): value is string;
export function isSafeLegacySlug(value: unknown): value is string;
export function decodeLegacyPath(
  pathname: string,
): { slug: string; requiresMigration: boolean } | null;
export function encodeLegacySlug(slug: string): string;
