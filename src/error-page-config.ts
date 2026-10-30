export const ERROR_PAGE_KEYS = ['error_403', 'error_404', 'error_disabled', 'error_500'] as const;

export type ErrorPageKey = (typeof ERROR_PAGE_KEYS)[number];
export type ErrorPage = { mode: 'text' | 'html'; text: string; html: string };

export const ERROR_PAGE_HTML_MAX_BYTES = 128 * 1024;

export function isErrorPageKey(value: unknown): value is ErrorPageKey {
  return typeof value === 'string' && ERROR_PAGE_KEYS.some((key) => key === value);
}

export function validErrorPageHtml(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    new TextEncoder().encode(value).byteLength <= ERROR_PAGE_HTML_MAX_BYTES &&
    !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)
  );
}
