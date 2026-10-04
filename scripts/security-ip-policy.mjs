import { isIP } from 'node:net';
import { ACCOUNT, ensure, listAll } from './cf-client.mjs';

function addressInteger(text, bits) {
  if (bits === 32) return text.split('.').reduce((n, part) => (n << 8n) + BigInt(part), 0n);
  let input = text;
  if (input.includes('.')) {
    const split = input.lastIndexOf(':');
    const v4 = addressInteger(input.slice(split + 1), 32);
    input = `${input.slice(0, split)}:${(v4 >> 16n).toString(16)}:${(v4 & 65535n).toString(16)}`;
  }
  const [left, right] = input.split('::');
  const l = left ? left.split(':') : [];
  const r = right ? right.split(':') : [];
  const segments =
    right !== undefined ? [...l, ...Array(8 - l.length - r.length).fill('0'), ...r] : l;
  ensure(segments.length === 8, 'IP_LIST_IPV6_INVALID');
  return segments.reduce((n, part) => (n << 16n) + BigInt(`0x${part}`), 0n);
}
export function validateRestrictedIPs(ips) {
  ensure(
    Array.isArray(ips) && ips.length > 0 && ips.length <= 100000,
    'PRODUCTION_IP_LIST_EMPTY_OR_TOO_LARGE',
  );
  const families = { 32: [], 128: [] };
  for (const ip of ips) {
    ensure(typeof ip === 'string' && !ip.includes('%'), 'IP_LIST_VALUE_INVALID');
    const parts = ip.split('/');
    ensure(parts.length <= 2, 'IP_LIST_VALUE_INVALID');
    const family = isIP(parts[0]);
    ensure(family > 0, 'IP_LIST_VALUE_INVALID');
    const bits = family === 4 ? 32 : 128;
    const prefix = parts[1] === undefined ? bits : Number(parts[1]);
    ensure(
      Number.isInteger(prefix) &&
        prefix >= 1 &&
        prefix <= bits &&
        (!parts[1] || /^\d+$/.test(parts[1])),
      'PRODUCTION_ALL_NETWORK_CIDR_FORBIDDEN',
    );
    const shift = BigInt(bits - prefix);
    const size = 1n << shift;
    const lo = (addressInteger(parts[0], bits) >> shift) << shift;
    families[bits].push([lo, lo + size - 1n]);
  }
  for (const [bits, ranges] of Object.entries(families)) {
    ranges.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    let coveredTo = -1n;
    for (const [lo, hi] of ranges) {
      if (lo > coveredTo + 1n) break;
      if (hi > coveredTo) coveredTo = hi;
    }
    ensure(coveredTo < (1n << BigInt(bits)) - 1n, 'PRODUCTION_FULL_FAMILY_ALLOWLIST_FORBIDDEN');
  }
  return { restricted: true, item_count: ips.length }; // Never return addresses or CIDRs to logs/configuration.
}
export async function verifyIPCondition(client, condition) {
  const named = /^ip\.src in \$([A-Za-z][A-Za-z0-9_]*)$/.exec(condition);
  let values;
  if (named) {
    const lists = await listAll(client, `${ACCOUNT}/rules/lists`);
    const found = lists.filter((l) => l.name === named[1]);
    ensure(
      found.length === 1 && found[0].kind === 'ip' && /^[a-f\d]{32}$/i.test(found[0].id),
      'PRODUCTION_IP_LIST_UNVERIFIED',
    );
    const items = await listAll(client, `${ACCOUNT}/rules/lists/${found[0].id}/items`, {
      pageSize: 500,
      maxPages: 200,
    });
    values = items.map((item) => item.ip);
  } else {
    const inline = /^ip\.src in \{([0-9a-fA-F:.\/ ]+)\}$/.exec(condition);
    ensure(inline, 'PRODUCTION_IP_CONDITION_UNVERIFIED');
    values = inline[1].trim().split(/\s+/);
  }
  return validateRestrictedIPs(values);
}
