import { describe, expect, it } from 'vitest';
import { auditFilterParams } from '../ui/audit-filters';

function params(overrides: Partial<Parameters<typeof auditFilterParams>[0]> = {}) {
  return auditFilterParams({
    q: '',
    actor: '',
    from: '',
    to: '',
    excludeActions: [],
    ...overrides,
  });
}

describe('audit filter query values', () => {
  it('leaves an empty form unfiltered and never introduces a pagination cursor', () => {
    expect(params().toString()).toBe('');
    expect(params({ q: '  ' }).toString()).toBe('');
    expect(params({ q: 'audit' }).has('cursor')).toBe(false);
  });

  it('preserves literal multilingual search text and safely encodes an exact administrator email', () => {
    const query = params({
      q: '  robot_% 中文 & action=backup.create  ',
      actor: 'actor:fixture+operator@example.test',
      excludeActions: ['backup.create', 'link.create', 'backup.create'],
    });
    const decoded = new URLSearchParams(query.toString());
    expect(decoded.get('q')).toBe('robot_% 中文 & action=backup.create');
    expect(decoded.get('actor')).toBe('fixture+operator@example.test');
    expect(decoded.getAll('exclude_action')).toEqual(['backup.create', 'link.create']);
    expect(decoded.has('action')).toBe(false);
    expect(decoded.has('system_only')).toBe(false);
  });

  it('distinguishes all known system jobs from one exact raw Token or system actor', () => {
    expect([...params({ actor: 'system' }).entries()]).toEqual([['system_only', '1']]);
    const tokenId = '00000000-0000-4000-8000-000000000001';
    expect([...params({ actor: `actor:${tokenId}` }).entries()]).toEqual([['actor', tokenId]]);
    expect([...params({ actor: 'actor:system:scheduled' }).entries()]).toEqual([
      ['actor', 'system:scheduled'],
    ]);
    expect(() => params({ actor: 'unknown-selection' })).toThrow();
    expect(() => params({ actor: 'actor:' })).toThrow();
  });

  it('converts Singapore calendar input across UTC dates and includes the selected final second', () => {
    const query = params({ from: '2026-10-31T00:00:00', to: '2026-10-31T23:59:59' });
    expect(query.get('from')).toBe(String(Date.parse('2026-10-30T16:00:00Z')));
    expect(query.get('to')).toBe(String(Date.parse('2026-10-31T15:59:59.999Z')));
    const sameInstant = params({ from: '2026-10-31T09:00', to: '2026-10-31T09:00' });
    expect(Number(sameInstant.get('to')) - Number(sameInstant.get('from'))).toBe(999);
    expect(params({ from: '1970-01-01T08:00:00' }).get('from')).toBe('0');
    expect(() => params({ from: '1970-01-01T07:59:59' })).toThrow();
  });

  it('accepts a real leap day but rejects normalized calendar dates, zones and reversed ranges', () => {
    expect(params({ from: '2024-02-29T13:32:40' }).get('from')).toBe(
      String(Date.parse('2024-02-29T05:32:40Z')),
    );
    for (const invalid of [
      '2026-02-29T13:32:40',
      '2026-02-30T13:32:40',
      '2026-10-31T24:00:00',
      '2026-10-31T09:00:00Z',
      '2026-10-31T09:00:00+08:00',
    ]) {
      expect(() => params({ from: invalid })).toThrow();
      expect(() => params({ to: invalid })).toThrow();
    }
    expect(() => params({ from: '2026-10-31T09:00:01', to: '2026-10-31T09:00:00' })).toThrow();
  });

  it('bounds search and exclusion inputs while retaining valid future operation codes', () => {
    expect(params({ q: '中'.repeat(200) }).get('q')).toBe('中'.repeat(200));
    expect(() => params({ q: 'x'.repeat(201) })).toThrow();
    const actions = Array.from({ length: 20 }, (_, index) => `future.action_${index}`);
    expect(params({ excludeActions: actions }).getAll('exclude_action')).toEqual(actions);
    expect(() => params({ excludeActions: [...actions, 'future.action_extra'] })).toThrow();
    expect(() => params({ excludeActions: Array(21).fill('backup.create') })).toThrow();
    expect(() => params({ excludeActions: ['backup.create OR 1=1'] })).toThrow();
    expect(() => params({ excludeActions: [''] })).toThrow();
  });
});
