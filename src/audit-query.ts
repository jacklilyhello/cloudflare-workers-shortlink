import { ApiError } from './core';

const SINGLE_PARAMETERS = ['q', 'from', 'to', 'actor', 'system_only', 'cursor'];
const MAX_TIME = 8640000000000000;
const ACTION = /^[a-z][a-z0-9_.-]{0,79}$/;

function invalid(message: string): never {
  throw new ApiError(400, 'INVALID_FIELD', message);
}

function timestamp(value: string | null): number | null {
  if (value === null) return null;
  if (!/^\d{1,16}$/.test(value)) invalid('审计时间须为有效的 Unix 毫秒');
  const time = Number(value);
  if (!Number.isSafeInteger(time) || time > MAX_TIME) invalid('审计时间须为有效的 Unix 毫秒');
  return time;
}

export function auditQuery(url: URL): { sql: string; params: (string | number)[] } {
  const search = url.searchParams;
  for (const name of SINGLE_PARAMETERS)
    if (search.getAll(name).length > 1) invalid('审计筛选参数不能重复');

  const rawCursor = search.get('cursor');
  if (
    rawCursor !== null &&
    (!/^\d{1,16}$/.test(rawCursor) || !Number.isSafeInteger(Number(rawCursor)))
  )
    throw new ApiError(400, 'INVALID_CURSOR', '游标无效');
  const params: (string | number)[] = [
    rawCursor === null ? Number.MAX_SAFE_INTEGER : Number(rawCursor),
  ];
  const where = ['a.rowid<?'];
  const query = search.get('q')?.trim() ?? '';
  if (query.length > 200) invalid('审计搜索条件不能超过 200 个字符');
  if (query) {
    // Literal substring search avoids D1's small LIKE/GLOB pattern limit.
    where.push(`(instr(lower(a.actor),lower(?))>0
      OR instr(lower(a.action),lower(?))>0
      OR instr(lower(a.entity_id),lower(?))>0
      OR EXISTS(SELECT 1 FROM tokens t WHERE t.id=a.actor AND instr(lower(t.label),lower(?))>0))`);
    params.push(query, query, query, query);
  }

  const from = timestamp(search.get('from'));
  const to = timestamp(search.get('to'));
  if (from !== null && to !== null && from > to) invalid('开始时间不能晚于结束时间');
  if (from !== null) {
    where.push('a.created_at>=?');
    params.push(from);
  }
  if (to !== null) {
    where.push('a.created_at<=?');
    params.push(to);
  }

  const actor = search.get('actor');
  if (actor !== null) {
    if (!actor.length || actor.length > 200 || /[\u0000-\u001f\u007f-\u009f]/.test(actor))
      invalid('操作者筛选须为 1–200 个字符，且不能包含控制字符');
    where.push('a.actor=?');
    params.push(actor);
  }

  const system = search.get('system_only');
  if (system !== null) {
    if (system !== '1') invalid('系统操作筛选无效');
    where.push('a.actor IN (?,?)');
    params.push('system:scheduled', 'system:production-migration');
  }

  const exclusions = search.getAll('exclude_action');
  if (exclusions.length > 20 || exclusions.some((action) => !ACTION.test(action)))
    invalid('最多排除 20 个操作类型，操作名称格式须有效');
  const actions = [...new Set(exclusions)];
  if (actions.length) {
    where.push(`a.action NOT IN (${actions.map(() => '?').join(',')})`);
    params.push(...actions);
  }
  return {
    sql: `SELECT a.rowid AS cursor,a.* FROM audit a WHERE ${where.join(' AND ')} ORDER BY a.rowid DESC LIMIT 51`,
    params,
  };
}
