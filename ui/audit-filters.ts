export interface AuditFilterValues {
  q: string;
  actor: string;
  from: string;
  to: string;
  excludeActions: readonly string[];
}

function auditTime(value: string): number | null {
  if (!value) return null;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(value))
    throw new Error('请输入有效的日期和时间。');
  const canonical = value.length === 16 ? `${value}:00` : value;
  const time = new Date(`${canonical}+08:00`).getTime();
  if (
    !Number.isFinite(time) ||
    time < 0 ||
    new Date(time + 8 * 3600000).toISOString().slice(0, 19) !== canonical
  )
    throw new Error('日期或时间无效，请使用 1970 年起的有效日期（UTC+8）。');
  return time;
}

export function auditFilterParams(values: AuditFilterValues): URLSearchParams {
  const params = new URLSearchParams();
  const query = values.q.trim();
  if (query.length > 200) throw new Error('搜索内容最多 200 个字符。');
  if (query) params.set('q', query);
  if (values.actor === 'system') params.set('system_only', '1');
  else if (values.actor) {
    const actor = values.actor.startsWith('actor:') ? values.actor.slice(6) : '';
    if (!actor || actor.length > 200 || /[\u0000-\u001f\u007f-\u009f]/.test(actor))
      throw new Error('操作者筛选无效，请重新选择。');
    params.set('actor', actor);
  }
  const from = auditTime(values.from);
  const to = auditTime(values.to);
  if (from !== null && to !== null && from > to) throw new Error('开始时间不能晚于结束时间。');
  if (from !== null) params.set('from', String(from));
  // datetime-local has second precision; include the entire selected ending second.
  if (to !== null) params.set('to', String(to + 999));
  if (values.excludeActions.length > 20) throw new Error('最多排除 20 种操作类型。');
  for (const action of new Set(values.excludeActions)) {
    if (!/^[a-z][a-z0-9_.-]{0,79}$/.test(action)) throw new Error('操作类型无效，请重新选择。');
    params.append('exclude_action', action);
  }
  return params;
}

const ACTION_LABELS: Record<string, string> = {
  'link.create': '创建短链接',
  'link.update': '修改短链接',
  'link.delete': '彻底删除短链接',
  'link.bulk.enable': '批量启用短链接',
  'link.bulk.disable': '批量停用短链接',
  'link.bulk.expiry': '批量设置到期时间',
  'token.create': '创建业务 Token',
  'token.revoke': '撤销业务 Token',
  'domain.register': '登记域名',
  'domain.verify': '核验域名绑定',
  'domain.verify_failed': '域名绑定核验失败',
  'domain.update': '修改域名状态',
  'backup.create': '创建备份',
  'settings.update': '修改系统设置',
  'error_page.update': '修改应用错误页',
};

export function auditActionLabel(action: string): string {
  return Object.hasOwn(ACTION_LABELS, action) ? `${ACTION_LABELS[action]}（${action}）` : action;
}
