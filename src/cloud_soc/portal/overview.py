"""Read-only, tenant-scoped case overview; totals are SQL aggregates, never samples."""
from cloud_soc.portal.cases import clean
from cloud_soc.portal.log_contract import parse_filters


def case_overview(store, actor, pairs):
    store.authorize(actor)
    pairs = list(pairs)
    args = dict(pairs)
    if len(args) != len(pairs) or set(args) - {'start', 'end', 'organization'}:
        raise ValueError('Invalid overview filters')
    period = parse_filters([(k, v) for k, v in pairs if k != 'organization'])
    conditions, params = store.scope(actor)
    with store.connect() as db:
        db.execute('BEGIN')
        base = ' WHERE ' + ' AND '.join(conditions) if conditions else ''
        # Only code-owned SQL fragments; values remain bound parameters.
        options = [r[0] for r in db.execute('SELECT DISTINCT organization FROM cases' + base + ' ORDER BY organization', params)]  # nosec B608
        if store.organizations[actor] is not None:
            options = sorted(set(options) | set(store.organizations[actor]))
        if 'organization' in args:
            org = clean(args['organization'], 128)
            if org != args['organization']:
                raise ValueError('Invalid organization')
            if not store.visible(actor, org):
                from cloud_soc.portal.cases import CaseError
                raise CaseError('forbidden', '기관 조회 권한이 없습니다.', 403)
            conditions.append('organization=?'); params.append(org)
        conditions.extend(['julianday(created_at)>=julianday(?)', 'julianday(created_at)<julianday(?)'])
        params.extend([period.start, period.end])
        where = ' WHERE ' + ' AND '.join(conditions)
        groups = [dict(r) for r in db.execute("SELECT organization,count(*) AS total,sum(status='new') AS new,sum(status IN ('triage','investigating','escalated')) AS active,sum(status='closed') AS closed,sum(priority IN ('high','critical') AND status<>'closed') AS high FROM cases" + where + ' GROUP BY organization ORDER BY high DESC,total DESC,organization', params)]  # nosec B608
        rows = [dict(r) for r in db.execute('SELECT * FROM cases' + where + ' ORDER BY created_at DESC,id DESC LIMIT 50', params)]  # nosec B608
        return {'organizations': options, 'groups': groups, 'rows': rows, 'total': sum(g['total'] for g in groups), 'active': sum(g['new'] + g['active'] for g in groups), 'closed': sum(g['closed'] for g in groups), 'rows_limit': 50, 'start': period.start, 'end': period.end}
