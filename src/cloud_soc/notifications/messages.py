"""Presentation of newly enqueued notifications; never rewrite saved payloads."""
import ipaddress
import re
from urllib.parse import quote, urlsplit

from cloud_soc.notifications.transport import SlackError

NOTICE_STATES = {'initial': '초기 탐지', 'verifying': '근거 검증 중', 'delayed': '검증 지연',
                 'confirmed': '근거 확정', 'corrected': '초기 판단 정정'}
SEVERITY = {'critical': '🔴 CRITICAL', 'high': '🟠 HIGH', 'medium': '🟡 MEDIUM', 'low': '🔵 LOW'}


def plain(value, limit=120):
    return ''.join(c for c in value if c.isprintable())[:limit].strip() if isinstance(value, str) else ''


def text(value):
    return {'type': 'plain_text', 'text': value, 'emoji': True}


def origin(value):
    """Only a deployment-owned portal origin, never a URL supplied by an alert."""
    try:
        if (not isinstance(value, str) or not value or len(value) > 512
                or any(c.isspace() or ord(c) < 32 or c in '\\<>|&\"\'' for c in value)):
            raise ValueError
        parsed = urlsplit(value)
        if (not parsed.hostname or parsed.username is not None or parsed.password is not None
                or parsed.path not in ('', '/') or parsed.query or parsed.fragment
                or parsed.port is not None and not 1 <= parsed.port <= 65535):
            raise ValueError
        host = parsed.hostname
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', p)
                                          for p in host.split('.')):
                raise ValueError from None
        if parsed.scheme != 'https' and not (parsed.scheme == 'http' and host in ('localhost', '127.0.0.1', '::1')):
            raise ValueError
        return parsed.scheme + '://' + parsed.netloc
    except (TypeError, ValueError):
        raise SlackError('notification_portal_origin_invalid', 503) from None


def connection_test():
    heading = '✅ Cloud SOC 연결 테스트 성공'
    description = 'Slack 알림이 정상적으로 연결되었습니다.'
    return {'text': heading + '\n' + description, 'unfurl_links': False, 'unfurl_media': False,
            'blocks': [{'type': 'header', 'text': text(heading)},
                       {'type': 'section', 'text': text(description)}]}


def alert(*, identifier, rule, severity, count, title, kind, state, portal_url=None):
    # Titles come from stored rule metadata. Future rules require no notifier code changes.
    title = 'SSH 로그인 실패 집중 탐지' if rule == 'AUTH-001' else plain(title) or '보안 이벤트 탐지'
    rule = plain(rule) or '미기록'
    observed = str(count) + '건' if type(count) is int and 0 <= count < 10**15 else '미기록'
    stage = '최종 경보' if kind == 'final' else '초기 통지 · ' + NOTICE_STATES[state]
    summary = '\n'.join(['Cloud SOC · ' + stage, title, '위험도: ' + severity.upper(),
                         '룰 ID: ' + rule, '관측 건수: ' + observed])
    # Fallback text also serves notifications/screen readers: escape Slack's mention/link syntax.
    summary = summary.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    blocks = [{'type': 'header', 'text': text(title)},
              {'type': 'section', 'fields': [text('위험도\n' + SEVERITY[severity]), text('룰 ID\n' + rule),
                                             text('관측 건수\n' + observed), text('알림 유형\n' + stage)]}]
    if portal_url:
        base = origin(portal_url)
        # Initial notices have no final alert yet, and the existing notice UI has no deep-link route.
        url = base + '/workbench.html?alert=' + quote(identifier, safe='') if kind == 'final' else base + '/index.html'
        label = '경보 자세히 보기' if kind == 'final' else '초기 통지 목록 보기'
        # An ordinary link needs no Slack interactivity endpoint or acknowledgement callback.
        blocks.append({'type': 'section', 'text': {'type': 'mrkdwn', 'text': '<' + url + '|' + label + '>',
                                                 'verbatim': True}})
    return {'text': summary, 'unfurl_links': False, 'unfurl_media': False, 'blocks': blocks}


def example_alert(*, reference_id, portal_url):
    """Operator-requested presentation test; never a detection or an Elasticsearch document."""
    payload = alert(identifier=reference_id, rule='AUTH-001', severity='high', count=10, title=None,
                    kind='final', state='final', portal_url=portal_url)
    title = '[테스트 예시] SSH 로그인 실패 집중 탐지'
    explanation = ('실제 탐지가 아닌 Slack 표시 확인용 예시입니다. 관측 건수 10건은 예시 값입니다. '
                   '상세 링크는 기존 경보의 참고 화면이며 해당 경보를 재발송한 것이 아닙니다.')
    payload['text'] = ('Cloud SOC · 테스트 예시 (실제 탐지 아님)\n' + title
                       + '\n위험도: HIGH\n룰 ID: AUTH-001\n관측 건수: 10건 (예시)\n' + explanation)
    payload['blocks'][0]['text'] = text(title)
    payload['blocks'][1]['fields'][2] = text('관측 건수\n10건 (예시)')
    payload['blocks'][1]['fields'][3] = text('알림 유형\n테스트 예시 · 실제 탐지 아님')
    payload['blocks'].insert(2, {'type': 'section', 'text': text(explanation)})
    return payload
