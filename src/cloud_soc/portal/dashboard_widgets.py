"""Application-owned widget capabilities. Configuration never grants query authority."""
import re
from copy import deepcopy
from cloud_soc.privacy import sensitive


def widget(key, title, category, source, renderer, description, *, admin=False, reason=None):
    charts = {'series': ['line', 'bar', 'heatmap', 'trend'], 'parts': ['bar', 'donut', 'stacked'],
              'alerts': ['table', 'timeline'], 'cases': ['table'], 'logs': ['table'],
              'agents': ['table'], 'entities': ['graph'], 'status': ['status'], 'kpi': ['kpi'],
              'overview': ['kpi'], 'notices': ['timeline']}[renderer]
    return dict(type=key, title=title, category=category, source=source, renderer=renderer,
                description=description, charts=charts, admin=admin, enabled=reason is None, reason=reason)


CATALOG = [
    widget('early-notices', '초기 탐지 통지', '보안', 'notices', 'notices', '최신 최대 50개 논리적 통지와 확정 경보 연결. 초기·확정을 공격 횟수로 합산하지 않습니다.'),
    widget('overview', '관제 요약', '보안', 'operations', 'overview', '저장 경보·수신 로그·미종결 사건의 실제 집계'),
    widget('alert-count', '저장된 경보 수', '보안', 'operations', 'kpi', '조회 기간의 저장 경보 전체 수. 공격 성공 횟수가 아닙니다.'),
    widget('intake-count', '수신 로그 수', '수집', 'operations', 'kpi', '서버 수신 시각 기준 전체 문서 수'),
    widget('case-count', '미종결 사건 수', '조사', 'cases', 'kpi', '조회 기간과 별도로 현재 미종결 사건 전체 집계'),
    widget('intake', '로그 수신 추이', '수집', 'operations', 'series', '서버 수신 시각 기준 5분/1시간 집계'),
    widget('trend', '경보 추이', '보안', 'operations', 'series', '경보 저장 시각 기준 전체 집계'),
    widget('severity', '최근 경보 심각도', '보안', 'operations', 'parts', '최신 최대 50건의 표본 분포. 전체 분포가 아닙니다.'),
    widget('alerts', '최근 탐지 경보', '보안', 'operations', 'alerts', '최신 최대 50건에서 필터·정렬·근거 조회'),
    widget('high-alerts', '최근 높은 위험 경보', '보안', 'operations', 'alerts', '최근 표본의 높은/긴급 심각도 경보'),
    widget('rule-counts', '최근 탐지 규칙별 경보', '보안', 'operations', 'parts', '최근 경보 표본에서 규칙별 건수'),
    widget('source-alerts', '최근 출발지별 경보', '보안', 'operations', 'parts', '경보에 실제 저장된 출발지 IP별 표본 건수'),
    widget('alert-timeline', '경보 시간순 목록', '조사', 'operations', 'alerts', '저장된 경보의 시간순 목록. 서로 다른 경보를 공격 흐름으로 연결하지 않습니다.'),
    widget('entities', '경보와 관측 출발지', '조사', 'operations', 'entities', '동일 경보 문서에 실제 기록된 출발지 관계만 표시'),
    widget('cases', '진행 중인 사건', '조사', 'cases', 'cases', '현재 미종결 사건 목록. 최대 첫 페이지 25건'),
    widget('case-status', '미종결 사건 상태', '조사', 'cases', 'parts', '같은 권한·필터의 사건 전체 상태 집계'),
    widget('cloud-events', '최근 AWS/OCI 이벤트', '클라우드', 'logs', 'logs', '최근 수신 로그 최대 50건에서 선별한 클라우드 이벤트 표본'),
    widget('cloud-services', '최근 클라우드 API 서비스', '클라우드', 'logs', 'parts', '최근 수신 로그 표본에 관측된 서비스별 건수'),
    widget('cloud-accounts', '최근 관측 클라우드 계정', '클라우드', 'logs', 'parts', '최근 수신 로그 표본에 나타난 계정. 등록 계정 총수가 아닙니다.'),
    widget('cloud-iam', '최근 IAM 변경 이벤트', '클라우드', 'logs', 'logs', '최근 수신 표본의 명시적 IAM 변경 API만 표시'),
    widget('cloud-audit', '최근 감사 설정 이벤트', '클라우드', 'logs', 'logs', '최근 수신 표본의 명시적 감사 설정 API만 표시'),
    widget('cloud-alerts', '최근 클라우드 경보', '클라우드', 'operations', 'alerts', '최근 경보 표본의 AWS/OCI 규칙만 표시'),
    widget('host-events', '최근 호스트 수신 로그', '수집', 'logs', 'logs', '최근 수신 로그 첫 페이지 표본과 실제 호스트'),
    widget('source-counts', '최근 수집 소스 분포', '수집', 'logs', 'parts', '최근 수신 로그 최대 50건의 소스별 분포'),
    widget('agents', '에이전트 마지막 수신', '운영', 'agents', 'agents', '관리자용 수신 활동 첫 페이지. 미수신은 오프라인 판정이 아닙니다.', admin=True),
    widget('pipeline', '분석 서비스 상태', '운영', 'operations', 'status', '현재 정규화·탐지 상태와 지연. 관리자 전용', admin=True),
    widget('processing', '정규화 처리 추이', '운영', 'operations', 'series', '처리 기록 전체 집계. 관리자 전용', admin=True),
    widget('world-map', '접속 위치 지도', '보안', 'operations', 'parts', '신뢰할 수 있는 위치 자료 필요', reason='검증된 위치 데이터가 없습니다.'),
    widget('offline-agents', '오프라인 에이전트', '운영', 'agents', 'parts', '별도 heartbeat 판단 필요', admin=True, reason='수신 활동만으로 연결 단절을 판단할 수 없습니다.'),
    widget('success-rate', '탐지 성공률', '보안', 'operations', 'parts', '실제 정답 라벨과 평가 결과 필요', reason='실제 탐지 성공률 측정 자료가 없습니다.'),
    widget('risk-score', '클라우드 계정 위험 점수', '클라우드', 'logs', 'parts', '승인된 계정 위험 계산 필요', reason='계정 위험 점수 산정 모델이 없습니다.'),
    widget('attack-sequence', '공격 근거 시퀀스', '조사', 'operations', 'alerts', '경보 상세의 실제 일치 근거를 기존 조사 화면에서 확인', reason='위젯은 미지원입니다. 경보의 근거 보기에서 실제 단계·참조를 조회하세요.'),
]
REGISTRY = {row['type']: row for row in CATALOG}
PERIODS = (0, 60, 1440, 10080)
TEMPLATES = {
    'security': ('통합 보안 현황', ['overview', 'trend', 'severity', 'intake', 'alerts', 'cases', 'rule-counts', 'source-counts']),
    'investigation': ('공격 탐지·사건 조사', ['alert-count', 'case-count', 'high-alerts', 'alert-timeline', 'entities', 'cases', 'case-status']),
    'cloud': ('클라우드 감사·IAM 현황', ['cloud-events', 'cloud-services', 'cloud-accounts', 'cloud-iam', 'cloud-audit', 'cloud-alerts']),
    'collection': ('에이전트·수집 현황', ['intake-count', 'intake', 'host-events', 'source-counts']),
    'empty': ('새 대시보드', []),
}


def catalog(role):
    return [{**row, 'enabled': row['enabled'] and (not row['admin'] or role == 'admin'),
             'reason': row['reason'] or ('관리자 전용 위젯입니다.' if row['admin'] and role != 'admin' else None)}
            for row in deepcopy(CATALOG)]


def instance(kind, number=0, *, size=6):
    row = REGISTRY[kind]
    return {'id': f'widget-{number}', 'type': kind, 'x': 0 if size == 12 else number % 2 * 6,
            'y': number * 3 if size == 12 else number // 2 * 3, 'w': size, 'h': 3,
            'config': {'title': row['title'], 'period': 0, 'chart': 'donut' if kind in ('severity', 'case-status') else row['charts'][0],
                       'limit': 8, 'sort': 'newest', 'severity': 'all', 'color': 'blue'}}


def template(key, role):
    name, kinds = TEMPLATES[key]
    kinds = list(kinds)
    if key == 'collection' and role == 'admin':
        kinds += ['agents', 'pipeline', 'processing']
    rows = [instance(kind, number, size=12 if kind in ('overview', 'alerts', 'high-alerts', 'cloud-events',
            'cloud-iam', 'cloud-audit', 'cloud-alerts', 'host-events', 'alert-timeline') else 6)
            for number, kind in enumerate(kinds)]
    x, y, height = 0, 0, 0
    for row in rows:
        row['h'] = 4 if REGISTRY[row['type']]['renderer'] in ('parts', 'alerts', 'logs', 'entities') else 3
        if x + row['w'] > 12:
            x, y, height = 0, y + height, 0
        row['x'], row['y'] = x, y
        x, height = x + row['w'], max(height, row['h'])
    return {'name': name, 'period': 1440, 'theme': 'light', 'widgets': rows}


def safe_title(value):
    return (isinstance(value, str) and 1 <= len(value.strip()) <= 48 and not sensitive(value)
            and not any(ord(char) < 32 or char in '<>' for char in value))


def valid_layout(value, role):
    if not isinstance(value, dict) or set(value) != {'name', 'period', 'theme', 'widgets'}:
        return False
    if (not safe_title(value['name']) or type(value['period']) is not int or value['period'] not in PERIODS[1:]
            or value['theme'] not in ('light', 'dark') or not isinstance(value['widgets'], list)
            or len(value['widgets']) > 24):
        return False
    seen, occupied = set(), []
    for item in value['widgets']:
        if not isinstance(item, dict) or set(item) != {'id', 'type', 'x', 'y', 'w', 'h', 'config'}:
            return False
        key = item['id']
        if not isinstance(key, str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', key) or key in seen:
            return False
        seen.add(key)
        definition = REGISTRY.get(item['type']) if isinstance(item['type'], str) else None
        if not definition or not definition['enabled'] or (definition['admin'] and role != 'admin'):
            return False
        if (any(type(item[k]) is not int for k in ('x', 'y', 'w', 'h')) or not 0 <= item['x'] <= 11
                or not 0 <= item['y'] <= 240 or item['w'] not in (3, 6, 12) or item['x'] + item['w'] > 12
                or not 2 <= item['h'] <= 8):
            return False
        if any(item['x'] < other['x'] + other['w'] and item['x'] + item['w'] > other['x']
               and item['y'] < other['y'] + other['h'] and item['y'] + item['h'] > other['y'] for other in occupied):
            return False
        occupied.append(item)
        config = item['config']
        if not isinstance(config, dict) or set(config) != {'title', 'period', 'chart', 'limit', 'sort', 'severity', 'color'}:
            return False
        if (not safe_title(config['title']) or type(config['period']) is not int or config['period'] not in PERIODS
                or config['chart'] not in definition['charts'] or type(config['limit']) is not int
                or config['limit'] not in (5, 8, 10, 25, 50) or config['sort'] not in ('newest', 'oldest', 'count')
                or config['severity'] not in ('all', 'critical', 'high', 'medium', 'low')
                or config['color'] not in ('blue', 'teal', 'amber', 'purple')):
            return False
    return True
