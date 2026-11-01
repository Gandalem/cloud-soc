# React 종합상황판

2026-11-01 구현. 기존 중앙 Flask 서버가 React 정적 번들과 읽기 전용 API를 함께 제공한다. 수집기·탐지기·Elasticsearch 연결 자격 증명·기존 사고 저장소는 재사용한다.

## 화면과 실행

- 접속: 기존 Portal에 로그인한 뒤 `/`, `/index.html`, `/soc.html`. 기존 메뉴의 **종합상황판**에서도 진입한다.
- 구성: 파랑/청록색 공통 메뉴, 기관 및 최근24시간/7일/30일 필터, 수신/경보/사고 지표, 시간대별 경보 차트, 경보등급 분포, 기관별 사고 현황, 최근 사고와 오른쪽 상세 패널.
- 기관·기간을 바꾼 다음 **조회**를 누른다. 새로고침은 마지막으로 적용한 조건으로 다시 조회한다. 상세 패널은 닫기·Escape로 닫고, 기존 사고 조사/경보 근거 화면으로 이동할 수 있다.
- 최근 사고는 최신50건이고 기관별 합계는 전체 일치 사고의 SQL 집계다. 기간은 **접수 시각**에 적용하며 상태는 현재 상태다. 처리 완료 시각 기준 통계가 아니다.
- 위험등급 분포는 기존 관제 응답의 최신 최대50개 경보 표본이다. 종합 위험점수를 임의로 만들지 않는다. 저장된 risk_level이 유효하면 우선하고, 아니면 severity를 사용한다.
- 기관 선택지는 권한 내 사고 저장소와 최초 전체기관 조회의 경보 표본에서 구성한다. 사고/경보 표본에 없는 기관의 전체 자산 목록 검색은 이번 범위에 포함하지 않는다. 제한 사용자의 허용 기관은 권한 설정에서도 가져온다.
- 조회 실패는 ‘—’와 재시도 안내로 구분한다. 자동 폴링 없이 사용자가 조회/새로고침한다.

`frontend/`는 React19/Vite6 소스다. 번들은 `prototype/soc/app.js`, `app.css`에 포함되어 기존 Python 이미지의 `COPY prototype`에 함께 들어간다. 운영 서버에서 Node를 실행하거나 외부 CDN을 사용할 필요가 없다. 기존 CSP의 self-only 정책과 no-store를 유지한다.

프런트엔드 변경 후 Node20.19+/22.12+ 및 pnpm 환경에서:

```bash
cd frontend
pnpm install --frozen-lockfile --ignore-scripts
pnpm build
```

기존 Flask Portal을 평소 설정으로 실행하면 새 화면을 제공한다. 실제 서버 갱신에는 프로젝트의 기존 보존형 배포 절차를 사용한다. 이번 작업에서 운영 서비스를 배포하거나 재시작하지 않았다.

## API 계약

`GET /api/overview?start=<ISO8601>&end=<ISO8601>&organization=<기관ID>`

- start/end는 함께 지정하고 최대30일의 양수 구간을 허용한다. organization은 선택 사항이다. 중복/알 수 없는 조건은400이다.
- `operations`: 기존 `Operations.summary`와 `display_summary`를 재사용한 수신/경보/분석 집계. 선택 기관으로 요청별 principal을 좁힌 뒤 Elasticsearch를 조회한다.
- `cases`: 기존 CaseStore의 권한과 SQLite를 사용한 기관별 합계, 미완료/완료 합계, 최근50개 사고. 값은 바인딩하며 접수 시각은 timezone을 고려해 비교한다.
- 모든 집계가 같은 확정 start/end를 사용한다. 기존 세션/Basic 인증, 기관 범위, 응답 마스킹을 보존한다. 기관 범위를 벗어난 조회는403이다.
- 상세는 기존 `GET /api/cases/<id>`, 이동은 기존 `/workbench.html?case=<id>` 및 `?alert=<id>`를 사용한다. 브라우저에는 Elasticsearch 주소·키를 전달하지 않는다.

## 로컬 검증

- 독립 테스트 `tests/test_soc_overview.py`:50건 초과 합계·기간 경계·기관 필터·타기관 거부·세션 viewer 권한·정적 파일 인증/CSP·기존 Operations 어댑터 연결을 확인했다.
- 기존 Portal/Case 검사42개 중 최초2개는 이전 홈 화면의 dashboard.js/shell.js 기대값으로 실패했다. 새 React 진입에 맞게 기대값을 수정하고 직접 영향 검사와 신규 세션 검사를 통과했다. 기존 실행환경 의존3건은 skip이다.
- 공통 shell 검사8개 통과. 홈/공통 메뉴의 새 진입 경로를 반영했다.
- Vite production build 통과.
- `tests/preview_soc_overview.py`는 임시 SQLite와 합성 관제 응답을 사용하는 별도 로컬 Flask 서버다. 운영 설정/키를 읽지 않는다. `tests/browser_soc_overview.cjs`로 실제 Flask 경로를 통해 최초 조회, 기관/7일 필터, 사고 상세/조사 링크, Escape, 모바일 메뉴 열기/닫기, 수평 넘침,503 재시도 상태 및 브라우저 예외0건을 확인했다. 모바일 메뉴 닫기 가림 문제를 수정 후 재검사했다.
- 캡처: `output/soc-overview.png`, `soc-overview-detail.png`, `soc-overview-mobile.png`. 캡처 수치는 검증용 예시이며 운영 데이터가 아니다.
- 운영 Elasticsearch·현재 중앙 서버의 실제 로그/API 응답 및 운영 브라우저 검증은 미수행이다. 배포·실데이터 인수·commit/push는 별도다.

검사 재현:

```bash
PYTHONPATH=src:tests python -m unittest test_soc_overview -v
node --test prototype/tests/shell.test.cjs
# 터미널1: 실제 서버 대신 격리된 검증 서버
PYTHONPATH=src python tests/preview_soc_overview.py
# 터미널2: playwright 설치 환경, Chrome 기본 경로는 /opt/google/chrome/chrome
node tests/browser_soc_overview.cjs
```


## 첨부 이미지 기준 전면 개편 — 2026-11-01

최신 사용자 요청의 샤이.png를 기준으로 이전 카드형 레이아웃을 교체했다. 왼쪽 청색 위험지수/리스크 피드, 짙은 청색 아이콘 레일, 중앙 조치 현황/보라색 레이더/노란 막대 추이, 오른쪽 청록색 지도 배경/기관 목록/순위 구성을 적용했다. 외부 이미지나 CDN 없이 CSS와 SVG로 렌더링한다.

- 위험지수는 서버가 반환한 최근 경보 표본 중 유효한 risk_score의 최댓값이다. 점수 부재 시 ‘—’와 저장된 경보 등급을 표시한다. 표본 최고점수이며 기관 전체 보안점수로 해석하지 않는다.
- 레이더는 긴급/높음/보통/낮음/미분류 경보 건수이며 표본 내 최대 건수를 축 최댓값으로 사용한다. 실제 근거가 없는 위험요인을 만들지 않는다.
- 막대 추이는 전체 버킷을 최대24구간으로 합산한다. 일부 버킷을 버려 총량을 줄이지 않는다.
- 지도는 배경 도형이며 실제 기관 위치나 지역별 위험을 나타내지 않는다. 기관 목록은 위치와 무관하게 배치하고 이를 화면에 표시했다. 실제 지리적 위험지도에는 검증된 기관 좌표/지역 메타데이터가 필요하다.
- 오른쪽 기관 카드와 순위의 기관명을 누르면 해당 기관으로 전체 지표를 다시 조회한다. 새 데이터 조회 중에는 이전 점수/자료를 지워 조건을 혼동하지 않게 했다.
- 위험 피드에서 기존 사고 상세 패널을 연다. 메뉴·권한·API 계약·기존 사고 조사 연결은 유지한다.
- 최신 캡처는 output/soc-reference-overview.png, soc-reference-detail.png, soc-reference-mobile.png이며 격리 예시 데이터다. 이전 soc-overview*.png는 이전 디자인 기록이다.
- production build, SQL/API/권한5검사 및 Chrome 필터/사고 상세/Escape/기관 카드/모바일 메뉴/수평 넘침/조회 실패 표시 검사를 통과했다. 운영 배포·실제 데이터 인수·commit/push는 수행하지 않았다.
