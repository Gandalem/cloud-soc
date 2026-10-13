# DASH-02 사용자 맞춤 대시보드 확장 인수

후속 실제 인수: 2026-10-13 사용자가 지정한 중앙192.168.32.60의 관리자 홈/개인·초기 통지 저장/재조회·두 크기/테마·포털 재시작을 추가 검증하고 기능 소스를 commit/push했다. [보호 배포 결과](early_deployment_validation_20261013.md)를 참고한다. 아래 미배포/미커밋 표현은 초기 로컬 인수 당시 기록이며 추가 조직/역할 인수는 여전히 남는다.

2026-10-13 KST. 기준 main `b67eefa`, 작업 브랜치 `codex/dashboard-platform-20261013`. 새 사용자 요청으로 대시보드 확장을 발표 사건 시연보다 우선했다. 제품 소스·로컬/합성 검증 범위이며 운영 배포·실제 계정/ES 인수·키 갱신·commit/push/merge는 수행하지 않았다. 기존 개인 Word·검증 JSON·완료 이력·P2-02 보류를 보존했다.

## 유지와 확장

홈 `index.html`/`dashboard.js`, 경보 근거·사건·로그 화면, 테마·세션·조직/역할·개인정보 정책, 수집/정규화/탐지 엔진과 규칙을 유지한다. 기존 `dashboards(actor, revision, body)`와 `/api/dashboard`는 그대로 읽고 저장한다. 새 조회가 기존 행을 생성/수정/삭제하지 않음을 검증했다. 기존 개인 화면을 편집할 때 명시적 복제본을 만든다. 기존 기술 위젯은 전과 같이 고객 화면에 표시하지 않지만 원래 행에서는 보존한다.

새 `dashboard_collections(actor, revision, body)`에는 계정당 최대 20개 개인 대시보드·기본 지정·즐겨찾기·최대 24개 독립 위젯을 저장한다. 기본 템플릿 4개(통합 보안, 공격 탐지·사건 조사, 클라우드 감사·IAM, 에이전트·수집)와 빈 화면, 생성·전환·이름 변경·복제·삭제 확인을 제공한다. 공유/팀 대시보드는 이번 범위 밖이며 공유 버튼을 만들지 않았다.

라이브러리 검색/분류/설명/사용 가능 여부, 위젯 추가·제거·독립 설정, 12열의 포인터 이동/크기 변경, Alt+위/아래 순서 변경과 버튼, 모바일 한 열/패널 전환을 지원한다. 설정은 짧은 제목·고정 데이터 유형·기간·호환 차트·표시 건수·정렬·경보 표본 필터·강조색·너비/높이다. 저장·취소·마지막 저장 복원·템플릿 초기화 미리보기·30단계 Undo와 미저장 변경 안내가 있다. 저장 중 잠금/실패/409와 서버 재조회 확인에서 편집을 보존한다.

## 데이터와 권한

`GET /api/dashboards`는 자기 컬렉션·읽기 전용 기존 구성·역할별 카탈로그·템플릿을 반환한다. POST는 revision과 고정 create/save/rename/duplicate/delete/default/favorite 작업만 받는다. 컬렉션 단위 revision/BEGIN IMMEDIATE로 충돌을 검출하고 응답은 해당 트랜잭션의 구성으로 고정한다. 서로 다른 개인 화면도 같은 컬렉션 충돌 범위에 포함된다. 자동 병합·충돌 후 자동 재저장은 없다.

사용자/조직/ES 인덱스·쿼리·외부 주소·HTML/스크립트는 설정 필드에 포함할 수 없다. 위젯 유형과 인스턴스 ID, 12열 범위·비겹침·허용 크기/기간/차트/필터·역할을 서버에서 검증한다. 저장 제목은 비밀 패턴·HTML·제어문자를 거절하고 DOM은 textContent/SVG text로 렌더링한다. 기존 같은 출처·JSON·X-Cloud-SOC·세션 CSRF를 유지한다. 조회자가 자기 표시 설정을 저장해도 사건 쓰기·원문·에이전트·전역 진단 권한은 생기지 않는다. Basic 제한 로그 조회자는 기존 제한을 유지한다.

데이터는 기존 `/api/operations`, `/api/operations/status`, `/api/cases`, `/api/logs`, 관리자 `/api/agents/status`를 재사용한다. 새로운 ES 집계·규칙·쓰기 권한은 추가하지 않았다. 로그 API에는 하위 호환 필드 `data_state=ok/no_index`만 추가해 미수집과 성공 빈 결과를 구분했다. 필터/필드/조직 범위·50개 표본·PIT·쿼리 제한은 그대로다.

동일 소스/기간은 갱신당 한 번 조회하고 동시에 최대 3개만 요청한다. 선택 가능한 3개 기간의 operations/logs, cases/agents/status를 모두 쓸 때 최대 9개 데이터셋이며, 위젯 개수만큼 호출하지 않는다. 동일 기간 경보 추이 24개 실제 브라우저 시험은 상태/경보 집계 **2회**였다. 45초 클라이언트 제한·갱신/숨김/이탈 취소·generation 검사로 오래된 응답 혼입을 막는다. 수동/60초 자동 갱신이 있다. 브라우저 저장소에는 기존 전역 테마 값만 쓰며 위젯 설정·데이터·권한·토큰을 복제하지 않는다.

## 위젯 카탈로그

31개 후보 중 관리자 26개, 분석가/조회자 23개를 실제 API에 연결했다. 아래 ‘사용 가능’은 코드/합성 인수이며 해당 운영 데이터가 실제 수집됐다는 뜻이 아니다. 인덱스 없음·정상 0건·권한 없음·API/부분 조회 실패·미지원·분석 미실행/지연은 구분한다.

| 유형 | API/근거 | 표시 범위 |
| --- | --- | --- |
| overview | operations + cases | 경보/수신 기간 전체·미종결 사건 현재 전체 |
| alert-count / intake-count | operations | 선택 기간의 정확한 전체 건수 |
| case-count | cases | 현재 미종결 전체·기간 별도 |
| intake / trend | operations | 수신/경보 전체 시간 집계, 선/막대/히트맵/추이 카드 |
| severity | operations.rows | 최신 최대 50개 경보의 심각도 표본 |
| alerts / high-alerts | operations.rows | 표본 목록·명시 심각도·근거 링크 |
| rule-counts / source-alerts | operations.rows | 표본의 규칙/실제 출발지 분포 |
| alert-timeline | operations.rows | 경보 저장 시각 순서·공격 인과 추정 없음 |
| entities | 동일 alert row의 source_ip | 동일 경보→기록된 출발지 한정 그래프, 미관측은 연결 안 함 |
| cases | cases | 미종결 첫 페이지 최대 25개·상세 이동 |
| case-status | cases.counts | 전체 미종결 중 조사 중/기타 미종결의 상호 배타 집계 |
| cloud-events | logs.rows | 최근 전체 수신 최대 50개 중 AWS/OCI 선별 표본 |
| cloud-services / cloud-accounts | logs.rows | 표본 서비스/관측 계정·전체 API량/등록 계정 총수 아님 |
| cloud-iam / cloud-audit | logs.rows.action | 명시적 AWS IAM 변경/감사 설정 API 허용 목록의 표본, OCI 범용 IAM 분류 아님 |
| cloud-alerts | operations.rows.rule | 표본의 AWS/OCI 규칙 경보 |
| host-events / source-counts | logs.rows | 호스트/소스 첫 페이지 표본·전체 분포 아님 |
| agents (관리자) | agents/status | 최근 30일 수신 활동 첫 페이지·마지막 수신, heartbeat 아님 |
| pipeline (관리자) | operations.pipeline | 현재 정규화/탐지 상태·성공 시각·위험 평가 범위 경고 |
| processing (관리자) | operations.processing | 기간 전체 처리 기록 추이·안전/탐지 성공률 아님 |

사용 불가 5개:

| 후보 | 부족한 근거/남은 구현 |
| --- | --- |
| world-map | 검증된 위치·정밀도·출처 자료 필요. IP만으로 지도점 생성 안 함 |
| offline-agents | 별도 heartbeat/연결 판단 기준 필요. 최근 미수신을 단절로 추정 안 함 |
| success-rate | 정답 라벨/실제 평가 분모·결과 없음 |
| risk-score | 계정별 승인된 위험 산정 모델/실제 계산 결과 없음 |
| attack-sequence | 위젯 전용 정확한 단계/근거 참조 투영 미구현. 기존 경보 근거 보기 이용 |

네트워크 노출 자원 총수·전체 API 호출 추이·MTTD/MTTR·ATT&CK 방어율·미측정 저장소/CPU/메모리 등도 만들어 표시하지 않는다. 클라우드 표본의 결과가 0건이어도 해당 계정의 전체 활동이 0건이라고 단정하지 않는다.

## 저장·복구

format 4 백업은 기존 개인 행과 새 컬렉션을 함께 포함한다. format 1/2/3 검증·새 경로 복원을 유지하며 형식 3 기존 단일 테이블을 복원해 앱을 시작하면 빈 새 컬렉션 테이블만 추가한다. 원본 설정은 유지한다. 현재/이전 감사 백업을 4/3/2로 함께 검증했다. 새 스키마에는 이번 버전의 백업 도구가 필요하다. 운영 파일 교체·DB 초기화·ES 삭제는 수행하지 않았다.

## 로컬 검증 결과

검증 런타임은 기존 `state/pr3-review-venv/Scripts/python.exe`(Python 3.13.2)와 Node 22.20.0이다. 기본 Python/샌드박스 런타임에는 필요한 의존성이 없거나 실행 권한이 제한돼 기존 격리 환경을 사용했다. 전역 OS 정책/의존성/운영 서비스는 바꾸지 않았다.

| 검사 | 명령/범위 | 결과 |
| --- | --- | --- |
| 전체 Python | `state/pr3-review-venv/Scripts/python.exe -m pytest -q -p no:cacheprovider` | 726 passed·19 skipped·257 subtests passed (78.51초) |
| 추가 별도 프로세스 포함 신규 파일 | `…python.exe -m pytest tests/test_dashboard_collection.py -q -p no:cacheprovider` | 31 passed. 위 전체 결과와 대부분 중복이며 합산하지 않음. 새 독립 프로세스 시험 1개 포함 |
| 전체 UI | `node --test --test-reporter=dot (Get-ChildItem prototype/tests -Filter '*.test.cjs' \| ForEach-Object FullName)` | 136 passed |
| 정적/보안 | `…python.exe -m ruff check src tests tools`, `…python.exe -m bandit -q -r src -ll`, `git diff --check` | 통과. Bandit의 기존 nosec 주석 경고는 중간/높음 발견과 구분 |
| 브라우저 기본 | `playwright-cli -s=dashboard-platform run-code --filename tests/browser_dashboard_platform.cjs` | CRUD/독립 설정/취소/충돌/재로그인·15개 화면/경계 검사, JS 예외 0 |
| 브라우저 추가 | `… --filename tests/browser_dashboard_platform_extra.cjs` | 포인터/키보드/Undo/초기화/24개 요청 공유/오래된 응답/503/정상 빈 결과/403/중단·4템플릿×3크기×2테마 24개, JS 예외 0 |
| 브라우저 경계 | `… --filename tests/browser_dashboard_edgecases.cjs` | 동일 경보 출발지 그래프·미수집/정상 0·저장 후 미지원 버튼 비활성·허용 높이5/7 5개, JS 예외 0 |

독립 앱 프로세스 재시작·재로그인에서도 같은 SQLite의 다중 설정을 읽었다. 두 독립 연결 동시 쓰기에서 한 성공/한 409, 다른 계정 접근 404, 역할/조직·CSRF·외부 Origin·제목 XSS/비밀·조작 ID/크기/필터·삭제 후 기본 복귀·기존 행 무변경·백업/새 경로 복원을 검증했다.

브라우저는 실제 Flask 세션/SQLite와 모의 ES/수집 응답을 사용한 `tests/preview_portal_ux.py`의 루프백 시험 서버다. 테스트 화면은 ‘합성 화면 검증 · 운영 데이터 아님’을 표시한다. 1440/768/390px, 두 테마, 많은 위젯·빈 화면·모바일 라이브러리/설정·기존 홈/로그/사건을 확인했다. 문서 가로 폭뿐 아니라 카드/헤더의 오른쪽 경계와 dialog 내부 폭도 대조했다. 의도한 403/409/503 콘솔 HTTP 오류는 기대된 실패이며 JavaScript 예외와 구분한다.

초기 시험에서 현재 상태 API에 기간을 생성하던 프런트 오류, 기본 요약 카드의 좁은 너비, 저장 후 비활성 버튼 상태를 보완했다. 시험 도구의 로그인/서버 재조회 비동기 대기·소스 안쪽 백업 목적지·Windows SQLite 연결 미종료·이전 형식 기대를 수정해 재검증했다. 최종 전체 시험은 위 결과이며 초기 실패를 숨기지 않는다. 19개 조건부 생략은 통과로 간주하지 않는다.

## 변경 파일과 화면 증거

- 서버: `src/cloud_soc/portal/dashboard_widgets.py`, `dashboards.py`, `app.py`, `auth.py`, `backup.py`, `log_query.py`.
- 개인 UI: `prototype/dashboard.html`, `dashboard-builder.js`, `dashboard-widgets.js`, `dashboard-builder.css`. 기존 홈 렌더러·공통 메뉴/테마는 유지.
- 시험: `tests/test_dashboard_collection.py`, `test_log_query.py`, `test_portal_backup.py`, `test_source_access.py`, `prototype/tests/dashboard-platform.test.cjs`, `tests/browser_dashboard_platform*.cjs`, `browser_dashboard_edgecases.cjs`.
- 문서: `docs/dashboards.md`, `portal_backup.md`, `work_tracker.md`, 이 인수 문서. `.gitignore`는 로컬 브라우저 증거만 제외.

실제 브라우저 스크린샷은 **Git 제외 PC 로컬** `output/playwright/dashboard-platform/`에 보존한다. 사용자 첨부 이미지는 디자인 참고이고 아래는 구현 화면이다. `security/investigation/cloud/collection-{1440,768,390}-{light,dark}.png`, `editor-1440-dark.png`, `personal-{1440,768,390}-{light,dark}.png`, `library-390.png`, `entity-graph.png`. 서버 재시작·키·원문/비밀·수신 증거를 의미하지 않는다.

## 운영 인수 잔여

실제 서버의 Git/이미지/overlay·보호 DB 백업·동일 버전 도구를 확인한 뒤 별도 승인된 보호 배포가 필요하다. 현재 승인된 계정/조직/역할의 기존 설정과 새 개인 구성을 대조하고 실데이터의 기간·표본·오류·재로그인/포털 재시작·복원까지 확인해야 한다. 실제 ES/클라우드 이벤트의 모든 위젯 운영 수치·상태와 추가 역할 인수는 이번 합성 시험으로 완료 처리하지 않는다. DASH-01/P6/P7 및 P2-02 보류의 전체 기준을 변경하지 않는다.
