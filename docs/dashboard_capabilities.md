# 대시보드 기능 확장 — DASHBOARD-FUNCTIONS-02

착수 2026-10-20, 구현 기록 2026-10-21 당시의 codex/operational-readiness 작업 이력이다. 현재 저장소 기준은 [프로젝트 상태](project_status.md)를 따른다.
당시 검수 지시는 약50%와 작성100%에서 큰 변경·계산/상태 판단만 확인하는 것이었다.
그 작업에서 전체 회귀, 일반 화면/브라우저 인수, 실장치 보고, 실제 평가 실행, 실제 cloud/GeoIP 위치 정확도, 재부팅은 범위 밖이었다. 다른 작업의 후속 성공까지 미수행으로 단정하지 않는다.
완료한 코드와 합성 결정 검사를 배포·실수집·실제 평가 통과로 바꾸어 표시하지 않는다.

## 연결과 기능

- catalog의 기존 위젯 type을 보존한다. attack-sequence는 기존 경보의 실제 근거를 지연 조회하고 sequence 규칙만 저장된 일치 순서로 설명한다. threshold는 건수/임계값과 근거 목록이며 사건 간 인과관계를 만들지 않는다.
- /api/dashboard-data/evidence는 기존 Operations.detail/evidence와 조직·정확한 raw/normalized 참조·event_hash 확인 경계를 재사용한다. 기본10근거와 추가 페이지, 조회 시각, 원본 해시 보장 범위를 구분한다. 원본 ES 문서 바이트의 독립 WORM 보장이 아니다.
- cloud-events/services/accounts/iam/audit는 /api/dashboard-data/cloud를 공유한다. 허용된 구체 인덱스에서 PIT로 읽고 서버에서 cloud source/provider/account/org/API 분류를 적용한다. IAM/감사 분류는 코드에 명시된 API 집합만 지원한다.
- 원본 page50 이후 자료도 계산한다. 표시 목록50/서비스·계정100개 상한과 실제 전체 건수는 구분한다. 한 요청은64인덱스/10,000문서/12초/30초PIT에 제한하고 한도·부분 실패·잘못된 정렬·조직/필터 불일치는 오류로 반환한다. 초과분을 버리고 전체 집계로 성공하지 않는다.
- cloud-alerts는 기존 Operations.series의 조직/기간 필터를 보존하면서 AWS-/OCI- 규칙을 검색 전에 제한한다. 첫50경보 목록과 전체 count는 별도다. 임의 규칙 이름만으로 모든 cloud 위협을 분류하지 않는다.
- 계정 관련 경보 조회는 최근 cloud 경보 중 최대5개의 첫 근거를 검증하고 조회 범위의 raw 참조/조직/계정과 대조한다. 계정 전체 경보 수가 아니며 대조 수와 한계를 표시한다.
- 읽기 자료 cache는 인증 주체별 인스턴스, 정확한 기간·공급자·계정·조직·분류 키로30초/최대12개에 한정한다. 서버/개인 범위를 브라우저 storage에 저장하지 않는다.
- 선택/펼침/폼 입력은 자동 갱신으로 교체하지 않는다. 한 출처 실패 시 다른 출처는 갱신하고 실패 출처는 마지막 내용을 실패 표식과 함께 보존한다.

## 장치 상태

새 dashboard-insights.sqlite는 기존 cases/dashboards/등록키와 별도의 원장이다. 기존 장치를 자동 등록하거나 기존 ES/S3 키로 보고하지 않는다.
POST /api/dashboard-devices 및 /api/dashboard-devices/<id>는 관리자 세션/CSRF 또는 기존 관리자 인증 경계를 사용한다.
등록은 request_id를 먼저 영속 기록하고 동일 요청/다른 내용 충돌을 구분한다. 비밀값 재조회는 없으며 응답 유실 후 같은 요청은 명시적409와 회전 안내를 반환한다.
rotate/pause/resume/revoke는 version 일치가 필요하다. 폐기는 되살리지 않고 키 회전은 이전 generation을 거부한다.
토큰은 ID와256-bit 임의값이며 원장에는 별도32-byte 서버 인증 키를 사용하는 HMAC만 저장한다. 일반 조회/감사에는 비밀값을 넣지 않는다.

POST /api/dashboard-heartbeat는 별도 기계 인증만 사용한다. Bearer 전용, X-Cloud-SOC: heartbeat, JSON, 브라우저 Origin/Fetch/Cookie 없음, 쿼리 없음, HTTPS가 필요하다.
외부 PUBLIC_URL이 HTTPS여야 한다. proxy TLS 종료는 SOC_HEARTBEAT_TLS_PROXIES에 명시한 실제 remote IP와 X-Forwarded-Proto=https가 함께 있을 때만 신뢰한다. 기본은 빈 목록이다.
body는 generation/sequence/generated_at/collector의 제한 스키마다. 조직·장치·인덱스 경로·엔진 자격 증명을 요청자가 바꿀 수 없다.
보고 생성 시각은 서버보다60초 미래/90초 과거 이내여야 한다. 단일 generation의 순번이 감소하거나 같은 순번의 내용이 다르면 충돌이다. 같은 보고 재전송은 최초 received_at을 유지한다.
보고 상태는 서버 수신 시각과 등록 interval로 판단한다. 3interval 이내 reporting, 6interval 이내 delayed, 이후 report_missing이다. 기본interval30초, 허용15-300초다. 로그가 없는 것을 보고 두절로 판단하지 않는다.
수집기 running/stopped/error/unknown은 장치가 보고한 관측이다. 장치 신뢰 실행/전원 상태를 증명하지 않는다. 중앙 DB/조회 실패는503이며 전체 장치를 offline으로 바꾸지 않는다.
등록 최대2000개, 목록50개 페이지/상태 건수는 전체 등록 대상 기준이다. revoked/paused/expired/최초대기/복원 후 재설정 필요를 따로 표시한다.

tools/device_heartbeat.py는 opt-in 별도 Python 보고기다. 실제 로그를 읽지 않고 지정 서비스의 읽기 전용 상태를 보고한다. 기존 제품 에이전트를 교체/설치하지 않는다.
--config는 private JSON 파일(url,credential,generation,service), --state는 새 전용 SQLite 순번 파일, --ca는 신뢰 CA 파일이다. --interval 30으로 주기 보고할 수 있다. 명령줄/출력/순번 DB에는 credential을 넣지 않는다.
POSIX config/state는0600이며 CA는 다른 사용자 쓰기를 금지한다. Windows는 전용 실행 계정에만 config/state 읽기·쓰기를 허용하는 ACL을 운영자가 부여해야 한다.
기존 큐/registry/SQLite를 지정하지 않는다. 프록시 환경/redirect/인증서 검증 비활성/관리 계정 우회는 없다. 순번 저장 실패 시 전송하지 않는다. 로컬 순번 분실 시 자동 재발급하지 않고 원장에서 회전한다.
등록 화면에서 받은 자격 증명/generation은 새 private config에만 넣는다. 이 구현 중 실제 장치를 등록하거나 보고기를 실행하지 않았다.

## 국가 지도

world-map는 별도 geo renderer다. 보호 스키마를 해석할 수 있는 웹 접근 문서만 집계하며 WAF 중복 스트림은 제외한다.
기본 단위는 접근 로그 문서이고 신원/사람/공격 횟수로 해석하지 않는다. 새로운 요청 중복 ID 계약을 추가해 원본 ID를 바꾸지 않는다.
공인 IP만 로컬 Country DB에 조회하고 사설/루프백/특수/잘못된 주소는 별도로 집계한다. 현재 raw 계약이 관측한 연결 상대를 사용하며 요청자가 만든 전달 헤더를 새로 신뢰하지 않는다.
전체 coverage=located/전체 해석된 접근*100, 공인IP coverage=located/public*100이다. 분모0은 계산 불가 또는 대상 없음으로 구분한다.
SOC_GEOIP_DATABASE가 로컬 GeoLite2-Country/GeoIP2-Country를 지정한다. 다른 DB 타입, symlink/잘못된 파일,256MB 초과는 거부한다. 빌드35일 초과/미래 자료는 갱신 필요 상태로 둔다. 이는 라이선스 보존 준수 보장이 아니다.
DB가 없거나 선택 의존성이 없으면 연결/설치 필요를 표시한다. 내부 주소뿐이면 그 상태를 표시한다. 외부 위치 API에 IP를 보내지 않는다.
optional maxminddb==3.2.0은 PyPI 공식 metadata의 Apache-2.0/Python>=3.10을 확인했다. requirements-geo.txt/pyproject geo extra로 고정하고 기본 설치는 바꾸지 않았다.
IP DB 내용은 배포하지 않고 기존 외부 계정/키를 사용하지 않았다. 운영자가 EULA/배포 조건과 업데이트를 관리해야 한다. UI는 MaxMind 출처를 표시한다.
지도 도형은 Natural Earth v5.1.2 110m admin0의 public-domain 자료이며 assets/world-countries.NOTICE.txt에 출처/원본hash/변환을 기록했다. Country DB와 독립된 도형이다.
지도/국가 목록에서 해당 국가 최근50개 원본 metadata로 이동한다. 위치는 추정이며 신원/국적/실제 공격자 위치를 확정하지 않는다.

공식 근거:
- https://pypi.org/project/maxminddb/3.2.0/ (Apache-2.0)
- https://dev.maxmind.com/geoip/docs/databases/city-and-country/
- https://www.maxmind.com/en/geolite/eula
- https://support.maxmind.com/knowledge-base/articles/sell-or-display-data-from-geolite-databases-and-web-services
- https://www.naturalearthdata.com/about/terms-of-use/

## 계정 보안 평가

risk-score는 관측 cloud 계정과 별도 등록 평가를 조직+공급자+계정 키로 연결한다. 최근 목록의 계정 수를 전체 등록 계정 수로 바꾸지 않는다.
기존 경보 triage-v1/evidence-first-v1 및 기존 risk_score는 변경하지 않는다.
관리자가 구조화된 폼으로 policy(id/org/version/purpose/items/explicit approval)를 등록한다. 항목은 id/title/weight/criterion/rationale이다. 근거 없는 기본 점수표를 활성화하지 않는다.
assessment는 별도 immutable ID, policy ID, 관측/만료 시각(최대31일), 수동 근거 평가 출처, 항목별 pass/fail/unknown/exempt와 근거를 저장한다. exempt에는 승인 사유가 필요하고 해당 snapshot 만료를 따른다.
계산: applicable weight는 승인 예외를 제외한 전체 정책 가중치, known weight는 pass/fail, failed weight는 fail의 합계다. 신선한 자료/모든 applicable 항목 평가/양수 분모인 경우에만 score=failed/applicable*100이다.
미등록 항목/unknown/만료/전부 예외는 score=null이며0을 생성하지 않는다. coverage는 known/applicable*100이다. 이 수치는 정책 위반 정도이며 침해 확률이나 모든 cloud 설정의 안전도를 의미하지 않는다.
동일 policy/snapshot ID의 다른 내용은409, 같은 내용은 중복으로 반환한다. 과거 기록/승인자/등록자/항목별 근거는 보존한다. 현재 snapshot은 관측 시각과 등록 시각의 안정적 순서로 선택한다.
읽기 전용 cloud 설정 API collector를 새 외부 계정에 연결한 것이 아니다. 현재 source는 operator_evidence_review이며 UI에도 평가자를 표시한다. 실계정 설정 수집/권한/주기 평가 연결은 별도 운영 인수다.

## 평가 기록과 수식

success-rate는 등록된 합성 시나리오 결과의 성능 평가 위젯이다. 실제 평가/공격을 이 작업에서 실행하지 않는다.
관리자만 /api/dashboard-records/evaluation으로 결과를 등록하며 실제 원본·키를 입력 자료로 사용하지 않는다.
run에는 organization/kind(rule,pipeline)/상태/시작완료/규칙·코드·입력digest·시나리오 버전/사례별 기대bool·실제판정·근거·선택경보ID를 고정한다.
연결한 경보ID는 기존 권한 경계에서 존재와 org/rule/version 일치를 확인한다. 경보 없음은 operator가 등록한 평가 결과이며 전체 경보 부재를 서버가 자동 검증했다고 표시하지 않는다.
complete run의 alert/no_alert 사례만 TP/FN/FP/TN으로 분류한다. failed/cancelled/inconclusive run과 실행 오류/판정불가 사례는 분모에서 제외하되 제외 사례/실행 실패 건수를 반드시 함께 표시한다.
precision=TP/(TP+FP)*100, recall=TP/(TP+FN)*100이다. 분모0은null이며100%나0%로 치환하지 않는다.
org/kind/rule/version/code/inputdigest/scenario가 다른 실행은 분리한다. 같은 run ID의 중복은 한 건이며 다른 내용은409다. 재평가에는 새 run ID가 필요하다.
운영 경보 일부의 정탐/오탐 판정을 운영 전체 탐지 성공률로 표현하지 않는다.

## 상태/보존/복구

insight_records는 정책/계정 평가/시나리오 결과의 append-only 원장이고 변경 audit를 별도 저장한다. request collision과 SQLite commit/audit 실패를 성공 처리하지 않는다.
새 DB만 사용하며 기존 packages/cases/dashboards/세션·제품 큐의 스키마/자료를 이관하지 않는다.
DB128MiB, audit100000, records20000, 조회별 records1000/본문256KiB, 웹 요청은 기존8KiB 한도를 유지한다. 용량 초과는 명시적 실패이며 자동 삭제하지 않는다.
중앙 백업 format5는 새 DB의 정확한5테이블/열만 추가하며 과거 format1-4 읽기 계약을 보존한다. 새 서버 인증 키 dashboard-report-auth.key는 이 DB 백업에 넣지 않는다.
새 복원 디렉터리에서는 새 인증 키로 epoch가 바뀌므로 과거 자격 증명은 재설정 필요/인증 실패가 된다. 관리자가 개별 회전을 해야 한다. 이전 인증 키까지 복사한 호스트 snapshot 복원/호스트 침해/HA/재해 전체 손실까지 막는다고 선언하지 않는다.
SQLite 백업 자체는 여러 DB의 분산 원자 snapshot이 아니다. 이 작업에서 실제 운영 백업/복원을 수행하지 않았다.

## 검수와 반영

약50%: 합성 결정/API 경계10항목, 큰 변경 Python 진단, JS3파일 구문만 확인했다. 미사용 import3개를 수정했다.
100%: 새 가중치/평가율/GeoIP 분모·특수주소·조직/버전 격리·DB저장 실패·복원 인증epoch·주요 API/RBAC와 큰 변경 구문만 확인한다.
세부 실행 결과/영향 수정은 docs/work_tracker.md와 Git 제외 state/dashboard-functions에 남긴다.
일반 브라우저/전체 회귀/실장치 heartbeat/실제cloud계정·위치DB·평가시나리오 실행/재부팅은 실행하지 않는다.
현재 실습 Portal 반영은 기존 파일을 백업하고 새 source/assets만 배포한다. 기존키·설정·원본/큐·체크포인트를 변경하지 않는다. 새 위젯은 사용자가 개인 화면에 선택해서 추가한다.


최종 기록(2026-10-21): 50% 합성10항목,100% 후반/영향11항목과 계정 식별 누락 계산 수정1항목, JS결정2항목을 확인했다. 나머지 전체 검증을 실행하지 않았다. 코드/실습 반영과 실제 장치·위치 자료·cloud 설정·평가 결과 연결 인수를 구분한다.
실습 release는 dashboard-capabilities-20261021이며 Portal 실행 경로를 전환해 재시작했다. 별도 Country DB/실장치/기존 자격 증명/실제 평가를 사용하지 않았다. 가려지거나 없는 계정은 개별 계정 수에 넣지 않고 식별 불가 이벤트로 별도 표시한다.


## 후속 연결 계획 — 2026-10-21

이 절은10/21 연결 계획과 인수 조건을 보존한다. 조회 API·화면·장치 상태 원장·계산 로직은 구현돼 있으며 아래 항목을 모두 미구현 기능으로 읽지 않는다. 다음 표는10/27까지의 후속 기록을 반영한 현재 구분이다.

| 계획 ID | 이미 있는 연결/결과 | 남은 범위 |
| --- | --- | --- |
| CONNECT-01 | 경보 상세/evidence API·원본 참조·조직 차단,10/19~20 실제 경보/브라우저 근거 | 새 위젯 경로의 정확한 연결·추가 페이지·없음/권한/실패 경계 중 미인수 부분 |
| CONNECT-02 | 지속 HTTPS heartbeat·서비스 관측·신선도 표시 구현,10/23 managed receipt와 일반 수신의 실제 ES 분리 | 별도 보고 원장과 해당 장치 수신의 정확한 식별 연결·실장치 조합/오류 인수. heartbeat 전체 신규 개발이 아님 |
| CONNECT-03~05 | 평가 기록·GeoIP 조회·계정 수동 근거 평가 코드 | 실제 평가/DB/정책 근거 연결. 자동 실행기·계정 설정 collector는 선택 확장 |
| CONNECT-06 | AWS/OCI 감사 수집·정규화/조회 코드와 격리 검증 | 승인된 실제 계정/자료 인수. OCI/보류된 cloud 운영 인수는 보류 유지 |

10/21 당시의 제안 순서는 경보 원본→장치 보고/수신→평가→지도→계정→클라우드였다. 이를 현재 승인된 전체 우선순위로 재사용하지 않는다. 상세 완료 환경과 제한은 [현재 상태](project_status.md), 남은 범위의 선택은 [작업 목록](work_tracker.md#다음-작업을-정하는-기준)을 따른다.

### DASHBOARD-CONNECT-01 경보에서 정확한 원본까지

- 구현된 evidence API/경보 상세를 재사용한다. 새 위젯의 연결을 인수할 때 규칙 revision, 탐지 조건, 일치 로그 목록, 정확한 raw index/id 및 기존 해시 확인 결과를 대조한다.
- 현재 저장된 실제 경보를 사용하며 원본/정규화/경보 문서를 보강하거나 덮어쓰지 않는다. threshold 근거 목록을 공격 순서나 인과관계로 표현하지 않는다.
- 필요한 조건: 해당 조직의 실제 경보와 읽기 가능한 정확한 원본 참조. 외부 클라우드 계정이나 새 장치 키는 필요하지 않다.
- 추가 인수 조건: 새 위젯 경로의 경보→일치 로그→정확한 원본, 근거 추가 페이지, 다른 조직 차단, 없는 원본·권한 오류·조회 실패 구분.10/19~20의 기본 경보/근거 화면 성공은 유지하고 미확인 경로만 선택한다.

### DASHBOARD-CONNECT-02 장치 상태 보고와 실제 로그 수신

- 지속 보고기는 이미 HTTPS·신뢰 CA/호스트 이름 검증을 사용한다. 실제 연결 대상을 선택하면 해당 Portal origin·프록시·세션 영향을 먼저 확인한다. 인증서 검증 비활성이나 HTTP 우회로 연결하지 않는다.
- 관리자 등록→일회성 전용 장치 자격 증명 전달→별도 보고기 실행→등록 장치 상태 연결 순서로 진행한다. 기존 에이전트를 자동 교체하지 않으며 기존 엔진 키를 보고용으로 사용하지 않는다.
- 현재 위젯의 보고 상태/수집기 관측 상태와, 해당 조직·장치에 바인딩된 실제 마지막 로그 수신 시각을 별개 지표로 연결한다. 로그의 이벤트 시각을 수신 시각으로 대신하지 않는다. 기존 원장과 수신 문서의 장치 ID 연결 가능 여부부터 조사하며 장치 일치 근거가 없으면 추정 매칭하지 않는다.
- 필요한 조건: 접근 가능한 HTTPS origin, 신뢰 인증서, 명시적 프록시 신뢰 범위, 보고기를 실행할 시험 장치와 수집 서비스, 정확한 장치별 수신 식별 계약. 현재 loopback HTTP 경로만으로 실장치 HTTPS 보고가 완료된 것은 아니다.
- 남은 인수: 정상 보고/실제 수집, 보고 정상·로그 중단, 보고 중단·기존 로그 보존, 최초 대기·지연·만료·폐기·회전, DB/통신 오류, 조직 격리. 로그가 발생하지 않는 정상 장치와 수집 장애는 수신 시각 하나만으로 확정하지 않는다.

### DASHBOARD-CONNECT-03 실제 탐지 평가 결과

- 현재 실습 쇼핑몰에서 지원하는 규칙별 정상/공격 시나리오와 기대 경보를 먼저 고정한다. 규칙·코드·입력 digest·시나리오 버전 및 실행 시간 범위를 기록한다.
- 실행 후 실제 수집·정규화·경보·정확한 원본을 대조한 결과를 평가 원장에 등록한다. 현재 등록 폼은 공격 실행기나 자동 평가기가 아니다. 자동화가 필요하면 별도 실행/결과 수집 경계를 구현한다.
- 필요한 조건: 명시된 시험 대상, 합성 입력, 실행 권한, 양성·음성 기대값과 경보 연결. 수동 no_alert 등록을 서버가 모든 경보 부재를 입증한 결과로 바꾸지 않는다.
- 남은 인수: 양성/음성, 실패·판정 불가의 분모 제외, 정밀도·재현율과 원본 근거 대조. 평가 점수와 계정 정책 위반 점수·기존 경보 우선순위를 혼합하지 않는다.

### DASHBOARD-CONNECT-04 국가별 지도

- 별도 이용 조건을 확인한 Country DB를 운영자가 제공하고, 고정 선택 의존성과 SOC_GEOIP_DATABASE 경로를 연결한다. 도형 파일만으로 IP 국가 판별이 되는 것은 아니다.
- 필요한 조건: 허용된 로컬 Country DB, 갱신/파일 권한 정책, 실제 공개 IP가 관측된 웹 접근 자료. 외부 위치 서비스에 IP를 전송하거나 임의의 외부 계정/키를 사용하지 않는다.
- 남은 인수: 국가 조회·원본 이동, 내부/특수/미식별 IP 분리, 위치 coverage 분모, DB 없음·만료·잘못된 타입·권한 실패. 실제 클라이언트 IP가 없으면 전달 헤더를 임의로 신뢰하지 않는다.

### DASHBOARD-CONNECT-05 계정 보안 평가

- 사람이 승인한 평가 기준·배점·판정 근거·예외·만료를 먼저 등록한다. 현재는 수동 근거 평가이며 실제 클라우드 설정을 자동 수집하지 않는다.
- 자동 평가는 별도 읽기 전용 설정 collector, 항목별 API 근거, 조직/공급자/계정 바인딩, 수집 시각/갱신 주기와 실패 상태를 설계한 뒤 연결한다.
- 필요한 조건: 승인된 정책과 실제 근거. 자동 수집 단계에는 대상 계정 및 명시적인 읽기 전용 권한이 추가로 필요하다.
- 남은 인수: 실제 근거별 판정, 승인 예외, 만료/미평가/null, 계정 격리와 가중치 설명. 임의의 기본 점수표나 자료 부재로 안전 점수를 생성하지 않는다.

### DASHBOARD-CONNECT-06 AWS·OCI 실제 수집

- 먼저 실제 사용하는 공급자만 선택하고 기존 cloud 수집/정규화 계약과 최소 권한을 조사한다. 감사 로그→수신/정규화→계정·서비스·행위 분류→기간·조직별 위젯 순서로 연결한다.
- 필요한 조건: 대상 계정/조직 식별, 승인된 수집 경로와 읽기 전용 권한, 해당 공급자의 실제 감사 자료. 해당 환경이 없다면 연결을 보류한다.
- 남은 인수: 실제 자료의 정확한 계정/조직 바인딩, 전체 건수와 표시 상한, IAM/감사 분류 지원 범위, 실제 cloud 경보와 원본 연결, 수집/조회 실패. 계정 ID가 없거나 가려진 이벤트를 하나의 실제 계정으로 세지 않는다.

### 후속 작업 공통 조건

- 이번 요청은 문서와 현재 개발 변경의 Git 보존이다. 추가 구현·장치 등록·자격 증명 발급·외부 계정 연결·서비스 변경·추가 테스트·재부팅은 수행하지 않는다.
- 후속 구현 검수는 현 사용자 지시에 따라 약50%와100%의 큰 변경/계산식 중심으로 계획하고 전체 재검사를 자동 추가하지 않는다. 실제 장치/화면/평가 인수는 해당 작업의 승인 범위를 명시한 뒤 수행한다.
- 기존 데이터·키·원본 참조·해시·큐·체크포인트·저장 배치를 보존하며 테스트 자료와 운영 자료를 혼합하지 않는다. 미연결/미확인 항목은 작업 목록에서 미체크 상태로 유지한다.
