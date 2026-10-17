# Security Mall 7-A 요청 단위 증거 연관

2026-10-17 최신 상태: **7-A/B 실제 ES 읽기 통합 검증 완료, 7-C 실제 Portal 고정 스냅샷 인수 완료**. 근거는 approved-20261017T105455Z-c289b4ba의 summary/lifecycle(exit0) 및 [실제 검증 기록](security_mall_ab_approved_console.md)이다. 6인덱스211문서·3종묶음8·원본/정규화105대조·증거해시1·격리SQLite12검사를 확인했다. 이번 정정은 저장 증거 대조만 수행했으며 ES 검증을 반복하지 않았다. 실제 AUTH60/반복 가산·실시간 발행·장애/재부팅 복구는 이 완료에서 추정하지 않는다.

로컬 구현 당시: 2026-10-17: **로컬 구현·관련 격리 테스트 완료**. VM 배포, 실ES 조회/쓰기, 서비스 변경, Portal/UI 연동과 사건 우선순위 계산은 수행하지 않았다. Mall systemd 전환·장애/재부팅 시험도 보류 상태를 유지한다.

## 기존 구조와 재사용

기존 `portal/cases.py`는 분석가의 사건 상태/소유자/경보 연결을 관리하며, 자동 요청 연관 엔진은 없었다. 기존 사건 DB에 자동 사건을 만들거나 상태를 덮어쓰지 않는다.

- 기존 `processing.contract.normalize()`의 앱/웹/WAF ECS 형태와 원본 provenance를 입력으로 받는다.
- 기존 `detection.engine.event_evidence()/event_fingerprint()`의 정규화 문서 위치·전체 증거 해시를 재사용한다. 탐지 엔진·룰·위험도·중복 차단은 변경하지 않는다.
- 기존 `LogPrincipal.organizations`의 서버 측 조직 범위를 재사용한다. 원문 열람은 기존 `Operations.evidence()`와 별도 원문 권한 정책의 책임이다.
- 기존 CaseStore와 같은 SQLite/트랜잭션 방식을 사용하되 **별도 비공개 DB**에 허용 메타데이터·참조만 저장한다. 새 범용 저장 프레임워크나 관제 서비스는 만들지 않았다.

변경 파일은 `src/cloud_soc/correlation/{__init__,security_mall,store}.py`, `tests/test_security_mall_correlation.py`, 이 문서 및 `docs/work_tracker.md`다. 기존 Mall·수집·정규화·탐지·Portal 코드는 수정하지 않았다.

## 입력 계약과 사이트/출처 경계

`Scope`는 신뢰하는 서버 설정으로 구성한다. 필수값은 organization/site/host/service, normalized/app-raw/edge-raw/alert **각각의 정확한 인덱스 이름 tuple**, 시간 범위(기본30초, 1~120), 수용량(기본10000)이다. wildcard/콤마 조회는 거부하며 실제/합성/운영 인덱스를 자동 포함하지 않는다.

현재 정규화 이벤트에는 별도 검증된 site 필드가 없다. 따라서 **단일 사이트 전용 수집 인덱스와 host를 서버가 site에 결합**한다. 이벤트가 임의로 주장한 site/collector 값을 사용하지 않는다. 서로 다른 사이트가 동일 host/인덱스를 공유해 구분 불가능하다면 그 설정으로 사이트별 연관을 확정할 수 없다. 배포 전 전용 범위를 확인하거나 별도 신뢰 가능한 사이트 계약이 필요하다. 이번 버전은 동일 host의 세 로그만 지원하며 호스트 사이를 추측해 연결하지 않는다.

입력 형식:

```python
# ES 읽기 어댑터가 반환한 기존 hit 형태. 이 모듈 자체는 ES에 접속하지 않는다.
normalized_hit = {"_index": "정확히 허용된 정규화 인덱스", "_id": "문서ID", "_source": normalized_event}
alert_hit = {"_index": "정확히 허용된 경보 인덱스", "_id": "기존경보ID", "_source": stored_alert}
```

정규화 입력에서 인정하는 어댑터/버전은 기존 `security_mall_audit_v1/security-mall-audit-v1`, `security_mall_edge_v1/security-mall-edge-v1`이다. recognized/event kind, 조직/host/service, 발생/수신 시각, 원본·정규화 위치를 검사한다. 앱 메타데이터는 기존 앱 파서로 재검증하고, edge는 기존 정확한 allowlist 및 조직/host 기반 event.id 산정을 재사용한다. request_id는 기존 Apache 27자 형식이며 없는 과거 앱 이벤트도 허용한다.

## 요청 묶음과 불확실성

연관 후보 키는 **서버 site binding + organization + host + service + http.request.id**다. 발생 시각을 실제 datetime으로 정렬하고, 각 묶음의 최초 시각부터 최대30초 이내의 이벤트만 묶는다. 연쇄적으로 범위를 늘리지 않는다. 수신 지연이 커도 발생 시각이 조건을 만족하면 지연 증거로 반영하며 수신 시각은 관측별로 따로 보존한다.

| 상황 | 결과 |
|---|---|
| 웹/WAF/앱 모두 존재 | `complete`: 세 종류 증거 존재, 출처 인증/침해 확정 의미 아님 |
| 웹만·웹/WAF·앱만·WAF만 | `incomplete`, missing 목록, 없는 이벤트 생성 없음 |
| request_id 없는 과거 앱 | 이벤트별 `unlinked` |
| 같은 ID지만 시간 범위 초과 | 별도 요청 인스턴스 |
| 같은 ID/시간 범위에 서로 다른 웹 접근 관측 복수 | 각각 단독 `ambiguous`, 앱/WAF를 특정 웹 요청에 임의 연결하지 않음 |
| 한 요청에 복수 앱 감사 이벤트 | 고유 event.id/시각별로 각각 보존 |
| 동일 관측 재처리 | 추가 중복 없음 |
| 같은 논리 이벤트의 추가 raw/normalized 참조 | 관측 alias와 증거 해시·수신 시각을 모두 보존 |

같은 ID를 가까운 시각에 재사용했지만 구별할 증거가 없으면 완전 식별은 불가능하다. 모든 결과에 이 한계를 기록한다. 기존 edge event.id는 request_id 기반이므로 수집 단계에서 동일 ID가 create-only로 거부돼 없어진 증거를 이 엔진이 복원할 수는 없다.

앱 ID는 직접 localhost 접근에서 위조 가능하다. `origin_authenticated=false`, `compromise_confirmed=false`와 고정 uncertainty를 항상 전달한다. source.ip는 관측 주소이며 프록시 뒤 실제 사용자를 추정하거나 IP만으로 묶지 않는다.

## 기존 경보 연결·판정

기존 저장 경보 중 WEB-ACCESS-01/WEB-AUTH-01만 입력받는다. `cloud_soc.provenance.evidence`의 **raw index/id + normalized index/id + detector event_hash**가 저장된 관측과 모두 일치해야 연결한다. 해시 없는 과거 증거나 아직 도착하지 않은 참조는 `incomplete/unresolved`다. 원문 메시지·rule snapshot·임의 탐지 문자열을 복사하지 않는다.

- WEB-ACCESS-01은 앱 접근 시도 거부라는 기존 규칙 의미로 연결한다. HTTP403만으로 이 경보를 만들지 않는다.
- WEB-AUTH-01은 여러 요청 묶음을 가리키는 하나의 경보 링크다. 실패/성공 요청을 단일 요청으로 합치지 않는다. 의심 인증 시퀀스이며 계정 탈취 확정이 아니다.
- 기존 `rule_severity`, 계산된 `risk_score`, `risk_level`을 분리해 보존하고 재계산하지 않는다. 합성 AUTH 사례는 medium / 60 / high다.
- 현재 edge 계약은 DetectionOnly/blocked=false만 지원한다. 설정된 rule action `block`을 실제 차단으로 해석하지 않는다. WAF 증거가 없으면 차단 여부는 false가 아닌 null이다. 미지원 차단 모드 입력은 거부한다.
- 웹403 + 동일 묶음의 앱 권한 거부는 `consistent_with_application_denial`로 표시한다. 원인 확정이 아니며 앱 증거 없는 일반403은 `undetermined`다.

## 저장·조회·동시성

`CorrelationStore(path, scope)`는 비공개 디렉터리의 별도 SQLite 파일을 사용한다. Linux에서는 소유자/0700 디렉터리/0600 파일을 요구하고 symlink·hardlink를 거부한다. Windows의 실제 배포 ACL 및 Linux 권한 분기 실환경 검증은 별도다. 기존 비어 있지 않은 파일은 read-only SQLite 연결로 전용 테이블 구성을 먼저 확인하며, 다른 DB나 손상 파일이면 수정 없이 거부한다. binding 초기화는 쓰기 트랜잭션으로 직렬화한다. 기존 Portal DB·H2·registry는 사용하지 않는다.

`ingest(normalized_hits, alert_hits)`는 신뢰하는 로컬 처리 경로다. 배치 검증 후 BEGIN IMMEDIATE로 메타데이터와 관측/경보를 원자적으로 병합한다. 동일 event identity의 내용 충돌, raw/normalized 위치 충돌, 불변 경보 충돌 또는 수용량 초과 시 배치 전체를 롤백한다. 예외를 무시하지 않으며 원문 입력을 오류 메시지로 출력하지 않는다.

`snapshot(principal)`은 일관된 SQLite 읽기 snapshot에서 연관 결과와 경보 링크를 함께 계산한다. 결과 테이블을 따로 누적하지 않으므로 지연 증거로 묶음이 바뀌어도 오래된 링크가 남지 않는다. 동일 입력의 ID/revision은 결정적이다. **더 이른 지연 증거나 모호성 발견으로 묶음 ID가 바뀔 수 있다.** 소비자는 이전 결과에 부분 append하지 말고 같은 scope의 새 revision을 원자적으로 교체한다. 불변 참조는 event.id와 raw/normalized index/id다.

단일 binding당 기본 이벤트·관측·경보 및 총 경보 증거 참조 상한은 각각10000이다. 넘으면 명시적으로 실패하며 조용히 삭제/축약하지 않는다. 자동 보존기간 정리·대용량 분산 처리·상주 갱신은 이번 범위가 아니다.

`request(bundle_id, principal)`은 조직 밖/존재하지 않음 모두 같은 `correlation_not_found`를 반환한다. `evidence()`는 참조/해시만 반환한다. 원문 조회에는 기존 원문 권한 검사와 raw/normalized 재검증을 계속 적용해야 한다. principal·Scope는 브라우저 요청에서 만들면 안 된다. 이 단계에서는 HTTP API를 추가하지 않았다.

## 7-B 전달 계약

2026-10-17 후속 [7-B 우선순위 계약](security_mall_triage.md)에서 `revision_order(publisher_id/sequence/binding_id)`와 경보 링크의 허용된 `evidence` 참조 목록을 추가했다. 순번은 같은 ledger 트랜잭션의 실제 변경에만 증가한다. content revision 계산에서는 순서 메타데이터를 제외하며 기존 증거/경보 ID는 유지한다. 기존 전용 DB 업그레이드는 로컬 임시DB에서만 검증했고 실제 배포는 하지 않았다. 아래7-A 원래 검증 이력은 보존한다.

| 위치 | 내용 |
|---|---|
| 루트 | schema_version=1, version=`mall-request-evidence-v1`, scope, revision, requests, alert_links |
| requests[].id / request_id | 증거 묶음 ID / 실제 Apache 상관 ID, 별도 개념 |
| scope | organization, site, host, service |
| state / present / missing | complete/incomplete/unlinked/ambiguous 및 web/waf/app 존재·누락 |
| events | event_id, stream, request_id, occurred_at, source_ip, 허용 metadata, observations |
| app metadata | action/outcome, 가명 account_id/account_key_id, resource_type/authorization_reason |
| web metadata | method, 템플릿 path, status_code, duration_us |
| waf metadata | 검증된 rules(id/severity/action/diagnostic), engine_mode, blocked |
| observations | normalized/raw index/id, event_hash, complete, ingested_at |
| related_alerts | 기존 경보 index/id |
| basis / uncertainties / assessment | 연결 근거, ID 위조·재사용·누락 한계, 앱 거부/403/WAF 상태; 공격 성공 추정 없음 |
| alert_links | alert index/id, rule_id, occurred_at, rule_severity/risk_score/risk_level, request_bundle_ids, state, unresolved, basis, interpretation |

`request_bundle_ids`는 requests[].id를 가리키며 실제 request_id 문자열 목록이 아니다. 사건 작업은 기존 CaseStore의 경보 연결을 사용하고, 7-B가 별도 우선순위 계약을 정할 때 증거 완전성/불확실성을 함께 전달한다. 여기서는 새 위험 점수·자동 사건 판정·신규 룰을 만들지 않는다.

## 테스트 및 남은 실제 검증

신규 고유 사례 **49건 통과**다. 47건 통과 후 최종 필드명/모호 상태 변경 영향8건만 재확인했고, 기존 다른 DB·손상 파일 보호2건 추가와 자체 DB 재개/사이트 binding 영향2건을 함께 확인해4건 통과했다. 신규 Python4파일 Pyflakes 진단0이며 미사용 import1건을 정리한 뒤 해당 정적 검사만 재확인했다.

기존 normalize()/앱·edge 파서 및 기존 detector/build_security_alert를 실제 호출하고 합성 TSV/Native/앱 이벤트, 임시 SQLite만 사용했다. 최초 공용 pytest 임시 폴더 권한 오류는 전용 state 임시 경로로 분리했다. 이후35건 중 웹 fixture의 필수 TSV 표식 누락으로10건 실패/25건 통과였고 표식만 수정해 실패10건을 재검증했다. 시간 소수점 정렬/증거 인덱스/한도 보강 후47건을 검증했다. 이전 단계49건/전체 Python·UI 테스트는 반복하지 않았다. 실행·코드 해시·보존 확인 기록은 Git 제외 `state/security-mall-correlation-7a-20261017/verification.json`이다.

다음은 로컬 구현 당시 남은 항목 기록이며 실제 ES 미실행이라는 과거 상태는 위 최신 결과로 대체한다. 당시 후속 승인된 배포에서 exact 인덱스와 단일 사이트 binding, ES 읽기 principal/CA·최소권한, 실제4-C 경보 hash 계약/정규화 전체 _source 읽기 범위, 보존기간 만료 증거, 실제 지연/ID재사용/재시작 후 재처리, 조직별 서버 API 정책 및 조회 비용을 확인해야 한다. 증거 해시는 원본 정규화 _source 전체와 문서 locator로 계산하므로 조회 어댑터가 필드를 생략하면 기존 경보 해시 검증에 실패하며 이를 무시하면 안 된다.

실제 원본·정규화·경보 문서, 실서비스·ES·수집 설정, 쇼핑몰 별도 저장소는 변경하지 않았다. 배포/실제 수집 성공을 로컬 테스트에서 추정하지 않는다.
