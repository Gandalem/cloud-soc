# WEB-WAF-01 — 9-B 자체 SQLi 의심 메타데이터 판정

2026-10-17: 로컬 구현·격리 합성 검증 완료. 실제 SQLi 요청/ES 경보/VM 배포/브라우저 인수는 미검증이다.

변경 파일:

- `rules/security_mall.yml`
- `src/cloud_soc/detection/{waf,engine,registry,rule_loader,profiles,telemetry}.py` (`waf.py` 신규)
- `src/cloud_soc/portal/operations.py`, `prototype/mall-alerts.js`
- `tests/test_security_mall_waf_detection.py`(신규), `tests/test_mall_alert_ui.cjs`
- `tests/test_rule_management.py`, `tests/test_ruleset_complete.py`, `tests/test_ruleset_integration.py`
- `docs/security_mall_waf_detection.md`(신규), `docs/work_tracker.md`

## 판정 계약

- 기존 `rules/security_mall.yml`의 threshold 타입과 기존 registry/슬라이딩 윈도/증분 runtime/경보 create-only 계약을 사용한다. 새 탐지 엔진·수집 필드·저장소는 없다. 기본 Worker는 AUTH-001 그대로이며 WEB-WAF-01은 명시 선택해야 한다. YAML enabled는 VM 활성화 증거가 아니다.
- 필수 범위: organization.id + service.name=security-mall + host.id + source.ip. 현재 edge-v1의 한 호스트/서비스는 하나의 고정 실습 사이트다. 여러 사이트가 이 범위를 공유하면 사이트별 collector 범위를 분리하기 전 합산하면 안 된다. 관측 IP는 실제 클라이언트/동일 공격자 인증이 아니다.
- `security_mall_edge_v1` / `waf_rule_match` / stream=waf의 정규화 이벤트만 사용한다. 기존 strict edge allowlist와 중복 필드, event.id, timestamp, http.request.id의 일치를 검사한다. event.id·정규화 index/id·원본 index/id·증거 SHA256을 그대로 유지하며 필수 provenance가 없으면 실패한다.
- SQLi ID 초기 allowlist: **942100, 942140, 942160, 942170, 942190, 942220, 942230, 942240**. [공식 CRS 3.3.5 SQLi 규칙 파일](https://github.com/coreruleset/coreruleset/blob/v3.3.5/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf)에서 확인했다. 전체 SQLi 규칙을 포괄하지 않는 제한된 초기 목록이며 942 접두사만으로 탐지하지 않는다. CRS 버전 자체는 이벤트에 없으므로 기존 실습 3.3.5 설정을 전제로 한다.
- 진단10002, CRS 초기화901001, Host 경고920350, 제어942011/942012, 그 밖의 비허용 ID만 있는 이벤트는 제외한다. 동일 이벤트에 SQLi와 진단 ID가 함께 있으면 SQLi ID만 근거로 사용한다. 요청 원문·매칭 문자열·쿠키·계정 원문은 추가 수집하지 않는다.

## 독립 요청·반복과 위험도

- **300초 안에서 같은 범위·관측 IP·request_id는 1요청**으로 센다. 한 요청의 복수 SQLi ID나 정규화 재처리는 요청 수를 늘리지 않는다. 이벤트 시각 정렬과 기존 window/runtime 직렬화를 재사용한다. 이미 유지 중인 요청의 재처리는 건너뛰고, 미처리 이벤트가 확정 runtime 시각보다 역전되면 기존 엔진의 안전한 실패를 유지한다. 무제한 지연 처리를 새로 구현하지 않는다.
- 단일 요청도 경보를 만든다. 2요청은 복수/반복 기준 미만, **5분 내 3요청 이상은 반복 의심**으로 별도 assessment를 기록한다. 3건/300초는 통계적으로 검증된 공격 임계치가 아니라 소수 요청으로 반복을 설명하고 한 요청의 다중 CRS 매치와 구분하기 위한 초기 실습 설정이다. YAML `waf_sqli.repeat_requests` 및 `time_window`에 집중 관리한다.
- 각 새 요청은 하나의 경보를 만들며 해당 시점 window의 증거를 참조한다. 경보 ID는 규칙 revision + 범위 + 트리거 요청 + 발생 시각에 고정한다. 같은 요청의 재처리/정규화 참조 변경은 create 충돌로 기존 경보를 보존한다. 지연 증거로 기존 경보를 갱신하지 않으며 임의의 장기 request_id 고유성을 주장하지 않는다.
- 규칙 severity는 **medium**. 기존 triage-v1 산식은 변경하지 않았다. 단일 요청은45/medium, 2요청 이상은 기존 threshold 빈도 가산(+10)으로55/medium이다. 반복3건에 별도 가산/심각도 승격은 없다. 기존 AUTH60 및 ACCESS20도 유지한다.
- assessment는 SQLi 근거 ID, 선언 동작, 독립 요청 수/ID, 증거 event.id, 반복 기준/판정, engine_mode/blocked, 한계를 담는다. 원본 index/id·해시는 기존 provenance에만 보존한다. 공격 성공/SQL 실행/출처 인증을 확정하지 않는다.

## DetectionOnly 및 Portal

기존 edge 계약은 DetectionOnly + blocked=false만 지원한다. `block`/`deny`는 규칙의 **선언 동작**이며 실제 차단이 아니다. On 또는 blocked=true는 현재 계약 밖으로 거부한다. 실제 차단을 확인했다고 보고하지 않는다.

기존 Mall 경보 API/카운트/상세와 공유 `mall-alerts.js`에 연결했다. 원래 severity/risk, 단일/반복 판단, 요청 수, SQLi ID, 선언 동작과 DetectionOnly, 검증된 정제 증거 링크를 표시한다. 7-C 스냅샷이 없으면 조사 분석 미확인으로 유지한다. 증거 해시·원본 identity·조직 검사 전에는 새 증거를 노출하지 않는다.

기존 정확 인덱스 allowlist/원문 역할 정책은 확대하지 않았다. 현재 실습 Portal의 앱 원본 전용 scope/읽기 키가 edge 인덱스를 허용하지 않으면 WAF 증거는 계속 조회 불가다. 실제 동시 앱/edge 조회를 위한 서버 allowlist·키 검토, 파일 배포 및 Portal 인수는 별도 승인 후 수행해야 한다. 8단계 수동 초안 작성기의 제한된 YAML 편집 계약은 확장하지 않았다.

## 실행한 최소 검증

- 신규 합성 Python31건: 실제 envelope/normalize → YAML/엔진 → 경보 → Flask API 경로. SQLi8 ID, 진단/비관련 제외, 요청 중복/정렬/300초 경계/반복, runtime JSON 복원, create 충돌, 조직·호스트·IP/서비스 분리, 잘못된 모드/필드/증거 거부, 비밀 표식 미출력, Portal 조직/원문/인덱스 조작/증거 변조 차단. 기존 증분 Worker/임시 SQLite에서 최초3경보·checkpoint 재실행 추가0건도 확인했다.
- 직접 영향 기존 Python7건: 명시 profile/기본 AUTH-001, ACCESS20/low, AUTH60/medium severity, 룰 관리 카탈로그17 및 승인/내보내기, Portal 기존 증거/기존 AUTH-001, 고정 카탈로그 CLI 검증.
- 공유 DOM12건(신규2 + 기존10), 변경 Python 정적 검사0건 오류. 실제 브라우저가 아닌 Node DOM 대역이다.
- 초기 fixture의 UTC 표기와 Windows 임시 디렉터리 권한, ES 대역의 문자열 시간 경계만 수정했다. 성공한 검사를 불필요하게 반복하지 않았다. 프로젝트 테스트 의존성은 Git 제외 state/waf-09b-test-deps에만 격리 준비했다.
- 기존 범용 ruleset fixture는 event 시각/결과만 바꾸므로 edge-v1의 대응 envelope/ID 검사를 표현하지 못한다. 그 두 기존 suite의 기존16규칙 범위는 유지하고 새 WEB-WAF-01은 별도31사례로 검증한다. inventory는 전체17규칙을 검사한다. Worker의 30초 조회 지연+60초 확정 대기보다 이른 합성 실행이 처리0건인 것은 정상이며 fixture 시각만 조정했다. 전체 suite를 통과했다고 주장하지 않는다.
- ES transport/create 충돌은 대역이다. 실제 SQLi 로그, ES 저장, 탐지 상주 배포 및 브라우저는 미검증. VM·서비스·실제 데이터·활성 탐지 설정은 변경하지 않았다.
