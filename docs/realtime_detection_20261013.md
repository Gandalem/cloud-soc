# 빠른 초기 통지·공격 징후 확장 — 2026-10-13

최신 후속은 [전체 장애 점검·사건/재시작·초기 상태 안내 보완·실제 후보 필드·키 만료](cloud_soc_issue_audit_20261013.md)입니다. 현재 기본 AUTH/early만 활성이고 새 후보는 계속 비활성입니다. 아래 개발/배포 당시 기록을 보존합니다.

FAST-01 / DET-EXT-01. main `b67eefa` 기준, `codex/dashboard-platform-20261013`의 대시보드·개인 Word/JSON을 보존했다. 아래는 초기 개발 당시 로컬/합성 인수와 제약의 기록이다. 후속 사용자 승인으로 192.168.32.60의 기본 AUTH/early·포털/정규화를 보호 적용해 실제9/10·약25.894초 화면·최종 frontier/근거·재시작과 정상 키 형식 보완을 검증하고 기능 브랜치에 push했다. 최신 실제 결과와 미완료 AWS/Windows·snapshot/역할 범위는 [보호 배포 인수](early_deployment_validation_20261013.md)를 따른다. 신규 패턴 운영 활성화·main push·PR 생성/병합은 없다.

## 1. 기존 탐지 시스템

원본 참조·event.ingested·cloud_soc.normalized_at을 유지한다. 최종 탐지의 PIT/spool 전체 읽기·이벤트 시각 frontier·유예 900초·수신 overlap 15분·grace 30초를 변경하지 않았다. AUTH-001은 조직/IP별 실패 10건/300초·cooldown 300초이며 기존 journald/ISO 5ms 미러 계약을 재사용한다. security-alerts create-only·기본 rule version/state identity는 유지했다.

## 2. 초기 통지 구조

명시 `--early-auth`만 실행하며 `<state>.early.sqlite`에 초기 스캔/관측/통지/outbox를 영속 저장한다. 최초 receipt 범위는 기존 start와 현재 5분 중 늦은 시각부터다. 초기 경로는 grace/유예를 기다리지 않고 정규화만 읽으며 AUTH 엔진·정확한 proof·미러 판정을 재사용한다. 원본/정규화 쓰기는 없다.

`soc-alert-notices-v1`에 같은 logical ID의 불변 revision을 create_doc으로 추가한다. 초기→검증 중→확정 또는 정정, 장애는 검증 지연이다. 확정/정정은 종결이며 정정은 정상/무해 판정이 아니다. ES 409는 revision 전체 해시가 같아야 성공이다. 초기 10 proof를 고정하고 최종 proof를 덮어쓰지 않는다.

최종 DB의 링크 outbox와 checkpoint를 함께 커밋해 sidecar에 적용한다. 같은 조직/IP/AUTH version·겹치는 구간·창 종료 차이 300초 미만의 cooldown episode를 연결하며 같은 세션/공격자라는 주장이 아니다. 지연 입력으로 최종 대표 proof가 바뀔 수 있다. frontier가 초기 창 종료를 5ms 이상 지난 뒤 final이 없으면 suppression 등을 포함한 정정이다.

초기 활성 입력 상한은 기존 명시 옵션을 따른다. notice는 sidecar당 10,000개, 전송은 회당 100 revision, 미전달 final 링크는 1,000개+frontier/gap marker다. 넘치면 final을 계속하고 불확실한 notice는 지연·수동 대조 필요로 둔다. gap을 자동 삭제/정상 종결하지 않는다. 영구 보존·처리량 보장은 아니다.

## 3. 추가 공격 시나리오

| 요청 | 구현/재사용 | 조건·한계 |
| --- | --- | --- |
| DET-01 SSH | AUTH-001 + 초기 통지 | 10/300. Hydra·침해 성공 미확정 |
| DET-02 다수 계정 실패 | AUTH-SPRAY-001 | 조직/IP, 10/300 + user.name 4종. 비밀번호 동일성 미관측 |
| DET-03 실패 후 성공 | AUTH-SEQ-001 | 조직/호스트/사용자/IP, 5회/300 후 실제 성공. 탈취 판정 아님 |
| DET-04 SSH 후 권한 활동 | ATTACK-01 | 기존 그룹/순서/창. sudo metadata만으로 동일 SSH session/상승 성공 미확정 |
| DET-05 Windows | WIN-AUTH-001, 비활성 | 4625 adapter 실패, 조직/호스트/IP/계정/실제 logon type, 10/300. type 3/10 분리·RDP 단정 금지 |
| DET-06 AWS ConsoleLogin | AWS-CONSOLE-001, 비활성 | 5/600, 조직/계정/명시 principal ID·ARN·지원 identity type·고유 event ID |
| DET-07 HTTP404 | WEB-404-001, 비활성 | 조직/웹 호스트/IP, 20/300, low 신뢰. 경로/취약점 종류 미관측 |
| DET-08 포트 탐색 | NET-PORT-001, 비활성 | 조직/src/dst IP·TCP/UDP·종료 flow ID, 15종/300, flow/tuple 중복 제거. Nmap/SYN 미확정 |
| DET-09 AWS 정찰 | ATTACK-02 | 지원 API 20/300 + 4종, 계정/명시 주체. 정상 inventory 가능 |
| DET-10 보안 변경 | 기존 single 4개 | 실제 성공 변경. 승인된 운영 활동 가능 |
| DET-11 권한 후 감사 중지 | ATTACK-03 | 계정/명시 주체, 정책 연결→900초 내 StopLogging/DeleteTrail 성공. 침해/전체 감사 제거 미확정 |

## 4. 기존 규칙 재사용

AUTH-001, AUTH-SEQ-001, ATTACK-01/02/03, AWS-IAM-001/AWS-AUDIT-001/AWS-NETWORK-001/OCI-IAM-001을 복제·완화하지 않았다. 기존 include-cloud/sequence/attacks 범위를 유지하며 다른 rule 경보를 같은 공격으로 자동 연결하지 않는다.

## 5. 실행·비활성·설계 후보

default는 AUTH-001만이다. 명시 `--include-patterns`는 현재 field 계약이 확인된 SSH 다수 계정 후보만 추가한다. 네 후보는 YAML enabled:false로 이 옵션에도 실행하지 않는다. 다섯 후보의 실행 코드는 실제 adapter 합성 시험에서 검증했고 운영 활성화/인수는 별도다.

WEB-01 SQLi / WEB-02 XSS / WEB-03 command injection / WEB-04 traversal / WEB-05 웹 로그인 대량 실패는 **명세/field gate만 정리했고 실행 rule은 없다**. URL/query/body/header·security signature·웹 로그인 outcome·요청/trace와 실행 연결 ID가 없다. HTTP400/500·확장자·동시 프로세스를 공격 근거로 쓰지 않는다. 새 WAF/CRS/ModSecurity/Sigma/MITRE DB·센서/민감 수집 확대는 없고 ATTACK-05 미지원 판단을 유지한다.

## 6. 신규 Rule ID·검증

metadata-cardinality-v1과 metadata_patterns.yml의 위 5개 ID를 추가했다. count/distinct/window/cooldown/field allowlist·typed metadata·group·고유 raw/flow/event ID를 검사한다. 누락은 unknown/기존 평가 제외로 기록하며 window 만료 때 식별자/종류 counter를 제거하고 finalized 순서를 유지한다. 웹 원문·비밀을 proof에 복사하지 않는다.

## 7. 초기 개발 당시 실제 필드·접속 확인

이전 SSH 실제 필드는 [2026-10-12 LIVE-AUTH-01](archive/validation/live_auth_validation_20261012.md)에서 확인했으며 이번 초기 기능 운영 인수가 아니다. Windows 4625 과거 수신은 있지만 새 IP/호스트/type gate는 미확인이다. 웹·종료 flow 포트·AWS ConsoleLogin 실제 field 집합도 미확인이다.

| 지정 서버 | 읽기 전용 확인 | 남은 범위 |
| --- | --- | --- |
| AWS 13.208.175.237 | ec2-user SSH, sagikazarmark/dvwa·HTTP80·기본 GET 1회 302. SOC filebeat/packetbeat LoadState not-found | 다른 전송 경로/중앙 수신·CloudTrail/signature·신규 탐지 미검증 |
| Ubuntu 192.168.32.60 | kopo SSH, 두 SOC 수집기·discovery timer active | Docker 권한 없음/sudo 비밀번호 요구, 중앙 ES/checkpoint/실수신 미조회. Running을 저장 성공으로 보지 않음 |
| Windows 192.168.1.138 | TCP22·등록 공개키/기존 로컬 키 일치 | hp 현재 키 인증 거부. 과거 등록을 현재 성공으로 보지 않음 |

제공 AWS 키의 일반 그룹 상속 읽기 권한 때문에 OpenSSH가 거부했다. 기존 ACL 메타데이터를 Git 제외 검증 경로에 백업하고 사용자/SYSTEM/Administrators 권한으로 제한했다. 키 내용은 변경·출력/문서화하지 않았다. AWS 첫 host key는 작업용 known-hosts에 고정했고 콘솔 지문 대조는 미실행이다. 서버 코드/키 발급/설정/재시작/AWS 자원 변경/공격 트래픽은 없다. 정상 SSH/기본 GET은 접속 로그를 남길 수 있다.

## 8. 시험 결과

최종 전체 Python **762 passed / 19 skipped / 257 subtests**, 86.94초. 최종 전체 UI **142 passed**, 0 failed. Ruff·diff 통과, Bandit 중간/높음 0. skip은 운영 성공이 아니다. 동일 원본의 정규화 버전 중복과 malformed UI 방어도 보완하고 마지막 전체 회귀를 통과했다.

실제 normalizer/엔진·임시 DB·ES 대역으로 9/10, 조직/IP/창/미러·raw/flow/event ID 중복·4624/4625/type3/10·HTTP 정상/오류/404·크롤러 한계·단일/15종 포트·종료 flow·ConsoleLogin 신원/ID/성공·누락·대량 중복·cooldown/순서를 확인했다. 초기/최종 checkpoint/900초 독립·부분 spool·409 내용 충돌·최종 장애·종결·큐 overflow·새 worker process 재시작·identity 전환 거부·원본 불변도 통과했다.

실제 portal 세션 401·admin/analyst/viewer read-only·조직/위조 헤더 무효·원문 권한 유지·proof/만료/부분 검색 실패·미설정/0을 검사했다. Chrome 홈/개인 저장·재조회·10초 갱신, 동일 ID 5상태·proof hash, 1440/768/390 두 테마/modal 넘침 없음, empty/unconfigured/503, JS 예외 0. 의도한 503 HTTP console 오류 1개는 기대된 실패다.

첫 전체 role 기대값 누락 1개를 수정하고 위 전체 검사를 통과했다. 브라우저 ES 대역 options 공유와 종결 역전을 기대하던 시험을 수정했다. 종결 역전은 제품 동작이 아니며 fixture에서 독립 표시 상태만 재생했다.

## 9. 실제 측정 지연

이 절의 초기 개발 당시 운영 ES tenth 검색 가능→UI는 **미측정**이었다. 후속 실제25.894초 인수는 [보호 배포 기록](early_deployment_validation_20261013.md)에 별도로 남겼다. normalized_at은 검색 가능 시각이 아니며 normalization_to_initial_seconds만으로 60초를 증명하지 않는다. 이벤트 창·첫 중앙 수신·proof 최대 정규화·검색 관측·초기 생성·최종 링크 시각을 따로 저장/표시한다.

실제 엔진/SQLite/Flask/Chrome과 검색 즉시 가능한 **합성 ES 저장소**에서 tenth 노출을 따로 기록해 초기 생성/10초 poll UI를 3회 측정한다. 최종 수치는 아래에 기록한다. 수신 배치·정규화·ES refresh·긴 최종 scan/큐/권한 오류까지 운영 보장하지 않는다. CLI default60초는 유지하며 early만10초다. 명시 interval은 유지한다.

## 10. 대시보드 연결

홈 초기 영역/개인 early-notices widget을 추가하고 기존 개인 설정 자동 이행은 없다. logical ID별 최신 revision collapse, **초기 생성 시각**으로 기간 선택해 기간 밖 final 때문에 옛 상태를 보여 주지 않는다. 최신50 표본이며 기존 final 수와 합산해 공격/성공 건수로 표시하지 않는다.

상세 시각·초기 proof/해시/원본 참조 상태·final 조사 링크를 표시한다. 원문은 기존 별도 감사/권한 흐름이다. 안전 DOM·24개 같은 widget 기간별 한 번 조회·limit/정렬·stale/abort·403 중단·페이지 숨김 정지. 개인 일반60초/선택 초기10초 갱신이다. 카탈로그는 이번 포함32개(관리자27/일반24 활성), 이전 DASH-02 당시31개 기록은 보존한다.

## 11. 오탐·한계

NAT/공유 gateway·정상 관리자/비밀번호/MFA/잠금·크롤러/잘못된 링크·모니터링/서비스 검색·승인 IAM 변경도 일치할 수 있다. 근거 없이 자동 제외하지 않고 snapshot/assessment에 한계를 보존한다. 비밀번호 동일성·Hydra/Nmap/SYN·침해/상승/웹 실행 성공은 미확정이다. 미수집/미설정/권한 오류/조회 실패와 실제0을 구분한다.

notice10,000 상한/sidecar 보존/gap 수동 대조는 운영 과제다. 긴 기존 최종 cycle 때문에 다음 초기 cycle이 늦어질 수 있어 지속 고유입의60초 SLO를 주장하지 않는다. 15분보다 긴 가시성 지연·NTP/실제 refresh/용량은 별도 인수다.

## 12. 운영 후속·전환

개발 당시 신규 배포와 setup --prepare-early의 실제 키 발급은 미실행이었다. 후속 승인 배포/전용 키 준비 결과는 [실제 보호 인수](early_deployment_validation_20261013.md)를 따른다. [런북](detection_deployment_runbook.md)의 실제 이미지/명령/start/source/profile/lateness/DB/키/권한부터 대조하고 보호 복구를 준비한다. early만 켤 때 기존 rule identity/main DB를 유지한다. notice mapping·detector create_doc/read/view_index_metadata·monitor read/view_index_metadata를 명시 준비해야 한다.

profile 추가는 identity 변경이며 승인된 새 state/start와 인수가 필요하다. 기존 state 자동 초기화·전체 재처리는 없다. rollback은 early flag만 제거해 final을 계속하고 sidecar/notice를 보존한다. 최종 DB/sidecar를 일관되게 함께 backup해 outbox/identity·복구를 확인하고 ES notice 보존도 별도다. overflow는 기존 final/notice 대조 후 수동 복구하며 gap 자동 삭제는 없다.

후속은 Windows 현재 접속 복구, Ubuntu 중앙 읽기 권한/실수신, AWS DVWA의 승인된 기존 메타데이터 전송 경로다. 이후 실제 tenth→UI→15분 뒤 final proof/동일 notice/재시작을 인수한다. 비활성 네 후보는 field gate 확인 전 유지한다.

## 13. 변경 파일

새 제품: src/cloud_soc/detection/{early,patterns}.py, portal/notices.py, rules/metadata_patterns.yml, prototype/alert-notices.{js,css}. 연결: detection __main__/engine/incremental/registry/rule_loader/setup/telemetry/worker, portal app/auth/status_setup/dashboard_widgets, prototype index.html/dashboard.html/dashboard-builder.js/dashboard-widgets.js.

시험: tests/test_early_notices.py·test_metadata_patterns.py·test_agent_status.py·preview_early_notices.py·browser_early_notices.cjs·browser_early_latency.cjs, prototype/tests/alert-notices.test.cjs. 문서: 본 보고서·런북·대시보드 안내·tracker. 기존 대시보드 작업/개인 Word/JSON은 별도 기존 변경이다.

## 최종 3회 지연 기록

2026-10-13 10:25 KST, 루프백 합성 저장소의 tenth 노출→초기 생성/Chrome 표시. 같은 PC의 실제 wall clock으로 측정했다. 세 회 모두 자동 조회를 포함하며 요청/갱신 타이밍에 따라 두 번째는 즉시 표시됐다.

| 회차 | 초기 생성(초) | 화면 표시(초) |
| --- | ---: | ---: |
| 1 | 0.013 | 10.082 |
| 2 | 0.011 | 0.050 |
| 3 | 0.010 | 10.529 |

초기 생성 10~13ms, UI 최대 10.529초로 이 합성 조건의 60초 목표 이내다. 실제 ES·수집기·운영 서버 지연/목표 달성 검증은 아니다. 증거: Git 제외 `output/playwright/early-notices/latency.json`, home 1440/768/390의 light/dark, proof 390의 light/dark, personal 1440/390 스크린샷. 화면/위젯의 실제 최종 링크와 운영 사건 인수는 별도다.
