# 백업 형식 호환성 회귀 — CI-BACKUP-REGRESSION-01

2026-10-21, Gandalem/cloud-soc codex/operational-readiness, PR18.

## 원인과 수정 범위

run39454882184의 Linux/Windows는 현재 Portal이 dashboard-insights.sqlite를 만드는 상태에서 과거format2/3/4를 기대해 실패했다. 제품의 format5 선택은 유지한다. 운영 DB나 백업·키는 사용하지 않는다.

tests/legacy_backup_fixtures.py에 format2의 packages/cases/source-access SQL과 format3 단일 dashboards/format4 collections SQL을 고정했다. 현재 app/store 생성자나 backup.SCHEMAS를 가져오지 않는다. 각 parameter 사례에 새 디렉터리를 만들고 서로 다른 사용자·배치·기본 선택·사건·감사·패키지 합성 자료를 저장한다. 최신상태를 삭제해 과거로 바꾸지 않는다.

과거자료는 두 경로로 확인한다. current_writer는 구버전 스키마가 있는 원본에서 현재 writer의 형식 선택·백업·복원을 확인한다. frozen_manifest는 stdlib 복사/고정 manifest 필드/SHA256/독립 table count만으로 과거 artifact를 구성해 현재 writer 없이 verify/restore를 확인한다. 최신 artifact의 버전숫자만 바꾸지 않는다.

## 실제 확인 대상

- test_dashboard_collection.py: 현재format5에서 개인별 legacy 배치와 collection/default, 새 장치 보고·정책/근거평가/시나리오 원장의 정확한 snapshot을 복원한다. 모든 파일·테이블/열·내용과 원본 불변을 확인한다. format3/4도 두 사용자별 값을 복원한 뒤 현재 DashboardStore로 읽는다.
- test_source_access.py: 현재format5에서 실제 합성 보호원문 조회의 감사 기록을 복원한다. format2/3/4는 독립 parameter로 각형식의 정확한 파일과 감사 참조를 복원한다.
- 복원 직후 read-only SQLite로 구조·내용을 먼저 비교하고 그다음 Store를 생성한다. 자동 초기화로 누락을 가리지 않는다.
- format5에는 인증키 파일을 포함하지 않는다. 새 복원 위치에서 생성한 서버 인증키가 다르고 이전 장치 자격 증명은 실패/재설정 필요다. 원장의 과거 내용은 그대로 보존된다.
- 기존 경로 덮어쓰기·잘못된 schema/manifest·WAL/권한 관련 제품 차단은 변경하지 않는다.

## 진행·검수

중간 검사 없이 작성 후 변경2파일/관련 core backup/기존 인증키 복원 검사와 변경 helper 정적 진단만 한번 수행한다. 실패 수정 시 영향 항목만 다시 실행한다. 이후 커밋/푸시하고 PR18 최신SHA Actions의 Linux/Windows 결과를 확인한다. 뒤 단계에서 새 실패가 나면 해당 원인을 조사해 범위 내 보완한다.

로컬 검사·원격 Actions·실제 운영 복원은 별개다. 전체 수동suite/전체브라우저·운영복원·배포·재부팅·main병합은 하지 않는다. 구체 결과는 docs/work_tracker.md와 Git 제외 state/ci-backup-regression에 보존한다.

로컬 결과: 관련71항목의 최초70통과/시험 경로1실패를 기록했다. 원본 내부 백업을 차단하는 제품 계약을 유지하고 시험 대상 경로만 형제 디렉터리로 바꿔 해당1항목 통과했다. 변경 정적 진단에서 unused import1건을 제거하고 재확인했다. 전체 수동suite/운영복원은 하지 않았다. 최신 PR18 Actions 확인은 다음 단계이며 아직 전체CI 통과로 표시하지 않는다.
