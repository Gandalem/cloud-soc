# Cloud SOC 작업 목록

기준: 2026-10-26, D:/cloud-soc main ac64198와 보존된 로컬 수정. 현재 기능/검증은 [프로젝트 상태](project_status.md), 사용은 [문서 색인](README.md)을 따른다.

## 작업 원칙

- 새 사용자 지시가 우선한다. 구현 시작 전에 관련 ID를 진행 중으로 기록하고, 명시된 인수 기준을 검증한 뒤에만 완료 체크한다.
- 구현·격리 검사·실제 설치·수신·배포는 별도다. 과거 부모 미체크나 오래된 실패를 현재 기능 전체의 부재로 확대하지 않는다.
- 기존 수정·로그/키/데이터·체크포인트와 완료 이력을 보존한다. 비밀값은 기록하지 않는다. 커밋/푸시·운영 배포·재부팅은 별도 요청 범위에서만 한다.
- 모든 이전 작업 ID의 상세 요구·순서·승인·완료 체크·실패/제한은 [압축 전 작업 목록](archive/README.md#record-docs-work-tracker-md)과 [10/12 누적 이력](archive/README.md#record-docs-work-history-20261012-md)에 원문 그대로 있다. 아래 ID가 생략됐다고 완료/취소된 것이 아니다.

## 현재 작업

- DOC-PUBLISH-20261026-01 요청/범위(2026-10-26): 사용자 추가 지시로 아래 문서 통합·압축 변경을 main에 커밋하고 origin/main으로 일반 푸시한다. 이전 문서 정리 시점의 커밋/푸시 제외는 이번 Git 반영 요청으로 대체한다. 대상은 README·문서/보관 ZIP·문서 검사 경로 수정이며 기존 Portal app.py/test_alert_navigation.py 미커밋 변경은 제외·보존한다. 운영 배포·키/데이터·재부팅 허가로 확대하지 않는다. 커밋과 원격 반영의 실제 결과는 Git 이력과 최종 응답으로 확인한다.

- [x] DOC-ARCHIVE-20261026-02 완료(2026-10-26): docs 루트85파일→현재 안내32개, 하위 포함125→41파일로 정리했다. 과거 설계/날짜별 검증·긴 작업 이력, Mall17문서, 참고/루트 중복 안내2개, 포트폴리오10자료, Word2개를5개 ZIP의 원래 경로·MANIFEST.json에 보존했다.98개 원본의 CRC/크기/SHA256을 대조한 뒤 개별 파일94개만 삭제했다. docs 전체 용량은 약4.40→3.14MB(약29% 감소)다. 현재 사용은 portal_usage.md와 optional_integrations.md로 모으고 이전 미체크 ID49개/전체 완료·승인 원문은 그대로 유지했다.
- 검수/범위: 문서 구문·참조16검사와 README 추가 정리 후 직접 영향2검사가 통과했다. 현재 상대 링크274개·압축 원문406개 누락0, 소스의 삭제 문서 참조0을 확인했다. CI용 coverage.svg/evaluation.json과 기존 app.py/test_alert_navigation.py 수정은 해시 불변이다. 원본/ZIP 계획·검수 결과는 Git 제외 state/document-archive-20261026에 있다. 문서 검사 외 기능 실행·서비스/배포·키/데이터 변경·재부팅·커밋/푸시는 하지 않았다. 압축 원문은 조회/복원용이며 현재 코드/서버에 덮어쓰는 배포물이 아니다.

## 최근 완료 요약

- [x] DOC-CONSOLIDATION-20261026-01(10/26): 중복11문서→4문서, 대상170,534→56,077bytes·1,162→473행. 문서16검사/상대 링크660개 통과. 현재 정리로 후속 경로가 다시 바뀌었으며 원본/기록은 history-docs.zip에 보존했다.
- [x] CODE-GAP-AUDIT-20261026-01 / DOC-STATUS-AUDIT-20261026-01(10/26): 문서/코드 대조 완료. 기본 설치·실수신·경보·기존 Repair/재등록·지속 heartbeat는 존재한다. 정상 설치 수집 키 교체/제거 후 복원과 보존 정책, 릴리스/미인수 범위를 구분했다. 새 실서버 검증은 하지 않았다.
- [x] GIT-UPDATE-20261026-01(10/26): 기존3파일 수정/백업을 보존하고 main34c2139→ac64198 fast-forward. 갱신이 배포를 뜻하지 않는다.
- [x] INSTALL-DEVICE-UX-01-NATIVE-MERGE(10/26): PR20 병합17a32c4, 코드50ebce9의 Ubuntu/Windows CI 성공 기록.10/25 양 OS 제품 설치·합성 경보·제거/TLS 결과는 [장치 설치](device_installation.md#검증-이력)에 모았다. 운영 서명/모든 복구/GUI 전체 인수는 별도다.

## 이전 미체크 작업 ID

압축 전 목록의 미체크49개를 관리상 그대로 남긴다. 아래는 현재 미구현 기능이나 새 실행 순서가 아니다. 예를 들어 WINDOWS-POLICY의 초기 실패는 후속 native LAB 성공으로 갱신됐지만 운영 릴리스 부모 체크는 유지됐고, DASHBOARD-MOVE-01은 사용자 지시로 검수를 생략했다. P2-02의 독립 저장소/보관·복원과 OCI 운영 연결 보류도 유지한다. 각 원문과 후속 완료를 함께 확인한 뒤 관련 ID만 갱신한다.

- [ ] INSTALL-DEVICE-UX-01-WINDOWS-NATIVE
- [ ] INSTALL-DEVICE-UX-01-WINDOWS-NATIVE-RELEASE
- [ ] INSTALL-DEVICE-UX-01-OS-LAB
- [ ] INSTALL-DEVICE-UX-01-WINDOWS-POLICY
- [ ] INSTALL-DEVICE-UX-01
- [ ] INSTALL-DEVICE-UX-01-RELEASE
- [ ] AWS-AGENT-EXEC-01
- [ ] PORTAL-NGROK-ENTRY-01
- [ ] VIDEO-E2E-01
- [ ] DASHBOARD-FUNCTIONS-02
- [ ] DASHBOARD-MOVE-01
- [ ] RULE-AUTHORING-01
- [ ] CORE-INGEST-ALERT-01
- [ ] GENERIC-WAF-01
- [ ] GENERIC-CORE-01
- [ ] GENERIC-SITE-01
- [ ] GENERIC-OPERATIONS-01
- [ ] OPS-RUNTIME-01
- [ ] OPS-ACCEPTANCE-01
- [ ] RULE-MANAGEMENT-08
- [ ] MALL-APP-06E2A-TWO-STOP-TRANSITION
- [ ] MALL-APP-06E2A-APPROVED-TRANSITION
- [ ] MALL-WAF-06E2A-FINAL-TRANSITION
- [ ] MALL-WAF-06E2A-WAF-RETRY
- [ ] MALL-WAF-06E2A
- [ ] MALL-WAF-06D
- [ ] GIT-INTEGRATE-20261015-CI
- [ ] PARITY-FRESH-OS-01
- [ ] PARITY-CENTRAL-LIVE-01
- [ ] DET-EXT-ACTIVATE-20261014
- [ ] SITE-AGENT-01
- [ ] SITE-LIVE-01
- [ ] ISSUE-12
- [ ] DET-EXT-LIVE-01
- [ ] DASH-01
- [ ] UX-02
- [ ] P0-02
- [ ] P2-02
- [ ] P2-03
- [ ] P3-01
- [ ] P4-01
- [ ] P5-01
- [ ] P5-02
- [ ] P5-03
- [ ] P5-05
- [ ] P6-02
- [ ] P6-04
- [ ] P7-01
- [ ] P7-02
