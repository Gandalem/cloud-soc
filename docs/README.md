# Cloud SOC 문서 안내

제품 사용은 [README](../README.md), 다음 개발과 인수는 [작업 목록](work_tracker.md)에서 시작합니다. 설계 제안·과거 검증은 보관 영역으로 분리했습니다. 아래 사용·운영 문서는 현재 소스 기준이며 실제 배포 여부는 작업 목록에서 확인합니다.

최근 실제 시험: [SSH 인증 실패→경보·정확한 근거·대시보드 검증](archive/validation/live_auth_validation_20261012.md). 사건 저장·재시작과 추가 조직/역할 인수는 후속입니다.

## 사용자 안내

| 목적 | 문서 |
| --- | --- |
| 홈·계정별 화면 | [대시보드](dashboards.md) |
| 로그 검색·보호 상세 | [통합 로그](log_explorer.md) · [접근 정책](log_access_policy.md) |
| 사건·메모·판정 | [사건 조사](incident_workflow.md) |
| 신규 설치·토큰 | [설치 상세](installation_reference.md) · [등록 토큰](agent_enrollment.md) |
| 키·마지막 수신 | [발급 키](agent_key_management.md) · [수신 현황](agent_status.md) |
| 기존 Windows 갱신·복구 | [Discovery 갱신](windows_discovery_update.md) · [복구](windows_install_recovery.md) |

## 운영 안내

수집/분석 상세는 운영자의 장애 확인 기능입니다. 고객 메뉴나 홈 기술 위젯으로 노출하지 않으며 데이터·접근 권한·직접 진단 경로는 보존합니다.

| 목적 | 문서 |
| --- | --- |
| 중앙 설치·업데이트 | [서버 가이드](../deploy/server/README.md) · [실제 시험 절차](aws_windows_e2e_test.md) |
| 분석 기동·진단 | [처리 운영](processing_operations.md) · [탐지 배포](detection_deployment_runbook.md) |
| 수집 오류·큐·보고 | [수집 계측](p2_collection_metrics.md) · [수집 보호](collection_protection.md) · [Windows 유실 감사](windows_log_loss_audit.md) |
| 보호 백업·복구 | [포털 백업](portal_backup.md) · [저장량/백업 설계](p2_capacity_backup.md) · [독립 백업 준비](p2_backup_readiness.md) |
| 탐지·소스 지원 범위 | [탐지 범위](detection_coverage.md) · [소스 표](data_source_matrix.md) · [OS 범위](os_log_collection_scope.md) |
| 선택적 클라우드 수집 | [AWS](aws_cloudtrail.md) · [OCI](oci_audit.md) |

## 개발과 검증

[로컬 개발](local_development.md), [공통 화면](portal_layout.md), [조회 계약](log_query_contract.md), [증분 탐지](incremental_detection.md), [수신→탐지 연결](intake_detection_bridge.md), [파이프라인 복구](pipeline_reliability.md), [조사 품질](investigation_quality.md), [공격 시나리오](p5_03_attack_scenarios.md)를 참고합니다. 테스트 통과는 실제 배포·수신 완료를 의미하지 않습니다.

## 과거 기록과 개인 자료

- [전체 작업 이력·기존 인수 기준](work_history_20261012.md): 완료 체크·날짜·검증 결과·제한·보류를 보존한 2026-10-12 정리 전 기록.
- [보관 색인](archive/README.md): 이전 설계·중복 설치 안내·날짜별 검증·포트폴리오 README.
- [후속 확장/제외 사유](deferred_work_20261012.md): 제외를 완료로 처리하지 않습니다.
- [포트폴리오](portfolio/demo.md): 당시 측정·시연 자료이며 현재 전체 인수 결과와 구분합니다.

기존 DOCX 보고서·개인 소감·포트폴리오 이미지/측정값은 수정하거나 삭제하지 않았습니다. 보존/삭제·독립 백업 P2-02의 사용자 보류는 유지합니다.
