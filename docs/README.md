# Cloud SOC 문서

현재 설치·운영·개발에 쓰는 문서32개를 이 폴더에 두고, 과거 설계/검증·선택 실습·포트폴리오·보고서는 [보관 색인](archive/README.md)의5개 ZIP으로 정리했다. 구현/배포/실수신을 구분한 요약은 [현재 상태](project_status.md), 승인과 진행은 [작업 목록](work_tracker.md)을 따른다.

학교·집에서 작업 안내가 다르면 [저장소와 최신 커밋 확인](local_development.md#여러-pc에서-같은-작업-목록-읽기)을 먼저 따른다. 폴더 이름·과거 채팅·부모 미체크 목록만으로 현재 미구현 기능이나 다음 작업 순서를 정하지 않는다.

## 설치와 일상 사용

| 목적 | 문서 |
| --- | --- |
| 빠른 시작·수동 설정 | [제품 README](../README.md) · [설치 참고](installation_reference.md) |
| 장치 설치·EXE/DEB·서버 메뉴 | [장치 설치](device_installation.md) |
| 등록·키·수신·기존 Windows 복구 | [에이전트 운영](agent_management.md) · [Windows 운영](windows_agents.md) |
| 대시보드·로그·사건 | [Portal 사용](portal_usage.md) · [추가 위젯/장치 보고](dashboard_capabilities.md) |
| 보호된 상세·조회 계약 | [접근 정책](log_access_policy.md) · [조회 계약](log_query_contract.md) |
| 규칙 작성·지원 범위 | [규칙 관리](rule_authoring.md) · [탐지 범위](detection_coverage.md) |

## 서버 운영

| 목적 | 문서 |
| --- | --- |
| 중앙 설치·업데이트·복구 | [서버 상세](../deploy/server/README.md) · [공통 런타임](runtime_deployment.md) |
| 상시 분석·처리·장애 | [상주/AJAX](live_ajax_runtime.md) · [처리 운영](processing_operations.md) · [파이프라인](pipeline_reliability.md) |
| 수집 범위·민감정보·통계 | [보안 정책](security_collection_policy.md) · [사이트](unified_site_agent.md) · [보호](collection_protection.md) · [계측](p2_collection_metrics.md) |
| 백업·보관·유실 | [Portal 백업](portal_backup.md) · [저장량/복구](p2_capacity_backup.md) · [독립 백업](p2_backup_readiness.md) · [Windows 유실 감사](windows_log_loss_audit.md) |
| 클라우드·Kibana | [AWS](aws_cloudtrail.md) · [OCI](oci_audit.md) · [클라우드 규칙](cloud_detection.md) · [Kibana](kibana_setup.md) |

## 개발·검증·보관

[로컬 개발](local_development.md) · [독립 SOC 인수](operational_acceptance.md) · [현재 구현/검증](project_status.md) · [선택 Mall/합성 시연/참고](optional_integrations.md) · [보관 ZIP과 이전 파일 경로](archive/README.md).

긴 이전 작업 목록과 모든 완료/미완료 체크·승인/제한 원문은 history-docs.zip에 보존했다. 날짜별 검증은 해당 환경/범위의 기록이며 현재 서비스가 실행 중임을 보장하지 않는다. 압축을 새 검증이나 배포로 해석하지 않는다.
