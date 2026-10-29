# Cloud SOC 문서

현재 설치·운영·개발에 쓰는 문서32개를 이 폴더에 두고, 과거 설계/검증·선택 실습·포트폴리오·보고서는 [보관 색인](archive/README.md)의5개 ZIP으로 정리했다. 구현/배포/실수신을 구분한 요약은 [현재 상태](project_status.md), 승인과 진행은 [작업 목록](work_tracker.md)을 따른다.

학교·집에서 작업 안내가 다르면 [저장소와 최신 커밋 확인](local_development.md#여러-pc에서-같은-작업-목록-읽기)을 먼저 따른다. 폴더 이름·과거 채팅·부모 미체크 목록만으로 현재 미구현 기능이나 다음 작업 순서를 정하지 않는다.

학교·집 코드 통합은 [선택적 추가 Portal 주소](runtime_deployment.md#선택적-추가-portal-주소--학교집-통합-3안)를 따른다. 학교의 review-compose와 복구 경로를 유지하고 기존 대표·ngrok·수신 주소를 바꾸지 않는 추가 DNS/IP만 연결한다.

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

[로컬 개발](local_development.md), [공통 화면](archive/README.md#record-docs-portal-layout-md), [조회 계약](log_query_contract.md), [증분 탐지](archive/README.md#record-docs-incremental-detection-md), [수신→탐지 연결](archive/README.md#record-docs-intake-detection-bridge-md), [파이프라인 복구](pipeline_reliability.md), [조사 품질](archive/README.md#record-docs-investigation-quality-md), [공격 시나리오](archive/README.md#record-docs-p5-03-attack-scenarios-md)를 참고합니다. 테스트 통과는 실제 배포·수신 완료를 의미하지 않습니다.

## 과거 기록과 개인 자료

- [전체 작업 이력·기존 인수 기준](archive/README.md#record-docs-work-history-20261012-md): 완료 체크·날짜·검증 결과·제한·보류를 보존한 2026-10-12 정리 전 기록.
- [보관 색인](archive/README.md): 이전 설계·중복 설치 안내·날짜별 검증·포트폴리오 README.
- [후속 확장/제외 사유](archive/README.md#record-docs-deferred-work-20261012-md): 제외를 완료로 처리하지 않습니다.
- [포트폴리오](archive/README.md#record-docs-portfolio-demo-md): 당시 측정·시연 자료이며 현재 전체 인수 결과와 구분합니다.

기존 DOCX 보고서·개인 소감·포트폴리오 이미지/측정값은 수정하거나 삭제하지 않았습니다. 보존/삭제·독립 백업 P2-02의 사용자 보류는 유지합니다.


- [규칙 작성·일괄 등록·빠른 탐지 관리](rule_authoring.md)

- [상시 처리·AJAX 갱신·실습 복구](live_ajax_runtime.md)

- [보안 중심 수집 정책과 통합 로그 종류](security_collection_policy.md)

- [대시보드 근거·연결 상태·국가 지도·계정 평가·성능 지표](dashboard_capabilities.md)

- 다음 작업: [대시보드 실제 자료 연결의 순서·필요 조건·인수 기준](dashboard_capabilities.md#후속-연결-계획--2026-10-21)

- [계산·권한·조회·장치·폼 테스트 보강과 검수 범위](archive/README.md#record-docs-test-quality-md)

- [백업 형식 2·3·4·5 호환성 회귀와 PR18 수정](archive/README.md#record-docs-backup-format-regression-md)

- [Security Mall 로그인 감사 배포 패키지](../deploy/security-mall/login-audit/README.md): 별도 쇼핑몰 패치와 전용 수집기. HTTPS 중앙 ES가 필요하며 인증 없는 로컬 개발 Compose와 구분합니다.

- [시드니 AWS·T-Pot 수집 계층](aws_sydney_ingestion.md): S3/SQS 대량 수집, 팀 Role/리소스 바인딩, 읽기 전용 조사와 실행 전제.
