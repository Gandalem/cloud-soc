# 보관 자료

현재 사용은 [문서 색인](../README.md), 구현/검증 요약은 [현재 상태](../project_status.md), 승인과 진행 상태는 [작업 목록](../work_tracker.md)을 따른다. 아래 ZIP은 과거 자료의 원본이며 현재 설치 명령이나 새 실행 승인이 아니다.

## 압축 파일

| 자료 | 파일 수 | 원본 → ZIP |
| --- | ---: | --- |
| [과거 설계·날짜별 검증·완료/승인 이력](history-docs.zip) | 62 | 1,700,795 → 665,064 bytes |
| [선택 Security Mall 실습](mall-docs.zip) | 17 | 176,894 → 84,753 bytes |
| [참고 설계·데이터·중복 루트 안내](reference-docs.zip) | 7 | 63,644 → 31,338 bytes |
| [포트폴리오·시연·측정·원래 이미지](portfolio-docs.zip) | 10 | 908,768 → 818,425 bytes |
| [기존 Word 보고서](reports-docs.zip) | 2 | 1,137,469 → 1,044,588 bytes |

원래 저장소 상대 경로·크기·SHA256은 각 ZIP의 MANIFEST.json에 있다. 모든 파일의 CRC와 원본 바이트 해시를 대조한 후 개별 원본을 정리했다. Word·이미지·완료 체크/승인 이력도 내용 변경 없이 포함했다. CI용 portfolio/coverage.svg와 평가 기본 출력 evaluation.json은 현재 위치에도 남긴다.

## 조회와 복원

ZIP을 새 임시 폴더에 풀어 원래 경로로 조회한다. 현재 저장소나 서버에 덮어쓰지 않는다. 압축 파일 사이의 상대 참조는 함께 풀거나 현재 가이드를 이용한다. 목록만 확인할 때는 다음 명령을 사용한다.

```text
python -m zipfile -l docs/archive/history-docs.zip
```

## 이전 경로 색인

각 항목은 ZIP 내부의 원래 경로다. 이전 문서 링크는 해당 항목으로 연결된다. 선택 실습의 현재 안내는 [선택 실습·참고](../optional_integrations.md)에 있다.

### 과거 설계·날짜별 검증·완료/승인 이력

- <a id="record-docs-archive-readme-md"></a>`docs/archive/README.md`
- <a id="record-docs-archive-readme-20261012-md"></a>`docs/archive/README_20261012.md`
- <a id="record-docs-archive-design-analyst-workflow-md"></a>`docs/archive/design/analyst_workflow.md`
- <a id="record-docs-archive-design-dashboard-data-requirements-md"></a>`docs/archive/design/dashboard_data_requirements.md`
- <a id="record-docs-archive-design-dashboard-implementation-plan-md"></a>`docs/archive/design/dashboard_implementation_plan.md`
- <a id="record-docs-archive-design-dashboard-requirements-md"></a>`docs/archive/design/dashboard_requirements.md`
- <a id="record-docs-archive-design-dashboard-wireframes-md"></a>`docs/archive/design/dashboard_wireframes.md`
- <a id="record-docs-archive-design-implementation-roadmap-v2-md"></a>`docs/archive/design/implementation_roadmap_v2.md`
- <a id="record-docs-archive-design-installation-md"></a>`docs/archive/design/installation.md`
- <a id="record-docs-archive-design-phase-a-decisions-md"></a>`docs/archive/design/phase_a_decisions.md`
- <a id="record-docs-archive-design-siem-architecture-md"></a>`docs/archive/design/siem_architecture.md`
- <a id="record-docs-archive-design-siem-product-requirements-md"></a>`docs/archive/design/siem_product_requirements.md`
- <a id="record-docs-archive-design-siem-reference-research-md"></a>`docs/archive/design/siem_reference_research.md`
- <a id="record-docs-archive-design-ui-specification-md"></a>`docs/archive/design/ui_specification.md`
- <a id="record-docs-archive-validation-chart-validation-20261012-md"></a>`docs/archive/validation/chart_validation_20261012.md`
- <a id="record-docs-archive-validation-customer-cleanup-20261012-md"></a>`docs/archive/validation/customer_cleanup_20261012.md`
- <a id="record-docs-archive-validation-customer-readiness-20261012-md"></a>`docs/archive/validation/customer_readiness_20261012.md`
- <a id="record-docs-archive-validation-dashboard-deployment-20261012-md"></a>`docs/archive/validation/dashboard_deployment_20261012.md`
- <a id="record-docs-archive-validation-improvements-1-12-md"></a>`docs/archive/validation/improvements_1_12.md`
- <a id="record-docs-archive-validation-integration-validation-20261008-md"></a>`docs/archive/validation/integration_validation_20261008.md`
- <a id="record-docs-archive-validation-live-auth-validation-20261012-md"></a>`docs/archive/validation/live_auth_validation_20261012.md`
- <a id="record-docs-archive-validation-log-query-validation-20261004-md"></a>`docs/archive/validation/log_query_validation_20261004.md`
- <a id="record-docs-archive-validation-p0c03-validation-20261004-md"></a>`docs/archive/validation/p0c03_validation_20261004.md`
- <a id="record-docs-archive-validation-p2-capacity-validation-20261007-md"></a>`docs/archive/validation/p2_capacity_validation_20261007.md`
- <a id="record-docs-archive-validation-p2-source-access-validation-20261004-md"></a>`docs/archive/validation/p2_source_access_validation_20261004.md`
- <a id="record-docs-archive-validation-p5-03-attack-detection-validation-md"></a>`docs/archive/validation/p5_03_attack_detection_validation.md`
- <a id="record-docs-archive-validation-park-p2-integration-20261008-md"></a>`docs/archive/validation/park_p2_integration_20261008.md`
- <a id="record-docs-archive-validation-pr3-review-fixes-20261008-md"></a>`docs/archive/validation/pr3_review_fixes_20261008.md`
- <a id="record-docs-archive-validation-protected-deployment-20261012-md"></a>`docs/archive/validation/protected_deployment_20261012.md`
- <a id="record-docs-archive-validation-theme-validation-20261012-md"></a>`docs/archive/validation/theme_validation_20261012.md`
- <a id="record-docs-aws-dvwa-web-collection-20261013-md"></a>`docs/aws_dvwa_web_collection_20261013.md`
- <a id="record-docs-aws-windows-e2e-test-md"></a>`docs/aws_windows_e2e_test.md`
- <a id="record-docs-backup-format-regression-md"></a>`docs/backup_format_regression.md`
- <a id="record-docs-cloud-soc-issue-audit-20261013-md"></a>`docs/cloud_soc_issue_audit_20261013.md`
- <a id="record-docs-dashboard-movement-md"></a>`docs/dashboard_movement.md`
- <a id="record-docs-dashboard-platform-validation-20261013-md"></a>`docs/dashboard_platform_validation_20261013.md`
- <a id="record-docs-dashboards-md"></a>`docs/dashboards.md`
- <a id="record-docs-deferred-work-20261012-md"></a>`docs/deferred_work_20261012.md`
- <a id="record-docs-detection-deployment-runbook-md"></a>`docs/detection_deployment_runbook.md`
- <a id="record-docs-early-deployment-validation-20261013-md"></a>`docs/early_deployment_validation_20261013.md`
- <a id="record-docs-first-install-walkthrough-md"></a>`docs/first_install_walkthrough.md`
- <a id="record-docs-host-security-audit-md"></a>`docs/host_security_audit.md`
- <a id="record-docs-incident-workflow-md"></a>`docs/incident_workflow.md`
- <a id="record-docs-incremental-detection-md"></a>`docs/incremental_detection.md`
- <a id="record-docs-intake-detection-bridge-md"></a>`docs/intake_detection_bridge.md`
- <a id="record-docs-investigation-quality-md"></a>`docs/investigation_quality.md`
- <a id="record-docs-lab-recovery-20261013-md"></a>`docs/lab_recovery_20261013.md`
- <a id="record-docs-lan-portal-fix-20261013-md"></a>`docs/lan_portal_fix_20261013.md`
- <a id="record-docs-latest-release-20261014-md"></a>`docs/latest_release_20261014.md`
- <a id="record-docs-log-explorer-md"></a>`docs/log_explorer.md`
- <a id="record-docs-portal-layout-md"></a>`docs/portal_layout.md`
- <a id="record-docs-realtime-detection-20261013-md"></a>`docs/realtime_detection_20261013.md`
- <a id="record-docs-rule-management-8c-validation-md"></a>`docs/rule_management_8c_validation.md`
- <a id="record-docs-rule-management-deployment-preflight-md"></a>`docs/rule_management_deployment_preflight.md`
- <a id="record-docs-rule-management-mvp-md"></a>`docs/rule_management_mvp.md`
- <a id="record-docs-ruleset-14-validation-20261014-md"></a>`docs/ruleset_14_validation_20261014.md`
- <a id="record-docs-runtime-parity-validation-20261014-md"></a>`docs/runtime_parity_validation_20261014.md`
- <a id="record-docs-test-quality-md"></a>`docs/test_quality.md`
- <a id="record-docs-ubuntu-update-20261014-md"></a>`docs/ubuntu_update_20261014.md`
- <a id="record-docs-unified-site-validation-20261014-md"></a>`docs/unified_site_validation_20261014.md`
- <a id="record-docs-work-history-20261012-md"></a>`docs/work_history_20261012.md`
- <a id="record-docs-work-tracker-md"></a>`docs/work_tracker.md`

### 선택 Security Mall 실습

- <a id="record-docs-security-mall-9c-predeployment-md"></a>`docs/security_mall_9c_predeployment.md`
- <a id="record-docs-security-mall-ab-approved-console-md"></a>`docs/security_mall_ab_approved_console.md`
- <a id="record-docs-security-mall-alert-integration-validation-md"></a>`docs/security_mall_alert_integration_validation.md`
- <a id="record-docs-security-mall-audit-md"></a>`docs/security_mall_audit.md`
- <a id="record-docs-security-mall-collection-md"></a>`docs/security_mall_collection.md`
- <a id="record-docs-security-mall-correlation-md"></a>`docs/security_mall_correlation.md`
- <a id="record-docs-security-mall-detection-md"></a>`docs/security_mall_detection.md`
- <a id="record-docs-security-mall-edge-collection-md"></a>`docs/security_mall_edge_collection.md`
- <a id="record-docs-security-mall-integration-validation-md"></a>`docs/security_mall_integration_validation.md`
- <a id="record-docs-security-mall-portal-md"></a>`docs/security_mall_portal.md`
- <a id="record-docs-security-mall-portal-investigation-md"></a>`docs/security_mall_portal_investigation.md`
- <a id="record-docs-security-mall-request-id-md"></a>`docs/security_mall_request_id.md`
- <a id="record-docs-security-mall-request-id-integration-validation-md"></a>`docs/security_mall_request_id_integration_validation.md`
- <a id="record-docs-security-mall-triage-md"></a>`docs/security_mall_triage.md`
- <a id="record-docs-security-mall-validation-reader-cli-md"></a>`docs/security_mall_validation_reader_cli.md`
- <a id="record-docs-security-mall-validation-reader-plan-md"></a>`docs/security_mall_validation_reader_plan.md`
- <a id="record-docs-security-mall-waf-detection-md"></a>`docs/security_mall_waf_detection.md`

### 참고 설계·데이터·중복 루트 안내

- <a id="record-cloud-core-detection-guide-md"></a>`cloud-core-detection-guide.md`
- <a id="record-docs-data-source-matrix-md"></a>`docs/data_source_matrix.md`
- <a id="record-docs-os-log-collection-scope-md"></a>`docs/os_log_collection_scope.md`
- <a id="record-docs-p5-03-attack-scenarios-md"></a>`docs/p5_03_attack_scenarios.md`
- <a id="record-docs-reference-securitydatasets-aws-s3-md"></a>`docs/reference_securitydatasets_aws_s3.md`
- <a id="record-docs-reference-stratus-red-team-md"></a>`docs/reference_stratus_red_team.md`
- <a id="record-soc-investigation-quality-guide-md"></a>`soc-investigation-quality-guide.md`

### 포트폴리오·시연·측정·원래 이미지

- <a id="record-docs-portfolio-architecture-md"></a>`docs/portfolio/architecture.md`
- <a id="record-docs-portfolio-coverage-svg"></a>`docs/portfolio/coverage.svg`
- <a id="record-docs-portfolio-demo-md"></a>`docs/portfolio/demo.md`
- <a id="record-docs-portfolio-evaluation-json"></a>`docs/portfolio/evaluation.json`
- <a id="record-docs-portfolio-images-alert-detail-png"></a>`docs/portfolio/images/alert-detail.png`
- <a id="record-docs-portfolio-images-dashboard-png"></a>`docs/portfolio/images/dashboard.png`
- <a id="record-docs-portfolio-images-investigation-png"></a>`docs/portfolio/images/investigation.png`
- <a id="record-docs-portfolio-measurements-md"></a>`docs/portfolio/measurements.md`
- <a id="record-docs-portfolio-mitre-md"></a>`docs/portfolio/mitre.md`
- <a id="record-docs-portfolio-screenshots-md"></a>`docs/portfolio/screenshots.md`

### 기존 Word 보고서

- <a id="record-docs-4-docx"></a>`docs/클라우드 보안관제(4조).docx`
- <a id="record-docs-mvp-docx"></a>`docs/클라우드_보안관제_MVP_구현계획.docx`
