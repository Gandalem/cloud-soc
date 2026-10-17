# 8-C 실습 Portal 실제 반영·인수

2026-10-17: **8-C 완료 — 수동 MVP 실습 인수 완료, AI 미연동, 운영 룰 적용 없음.**

- 사전점검 명세의13파일이 불변인 것을 확인하고 반영했다. 기존 Portal과 대상/의존 파일·WSGI/unit이 기준선과 일치했으며 추가 파일은 Portal 전용 코드/UI와 검증 참조 YAML뿐이다. 기존 탐지기 파일은 교체하지 않았다.
- 백업: `/home/kopo/soc-mall-lab/portal-lab/backups/8c-87a6d2`. SQLite4개를 read-only 소스의 Online Backup으로 복제하고 각각 integrity_check=ok와 SHA를 기록했다. 코드·실행 설정·unit·비밀 config 복구본은 VM의0700/0600 보호 경로에만 유지한다. DB 전체 복원·정상 이력 삭제는 하지 않았다.
- Portal 한 번 restart(exit0): **892692→933317**, active/running, login HTTP200. `cases.sqlite`에 rule_drafts/rule_history 및 rule_approved_id만 새로 생겼다. IF NOT EXISTS 방식이며 기존 스키마/사건 레코드와 기존 대시보드 행이 보존됐다. config·기존 엔진/7-A/B/C 코드·다른 사용자 서비스의 PID/시작 시각/상태도 불변이다. 롤백 불필요.

## 실제 Edge 인수 — 핵심 흐름1회

| 확인 | 결과 |
| --- | --- |
| 기존 관리자 로그인·AI 미연동 UI·수동 YAML 작성 | 성공 |
| 기존 엔진 형식 검증 | 성공 |
| 잘못된 YAML 검증 실패·승인 비활성화·관리자 거부 | 성공 |
| 명시 승인·승인자/시각/동일 SHA·이력·원문 YAML 내보내기 | 성공 |
| 승인 전 apply/export | 409 |
| CSRF 없는 관리자 validate/approve | 403 |
| 일반·타 조직 사용자의 관리 화면/API/승인/이력/export | 403 |
| 조직 파라미터 조작 | 400 |
| 기존 ACCESS1·조사20/low·limited·severitylow/risk20low | 보존 |
| 기존 증거 해시·메타데이터 링크 | normalized_hash_verified / HTTP200 |
| 타 조직 경보/증거·보호 원문 | 404 / 403 |

Edge155.0.4283.45·5검사군 통과·pageerror0이며 스크린샷도 확인했다. 기존 전역 관리자는 두 설정 조직을 관리할 권한이 있고, 제한 관리자 별도 역할은 이번에 추가하지 않았다. 조직 제한 관리자404는 이전 격리 테스트 범위로 구분한다.

새 테이블에 **실습 초안2개·승인1개·거부1개·이력7행**을 남겼다. 승인 규칙 `DEMO-MANUAL-20261017-87A6D2`는 pending_deployment/active=false이며 탐지기에 전달하거나 활성화하지 않았다. 테스트 이력을 삭제하지 않는다. 기존 사건·승인 이력 삭제, ES 데이터 쓰기/재수집, 다른 서비스 재시작, VM 재부팅, Git commit/push는 없다.

Git제외 로컬 근거: `state/rule-management-8c-20261017/acceptance.json`, `deployment.json`, `rules-approved.png`, `rules-rejected.png`, `access-preserved.png`. VM 배포 기록은 `portal-lab/staging/8c-87a6d2/deployment.json`이다. 백업의 원본 비밀 파일은 로컬이나 Git에 복사하지 않았다.

## 기존 기록 정정·남은 범위

7-A/B의 과거 ‘실ES 미실행’ 설명을 기존 c289b4ba의 완료 summary/lifecycle(exit0)와 대조해 최신 완료 상태로 정정했다. 새 ES 통합 시험은 수행하지 않았다. 실제 AUTH60/반복 가산, 실시간7-A/B 발행 및 장애 복구를 성공으로 확장하지 않는다.

AI는 미연동이고 적용 요청은 별도 배포 대기다. 기존 최소 읽기 권한 때문에 전역 수집 상태 일부는 미확인으로 남는다. 8-D는 공급자·비밀 관리·외부 전송 범위·비용 승인 후 별도로 시작할 수 있으며 이번에는 구현/연결하지 않았다.
