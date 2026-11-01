# Security Hub 전달 확인 계획 · 2026-11-01

실행 결과: 승인한 정보 수준 검증 Finding1건을 생성해 기존 EventBridge→CloudWatch 전달을 확인하고 동일 Finding만 ARCHIVED로 보관했다. 실제7종의 개발 ES·정규화·인증 Portal API 인수에 포함해 통과했다. 규칙/다른 Finding/GuardDuty는 변경하지 않았다. 아래는 당시 계획 이력이며 생성 명령을 다시 실행하지 않는다.

## 원인 범위와 선택한 방법

현재 규칙은 ENABLED이며 Osaka/계정/source/detail-type와 RDS DB·VPC ARN 두 개를 조건으로 한다. 조회한 기존 Finding5개는 다른 EC2 ARN을 가지므로 이5개가 전달되지 않는 것은 현재 리소스 조건과 맞는다. 전체 Finding 부재나 모든 미전달 원인이 확정된 것은 아니다.

규칙을 계정 전체로 넓히거나 GuardDuty/팀원 Finding을 수정하지 않고, **현재 RDS ARN을 대상으로 하는 정보 수준 검증 Finding 한 개**를 고객 기본 custom product로 발행한다. 실제 RDS 보안 결함이나 공격을 의미하지 않으며 TEST ONLY를 제목/설명/소유 태그에 명시한다.

## 정확한 쓰기 범위

- 계정897722691159 / ap-northeast-3.
- ProductArn: `arn:aws:securityhub:ap-northeast-3:897722691159:product/897722691159/default` (이미 생성된 기본 제품).
- 유일한 Finding ID: `cloud-soc-validation/20261101-gyumin-rds-delivery-01`.
- Resource ID: `arn:aws:rds:ap-northeast-3:897722691159:db:cloud-soc-rds-mysql`.
- Severity INFORMATIONAL, RecordState ACTIVE, Workflow NEW. 제목 `[TEST ONLY] Cloud SOC delivery verification`.
- `BatchImportFindings` 생성1회, 기존 EventBridge→CloudWatch에서 같은 ID를 조회해 파싱, 마지막에 **동일하게 생성한 한 Finding만** RecordState ARCHIVED로 보관하는 import1회.
- DB/규칙/대상/resource policy/standards/GuardDuty·다른 Finding/라우팅/키는 변경하지 않는다. 기존 로그/데이터 삭제나 신규 AWS 인프라 생성은 없다. Finding/이벤트/로그 수집 사용량이 소량 추가될 수 있으므로 실행 전 사용자의 비용·상태 변경 승인이 필요하다.

## 실행 전 guard와 검증

계정·상용 AWS ARN, 규칙 ENABLED, target이 정확한 CW 그룹1개뿐인지, input 변형이 없는지, 현재 pattern이 예정 ASFF 이벤트와 `test-event-pattern`에서 일치하는지, 같은 ID/ProductArn이 이미 존재하지 않는지를 먼저 읽는다. 하나라도 다르면 생성 전에 중단한다. 기본 CLI는 offline plan이며 `--apply`만 위 쓰기를 수행한다.

공식 SDK의 BatchImportFindings 입력 shape에 요청 JSON을 대조했고 생성/같은 ID archive·조건 변화 시 사전 중단·CW 미전달 시 실패 구분에 대한 고유6개 로컬 검사가 통과했다. 실제 전달/권한 성공으로 간주하지 않는다.

확인 대상은 원문 Finding 전체를 공유하는 것이 아니라 기존 파서의 보호 투영이다. 대기 상한 내 전달이 없으면 실패/미관측으로 보고한다. 성공 후 로컬 개발 ES·정규화·인증 포털로 확인하며 해당 표본은 **의도적 서비스 검증용 Finding**이라고 계속 구분한다. 실제 보안 위협 탐지 성공으로 표시하지 않는다.

## 정리·실패 시 복구

새 표본 생성에 성공한 경우에만 마지막에 같은 payload/ID/ProductArn을 ARCHIVED로 보관한다. archive는 삭제가 아니며 감사 이력을 보존한다. 미전달이어도 이 표본만 보관 정리를 시도한다. 생성 실패/동명 기존 Finding 발견 시 기존 레코드를 건드리지 않는다. archive가 실패하면 이 정확한 ID와 소유 태그를 확인해 보관 작업만 재개한다. 생성 명령을 반복해 다른 표본을 만들거나 원래 rule/target을 바꾸지 않는다.

실행 원본: `src/cloud_soc/aws/securityhub_validation.py`. 검토용 비실행/읽기 전용 모드는 `python -m cloud_soc.aws.securityhub_validation` / `--preflight`, 승인된 생성·검증·보관은 `--apply`다. 전달한 checksum ZIP 명령의 코드 해시는 Git 제외 `state/aws-real-source-check/manifest.json`에 있다.

공식 근거: [기본 custom product ARN](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-custom-providers.html), [Finding 제공자의 import/보관](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-update-batchimportfindings.html), [CSPM EventBridge 형식](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-event-formats.html).
