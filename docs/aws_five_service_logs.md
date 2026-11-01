# AWS 5개 서비스 로그 수집 인계 · 2026-11-01

현재 결과: **5개 서비스7종의 실제 로그·개발 연동 검증 완료**다. CloudShell 수동 보호 표본→격리 Linux ES→정규화→인증 Portal API 범위이며 자동 상주 collector/학교 배포·브라우저 렌더링은 미완료다. 최신 인수 표와 제한은 마지막 절을 따른다. 아래 초기 분석·조회와208/30 검사 수치는 당시 이력이다.

## 분석 기준과 기존 구현

최신 `origin/main caefeb2`에서 분석을 시작한 뒤 사용자 지시로 `origin/gyumin 5f57818` 기반 로컬 `gyumin`으로 전환했다. 작업 폴더는 `D:/cloud-soc/state/aws-five-service-logs`다. gyumin의 기존 OS 로그 표시·mget 상세 조회 개선과 이력을 보존해 AWS 변경을 결합했다. 기존 `D:/cloud-soc`의 Mall 브랜치·미추적 작업은 변경하지 않았다. 소스 존재·자동 시험과 실제 배포·수신은 별도다.

| 항목 | main의 근거 | 판정 |
|---|---|---|
| AWS 수집 | `src/cloud_soc/aws/collector.py:poll_region`, `__main__.py` | CloudTrail `LookupEvents` 관리 이벤트 전용. CloudWatch 읽기 없음 |
| 재전송/체크포인트 | `collector.py:State`, `ElasticsearchSink` | SQLite 범위 지문·구간 완료 후 전진·결정적 ID·create/409 재사용 가능 |
| 정규화/민감정보 | `aws/cloudtrail.py:project_event` | 계정/리전 검사·선별 메타데이터. DNS/Finding/SQL/접근/방화벽 파서는 없음 |
| ES 매핑/배포 | `deploy/aws/index-template.json`, `deploy/server/bootstrap.py` | `soc-cloud-aws-*`, 서버 수신시각 pipeline·기존 reader/writer 준비. 자동 AWS 실행 없음 |
| Portal | `portal/log_contract.py`, `log_query.py`, `security_detail.py`, `prototype/logs.js` | CloudTrail만 AWS 출처로 인식. 새 출처는 미분류/미지원 처리됨 |
| 처리 worker | `processing/contract.py`, `worker.py` | 기존 raw→정규화→정확한 raw 참조 연결 재사용. 새 어댑터/선택 필드 필요 |
| 탐지 | `rules/cloud.yml`, `rules/metadata_patterns.yml`, `rules/attacks.yml` | CloudTrail 관리·콘솔/IAM 시나리오. 5개 서비스 전용 시나리오 없음. 기존 규칙은 보존 |
| 시험 | `tests/test_cloudtrail.py`, `test_cloud_detection.py`, `p4_live_checks.py` | CloudTrail 합성/SDK/선택 ES 검사. 5개 서비스 실제 수신 증거 없음 |

## 변경 범위와 우선순위

1. 공통 CloudWatch `FilterLogEvents` 수집기: 계정 확인, 명시적 리전/로그 그룹, 페이지 완주, 재전송 ID, 실패 시 구간 재실행. 기존 CloudTrail CLI·체크포인트를 덮어쓰지 않는다.
2. Resolver JSON, Security Hub CSPM ASFF/EventBridge, RDS general/error 메타데이터, CloudFront JSON, Network Firewall EVE alert/netflow 파서와 기존 Portal/정규화 연결.
3. 실제 AWS 읽기·이벤트 발생·ES·Portal 인수는 유효한 기존 AWS 인증과 중앙 서버 설정이 준비된 뒤 수행한다. 서비스별 현재 상태와 재현 절차를 아래 기록한다.
4. 새 탐지 운영 활성화는 실제 필드 확인 후 진행한다. 기존 CloudTrail 규칙을 새 서비스에 자동 적용하거나 일반 SQL/DNS/HTTP 오류를 공격으로 확정하지 않는다.

## 원본과 개인정보 계약

기존 Cloud SOC는 클라우드 원문 전체를 ES/SQLite/Portal에 복제하지 않는다. 같은 설계를 따라 CW 계정·리전·그룹·스트림·eventId·시각·원문 SHA256을 보존하고 원문은 AWS에서 대조한다. RDS SQL/사용자·쿼리 인자, CloudFront URL/쿠키/헤더, Finding 설명 및 방화벽 payload는 중앙에 복사하지 않는다. SHA256은 원문의 재조회/변경 대조 수단이며 백업이나 무기한 원본 보존은 아니다. AWS 보존기간 이후 원문 재현은 보장하지 않는다. 사용자 최종 기준 중 원문 장기 보존·별도 보호 저장소는 잔여 설계다.

## 공식 형식 근거

- [CloudWatch FilterLogEvents](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_FilterLogEvents.html): 빈 페이지도 nextToken이 있으면 계속 읽으며 토큰은 상태에 저장하지 않는다.
- [Resolver 로그 필드](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs-format.html).
- [Security Hub CSPM EventBridge/ASFF](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-event-formats.html). 새 Security Hub의 Findings Imported V2/OCSF는 별도 형식이다.
- [RDS MySQL 로그](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.MySQL.LogFileSize.html).
- [CloudFront v2](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/standard-logging.html), [필드·지연](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/standard-logs-reference.html).
- [Network Firewall alert/netflow](https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-logging-contents.html).

## 이번 구현

- `aws/service_logs.py`: 7개 로그 종류(5개 서비스)의 순수 파서. 서비스/계정/리전/설정 자원·관측 시각·CW 수신 시각·원문 해시·원본 위치, DNS 응답·Finding 상태·SQL 명령 **종류만**·HTTP 결과·방화벽 규칙 ID/동작/flow 카운터를 선택한다. Security Hub 배열은 Finding별 문서로 분리하며 같은 Finding의 새 CW 이벤트도 보존한다.
- `aws/log_collector.py`, `aws/cloudwatch.py`: CloudTrail과 분리된 opt-in CLI. 기존 STS/HTTPS/CA/키 파일·create-only sink·SQLite State를 재사용한다. 명시한 계정의 그룹만 조회하며 다른 계정·구성 변경은 중단한다. 그룹별 체크포인트로 CloudFront의 `us-east-1`과 Osaka를 분리한다.
- `portal/{security_detail,log_contract,log_query,log_types}.py`, `processing/contract.py`, `prototype/logs.{html,js}`: 기존 통합 로그의 AWS 출처/수집기 필터·상세·원본 참조·정규화에 연결한다. gyumin의 OS 표시와 POST mget 보호 조회를 유지한다. Mall 전용 제한 Portal은 기존 scope를 유지하므로 그 화면에 AWS 인덱스를 자동 추가하지 않는다.
- `deploy/aws/index-template.json`, `service-logs*.json`: additive 매핑과 최소 읽기 권한 예시. 기존 CloudTrail CLI/룰/체크포인트를 교체하지 않는다. 원문 메타데이터 객체는 비색인 `_source`이며 서비스·계정·리전·DNS/HTTP/IP 필드는 명시 매핑한다.
- `deploy/aws/service-rules.example.yml`: DNS NXDOMAIN 10회/300초, 미해결 ACTIVE HIGH/CRITICAL Finding, MySQL ERROR 수준, CloudFront 5xx 5회/300초, Firewall alert 관측 후보. 전부 `enabled: false`이고 활성 `rules/`·기존 프로필 밖에 둔다. 합성 엔진 검증만 수행하며 정상 DNS/HTTP 실패·DB 오류를 공격으로 확정하지 않는다. Flow는 경보 자체가 아닌 통신 증거다.

### 전달·재실행 계약과 한계

1. 매 주기 STS 계정을 확인한 뒤 각 그룹을 최대 1시간 전진한다. 최근 5분은 대기한다. 빈 `events` 배열이어도 nextToken이 있으면 계속 읽는다. 고정 구간의 모든 페이지·모든 자식 문서가 ES create 성공 또는 같은 ID의 409일 때만 전진한다.
2. 토큰 반복/페이지 상한/파서 오류/권한·그룹 부재/ES 오류 시 해당 구간은 미완료다. 원문이나 토큰을 DB·오류에 저장하지 않으며 다음 실행에서 처음 페이지부터 재시도한다. 잘못된 이벤트는 **조용히 건너뛰지 않으므로** 해당 그룹을 막을 수 있다. AWS에서 원문을 보호 조회해 형식/파서를 보완해야 한다. 오류 상태에서 DB를 삭제하지 않는다.
3. 원본 ID = 조직·계정·리전·그룹·스트림·CloudWatch eventId·Finding ID의 SHA256. UTC 발생일 인덱스 + create-only로 재전송 시 기존 문서를 보존한다. CW에 같은 서비스 이벤트가 **다른 eventId로 재발행**되면 별개 관측이다. 서비스 수준의 완전한 중복 제거/변경 충돌 대조를 보장하지 않는다.
4. 예시 최초 범위48시간·겹침26시간은 CloudFront 지연을 고려한 기본값이다. 지연이 겹침/최초 floor를 넘거나 AWS 보존기간이 지났다면 누락될 수 있다. 조회량이 증가하므로 비용·보존기간·수집 주기를 검토하고 한 계정/그룹당 실행자 하나만 둔다. 설정 변경은 지문이 달라 기존 state를 재사용할 수 없다. 필요 시 기존 state를 보존한 **별도 경로**로 승인된 과거 조회를 수행한다.
5. `--once`는 그룹당 최대1시간 전진 **한 번**이며 48시간 전부 완료가 아니다. `status=ok`, 빈 조회, `--status`만으로 실제 수집 성공을 주장하지 않는다. 현재 클라우드 수집 상태는 CLI에만 있고 장치 heartbeat/종류별 전용 대시보드 위젯은 추가하지 않았다.
6. 지원 형식은 Resolver v1 JSON, CSPM EventBridge ASFF, MySQL general/error 텍스트 메타데이터, CloudFront JSON의 date/time·c-ip·cs-method·sc-status·x-edge-request-id·x-edge-result-type, Network Firewall EVE alert/netflow다. EventBridge input transformer로 감싼 다른 형식, OCSF V2, S3/Firehose, RDS slow/audit, Firewall TLS 로그는 미지원이다. RDS 발생 시각이 행에 없으면 CW 시각을 사용하고 `time_basis`에 명시하며 SQL 실행 시각/성공을 추정하지 않는다.
7. CloudFront 배포와 로그 그룹은 설정으로 바인딩한다. 로그 그룹을 여러 배포가 공유하면 혼합될 수 있으므로 실제 delivery source가 단일 대상 배포인지 선행 확인한다. Finding 원래 리전은 `finding_region`, 수집 리전은 `cloud.region`에 보존한다. 원문 전체·세부 자원 목록 무제한 보존은 제공하지 않는다.

## 실행 준비와 중앙 연결 (이번에 실행하지 않음)

먼저 기존 AWS 프로파일/IAM 역할을 준비한다. 이 PC의 SDK 확인 결과 `profiles_available=false`, `credentials_available=false`였으며 실제 AWS API는 호출하지 않았다. 자격 증명은 기존 SDK 체인으로 제공하고 채팅/저장소에 붙여넣지 않는다. EC2 SSH 개인키는 AWS API 인증을 대신하지 않는다.

아래는 중앙 Ubuntu에서의 예시다. 예시 계정·조직·CloudFront 실제 배포 ID와 확인된 로그 그룹을 수정한다. 필요 서비스만 sources에 남긴다. 의존성은 기존 고정 파일을 사용한다.

```bash
python3 -m venv .venv-aws
.venv-aws/bin/python -m pip install -r deploy/aws/requirements.txt
mkdir -p state/aws-service-logs
chmod 700 state/aws-service-logs
cp deploy/aws/service-logs.example.json state/aws-service-logs/config.json
# 위 config의 계정·조직·실제 배포 ID를 편집한다. 키는 넣지 않는다.
PYTHONPATH=src .venv-aws/bin/python -m cloud_soc.aws.cloudwatch \
  --config state/aws-service-logs/config.json
```

마지막 명령은 오프라인 문법/범위 검증이다. AWS/ES 연결·DB 생성이 없으며 계정/그룹 존재는 검증하지 않는다. IAM 예시 `service-logs-policy.example.json`은 `logs:FilterLogEvents`만 7개 그룹에 허용한다. 설치/설정 조사에 필요한 서비스 Describe/List 권한은 별도 관리자 읽기 권한이다. 정책 연결/키 생성은 자동 실행하지 않는다.

중앙 관리자가 검토한 변경 범위:

- 새 파서/CLI와 Portal 코드를 배포하되 기존 서비스·구성·SQLite를 먼저 백업한다. 실제 서버 주소·실행자·배포본을 확인하기 전 기존 서버에 접속하거나 재시작하지 않는다.
- 기존 `cloud-soc-received-at-v1` 수신 pipeline과 기존 `cloud-soc-aws` 템플릿을 보호 저장한다. 새 raw 매핑은 기존 AWS 템플릿에 **추가**하고 기존 final/default pipeline·replica 설정을 보존한다. `portal.status_setup.configure_template`는 bootstrap에서 수신 매핑/pipeline을 결합하는 기존 함수다. JSON 파일만 PUT해 서버 수신 설정을 잃지 않도록 한다.
- 템플릿 갱신은 **새 인덱스에만** 적용된다. 오늘 인덱스가 이미 있으면 정확한 `soc-cloud-aws-YYYY.MM.DD`의 현재 매핑을 확인해 새 event.category/source.port/destination/service/network/dns/http/aws.service_logs 필드만 additive `put_mapping`으로 보완한다. 기존 필드 타입 충돌 시 중단한다. 이 작업은 준비/실행하지 않았다.
- ES 쓰기는 기존 `publisher-role.json`의 `soc-cloud-aws-*` create_doc/auto_configure 범위를 가진 별도 키 파일을 사용한다. 운영 키 발급·재사용 승인을 확인한다. 기존 CloudTrail 키를 임의 교체하지 않는다. 정상 Portal/normalizer는 해당 AWS 인덱스 읽기 범위를 이미 가지고 있지만 실제 키·실행자의 유효 권한은 별도 확인한다. JEONGRIM-SEO의 `soc-multicloud-*` 전용 키는 이 경로에 쓸 수 없다.
- 기존 normalizer가 돌아가도 새 코드 배포·현재 backlog와 허용 지연 범위를 확인해야 한다. 늦은 과거 로그를 넣었다고 기존 normalizer cursor를 되감지 않는다. 기존 재처리/회고 검토 경로 또는 보호된 별도 상태의 계획이 필요하며 이번 작업에서 실행하지 않았다.
- Portal에 새 코드가 반영돼야 수집기 `AWS 서비스 로그`와 서비스별 종류/상세가 나타난다. 활성 탐지 프로필에는 후보5개가 없으므로 경보가 자동 생성되지 않는다. 실제 필드·정상/임계/오탐·기존 경보/Slack 영향 검증 후 별도 프로필/상태로 운영 연결해야 한다.

TLS CA와 ES 키 파일을 보호 준비한 **뒤**, 명시적으로 실행한다. 정상 로그가 이미 발생하는 기존 그룹을 읽는 명령이며 AWS 설정은 변경하지 않는다. 조회 API/로그 보존·요청 발생에는 기존 AWS 과금이 적용될 수 있다. 신규 리소스·로깅 증가 변경은 비용 설명과 승인 후에만 한다.

```bash
chmod 600 state/aws-service-logs/es-api-key
PYTHONPATH=src .venv-aws/bin/python -m cloud_soc.aws.cloudwatch \
  --config state/aws-service-logs/config.json \
  --state state/aws-service-logs/checkpoint.sqlite \
  --es-url 'https://CENTRAL_ES_HOST:9200' \
  --ca-file state/aws-service-logs/ca.crt \
  --api-key-file state/aws-service-logs/es-api-key --run --once

PYTHONPATH=src .venv-aws/bin/python -m cloud_soc.aws.cloudwatch \
  --config state/aws-service-logs/config.json \
  --state state/aws-service-logs/checkpoint.sqlite --status
```

상주 시에만 `--once`를 제거한다(기본300초). 같은 그룹의 두 실행자를 동시에 시작하지 않는다. 중단/롤백은 새 수집기만 정상 종료하고 새 state를 보존한 뒤 이전 Portal/normalizer 배포본을 복구한다. 기존 ES 문서·인덱스·역할·체크포인트를 삭제하지 않는다. additive 매핑은 기존 자료를 보존하며 자동 제거하지 않는다.

## AWS 실제 점검과 정상 이벤트 발생 절차

아래는 실행하지 않은 명령/콘솔 절차다. 예시의 프로파일은 환경변수 `AWS_PROFILE`로 기존 인증을 선택한다. 현재 사용자 인계의 리소스 ID·IP·READY/설정 상태는 **이전 관측**이며 이번 실시간 상태로 간주하지 않는다. 기존 CloudTrail/팀원 리소스는 변경하지 않는다.

### 공통 읽기

```bash
aws sts get-caller-identity --query Account --output text
aws logs describe-log-streams --region ap-northeast-3 \
  --log-group-name /cloud-soc/aws/route53-resolver \
  --order-by LastEventTime --descending --limit 5 --no-paginate \
  --query 'logStreams[].{stream:logStreamName,last:lastEventTimestamp}'
# START_MS/END_MS는 실제 시험을 감싼 UTC epoch milliseconds로 지정한다.
aws logs filter-log-events --region ap-northeast-3 \
  --log-group-name /cloud-soc/aws/route53-resolver \
  --start-time "$START_MS" --end-time "$END_MS" --limit 10 --no-paginate \
  --query '{events:events[].{id:eventId,at:timestamp,ingested:ingestionTime,stream:logStreamName},next:nextToken}'
```

다른 서비스는 아래 그룹/리전으로 바꾼다. CLI 예시는 원문 message를 출력하지 않는다. nextToken이 있으면 다음 페이지를 확인해야 하며 빈 첫 페이지를 수신 없음으로 단정하지 않는다. 서비스 원문은 권한 있는 AWS 콘솔에서 보호 조회하고 중앙 저장 문서의 original_sha256/원본 위치와 대조한다. RDS 원문·SQL을 보고서/채팅에 복사하지 않는다.

### Route 53 Resolver

`ap-northeast-3`, `/cloud-soc/aws/route53-resolver`. 콘솔 Resolver의 Query logging configuration이 VPC `vpc-0e4bb99234215e866`에 연결됐는지, 상태가 정상인지, 대상 그룹 ARN/리전/계정과 CloudWatch resource policy를 읽는다.

```bash
aws route53resolver list-resolver-query-log-config-associations --region ap-northeast-3
aws route53resolver list-resolver-query-log-configs --region ap-northeast-3
aws ec2 describe-vpc-attribute --region ap-northeast-3 \
  --vpc-id vpc-0e4bb99234215e866 --attribute enableDnsSupport
```

기존 EC2 `i-0e94f1225ca4df1e9`에서 현재 DNS resolver를 확인한 뒤 `getent ahostsv4 example.com` 같은 정상 DNS 조회를 한 번 수행한다. 캐시로 로그가 없을 수 있어 승인된 테스트 도메인의 고유 하위 이름을 사용해 구분한다. 임의 외부 DNS로 질의하면 VPC Resolver 경로를 우회할 수 있다. 원문 `query_timestamp/account_id/region/vpc_id/srcaddr/query_name/rcode`와 ES 필드·포털 행을 대조한다.

### Security Hub CSPM

`ap-northeast-3`, `/cloud-soc/aws/securityhub-findings`.

```bash
aws events describe-rule --region ap-northeast-3 --name cloud-soc-securityhub-findings --event-bus-name default
aws events list-targets-by-rule --region ap-northeast-3 --rule cloud-soc-securityhub-findings --event-bus-name default
aws securityhub describe-hub --region ap-northeast-3
aws securityhub get-findings --region ap-northeast-3 --max-results 1 --no-paginate \
  --query 'Findings[].{Id:Id,UpdatedAt:UpdatedAt,Severity:Severity.Label,State:RecordState,Workflow:Workflow.Status}'
```

실제 이벤트는 `source=aws.securityhub`, `detail-type=Security Hub Findings - Imported`, `detail.findings[]` 구조다. 최상위 `resources`와 Finding 내부 `Resources[].Id`를 혼동하지 않는다. 실제 계정/리전/Findings 원문에 대해 기존 패턴을 `aws events test-event-pattern --event-pattern file://pattern.json --event file://event.json`으로 오프라인 판정한다. 보호된 파일을 사용하고 출력에는 일치 boolean만 남긴다. `test-event-pattern`은 전달이나 수집 검증이 아니다. Rule/FailedInvocations/target resource policy도 읽는다.

실제 Finding 생성/업데이트 이벤트를 관측해 CW→ES→Portal을 대조한다. 콘솔의 샘플 Finding 생성이나 `BatchImportFindings`는 계정 상태를 바꾸므로 필요 권한·샘플 자원/비용 영향·제거/보존 방법을 제시하고 승인 후 실행한다. 기존 Finding 삭제/상태 변경·패턴 완화는 자동 실행하지 않는다. 패턴 변경 계획은 현재 패턴/targets/상태의 보호 저장→최소 조건 조정→실제 전달 비교이며, 롤백은 저장한 정확한 패턴/targets/상태 복원이다. 이번에는 변경하지 않았다.

### RDS MySQL

`ap-northeast-3`, `/aws/rds/instance/cloud-soc-rds-mysql/general`, `/aws/rds/instance/cloud-soc-rds-mysql/error`.

```bash
aws rds describe-db-instances --region ap-northeast-3 --db-instance-identifier cloud-soc-rds-mysql \
  --query 'DBInstances[].{Status:DBInstanceStatus,ParameterGroups:DBParameterGroups,Exports:EnabledCloudwatchLogsExports,Public:PubliclyAccessible,Pending:PendingModifiedValues}'
aws rds describe-db-parameters --region ap-northeast-3 \
  --db-parameter-group-name cloud-soc-mysql84-logging --source user \
  --query 'Parameters[].{Name:ParameterName,Value:ParameterValue,Apply:ApplyMethod}'
```

`general_log=1`, `log_output=FILE`과 export general/error, 파라미터 그룹 in-sync/pending-reboot를 분리 확인한다. 재부팅은 실제 DB 가용성에 영향이 있으므로 승인 없이 수행하지 않는다. 이미 DB 접속이 허용된 EC2에서 기존 DB 계정으로 `mysql --host "$RDS_ENDPOINT" --user "$DB_USER" --password --execute 'SELECT 1;'`을 한 번 수행한다. 비밀번호는 프롬프트로 입력하고 원문/출력은 보고서에 남기지 않는다. 오류 로그가 없는 것만으로 실패라고 판정하지 않으며 오류를 만들기 위해 DB를 중단하지 않는다. SG/라우팅을 열거나 신규 계정을 만들기 전 변경 계획이 필요하다.

### CloudFront

`us-east-1`, `/cloud-soc/aws/cloudfront-access`. `cloud-soc-cloudfront-osaka`는 이름/설명 이력이므로 실제 distribution ID와 DomainName을 콘솔에서 확인한다. CW delivery source→destination→delivery의 배포 ARN·그룹 ARN·JSON 형식·필수 recordFields를 확인한다. CloudFront 서비스 리전과 로그 대상 리전을 혼동하지 않는다. 이후 확인된 배포의 **읽기 전용 공개 경로**를 `curl --fail --silent --show-error --output /dev/null "https://$CF_DOMAIN/"`로 한 번 요청한다. 비공개 객체·서명 URL·개인 쿠키는 쓰지 않는다.

기본 로그 전달에는 지연이 있으며 일부 항목은 24시간 늦을 수 있다. 즉시 스트림0만으로 실패 처리하지 않는다. native date/time·request ID·관측 IP·상태, CW eventId, ES 원문 위치/해시, 포털을 비교한다. CloudFront의 IP는 관측 peer이며 X-Forwarded-For로 덮어쓰지 않는다. 원본 서버/배포/캐시 설정은 변경하지 않는다.

### Network Firewall: 읽기·설계까지만

`ap-northeast-3`, `/cloud-soc/aws/network-firewall-alert`, `/cloud-soc/aws/network-firewall-flow`.

```bash
aws network-firewall describe-firewall --region ap-northeast-3 --firewall-name cloud-soc-network-firewall
aws network-firewall describe-logging-configuration --region ap-northeast-3 --firewall-name cloud-soc-network-firewall
aws ec2 describe-route-tables --region ap-northeast-3 \
  --filters Name=vpc-id,Values=vpc-0e4bb99234215e866
aws ec2 describe-instances --region ap-northeast-3 --instance-ids i-0e94f1225ca4df1e9 \
  --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name,Subnet:SubnetId,AZ:Placement.AvailabilityZone,Private:PrivateIpAddress,Public:PublicIpAddress}'
```

현재 인계상 mall subnet 기본 경로는 IGW 직행으로 방화벽을 우회한다. READY/동기화만으로 검사 성공이라고 표시하지 않는다. 실제 endpoint ID·AZ·firewall subnet RT·IGW edge association과 기존 모든 경로를 재확인하고 다음 **계획만** 검토한다.

| 경로 | 필요한 대칭 경로 계획 |
|---|---|
| mall `subnet-01a1c4d0b3cb9f88a`, AZ3b | `0.0.0.0/0 → 같은 AZ의 Firewall endpoint` |
| Firewall subnet3b | `0.0.0.0/0 → igw-07e3020d17e2a282f`, VPC local→mall |
| IGW edge-associated RT | `10.250.10.0/24 → 같은 Firewall endpoint`, 나머지 기존 경로 유지 |

영향: 기존 `rtb-0451cd3c7d6a78b05`를 공유하는 모든 장치의 인터넷/SSH·응답 경로와 세션에 영향이 있다. AZ/endpoint가 다르거나 되돌아오는 트래픽이 우회하면 연결이 끊길 수 있다. 기존 stateful 테스트 규칙과 SG/NACL도 읽어 의도한 정상 요청의 허용/alert 조건을 확인한다. 팀원 리소스가 같은 subnet/RT를 공유하면 먼저 협의한다. 인스턴스 IP는 stop/start로 바뀔 수 있으므로 마지막 공개 IP를 그대로 신뢰하지 않는다.

적용 전 제출할 자료: 대상/연결 RT·현재 모든 route/association·endpoint 상태·기존 규칙의 보호 사본, 변경할 정확한 경로 목록, 중단 가능 시간과 콘솔/Instance Connect 등 실제 검증된 복구 접근, 정상 HTTPS 단1회 시험 및 CW alert/flow 비교 시간, 관측 실패 시 중단 기준. 새 NAT/EC2/방화벽·트래픽/보존 확대의 비용은 별도 설명/승인을 받는다. **현재 라우팅 수정은 실행하지 않았다.**

롤백: 검증된 콘솔 복구 경로로 mall 기본 경로를 저장된 기존 IGW 경로로 복원하고, 새로 추가/바꾼 IGW edge association·mall CIDR route만 저장본으로 되돌린다. 원래 없던 association이면 이번에 추가한 것만 해제한다. 기존 전체 RT/규칙/방화벽을 삭제하지 않는다. route ID를 추측하거나 공유 RT를 통째로 교체하지 않는다. 원래 SSH/정상 요청이 회복됐는지 확인한다. 승인 후 경유시킨 정상 트래픽의 같은 IP/port/시각/flow와 alert action allowed/blocked를 대조해야 실제 검사 성공이다.

## 실제 AWS 확인 결과 (사용자 CloudShell 출력 · 2026-11-01)

사용자가 콘솔 CloudShell에서 STS 계정 `897722691159`와 Osaka 로그 그룹4개의 존재를 확인했다. 최초 EC2 root 터미널에서는 `NoCredentials`가 났고 이는 EC2의 API 인증이 없는 관측이지 콘솔 로그인이 실패했다는 뜻은 아니다. 이 PC에서는 SDK 자격 증명이 없으며 브라우저 자동화 실행기도 sandbox 권한 오류로 시작되지 않아 실제 AWS 조회는 사용자가 수행했다. 페이지 토큰과 원문은 기록하지 않는다.

| 원천 | 확인된 근거 | 아직 확인되지 않은 사항 |
|---|---|---|
| Resolver | VPC `vpc-0e4bb99234215e866`의 연결 `rqlc-f9b65da388604b4d` ACTIVE. 해당 vpc_id JSON 필터로 EC2 `i-0e94f1225ca4df1e9`의 실제 query 로그 조회. 스트림 `vpc-0e4bb99234215e866_20261101T1000Z_i-0e94f1225ca4df1e9` | 전체 native 값 검증·중앙 수집/ES/Portal. 실제 `srcport` 자료형은 문자열이며 구현에 엄격한 decimal→int 지원 추가 |
| Security Hub | 규칙 ENABLED, 정확한 CW target 존재. 패턴은 계정/Osaka/source/detail-type + RDS DB ARN·VPC ARN 두 개. 최근48h 로그0. 현재 조회된 Finding5개는 GuardDuty 제공 EC2 `instance/i-99999999`, MEDIUM | 이5개는 현재 리소스 조건에 불일치. 전체 Finding 부재나 패턴 문법 오류라고 단정하지 않음. 대상 RDS/VPC Finding/새 전달 이벤트·권한/실제 중앙 인수 미확인 |
| RDS | DB available, custom 그룹 `cloud-soc-mysql84-logging` **pending-reboot**, exports general/error. 사용자 파라미터 general_log1/log_outputFILE/slow_query_log0. error 그룹의 실제 DB 스트림 기록 존재 | general 그룹은 ResourceNotFound. 런타임 값·일반 SQL 로그 생성/수신 미확인. 재부팅은 미실행 |
| CloudFront | us-east-1 그룹의 `CloudFront_EGVZJI81RXNWQ`에 기록 존재. 실제 date/time/c-ip/cs-method/sc-status/x-edge-request-id/x-edge-result-type 자료형 모두 문자열로 현재 파서 계약과 일치 | 배포 source/destination 연결 독립 조회·실제 본문 값/해시 비교·중앙 인수 미확인. EGVZJI81RXNWQ는 스트림에서 관측한 ID 후보이며 배포 목록 독립 확인은 하지 않음 |
| Firewall | Alert/Flow 그룹 존재. 최근48h native `event.event_type=alert/netflow` 필터 결과 모두0 | 실제 경유/검사/규칙 일치·중앙 인수 미확인. 라우팅은 변경하지 않음 |

Resolver/Firewall의 최초 `limit=1` 결과는 `log_stream_created_by_aws_to_validate_log_delivery_subscriptions`에서 나온 **AWS 전달 확인용 메시지**였다. 실제 서비스 로그로 세지 않는다. 단일 페이지에는 nextToken이 남아 있어 최초 결과만으로 부재를 판정하지 않았고, 사용자가 JSON 필터+CLI 자동 페이지 조회를 추가 수행했다. 수집기는 이 정확한 예약 스트림을 제외하고 `ignored_delivery_checks`로 별도 출력하며 다음 페이지를 계속 읽는다. 이 수는 주기 출력 진단이고 기존 공통 State schema에는 추가하지 않았다. 다른 스트림의 파서 오류는 그대로 중단한다.

개발/배포 대상: 사용자에 따르면 `https://192.168.235.128`은 집 서버이고 향후 학교 서버에서 운영할 계획이다. 현재 학교 서버 주소·배포 상태·권한은 미확정이다. 해당 집 서버에는 연결/배포하지 않았다. WSL Ubuntu는 중지 상태·Python3.14/pytest없음·Docker integration 미연결이었다. 기존 Docker Desktop과 보유 Linux Python3.12/ES9.5.2 이미지를 사용한 **WSL2 백엔드 격리 컨테이너**에서 검증하며 Ubuntu의 설정/시스템 패키지를 바꾸지 않는다. 이는 전체 중앙 서버의 WSL 설치/운영 인수와 다르다.

### 실제 변경을 진행하기 전 남은 결정

- RDS: 대상은 위 DB 한 개의 reboot이며 새 DB/스토리지·엔진 업그레이드는 계획하지 않는다. 연결 중단과 일반 로그 추가 저장/수집 비용·민감 SQL의 AWS 보존 영향을 먼저 설명하고 승인을 받아야 한다. 현 연결/업무 영향·현재 런타임 변수/파라미터 그룹 공유 범위·복구 접근을 확인한 뒤 실행한다. 재부팅 자체는 취소/되돌릴 수 없다. 이후 문제가 생기면 기존 서비스 복구와 로그 설정의 최소 되돌림을 검토하며, 이전 런타임 값을 모른 채 default 그룹이나 general_log0을 추측 적용하지 않는다. 일반 로그가 생성되는지 확인하기 전 완료하지 않는다.
- Security Hub: 현재 조건을 유지하면서 승인된 RDS/VPC의 새 Finding을 관측하는 방법을 먼저 검토한다. 계정 전체로 resource filter를 제거하면 다른 팀 소스와 CW 수신/과금 범위가 늘어나므로 실행하지 않았다. 좁은 시험 범위 추가나 샘플 Finding 생성이 필요하면 정확한 변경 패턴·대상·비용·원본 pattern/target/state 보호본과 복원 명령을 준비해 승인받는다. 조회만으로 기존 Finding이 재전달되지는 않는다.
- Firewall: 위 대칭 라우팅 계획을 실제 RT/endpoint·공유 장치·복구 접근과 대조한 뒤 검토/승인해야 한다. 현재 경유하지 않는 트래픽으로 Flow/Alert 성공을 주장하지 않는다.
- 중앙: 학교 서버 대상이 확정되기 전 운영 배포/키 발급·Portal/normalizer 재시작을 하지 않는다. IAM 역할/기존 프로파일·ES TLS/키·조직 scope·독립 상태를 준비하고, Resolver/CloudFront처럼 이미 원천이 있는 경로부터 실제 E2E 인수한다.

## 실제 수집 인수 표 (초기 조회 시점 이력, 최신 결과는 아래)

| 서비스 | AWS 이벤트 | AWS 대상 전달 | 수집기 | ES/필드 | Portal | 실제 탐지·경보 |
|---|---|---|---|---|---|---|
| Resolver | 실제 DNS 기록 있음 | CW query 조회 확인 | 합성의 실제 ES 경로까지 | 합성 ES만 | 합성 API/DOM만 | 합성 후보만 |
| Security Hub CSPM | 기존 Finding5건 있음 | 최근48h 비어 있음 | 합성의 실제 ES 경로까지 | 합성 ES만 | 합성 API/DOM만 | 합성 후보만 |
| RDS MySQL | error 스트림 기록 있음/general 미확인 | error 있음/general 그룹 없음 | 합성의 실제 ES 경로까지 | 합성 ES만 | 합성 API/DOM만 | ERROR 후보 합성만 |
| CloudFront | 서비스 스트림 기록 있음 | CW 조회/자료형 확인 | 합성의 실제 ES 경로까지 | 합성 ES만 | 합성 API/DOM만 | 5xx 후보 합성만 |
| Network Firewall | native alert/flow 최근48h 없음 | 전달 확인 메시지만 | 합성의 실제 ES 경로까지 | 합성 ES만 | 합성 API/DOM만 | alert 후보 합성만 |

각 실제 시험에서 다음을 함께 기록해야 완료다: 시험 UTC 구간·계정/리전/서비스, CW 그룹/스트림/eventId와 원문 해시, 수집기 created/duplicates·완료 경계, 정확한 ES index/id·원본/정규화 참조와 발생/수신 시각, Portal 목록/상세 및 조직/원문 권한, 실제 규칙 버전·정상/임계/오탐·정확한 경보 증거와 재실행 중복 여부. 오류·미수신·권한 불가를 성공으로 채우지 않는다. 민감한 SQL·계정 비밀·개인정보 원문은 기록하지 않는다.

## JEONGRIM-SEO 호환 범위

검사 기준 `gyumin 5f57818` + 이번 미커밋 변경, 상대 `JEONGRIM-SEO c14e426`, 공통 조상 `c87e9ca`. 상대는 AWS CloudTrail/Azure/Naver 관리 감사를 `soc-multicloud-*`·별도 상태/키·전용 Portal에 연결한다. 이번 경로는 5개 서비스의 CloudWatch 원천→기존 `soc-cloud-aws-*`→통합 로그/정규화다. 상대의 transport/정규화·bootstrap·권한·메뉴·배포 코드는 수정하지 않았다. 같은 AWS 서비스 이벤트를 CloudTrail 메타데이터와 같은 로그로 취급하지 않는다.

기존 두 브랜치에도 작업 추적 문서의 동시 추가 충돌이 있었다. gyumin 게시/OS 완료 이력과 이번 AWS 기록을 변경 없는 내부 구간으로 이동해 보존했다. 공통 수정 파일의 현재 snapshot을 `git merge-file`로 3-way 검사하고, 상대 전체 tree + gyumin 변경을 임시 사본에 결합해 관련 회귀를 실행한다. 실제 merge commit/브랜치 병합·원격 push는 하지 않았다. 미래 상대 변경과 전체 운영 조합까지 충돌 없음을 보장하지 않는다. 자세한 최종 결과는 아래/작업 추적 기록을 따른다.

## 로컬 최종 검증 결과

아래 208/30 결과는 c14e426 기준의 이전 검사 이력이다. 이후 JEONGRIM-SEO 2cf0e39 결합 검사241통과/32subtests·DOM31통과 및 텍스트 충돌0을 확인했다. 현재 gyumin 완료 이력은 원래 위치를 유지한다. 실제 merge/commit/push는 하지 않았다.

- 결합 사본(위 두 고정 SHA + 현재 AWS 코드)의 Linux Python3.12 관련 회귀: **208 passed / 27 subtests passed / 실패·제외0**. 신규 AWS 단위/SDK/권한/실패·재시작/자료형/전달 확인 스트림 시험75개 및 새 실제 ES 검증1개가 포함된다. 반복 실행 결과를 더해 고유 건수로 집계하지 않는다.
- 실제 격리 ES9.5.2: 새 전용 Linux ES·Python 컨테이너/네트워크에서 합성 원본20건의 create/409, 서버 event.ingested 강제 생성, 단일 create_doc 쓰기 키의 검색 거부, 기존 normalizer의 실제 조회·정규화20/처리20/재실행 수 불변, 실제 ES 기반 Portal reader 목록7종/상세20, 비활성 후보를 시험 메모리에서만 선택한 경보5/동일ID 재저장 existing, Operations의 정확한 normalized/raw 증거 참조를 확인했다. payload canary가 ES 투영·Portal 상세·증거에 없는 것도 확인했다. 원천은 합성이고 실제 AWS E2E가 아니다.
- gyumin 및 결합 사본의 로그 화면/상대 공통 메뉴 **DOM30건 통과**. 변경 Python Ruff와 diff 공백 통과, 새 CLI의 실제 별도 프로세스 오프라인 config_valid/7개 source/AWS·ES 미접속 확인. 실제 브라우저 클릭/렌더링·학교 서버 배포/운영 키·실제 AWS 원문 수집/장기 보존·선택 룰 운영 활성화·Slack은 미검증이다.
- 기존 Docker Desktop의 WSL2 백엔드와 보유 `python:3.12-slim-bookworm`, ES9.5.2 이미지를 사용했다. Ubuntu WSL의 Python3.14/의존성/미연결 integration을 변경하지 않았다. 시험에서 생성한 소유 label·정확한 이름의 컨테이너/네트워크만 정리했다. 기존 컨테이너/볼륨·AWS·집/학교 서버를 수정하지 않았다.
- 재현: 기본 시험은 `.venv/Scripts/python.exe -m pytest -q tests/test_aws_service_logs.py`(Linux는 해당 Python 경로로 변경), DOM은 기존 잠금 의존성 설치 후 `node --test prototype/tests/logs-live.test.cjs`다. 실제 ES 시험 `tests/test_aws_service_logs_live.py`는 기본 제외이며 전용 Docker 네트워크의 고정 alias와 새 test cluster 신원 확인·명시 opt-in을 요구한다. 운영 URL은 받지 않는다. Git 제외 `state/aws-gyumin-transfer-20261101`의 검사 실행 도구와 결합 사본 `state/aws-compatibility-20261101/state/aws-linux-es-results/{pytest.xml,result.json,cleanup.json}`에 실행/정리 근거를 보존했다.

## 실제 AWS 보호 표본의 개발 인수 — 2026-11-01 최신

| 서비스 | 확인된 AWS 범위 | 로컬 개발 인수 | 남은 범위 |
|---|---|---|---|
| Resolver | 실제 DNS JSON→CloudWatch | 보호 표본1건 ES·정규화·인증 Portal API 통과 | 상주/학교 배포·의심 도메인 탐지 |
| CloudFront | 실제 요청403→CloudWatch | 보호 표본1건 동일 경로 통과 | 상주/학교 배포·5xx 임계 탐지 |
| RDS | 승인한 reboot1회 후 available/in-sync, error/general 그룹·실제 Query 확인 | System error1건 + 일반 Query/SET1건 동일 경로 통과 | 접속/인증 실패 시나리오·상주/학교 배포 |
| Security Hub | 승인한 정보 수준 Finding1건→기존 EventBridge→CloudWatch 전달, 동일 Finding ARCHIVED 요청 성공 | 보호 표본1건 동일 경로 통과 | 실제 보안 Finding 탐지·상주/학교 배포 |
| Network Firewall | 승인한 임시 경로에서 실제 ALERT/FLOW, 이후 원래 경로 복귀·임시 RT2개 정리 | 보호 표본 각1건 ES·정규화·인증 Portal API 및 시험 규칙 관측 경보1/정확한 근거 통과 | 지정 example.com 요청의 직접 상관관계·상주/학교 배포·실제 침해 탐지 |

CloudShell 수동 읽기/투영으로 얻은 실제 보호 표본7건을 JEONGRIM-SEO 2cf0e39 + gyumin 변경 결합 사본의 격리 Linux ES9.5.2에 적재했다.
raw7/normalized7/processing7·인증 Flask 목록7/상세7·정확한 원본 참조/시각/해시·재전송/재실행 추가0을 확인했다.
비활성 후보를 시험 메모리에서만 평가해 Firewall 규칙 관측 경보1건·동일ID 재저장 existing·재평가 ID 일치·정확한 근거 참조를 확인했다. 활성 규칙/프로필은 변경하지 않았다.
실제 통합 검사1건 통과와 시험 컨테이너/네트워크 정리를 확인했다. SQL/쿠키/키를 전달하지 않았다.
INFO 검증 Finding은 공격이 아니며 전달 당시 ACTIVE인 과거 로그는 보관 후에도 원래 값으로 보존했다.
처음 결합4건 검사에서 보안 인덱스 초기화503이 나와 준비 대기를 보강한 뒤5건 검사가 통과했다.
학교 운영 배포·자동 상주 수집·브라우저 렌더링과 구분한다. 상위 작업은 미완료다.

Firewall 표본은 자기 EC2의 TCP443·시험 sid1000001/allowed이며 정상 시험 규칙 관측이다. ALERT와 FLOW는 flow ID가 다르고,
앞선 example.com 요청 peer와 목적지도 다르므로 서로 같은 세션 또는 그 요청이라고 연결하지 않는다.
좁은 peer/port 조건의 첫 조회가 비었지만 조건 완화로 실제 서비스 stream을 찾았다. 복구 시 남은 disassociated 종료 기록 처리 문제를 보완해
FIREWALL_ROUTES_RESTORED 및 소유 임시 RT 삭제·기존 routes/associations 대조를 확인했다. 재라우팅은 하지 않았다.
최신 실제7건 통합 검사는1건17.21초 통과, 최신 snapshot 텍스트 충돌0, 소유 Docker 컨테이너/네트워크 정리 완료다.
근거는 Git 제외 state/aws-real-source-check/{firewall-native-sample,real-samples-seven}.json과
결합 사본 state/aws-real-seven-intake-results/{result,real-intake-summary,cleanup}.json·pytest.xml에 있다.
최초5건/결합4건 실패·초기3건 결과는 이전 시점 이력이며 현재7건 성공과 중복 합산하지 않는다.
