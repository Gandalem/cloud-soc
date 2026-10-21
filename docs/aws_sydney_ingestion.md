# 시드니 AWS·T-Pot 수집 계층

범위는 같은 AWS 계정, `ap-southeast-2`, 팀원별 IAM Role입니다.
이 문서는 추가 수집 코드의 실행 계약입니다. 리소스를 생성하거나 기존 서비스를 자동 변경하지 않습니다.

## 수집 경로와 출처 구분

| 소스 | 대용량 수집 경로 | 코드 지원 | 팀 구분 근거 |
| --- | --- | --- | --- |
| CloudTrail 관리 이벤트 | Trail S3 JSON.gz → 같은 리전 SQS → worker | cloudtrail | 정확한 session issuer Role ARN |
| VPC Flow Logs | 기본 v2 text/gzip S3 → SQS → worker | vpc_flow_v2 | 운영자가 승인한 리소스 전용 prefix |
| ALB 접근 로그 | 기존 ALB의 S3 접근 로그 → SQS → worker | alb | 설정한 ALB 리소스 ID와 전용 prefix |
| 서비스 로그 | CloudWatch subscription → Firehose → S3 → SQS | cloudwatch | 전용 log group/prefix 또는 미분류 |
| T-Pot Cowrie | 별도 exporter → S3 JSONL.gz → SQS | tpot_cowrie | 고정 sensor ID/prefix |
| T-Pot Suricata | alert만 별도 exporter → S3 JSONL.gz → SQS | tpot_suricata | 고정 sensor ID/prefix |

T-Pot은 허니팟 source이며 AWS 관리 로그의 범용 수집기로 사용하지 않습니다.
기존 T-Pot 내부 ELK 설정을 대체하지 않고 독립 exporter를 사용합니다.
현재 exporter는 Cowrie와 Suricata alert 메타데이터만 다룹니다. 다른 허니팟 전체 지원은 아닙니다.

Flow·ALB에는 요청자의 IAM Role이 직접 기록되지 않습니다. 팀 이름을 payload에서 신뢰하거나
IP만으로 Role을 추정하지 않습니다. 공유 VPC/ALB를 사용하는 경우 팀을 미분류로 두거나
전용 리소스/prefix를 나눕니다. 팀 리소스 소유와 실제 IAM 호출자는 서로 다른 의미입니다.
CloudTrail issuer가 매핑에 없거나 IAM 사용자로 직접 실행한 이벤트는 `unattributed`입니다.

## 안전한 기존 자원 확인

Python3.12 이상 및 기존 AWS 인증이 필요합니다. AWS 키를 JSON 설정·채팅·Git에 넣지 않습니다.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -c constraints.txt -r deploy/aws/requirements.txt
export PYTHONPATH="$PWD/src"
# AWS 접촉 없이 사용법 확인
.venv/bin/python -m cloud_soc.aws.inventory
# 기존 프로필의 읽기 권한으로 조회. 결과 파일이 있으면 덮어쓰지 않음
.venv/bin/python -m cloud_soc.aws.inventory --run --profile YOUR_EXISTING_PROFILE
```

CloudShell에서는 `--profile`을 생략합니다. CloudShell 로그인은 로컬 CLI 인증으로 복사되지 않습니다.
`aws configure list-profiles`는 PC의 프로필 이름이고 `aws sts get-caller-identity`는 현재 계정/주체입니다.
콘솔 IAM → 역할 → ARN에서 팀원에게 승인된 Role을 확인합니다. 서비스 실행용 Role을 팀원 Role로
임의 재사용하지 않습니다. 읽기 권한 부족/페이지 한도는 inventory의 errors/truncated에 표시됩니다.

## 기존 로그를 제한적으로 실제 조회

```bash
.venv/bin/python -m cloud_soc.aws.sample --account YOUR_12_DIGIT_ACCOUNT \
  --log-group /ecs/YOUR_APPROVED_GROUP --run --profile YOUR_EXISTING_PROFILE
```

기존 CloudTrail 최근24시간 최대3페이지/150건과 지정 그룹 최근7일 최대20건/그룹을 조회합니다.
원문 message·request/response·인증키·IAM 사용자 이름을 저장하지 않습니다. `state/`의 결과는0600이며
같은 파일을 덮어쓰지 않습니다. `cloudtrail_more_available=true`는 전체 로그를 수집하지 않았다는 뜻입니다.
이 제한 표본은 상시 수집·처리량 시험·탐지 성공 증거가 아닙니다.

## 대용량 worker 설정 및 실행

`deploy/aws/sydney/collector.example.json`을 `state/` 아래 복사하고 실제 승인된 값으로 바꿉니다.
예시 계정123456789012와 replace-* 값은 실행 대상이 아닙니다.

- collector_account: 수집기를 실행하는 계정.
- organization: Cloud SOC 조직 ID.
- queue_url: 승인된 시드니 Standard SQS 큐. FIFO와 SNS wrapper는 지원하지 않습니다.
- sources: bucket/prefix별 허용 형식·소스 계정·실제 버킷 소유 계정·sensor/source ID.
- role_teams: 팀원이 실제 AssumeRole할 IAM Role ARN → 팀 ID.
- ALB의 resource_id: ARN의 loadbalancer/ 뒤 `app/name/id` 부분.
- cloudwatch의 resource_id: 지정하면 정확한 logGroup 일치를 강제합니다. 공유 그룹에는 팀을 지정하지 않습니다.
- prefix는 `/`로 끝나야 하며 동일 버킷에서 서로 겹치면 거부합니다.

```bash
# AWS와 ES에 접촉하지 않는 구성 검사
.venv/bin/python -m cloud_soc.aws.stream_cli --config state/aws-sydney.json
# 실제 수집: 아래 경로/주소는 승인된 중앙 설정으로 바꾼 뒤 실행
.venv/bin/python -m cloud_soc.aws.stream_cli --config state/aws-sydney.json \
  --run --once --profile YOUR_EXISTING_READER_PROFILE \
  --es-url https://YOUR_APPROVED_SOC_HOST:9200 \
  --ca-file state/central-ca.crt --api-key-file state/aws-stream-writer.key
```

`--once`를 빼면 long polling을 반복합니다. 프로세스를 여러 개 실행해 같은 큐에서 나누어 처리할 수 있습니다.
CloudShell의 임시 세션을 상시 worker로 사용하지 않습니다. 기존 runner 인스턴스에 임의 설치하지 않습니다.
운영 worker의 서비스 등록·자동 재시작·네트워크/용량 배치는 별도 인수 대상입니다.

시작 전 STS 계정, SQS ARN, DLQ 설정, 각 버킷의 소유 계정과 시드니 리전을 확인합니다.
실제 키는0600 파일로 전달하고 HTTPS 인증서 검증을 유지합니다. ES 전용 키와 AWS 인증은 별개입니다.

## AWS 연결 전제

`reader-policy.example.json`, `queue-policy.example.json`, `s3-notifications.example.json`은 검토용 조각입니다.
실제 계정/버킷/ARN/prefix로 변경하고 **기존 정책·notification 목록과 병합**해야 합니다.
특히 PutBucketNotificationConfiguration은 전체 목록을 바꾸므로 예시를 기존 버킷에 그대로 덮어쓰지 않습니다.
같은 버킷/prefix에 겹치는 알림이 있으면 기존 소비자와 함께 설계합니다.

- 새/기존 로그 버킷은 public access block, TLS 강제, 버전 관리, 보존 기간을 결정합니다.
- ALB의 기존 S3 접근 로그는 같은 리전 버킷과 SSE-S3가 필요합니다. KMS 강제를 추가해 ALB 쓰기를 막지 않습니다.
- SQS 메시지 retention은 예를 들어4일, DLQ는14일, maxReceiveCount5로 잡되 승인된 장애 대응 시간에 맞춥니다.
- 큐 정책은 지정 버킷 ARN·SourceAccount만 SendMessage를 허용합니다. collector는 receive/delete/change-visibility만 사용합니다.
- 수집기에는 GetBucketLocation/GetObject/GetObjectVersion만 주며 S3 원본 삭제 권한을 주지 않습니다.
- CloudWatch subscription → Firehose는 공식 Decompression을 사용하고 message extraction은 끕니다.
  owner/logGroup/logStream/logEvents를 보존해야 합니다. 이미 구독이 있는 그룹은 자동 교체하지 않습니다.
- Flow는 기본 v2 text만 지원합니다. Parquet/사용자 정의 필드순서/Hive 경로는 별도 adapter가 필요합니다.
- S3 알림 이전의 과거 객체는 자동 backfill되지 않습니다. 별도 목록/버전 확인과 replay 계획이 필요합니다.
- S3 버킷과 직접 SQS notification은 같은 리전이어야 합니다. 기존 타 리전 Trail 버킷을 시드니 큐에
  직접 연결할 수 없습니다. 기존 Event History 수집을 유지하거나 별도 교차 리전 전송을 승인해야 합니다.
- 중복 Trail을 무조건 새로 만들지 않습니다. 기존 다중 리전 Trail과 같은 관리 이벤트를 추가 기록하면
  비용과 중복이 생길 수 있습니다. 새 Trail/복제/데이터 이벤트는 별도 검토합니다.

## ES 쓰기 계약과 재처리

관리자가 `index-template.json`과 기존 `cloud-soc-received-at-v1` 수신 pipeline을 먼저 준비합니다.
`publisher-role.json`은 soc-ingest-aws-* 및 soc-ingest-tpot-*에만 auto_configure/create_doc을 허용합니다.
다른 인덱스·기존 경보·원본 수정/삭제 권한을 주지 않습니다.

각 Bulk는 최대500건/본문 약2MiB이며 객체는 압축32MiB, 압축해제64MiB, 최대100000건으로 제한합니다.
S3 ETag/VersionId/길이가 알림과 다르거나 payload·계정·리전·바인딩이 틀리면 큐를 ack하지 않습니다.
버킷 소유자도 요청마다 ExpectedBucketOwner로 검증합니다.

CloudTrail eventID와 CloudWatch eventID는 같은 이벤트의 다른 S3 파일 전달도 중복 처리합니다.
Flow/ALB/T-Pot은 객체 버전·ETag·행 번호 기반 ID라 같은 파일 재전송에서 중복을 막습니다.
상이한 객체로 복제한 Flow/ALB/T-Pot까지 논리 중복이라고 추정하지 않습니다.

SQS visibility는180초로 받고30초마다 연장합니다. 모든 문서가201 또는409로 확인된 뒤만 삭제합니다.
429/5xx/잘못된 문서/중간 행 오류/수집기 종료 시 메시지는 남고 재전송됩니다. 이미 기록된 앞부분은
create-only 중복으로 처리합니다. poison 객체는 DLQ에서 원인과 크기를 확인하며 자동 폐기하지 않습니다.
수동 보정한 원본을 새 키로 재발행하면 문서 ID 계약도 달라질 수 있으므로 운영자가 중복을 검토합니다.

인덱스에는 선별 메타데이터만 쓰며 원본 로그 보존은 승인된 S3 archive에서 수행합니다.
CloudTrail data/Insights/network activity 이벤트는 현재 adapter 범위가 아닙니다.
T-Pot 비밀번호·입력 명령·payload, ALB URL/query/user agent, 서비스 message는 ES에 복사하지 않습니다.

새 soc-ingest-* 인덱스는 기존 Portal 조회 allowlist와 탐지 worker에 자동 연결하지 않았습니다.
ES 수집과 Portal/규칙/경보 활성화는 다른 인수 작업입니다. 새 인덱스의 ILM/retention도 자동 변경하지 않습니다.

## T-Pot export 준비

`tpot-export/`에는 독립 Logstash의 Cowrie/Suricata 메타데이터 export 예시를 제공합니다.
원본 T-Pot의 내부 pipeline·포트·기존 ELK·센서 설정을 바꾸지 않습니다.

- Cowrie와 Suricata는 각각 다른 Compose project/volume/prefix로 실행합니다.
- 로그 source 디렉터리만 read-only로 마운트하고 Docker socket·T-Pot 전체 data·개인키는 전달하지 않습니다.
- 고정 이미지의 logstash-output-s3 플러그인 존재와 config 구문을 먼저 검사해야 합니다.
- EC2 instance role/IMDSv2 접근을 승인된 전용 호스트에서 설정합니다. 정적 AWS 키는 예시에 없습니다.
- tpot-writer-policy.example.json은 해당 sensor prefix에 쓰기만 허용하며 원본 GetObject 권한이 없습니다.
- persistent queue와 sincedb, 미전송 S3 임시 파일은 전용 volume에 보존합니다. 회전/재시작/장애 복구는 실제 인수가 필요합니다.
- 새 T-Pot EC2 생성, OS/버전 선택, 관리 접근 IP, 공개 허니팟 포트, 비용/디스크/retention은 별도 승인 범위입니다.

이 exporter 구성은 실제 T-Pot/Logstash에서 실행 검증하지 않았습니다. Python adapter의 합성 회귀 통과와 구분합니다.

## 용량 및 검증

실제 목표 events/sec·일별압축GB·피크배수·보존일수·월 예산·허용 지연을 정한 뒤 부하 시험합니다.
S3/큐 버퍼는 ES 처리량을 늘려 주지 않습니다. queue age/depth/DLQ, 처리 bytes/sec, Bulk429,
worker CPU/메모리, ES heap/shard/disk를 함께 측정합니다. worker1개당 압축/해제 버퍼와 JSON 객체의
추가 메모리를 고려합니다. 실행 코드에 최대 입력 크기는 있지만 대규모 클라우드 벤치마크는 하지 않았습니다.

```bash
.venv/bin/python -m pip install -c constraints.txt -r requirements-dev.txt
.venv/bin/python -m pytest -q tests/test_aws_sydney_streaming.py tests/test_cloudtrail.py
```

1201개 합성 Flow의500/500/201 전송, 같은 파일 replay 추가0, 다른 객체의 CloudTrail/CloudWatch 중복,
부분 Bulk 실패·잘못된 후반 행·계정/리전/prefix 차단·버전/길이/압축 한도·메타데이터 가림을 검사합니다.
실제 AWS·T-Pot·ES 쓰기·Portal·로그 보존 복구와 처리량 인수는 별도입니다.

## 공식 근거

- [T-Pot 공식 저장소](https://github.com/telekom-security/tpotce)
- [S3 이벤트 구조](https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-content-structure.html)
- [S3 이벤트 알림 대상](https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html)
- [VPC Flow 형식](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html)
- [ALB 접근 로그 활성화와 암호화](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html)
- [CloudWatch → Firehose](https://docs.aws.amazon.com/firehose/latest/dev/writing-with-cloudwatch-logs.html)

## Security Mall 적용

[새 EC2 설치·수집 안내](../deploy/aws/sydney/security-mall/README.md)를 사용합니다. 세 화면 접근·HTTP 오류·HMAC 로그인 감사를 수집합니다. IAM 사용자 네 명은 `user_teams`, AssumeRole은 `role_teams`로 정확히 매핑합니다. 웹 방문자와 IAM 주체는 자동 연결하지 않습니다.
