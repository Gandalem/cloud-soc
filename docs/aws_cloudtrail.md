# P4 AWS 관리 이벤트 수집

## 1. 구현과 범위

이 수집기는 기존 CloudTrail의 **Event History / LookupEvents**를 읽습니다. EC2 안의 Filebeat와 별개이며 중앙 관리용 프로세스 하나로 실행합니다. Trail 생성·시작·중지, 로깅 선택자, S3 버킷 정책, AWS 계정/리전 활성화는 변경하지 않습니다.

| 구분 | 지원 |
| --- | --- |
| AWS | 명시한 상용 AWS 계정 1개, 리전 목록 최대 20개. 실행 주기마다 STS 실제 계정 확인 |
| 이벤트 | 선택 리전의 관리 이벤트. 콘솔 로그인, IAM API, 보안그룹 API 등의 메타데이터 |
| 비지원 | S3 GetObject/PutObject 등 데이터 이벤트, Insights, CloudTrail Lake/S3 원본 읽기, 조직 전체 자동 수집, GovCloud/China |
| 저장 | `soc-cloud-aws-YYYY.MM.DD` (UTC 발생일). 개인정보 필터를 거친 선택 필드만 저장 |
| 조회 | 통합 로그의 `CloudTrail` 수집기 / `클라우드 API` 영역 필터, 문서 상세 |
| 현재 검증 | 합성 AWS 이벤트·공식 SDK Stubber·격리 ES·로컬 UI. 실제 AWS 계정/배포는 미검증 |

AWS는 LookupEvents 조회를 최근 90일로 제한하며 페이지당 최대 50건, 계정·리전별 초당 2회 제한을 둡니다. 이 구현은 페이지마다 0.55초 간격과 제한된 SDK 재시도를 적용합니다. **같은 계정/리전에 수집기를 중복 실행하지 마세요.** 다른 관리 도구의 호출까지 합쳐지면 제한에 걸릴 수 있습니다. [AWS LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)

IAM 전역 이벤트 확인에는 `us-east-1`이 중요하지만 ConsoleLogin이 항상 그 리전에만 기록되는 것은 아닙니다. 사용하는 서비스·콘솔 엔드포인트에 맞게 리전을 검토하세요. 예시의 도쿄/버지니아 두 리전을 모든 리전 수집으로 간주하지 않습니다. [IAM/STS 기록](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html), [콘솔 로그인 리전](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html)

## 2. 보호 및 조사 필드

- 행위 주체의 이름/ID/ARN·유형·계정·세션 발급 역할, API·서비스, 수신 계정·리전, 관측된 자원 ARN을 보존합니다. IAM 대상 사용자/역할/정책 ARN과 EC2 보안그룹 ID도 선택적으로 보존합니다.
- 출발지가 IP이면 `source.ip`, AWS 서비스명 등 비-IP이면 `source.address`에 남깁니다. 없는 IP나 호스트명을 만들지 않습니다. 클라우드 자원을 수집 서버의 호스트로 표시하지 않습니다.
- AWS `eventTime`과 서버가 강제로 기록하는 `event.ingested`를 구분합니다. 상세에는 ES 문서 인덱스/ID와 원래 CloudTrail eventID가 모두 남습니다.
- ConsoleLogin은 명시된 응답으로 성공/실패를 구분하고 응답이 없으면 미확인입니다. 오류 코드가 있으면 실패입니다. 다른 API의 성공 표시는 **오류 코드 미보고**에 근거하며 비동기 작업의 최종 성공·안전·공격 여부를 보장하지 않습니다. [CloudTrail 필드 정의](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
- 전체 `CloudTrailEvent`, requestParameters/responseElements, 정책 문서, userData, accessKeyId, 세션 토큰, 자유 형식 오류 메시지, 파일 본문은 저장하지 않습니다. 선별 문자열도 비밀값 패턴·제어문자·512자 초과이면 가립니다. 자원은 최대 20개이며 생략 여부를 기록합니다. 일반 DLP나 법적 원본 보존 기능은 아닙니다.
- 원본 JSON은 SDK 응답을 처리하는 동안 메모리에만 존재하며 SQLite·응용 로그·포털 응답으로 복사하지 않습니다. SDK 디버그 로깅을 켜거나 예외 전체를 공유하지 마세요. 원본 증거의 별도 AWS 보존/검증 설계는 후속 범위입니다.
- 현재 포털은 단일 관리자용입니다. 조직 ID는 분류 메타데이터이며 조직별 접근 통제를 제공하지 않습니다. AWS 인덱스 조회는 기존 신뢰된 포털 조회/분석 계정에 추가됩니다.

## 3. 자격 증명과 최소 권한

권장 인증은 중앙 EC2 인스턴스 프로파일의 **IAM 역할**입니다. 수집 대상 Windows/Linux 에이전트에 AWS 키를 배포하지 않습니다. 로컬 개발에서는 이미 승인된 AWS 프로파일/SDK 자격 증명 체인을 사용합니다. 소스 코드·설정 JSON·명령 인자·Git에 AWS 키를 넣지 마세요. [Boto3 자격 증명](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html)

[lookup-policy.example.json](../deploy/aws/lookup-policy.example.json)의 리전 목록을 승인된 범위로 바꾸고 관리자 검토 후 역할에 연결합니다. 이 정책의 권한은 `cloudtrail:LookupEvents` 하나입니다. `Resource: "*"`는 이 조회 API 범위를 뜻하며 AWS 관리자 권한이 아닙니다. 역할 생성/연결은 자동 수행하지 않습니다. STS `GetCallerIdentity`로 실제 계정을 비교하고 다르면 CloudTrail 호출 전에 중단합니다. 이 STS API 자체는 별도의 허용 권한을 요구하지 않습니다. [AWS STS](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)

ES 키는 AWS 키와 다릅니다. [publisher-role.json](../deploy/aws/publisher-role.json)은 `soc-cloud-aws-*`에 `auto_configure`, `create_doc`만 허용합니다. 호스트 에이전트 키를 재사용하지 마세요. CloudTrail 키는 조회·수정·삭제·호스트 로그 쓰기 권한이 없습니다.

먼저 검토한 서버 코드를 반영하고 [기존 서버 업데이트 절차](agent_status.md#기존-중앙-서버-업데이트)를 실행합니다. bootstrap은 AWS 인덱스 템플릿·서버 수신 파이프라인·읽기 역할·전용 쓰기 역할만 준비합니다. AWS 수집기를 자동 실행하거나 API 키를 자동 발급하지 않습니다. 기존 CA·데이터·비밀번호·수집기 키는 보존합니다.

승인된 Elasticsearch 관리자가 Kibana Dev Tools 등에서 다음과 같이 **별도 만료 키**를 발급합니다. 키의 `encoded` 값은 보호된 로컬 파일에만 기록하고 채팅/로그/Git에 남기지 마세요.

```http
POST /_security/api_key
{
  "name": "cloud-soc-cloudtrail",
  "expiration": "30d",
  "role_descriptors": {
    "cloudtrail": {
      "cluster": [],
      "indices": [{"names": ["soc-cloud-aws-*"], "privileges": ["auto_configure", "create_doc"]}]
    }
  }
}
```

## 4. Ubuntu에서 명시적으로 실행

중앙 서버의 저장소 루트에서 진행합니다. 중앙 Compose 설치기는 이 선택적 수집기를 자동 설치하지 않습니다. 기존 운영 가상환경을 사용한다면 의존성 변경을 먼저 검토하세요.

```bash
python3 -m venv .venv-aws
.venv-aws/bin/python -m pip install -r deploy/aws/requirements.txt
mkdir -p state/aws
chmod 700 state/aws
cp deploy/aws/collector.example.json state/aws/collector.json
```

`state/aws/collector.json`의 예시 계정 `123456789012`, 조직과 리전을 실제 승인된 값으로 수정합니다. 기본 최초 조회 범위는 24시간이며 `lookback_hours`는 1~2136(89일)입니다. 실제 AWS 키는 이 JSON에 넣지 않습니다. `state/`는 Git에서 제외됩니다.

기본 실행은 **오프라인 설정 검증만** 수행합니다. SDK 자격 증명 조회, AWS/ES 통신, 상태 DB 생성이 없습니다.

```bash
PYTHONPATH=src .venv-aws/bin/python -m cloud_soc.aws \
  --config state/aws/collector.json
```

승인된 CA 인증서를 `state/aws/ca.crt`, ES 키의 encoded 값만 `state/aws/es-api-key`에 준비합니다. 파일은 실행 사용자만 관리하게 하세요. Linux 키 파일은 400/440/600/640 권한만 허용하며 Windows에서는 별도 ACL 보호가 필요합니다. TLS 검증 우회 옵션은 제공하지 않습니다.

```bash
chmod 600 state/aws/es-api-key
PYTHONPATH=src .venv-aws/bin/python -m cloud_soc.aws \
  --config state/aws/collector.json --state state/aws/checkpoint.sqlite \
  --es-url https://YOUR-CENTRAL-HOST:9200 \
  --ca-file state/aws/ca.crt --api-key-file state/aws/es-api-key \
  --run --once
```

`--run`이 실제 통신과 ES 쓰기를 시작합니다. `--once`는 리전별 **최대 1시간 전진** 한 번만 실행하므로 24시간 전체 수집 완료를 뜻하지 않습니다. 오류는 종료 코드 1, 정상/대기는 0입니다. AWS 계정 불일치·권한 실패·TLS/키 실패를 데이터 없음으로 처리하지 않습니다.

주기 수집은 위 명령에서 `--once`를 빼고 `--interval 60`을 지정합니다. 60~3600초 간격으로 반복하며 장기 운영은 승인된 서비스 관리자에 등록하세요. 운영 서비스 등록/자동 시작은 이번 구현에서 수행하지 않았습니다. 중단은 Ctrl+C이며 체크포인트를 지우지 않습니다.

```bash
PYTHONPATH=src .venv-aws/bin/python -m cloud_soc.aws \
  --config state/aws/collector.json --state state/aws/checkpoint.sqlite --status
```

상태에는 리전별 최초 범위·완료 경계·최근 시도/성공·고정 오류 코드·마지막 성공 회차의 생성/중복 수가 표시됩니다. 자격 증명·본문·페이지 토큰은 저장하지 않습니다. 이 상태는 로컬 CLI용이며 중앙 에이전트 접속/수집 품질 화면에 AWS 온라인 상태를 추가한 것은 아닙니다.

## 5. 체크포인트와 누락 한계

SQLite 상태 파일은 로컬 영속 디스크에 보관합니다. NFS/공유 드라이브나 실행마다 사라지는 임시 디렉터리는 사용하지 마세요. 조직·계정·리전 목록·초기 조회 설정 지문을 고정하고 다른 설정의 재사용을 거부합니다. 범위를 바꿀 때는 기존 상태를 보존하고 명시적으로 새 상태 경로에서 필요한 기간을 재조회합니다. 운영 중인 기존 수집기와 겹쳐 실행하지 않습니다.

- 리전별 최대 1시간 구간을 고정하고 같은 시작/종료 조건으로 페이지를 끝까지 읽습니다. 구간당 최대 1000페이지이며 초과하면 완료 경계를 전진시키지 않습니다. 고유 시간 범위를 더 잘게 나누는 고유량 수집은 후속 과제입니다.
- 모든 문서 생성 성공 또는 동일 ID 중복 확인 뒤에만 완료 경계를 갱신합니다. 중간 AWS/ES 실패·토큰 오류·재시작에서는 해당 구간 첫 페이지부터 재실행합니다. 페이지 토큰을 영속 저장하지 않아 만료 토큰에 매달리지 않습니다.
- 문서 ID는 조직·계정·리전·eventID, 인덱스는 발생일로 고정합니다. `create`만 사용하므로 재전송은 기존 문서나 첫 수신 시각을 덮어쓰지 않습니다. 정확히 한 번 전송이 아니라 재조회+중복 방지 방식입니다.
- 최근 5분은 대기하고 완료 경계 이전 15분을 다시 조회합니다. 더 오래 지연된 AWS 기록은 놓칠 수 있으므로 완전 무손실 수집으로 보장하지 않습니다. 필요하면 90일 내 별도 상태의 승인된 과거 재조회로 보완합니다.
- 90일을 넘긴 미완료 구간은 `history_gap_requires_review`로 중단하며 자동으로 건너뛰지 않습니다. 이벤트 형식/계정/리전/시각 오류도 구간을 실패 처리합니다. 본문을 자동 격리 저장하거나 불량 이벤트를 몰래 버리지 않습니다.
- 애플리케이션 오류에는 원문을 출력하지 않습니다. `aws_throttled`, `aws_access_denied`, `aws_page_token_invalid`, `aws_identity_unavailable`, `elasticsearch_write_failed` 등을 확인하세요. 실제 SDK 인증 실패의 세부 사유는 보호된 환경에서 별도로 점검합니다.

운영 ILM/삭제는 자동 설정하지 않습니다. P2 저장량 보고에는 AWS 인덱스가 포함되지만 보존 기간·디스크/백업 승인은 여전히 필요합니다. 수집 확대 전 용량을 점검하세요.

## 6. 화면 및 실제 검증 순서

1. 통합 로그에서 수집기 **CloudTrail** 또는 영역 **클라우드 API**를 선택합니다. 기본 서버 수신 시각 기준은 신규 도착한 과거 AWS 이벤트도 보여줍니다.
2. `호스트 / AWS 계정·리전` 열은 AWS 계정/리전을 표시합니다. 호스트 검색 조건은 AWS 계정 검색이 아닙니다. 문서 ID를 눌러 주체·API·대상 ARN/그룹·출발지·결과 근거를 확인합니다.
3. 승인된 계정의 기존 콘솔 로그인·IAM/보안그룹 관리 기록을 AWS Event History와 대조합니다. eventID·계정·리전·시각·결과를 각각 확인하세요. 시험을 위해 운영 권한/보안그룹을 변경하지 마세요.
4. 수집기 재시작/일시 장애 후 완료 경계와 중복 건수를 확인합니다. 쓰기 권한으로 조회/삭제가 불가능한지, 개인정보 canary가 저장되지 않는지도 격리 환경에서 확인합니다.

저장된 관리 이벤트만으로 S3 개인 문서/객체 접근까지 관측했다고 표시하지 않습니다. **P4-03 데이터 이벤트는 대상 버킷/접근 종류·비용·보존 기간 합의 전 비활성**이며 별도의 수집 경로가 필요합니다. 기존 데모 조사 Workbench를 실데이터 사건 조사 화면으로 전환하는 작업은 P6입니다. 이번 조사 필드 연결은 통합 로그 상세까지입니다.

로컬 회귀:

```powershell
.\.venv\Scripts\python.exe -m pip install -r deploy/aws/requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests
node --test deploy/agents/tests/*.test.cjs prototype/tests/*.test.cjs
```

선택적 SDK 미설치 시 해당 Stubber 검증은 건너뜁니다. 실제 로컬 Docker ES 검증은 `$env:SOC_TEST_AGENT_STATUS_ES='1'`로 켭니다. 이 테스트는 임시 컨테이너와 합성 이벤트만 사용하며 실제 AWS 자격 증명을 조회하지 않습니다.
