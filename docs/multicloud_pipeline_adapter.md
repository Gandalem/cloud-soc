# 멀티클라우드 통합 로그·정규화 어댑터

2026-11-01. `codex/merge-gyumin-jeongrim-react` 통합 후보에 구현했다. 코드와 격리 검증 상태이며 운영 키 발급·워커 시작·규칙 활성화·배포는 하지 않았다.

## 데이터 경로

`soc-multicloud-*` → 전용 `cloud_soc.multicloud.processing` → 공통 `soc-normalized-v1` / `soc-processing-v1` → 기존 탐지 엔진.

통합 로그의 고정 허용 인덱스·원본 참조·OS/소스 분류·조회 필드에 멀티클라우드 감사 계약을 추가했다. AWS/Azure/Naver의 schema/provider/dataset/event ID/account/organization/action/outcome을 검증한다. 원본은 이미 수집기가 선택한 메타데이터이며, 공급자 전체 원문이라고 표현하지 않는다.

- 공통 어댑터 이름 `multicloud_audit_v1`, 버전 `multicloud-audit-v1`.
- 발생 시각 `@timestamp`, 수신 시각 `event.ingested`, 처리 시각 `cloud_soc.normalized_at`을 따로 유지한다. 현재 multicloud 수집기의 event.ingested는 **collector 시계 기준**이며 서버 final ingest pipeline으로 검증한 시각이라고 주장하지 않는다. 수집기와 서버의 시각 동기화가 필요하다.
- 원본의 정확한 index/id를 정규화 provenance에 유지한다. 동일 참조 재처리는 같은 정규화 ID를 사용한다. 민감값/스키마/제공자·dataset 불일치/이벤트ID 변조는 invalid로 처리한다.
- Portal 조회는 기존 기관 권한 및 원본 접근 감사/필드 제한을 유지한다. AWS/Azure/Naver가 Linux/Windows로 표시되지 않는다.
- 기존 일반 정규화기의 기본 입력과 ROLE은 기존 범위로 고정했다. 새 인덱스를 기존 키로 읽게 만들어 정상 워커가 권한 오류로 멈추지 않게 한다.
- 전용 워커는 soc-multicloud-*만 읽는 키, 별도 multicloud-checkpoint.sqlite와 normalizer-multicloud 상태 문서를 사용한다. 다른 워커 status ID와 멀티클라우드 범위를 섞으면 시작을 거부한다. 날짜별 인덱스가 증가해도 scope 지문은 동일하다.
- 운영 상태 API의 multicloud_normalizer에서 전용 처리기를 확인한다. 실행된 전용 처리기의 실패/오래된 상태/지연은 전체 coverage에도 반영한다. 기관 제한 사용자는 전역 처리기 상태를 읽지 못한다.

## 탐지 범위와 한계

공통 정규화 출력은 기존 탐지기의 입력/원본 근거 계약을 만족한다. AWS StopLogging 감사 이벤트가 실제 AWS-AUDIT-001 규칙에 일치하고 SSH 규칙에 잘못 일치하지 않는 검사를 통과했다.

어댑터 추가가 모든 공급자의 새 탐지 규칙 활성화를 뜻하지 않는다. 기존 운영 manifest에 AWS-AUDIT-001이 없으면 별도 검토/활성화가 필요하다. AWS IAM/네트워크 규칙에 필요한 target_policy_arn/public ingress 등의 필드를 수집기가 보존하지 않으면 해당 조건은 평가할 수 없다. Azure/Naver 전용 행위 규칙도 별도 정의·인수가 필요하며 API 실패를 곧바로 침해 성공으로 해석하지 않는다.

Naver 등 지연 공개 감사 로그는 사건 발생 시각이 오래될 수 있다. 정규화 시각을 임의로 과거/현재로 바꾸거나 기존 탐지 lateness를 확대하지 않았다. 실시간 탐지의 late 제외와 별도 retrospective 경로를 구분해 운영 규칙 프로필·독립 상태로 검토해야 한다. 어댑터 설치만으로 과거 로그 탐지가 완료됐다고 판단하지 않는다.

## 운영 연결 준비

1. 이 통합 후보로 중앙 런타임 이미지를 빌드/검토하고 기존 공통 처리 인덱스가 준비돼 있는지 확인한다.
2. 기존 관리자 API 키를 파일로 제공해 `python -m cloud_soc.multicloud.processing_setup --es-url <HTTPS> --ca-file <CA> --admin-key-file <관리자키파일> --output <새전용키파일>`의 계획을 먼저 확인한다. 실제 발급은 같은 명령에 `--apply`를 추가한다. 출력 경로 부모는0700이고 새 파일이어야 한다. 대상 인덱스/계약을 검증하고30일 전용 키를0600으로 저장한다. 기존 역할/키를 덮어쓰지 않는다. 키 자체를 명령 인자·환경변수·출력에 넣지 않는다.
3. `deploy/multicloud/processing.compose.yaml`의 필수 변수에 검토한 중앙 이미지, 기존 중앙 Docker 네트워크, CA 파일, 새 전용 키 파일, **별도** state 디렉터리 및 변경하지 않을 수신 시작 시각을 지정한다. SOC_ADAPTER_START는 사건 발생 시각이 아닌 event.ingested 조회 구간의 시작이다. 기존 일반/우선/collector SQLite를 재사용하지 않는다.
4. 운영 승인 후 별도 Compose 프로젝트 `cloud-soc-multicloud-adapter`로 명시 시작한다. 기존 중앙/collector 프로젝트를 다시 초기화하지 않는다. 기본 compose에는 자동 추가하지 않았다.
5. API `/api/logs?os=cloud` 및 `/api/operations/status`의 multicloud_normalizer를 확인한다. 선택한 원본의 참조와 공통 정규화 근거, 승인한 탐지 규칙의 실제 경보를 각각 대조한다.

CLI 검토 모드(실제 파일 경로/시각으로 교체):

```text
python -m cloud_soc.multicloud.processing --start <수신시작ISO8601> --state <별도폴더>/multicloud-checkpoint.sqlite --es-url <HTTPS> --ca-file <CA> --api-key-file <전용키파일>
```

이 모드는 네트워크/상태 변경 없이 입력을 검증한다. 운영 실행은 명시적으로 --run을 붙인다. 키 갱신은 만료 전에 별도 키 파일로 수행해야 한다.

## AWS 선택지 수정

prototype/multicloud.html에 `전체 클라우드</option value="aws">`라는 깨진 태그가 있어 AWS가 선택지로 나타나지 않았다. `<option value="aws">AWS</option>`를 복원했다. 전체 클라우드/AWS/Microsoft Azure/Naver Cloud를 모두 유지하며 AWS 선택 시 기존 API에 provider=aws가 전달된다.

## 검증

- 관련 Python144검사/78 subtests 통과. 이후 독립 status binding·host source 위장 거부·adapter failure coverage 등 추가 영향 범위49검사 통과, 키 발급 대상 검증 추가1검사 통과.
- 신규 어댑터는3제공자/원본 근거/시각/결정적ID/기관경계/스키마·민감값 거부/날짜별 인덱스 증가/기존 scope·key 보존/실제AWS규칙 일치를 검증한다.
- 기존 로그UI21개 및 전체 선택지 보존·AWS API 필터 DOM 검사1개 통과.
- 최초 기존 scope 검사1개는 새 Portal 허용 인덱스 기대값을 갱신했다. AWS UI 테스트의 timer/selected 모의 DOM 설정 누락을 수정 후 통과했다.
- 운영 Docker/Elasticsearch·공급자 계정·키·규칙·체크포인트는 변경하지 않았다. 실제 서비스 적용과 로그/경보 인수는 별도다.
