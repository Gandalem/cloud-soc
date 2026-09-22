# OCI Audit 수집 및 통합 로그

## 구현 범위

OCI Audit API를 명시한 **테넌시·리전·구획(Compartment)** 범위에서 읽고 `soc-cloud-oci-YYYY.MM.DD`에 선택 메타데이터를 저장합니다. Filebeat가 읽는 Ubuntu/Windows 로그, AWS CloudTrail과는 별도 수집기입니다. 중앙 서버가 AWS에 있어도 승인된 OCI API 키 프로파일로 실행할 수 있습니다.

- 지원: 상용 OC1 테넌시 1개, 고정 SDK가 아는 OC1 리전, 명시한 구획 목록. 리전 최대 20개·구획 최대 50개·조합 최대 100개.
- 구획 자동 탐색/하위 구획 재귀 수집 없음. 루트 기록이 필요하면 `compartments`에 테넌시 OCID 자체도 명시합니다. 루트 하나를 지정했다고 모든 하위 구획 수집으로 취급하지 않습니다.
- Compute·네트워크·IAM 등 Audit API가 반환하는 지원 이벤트를 처리합니다. 미지원 스키마는 조용히 버리지 않고 해당 구간을 실패 처리합니다.
- Object Storage **객체** 접근과 Identity Domains 로그인 감사 API는 연결하지 않았습니다. 버킷 관리 기록이나 OCI Audit만으로 모든 파일 접근/로그인을 관측했다고 표시하지 않습니다. [Audit 범위](https://docs.oracle.com/en-us/iaas/Content/Audit/Concepts/auditoverview.htm), [Identity Domains 감사 API](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/usingauditeventapis.htm)
- 검증은 합성 이벤트·공식 SDK 모의 HTTP 응답·격리 ES·로컬 UI입니다. 실제 OCI 인증/수신·배포·자동 서비스 시작은 아직 하지 않았습니다.

## 인증과 권한

**AWS/일반 서버에서 실행:** 별도로 승인된 OCI API-key 프로파일을 사용합니다. `~/.oci/config`의 테넌시·사용자 OCID·fingerprint·`key_file`을 OCI 공식 설정 절차에 따라 준비하세요. 프로파일과 개인키는 실행 사용자만 읽도록 보호하며 Git, 설치 패키지, 채팅에 올리지 않습니다. 이 프로그램은 OCI 키를 생성/업로드하거나 OS 에이전트로 배포하지 않습니다. API 키 인증만 지원하며 OCI CLI 세션 토큰 프로파일은 현재 지원하지 않습니다. [SDK 설정](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm)

**OCI Compute에서 실행:** `--auth instance-principal`을 지정할 수 있습니다. 관리자가 먼저 해당 인스턴스를 제한된 동적 그룹에 포함하고 읽기 정책을 검토해야 합니다. AWS EC2에서는 이 인증을 선택하지 마세요. 선택적 인증은 `--run` 후에만 메타데이터/OCI 통신을 시작합니다. 구성/서명자의 테넌시가 수집 설정과 다르면 Audit 호출 전에 중단합니다. OCI 리전 엔드포인트는 고정된 공식 HTTPS 주소를 사용하며 임의 endpoint와 메타데이터 주소 override를 허용하지 않습니다. [Instance Principal 서명](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/signing.html)

최소 정책 예시입니다. 승인된 그룹과 구획 이름으로 바꿔 관리자가 적용합니다. 두 인증 방식 중 사용하는 것만 선택하세요.

```text
Allow group SocAuditReaders to read audit-events in compartment ProjectA
Allow dynamic-group SocAuditCollectors to read audit-events in compartment ProjectA
```

테넌시 전체 읽기 정책을 기본으로 부여하지 않습니다. 루트 조회가 필요하면 별도로 권한 범위를 검토하세요. 이 정책은 Audit 읽기이며 인스턴스/IAM/버킷 변경이나 Object Storage 본문 읽기 권한을 요구하지 않습니다. 수집 설정의 구획이 승인된 테넌시에 속하는지도 관리자가 확인해야 합니다. 프로그램은 IAM 구획 열거 권한을 추가로 요구하지 않습니다. [Audit 읽기 정책](https://docs.oracle.com/en-us/iaas/Content/Audit/Tasks/viewinglogevents.htm)

## 중앙 서버 준비

검토한 코드를 반영하고 [기존 중앙 서버 업데이트](agent_status.md#기존-중앙-서버-업데이트) 절차로 bootstrap/portal을 갱신합니다. bootstrap이 준비하는 것은 OCI 인덱스 템플릿·서버 수신 시각 파이프라인·읽기 역할·전용 쓰기 역할뿐입니다. SDK 설치·OCI 인증·수집기 실행·OCI 정책 변경은 자동으로 하지 않습니다.

기존 CA·데이터·비밀번호·에이전트 키를 보존합니다. 설치기를 처음부터 다시 실행하거나 `down -v`를 실행하지 마세요. 포털은 기존 단일 관리자 모델이며 조직별 격리/RBAC를 새로 제공한 것은 아닙니다.

승인된 ES 관리자가 별도의 만료 키를 발급합니다. 기존 호스트나 AWS 수집 키를 재사용하지 마세요. 응답의 `encoded`만 보호된 로컬 파일에 기록하고 화면/채팅으로 공유하지 않습니다.

```http
POST /_security/api_key
{
  "name": "cloud-soc-oci-audit",
  "expiration": "30d",
  "role_descriptors": {
    "oci_audit": {
      "cluster": [],
      "indices": [{"names": ["soc-cloud-oci-*"], "privileges": ["auto_configure", "create_doc"]}]
    }
  }
}
```

이 키로는 OCI 인덱스 문서 생성만 가능하며 조회·덮어쓰기·삭제·AWS/호스트 인덱스 쓰기는 불가능합니다. [역할 정의](../deploy/oci/publisher-role.json)

## Ubuntu 실행

저장소 루트에서 선택적 별도 가상환경을 준비합니다. OS의 `python3-venv`가 필요합니다.

```bash
python3 -m venv .venv-oci
.venv-oci/bin/python -m pip install -r deploy/oci/requirements.txt
mkdir -p state/oci
chmod 700 state/oci
cp deploy/oci/collector.example.json state/oci/collector.json
```

`collector.json`의 예시 테넌시·구획 OCID, 조직, 리전을 실제 승인한 값으로 수정합니다. 홈 리전의 IAM 활동을 확인하려면 그 리전도 명시적으로 포함하세요. 최초 조회는 기본 24시간이며 `lookback_hours`는 1~8736(364일)입니다. OCI 키·ES 키는 이 JSON에 넣지 않습니다. `state/`, `.venv-oci/`는 Git에서 제외합니다.

다음 명령은 **오프라인 설정 검증만** 수행합니다. SDK 인증/키 파일 읽기/네트워크 요청/체크포인트 생성이 없습니다.

```bash
PYTHONPATH=src .venv-oci/bin/python -m cloud_soc.oci \
  --config state/oci/collector.json
```

중앙 ES의 CA를 `state/oci/ca.crt`, 전용 ES 키의 encoded 값을 `state/oci/es-api-key`에 준비합니다. Linux 키 파일은 400/440/600/640 권한만 허용합니다. OCI 개인키·프로파일에도 별도로 최소 파일 권한을 적용하세요. Windows에서는 NTFS ACL 보호가 필요합니다.

```bash
chmod 600 state/oci/es-api-key
PYTHONPATH=src .venv-oci/bin/python -m cloud_soc.oci \
  --config state/oci/collector.json --state state/oci/checkpoint.sqlite \
  --auth config --oci-config ~/.oci/config --profile DEFAULT \
  --es-url https://YOUR-CENTRAL-HOST:9200 \
  --ca-file state/oci/ca.crt --api-key-file state/oci/es-api-key \
  --run --once
```

`--run`부터 실제 수집·ES 쓰기를 수행합니다. `--once`는 각 구획/리전에서 최대 1시간만 전진하는 한 회차이며 전체 과거 조회 완료를 뜻하지 않습니다. 정상/대기는 종료 코드 0, 실패는 1입니다. 주기 수집은 `--once`를 제거하고 `--interval 60`을 사용합니다(60~3600초). OCI 인스턴스 인증은 `--auth config --oci-config ... --profile ...` 대신 `--auth instance-principal`을 사용합니다.

장기 운영 서비스 등록과 자동 재시작은 운영자가 별도로 설정해야 합니다. 같은 범위를 여러 프로세스로 중복 실행하지 마세요. 주기 실행 중 API 실패는 다음 회차에 해당 구간을 재조회합니다. 초기 인증 실패는 고정 오류로 종료하므로 인증 복구 후 재시작합니다.

```bash
PYTHONPATH=src .venv-oci/bin/python -m cloud_soc.oci \
  --config state/oci/collector.json --state state/oci/checkpoint.sqlite --status
```

로컬 상태에는 구획/리전별 최초 조회 범위, 완료 경계, 마지막 시도/성공·고정 오류·마지막 성공 회차 생성/중복 수가 나옵니다. 중앙 에이전트 접속 현황의 heartbeat/온라인 상태로 표시하는 기능은 아닙니다.

## 데이터와 복구 한계

조회 조건은 UTC 분 단위로 고정하고 `opc-next-page`를 따라갑니다. Oracle API의 시작은 포함·종료는 미포함이며 **처리 시각 범위**를 조회합니다. 개별 `event_time`은 발생 시각이므로 조회 시작보다 오래된 이벤트도 버리지 않습니다. 수집 리전은 요청한 API 리전이고 대상 자원의 실제 위치를 추정한 값이 아닙니다. [ListEvents SDK 계약](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/audit/client/oci.audit.AuditClient.html)

- 구간 최대 1시간, 최근 10분 대기, 이전 15분 재조회, 구간당 최대 1000페이지. 과도한 페이지·이상 이벤트·권한/통신 오류에서는 완료 경계를 전진시키지 않습니다. 대량 bulk export 용도는 아닙니다.
- 초당 약 1.8회 이하의 직렬 페이지 요청, 요청 연결/읽기 제한 5/20초를 사용합니다. SDK 내부 재시도는 끄고 다음 실행 회차로 복구합니다. 다른 클라이언트와 합산된 제한이나 전체 회차 소요 시간은 별도입니다.
- SQLite 영속 상태와 조직/테넌시/리전/구획/초기 범위 지문을 사용합니다. 변경된 설정으로 기존 상태를 덮어쓰지 않습니다. 범위를 바꿀 때는 이전 파일을 보존하고 별도의 상태 경로를 명시합니다. AWS와 상태 파일을 공유하지 마세요.
- 모든 문서 생성 또는 중복 확인 후에만 체크포인트를 전진시킵니다. 장애/재시작 시 구간 첫 페이지부터 반복하며 eventID 기반 ID로 기존 문서/수신 시각을 덮어쓰지 않습니다.
- 조회 경계의 15분 재조회 밖에서 늦게 노출되는 기록까지 완전 수집을 보장하지 않습니다. 장기 중단/누락은 승인된 별도 상태의 과거 재조회가 필요합니다. 365일 이전 미완료 경계는 중단합니다. 서비스 보존/가용성을 따르며 과거 데이터 존재를 보장하지 않습니다. [Audit 보존](https://docs.oracle.com/en-us/iaas/Content/cloud-adoption-framework/auditing.htm)
- 저장 필드는 주체/대리 호출자·테넌시·구획·API·자원 ID/이름·출발지·요청 ID/메서드·HTTP 상태·발생/서버 수신 시각입니다. 2xx는 API 응답 성공, 4xx/5xx는 실패, 나머지/누락은 미확인입니다. 202 같은 응답은 이후 작업 완료나 공격 여부의 확정 판정이 아닙니다.
- 전체 JSON, 요청/응답 헤더·파라미터·경로·본문, stateChange, tags/additionalDetails, credentials, consoleSessionId는 저장/표시하지 않습니다. 선택 문자열도 기존 비밀값 마스킹·제어문자/512자 제한을 적용합니다. 일반 DLP나 전체 원본 증거 보존은 아닙니다. [Audit 필드 정의](https://docs.oracle.com/en-us/iaas/Content/Audit/Reference/logeventreference.htm)

## 화면 및 검증

통합 로그에서 **OCI Audit** 수집기 또는 **클라우드 API** 영역을 선택합니다. OCI 테넌시/리전은 호스트명 대신 별도로 표시합니다. 문서 ID를 누르면 구획·행위 주체·대상 자원·HTTP 결과 근거를 확인할 수 있습니다. 호스트 검색은 OCI 테넌시 검색이 아니며 개별 구획 검색 UI는 후속 범위입니다. 별도 사건 조사 화면/탐지 규칙은 이번에 변경하지 않았습니다.

실제 적용 후 승인된 기존 Audit 이벤트 1건의 eventID·구획·시각·결과를 OCI Console과 대조하세요. 시험을 위해 운영 IAM/보안 목록을 변경할 필요는 없습니다. 운영 삭제/ILM 보존은 자동 적용하지 않으며 저장량 보고에 OCI만 추가했습니다.

```powershell
.\.venv\Scripts\python.exe -m pip install -r deploy/oci/requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_oci_audit.py
```

선택 SDK가 없으면 SDK 검증만 건너뜁니다. 전체 격리 ES 시험은 `$env:SOC_TEST_AGENT_STATUS_ES='1'` 후 전체 unittest를 실행합니다. 테스트는 임시 컨테이너와 합성 이벤트만 사용하고 실제 OCI 자격 증명에 접근하지 않습니다.
