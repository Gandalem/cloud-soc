# security-mall 수집 3-B: 독립 격리 구성

2026-10-16 후속 실제3-C 인수는 [통합 검증 기록](security_mall_integration_validation.md)에 별도로 기록했다. 아래3-B의 모의 검증 이력과 구분하며, 실제 원본4/정규화4·최소권한/create-only·registry/rename/GZIP 인수가 완료됐다.

목표 경로는 앱 JSONL → Filebeat → 전용 원본 인덱스 → 기존 `normalize()`다. 쇼핑몰 코드와 기존 운영 수집/정규화 설정은 변경하지 않는다. 이 단계는 구성과 모의 검증이며 Filebeat·Elasticsearch 서비스를 설치/기동/배포하지 않는다. 실제 로그/키/DB는 사용하지 않는다.

## 수집 방식과 신뢰 경계

기존 Filebeat **filestream + 전용 script processor**를 재사용한다. 별도 Python 수집 데몬은 없다. 기본 NDJSON 디코딩만으로 중복 키·정확한 필드 집합·권한 사유 조합을 모두 검증한다고 가정하지 않는다. 원래 한 줄을 전용 ECMAScript 5.1 스크립트에서 검증한 다음 구조화한다. JSON.parse의 마지막 중복 키 선택을 허용하지 않도록 scalar-only 원본을 별도 스캔하며 이스케이프된 동일 키도 거부한다. JSON 숫자 1.0/1e0을 정수 schema_version=1로 오인하지 않는다.

파일은 UTF-8이며 허용 앱 필드는 모두 ASCII 값이다. 한 이벤트는 최대8192바이트, LF/CRLF로 끝나는 단일 JSON 객체다. 앱 schema_version1의 공통9필드와 권한 이벤트2필드만 허용한다. 알려지지 않은 키(조직·호스트·event.ingested 주장 포함), 객체/배열 값, 민감 키, 잘못된 UUID/가명/IP/시각·사유 조합은 **전송 큐 진입 전 취소**한다. 실제 `message`는 처리 중 메모리에서만 읽고 삭제하며 event.original도 출력하지 않는다. 비밀값/원문을 오류에 넣지 않는다. 앱의 HMAC 비밀키는 필요 없다.

스크립트에 성공 표시가 없거나 문서 ID가 없으면 후속 drop_event가 전송을 막는다. 예외/시간초과도 검증 성공으로 처리하지 않는다. include_fields는 관리 scope와 앱의 명시적11개 leaf만 통과시킨다. 기본 agent/host 이름·파일 경로·offset·진단 tags·임의 ECS 필드를 저장하지 않는다. 실패 이벤트 자체를 원문으로 보관하는 DLQ는 추가하지 않았다. 드롭은 Filebeat 필터/입력 metrics와 격리 진단을 통해 확인하며 정확한 원문별 실패 원인 이력은 제공하지 않는다.

## 파일 및 설정

| 파일 | 용도 |
| --- | --- |
| `filebeat/security-mall/filebeat.example.yml` | 독립 filestream·실패 시 차단·fingerprint·TLS/create-only 예시 |
| `filebeat/security-mall/security-mall-audit.js` | 전송 전 엄격 검증과 고정 수집 scope 부여 |
| `deploy/security-mall/ingest-pipeline.yml` | 중앙 검증·앱 시각에서 루트 시각 생성·중앙 수신 시각 부여 |
| `deploy/security-mall/index-template.json` | 격리 인덱스만의 strict mapping/final pipeline |
| `deploy/security-mall/writer-role.example.json` | 새 테스트 writer의 최소 권한 제안(발급하지 않음) |

Filebeat 예시는 `compression: auto`가 지원되는 9.5.x 빌드를 기준으로 한다. `path.config`는 위 yml/JS가 함께 있는 디렉터리로 지정한다. 다음 값을 독립 테스트 환경에만 설정한다. 실제 사용 중인 에이전트 설정에 병합하거나 기존 registry를 가리키지 않는다.

- `MALL_TEST_DATA_PATH`: 새 빈 registry/상태 디렉터리의 절대 경로. 재시작 시 같은 값을 유지한다.
- `MALL_TEST_LOG_PATH`: 별도 진단 디렉터리.
- `MALL_TEST_AUDIT_PATH`: 합성 JSONL의 절대 경로. 해당 파일과 같은 경로의 `.*` 회전 사본만 읽는다.
- `MALL_TEST_ES_URL`, `MALL_TEST_ES_CA`: 명시적으로 격리된 로컬 HTTPS ES와 CA. 운영 주소/기존 서버를 사용하지 않는다.
- `MALL_TEST_RAW_INDEX`: 새 고유 `soc-host-raw-mall-isolated-<runid>` 이름. 일별 시각·파일명으로 라우팅하지 않는다.
- `MALL_TEST_ES_API_KEY`: 별도 테스트 키만 keystore에서 제공한다. 예시에 실제 키/값을 저장하지 않는다.

조직 `mall-isolated`, 호스트 `mall-host-isolated`, 출처 `security_mall_audit`는 **설정**에서 부여한다. pipeline params와 Filebeat params가 정확히 같아야 한다. 조직/호스트는 `[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`의 비민감 식별자다. 서비스/키 버전은 3-A의64자 제한을 따른다. 새로운 환경에서는 관리자가 전용 scope·설정 사본을 검토해야 하며 앱 JSON을 루트로 병합해서는 안 된다.

## ES 준비 계약 (이번 단계에서는 적용하지 않음)

1. 다른 서비스와 분리된 ES인지 확인한다. 기존 인덱스·pipeline·template 이름과 충돌하면 덮어쓰지 않고 전용 이름과 참조를 함께 변경한다.
2. `ingest-pipeline.yml`을 PyYAML의 safe_load → json.dumps로 변환한다. 예: `python -c "import json,yaml; from pathlib import Path; print(json.dumps(yaml.safe_load(Path('deploy/security-mall/ingest-pipeline.yml').read_text(encoding='utf-8'))))"`. JSON 본문을 `PUT _ingest/pipeline/security-mall-isolated-final-v1`에 설치하는 것은 별도 관리 작업이다.
3. JSON template 본문을 `PUT _index_template/security-mall-isolated-v1`로 준비하고, **새** 원본 인덱스를 사전 생성한다. effective mapping이 strict이고 `index.final_pipeline=security-mall-isolated-final-v1`인지 확인해야 한다. 기존 인덱스에 설정을 덮어쓰지 않는다.
4. writer 제안은 cluster `monitor`, 사전 생성·final pipeline을 확인한 **단일 새 인덱스**의 `create_doc`뿐이다. role 예시의 `soc-host-raw-mall-isolated-example`을 확인한 실제 이름으로 치환하며 wildcard를 부여하지 않는다. template/pipeline/인덱스는 별도 설정 담당자가 사전 생성한다. 자동 setup/ILM·모니터링 전송은 끈다. Filebeat 특정 빌드가 `auto_configure` 등을 추가 요구하면 기존 키 권한을 확대하지 말고 사전 생성/권한 흐름을 재검토한다. 이 축소 권한의 실제 빌드 인수도 미검증이다. 운영 키를 발급/수정하지 않았다.
5. 기존 normalizer 실행이나 기본 `soc-normalized-v1`에 실제 테스트 데이터를 게시하지 않는다. 실제 선택 통합 시 순수 normalize 결과를 고유 `soc-normalized-mall-isolated-<runid>`에 create-only로 검증해야 한다. 3-A의 기존 연결은 변경 없이 재사용한다.

템플릿은 `soc-host-raw-mall-isolated-*`에만 적용된다. 최종 pipeline이 없으면 인덱싱이 실패해야 한다. `pipeline=_none`으로 요청 pipeline을 생략해도 index.final_pipeline은 실행된다. 수집 writer에는 pipeline/template/인덱스 설정 변경 권한이 없다. 외부가 임의로 제출한 event.ingested는 버리고 `{{{_ingest.timestamp}}}`로 중앙에서 덮어쓴다. 허용하지 않은 구조/필드는 strict mapping/중앙 검증에서도 거부한다.

## 원본/정규화 매핑과 시간

| 값 | 원본 저장 | 정규화 |
| --- | --- | --- |
| 관리 조직/호스트/출처 | `organization.id`, `host.id`, `labels.log_source` | 조직/호스트 및 파서 선택 |
| 허용 앱9/11필드 + 선택 request_id | `security_mall.audit` 객체 | 3-A 필드 매핑, 선택 ID는 `http.request.id` |
| 앱 `@timestamp` | 감사 시각과 같은 문자열로 생성한 루트 `@timestamp` | 사건 발생 시각 |
| 중앙 수신 시각 | final pipeline의 `event.ingested` | 수신 시각(재전송409에서는 최초 저장값 유지) |
| 앱 event_id | `security_mall.audit.event_id` | `event.id` |
| 안정 ID | ES `_id` 메타데이터 | `cloud_soc.provenance.raw={index,id}` |

Filebeat의 최초 루트 timestamp는 파일을 읽은 시각이다. 중앙은 검증된 앱 시각에서 authoritative 루트를 새로 생성해 두 앱 시각이 같음을 보장하며, Filebeat 시각을 앱 시각으로 추측하지 않는다. date mapping은 검색 시 밀리초지만 기본 stored `_source`는 앱의 나노초 문자열을 보존한다. synthetic source 모드로 바꾸지 않는다. 기존 정규화는 마이크로초를 사용하고 상세의 timestamp에 원래 문자열을 남긴다. account_id=null과 account_key_id를 그대로 보존하며 실명·키를 복원하지 않는다. peer IP는 최종 사용자 IP의 보증이 아니다.

## 원본 ID·재시작·회전

Filebeat fingerprint(SHA256 hex)는 `organization.id`, `host.id`, `security_mall.audit.service_name`, `security_mall.audit.event_id`의 **필드 이름을 정렬**하고 공식 형식 `|필드|값|필드|값|`을 해시한다. ID 값에 구분자 `|`를 허용하지 않아 연결 모호성을 피한다. 경로/offset/inode/수신 시각·HMAC 키 버전은 이벤트 정체성이 아니다. 같은 scope+event_id는 재전송/재시작/회전 재독에서도 같은 고정 인덱스·같은 ID가 되고 create-only409는 기존 문서를 유지한다. 다른 UUID 또는 다른 조직/호스트/서비스는 별도 ID다. 같은 UUID로 내용이 바뀌어도 최초 문서를 덮어쓰지 않는다. writer는 기존 내용을 읽어 충돌 내용을 대조하는 기능이 없다.

등록 상태의 input.id와 fingerprint 설정은 유지한다. 파일 지문은 압축 해제된 앞64바이트를 사용하고 64바이트 미만은 읽기 시작이 지연된다. 앞64바이트가 같은 파일들의 지문 충돌 가능성이 있으므로 실환경 로그/회전 패턴 인수가 필요하다. active+회전 파일을 모두 포함하고 compression:auto로 gzip을 읽도록 구성했다. rename 후 열린 파일을 바로 닫지 않는다. gzip은 immutable로 취급하며 gzip footer/검사 실패, 보존 만료 전에 못 읽은 파일, 오프라인 중 삭제, 손실된 registry, fingerprint 충돌·copytruncate에서는 누락 가능성이 있다. copytruncate를 사용하지 않는다. registry의 지속성/디스크 여유·미수집 보존 기간과 Filebeat input/output/gzip/filtered metrics를 감시해야 한다.

LF 없는 마지막 줄은 게시하지 않는다. LF가 붙었지만 JSON이 미완성이면 검증에서 취소한다. native 상한64KB는 스크립트 상한8KB보다 커서 잘린 대형 줄의 유효한 짧은 접두사만 수용하지 않는다. Filebeat는 재전송할 수 있으며 **정확히 한 번 전달은 보장하지 않는다**. 고정 ID/create-only는 같은 인덱스 내 중복 저장을 제한한다. rollover나 index명 변경으로 다른 인덱스에 쓰면 원본 참조/ID 공간이 달라져 중복될 수 있으므로 이번 예시는 rollover하지 않는다. 손실 복구/원본 삭제/재색인은 자동화하지 않았다.

## 검증 수준

A: 합성 JSONL·임시 디렉터리·Node VM의 실제 collector JS 실행 + Filebeat native fingerprint/include_fields/framing와 ES final pipeline의 **명시적인 모의 모델**을 사용한다. 원본/정규화 저장은 모의 ES create-only다. 로그인 성공·실패/권한 거부, 중복/다른 UUID·scope, gzip 회전/재시작 재독 모델, 미완성 줄, 오류·미지원 필드/민감값 배제, 시각·정확 참조와 기존 웹/Linux 회귀를 검사한다.

B: Filebeat Goja/filestream/registry와 ES Painless/template/권한을 실제 실행하는 별도 통합 인수다. 이번에는 준비된 명확한 격리 ES/Filebeat 환경이 확인되지 않아 실행하지 않는다. 설치·기동·Docker·기존 ES/SQLite/에이전트·원격 접속을 시도하지 않는다. Node 검사나 pipeline 구조 시험을 실제 Filebeat/ES 성공으로 간주하지 않는다.

3-C에는 지원 Filebeat 빌드, 실제 Painless 컴파일/`_simulate`, strict template·final pipeline·최소 writer 권한·TLS·null 보존·안정 ID/create409의 native 검증, 고유 합성1~3건의 원본/독립 정규화 인덱스 exact-reference 대조, 실제 경로·읽기 권한·gzip/registry/장애와 보존 정책 인수가 필요하다. 운영 적용은 그 뒤 별도 승인 범위다. 이번에는 탐지·위험도·UI로 넘어가지 않는다.

근거: [Filebeat script processor](https://www.elastic.co/docs/reference/beats/filebeat/processor-script), [fingerprint 형식](https://www.elastic.co/docs/reference/beats/filebeat/fingerprint), [filestream/gzip](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-filestream), [final pipeline](https://www.elastic.co/docs/reference/elasticsearch/index-settings/index-modules), [LF 필요 조건](https://www.elastic.co/docs/reference/beats/filebeat/newline-character-required-eof), [일반 writer 권한과 auto_configure](https://www.elastic.co/docs/reference/beats/filebeat/privileges-to-publish-events). 축소된 격리 writer 권한과 실제 native 동작은 B에서 확인해야 한다.
