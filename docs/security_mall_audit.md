# security-mall 감사 정규화 계약 (3-A)

쇼핑몰 `docs/security-audit.md`의 schema_version=1을 읽기 전용으로 기준 삼았다. 순수 파서는 `cloud_soc.parsers.security_mall.parse`이고 파서/정규화 버전은 `security-mall-audit-v1`, 상세 어댑터는 `security_mall_audit_v1`이다. 실제 로그·HMAC 비밀키·DB를 읽지 않으며 수집기 설정·배포·ES mapping 변경은 포함하지 않는다.

## 3-B 입력 원본 문서의 최소 계약

```json
{
  "_index": "soc-host-raw-mall-synthetic",
  "_id": "synthetic-raw-1",
  "_source": {
    "@timestamp": "2026-10-16T05:00:00Z",
    "organization": {"id": "collector-org"},
    "host": {"id": "collector-host"},
    "labels": {"log_source": "security_mall_audit"},
    "event": {"ingested": "2026-10-16T05:01:00Z"},
    "security_mall": {"audit": {
      "schema_version": 1,
      "@timestamp": "2026-10-16T05:00:00Z",
      "event_id": "784a9b30-4a77-43a8-b698-cb67f95269f1",
      "service_name": "security-mall",
      "event_action": "order_view",
      "event_outcome": "failure",
      "source_ip": "192.0.2.25",
      "account_id": null,
      "account_key_id": "v1",
      "resource_type": "order",
      "authorization_reason": "unauthenticated"
    }}
  }
}
```

- `_index`/`_id`는 기존 원본 참조 검사를 통과하는 실제 문서 참조여야 한다. 새 어댑터는 `soc-host-raw-*` 원본만 허용한다. 위 이름/주소/ID는 합성 예시다.
- 조직/호스트/출처 표지는 인증된 수집 경로의 관리 설정에서 제공한다. `host.id`는 필수이며 1~128자의 기존 개인정보 필터를 통과하는 문자열이다. 앱 JSON의 조직·호스트·사용자/역할/다른 ECS 필드는 복사하거나 신뢰하지 않는다. 수집기가 앱 JSON을 문서 루트로 병합해서는 안 된다. 원본 문서 자체를 쓸 수 있는 주체의 신뢰 검증은 3-B 책임이다.
- `event.ingested`는 중앙 수신 시각(명시적 시간대 필수)이며 앱이 주장하는 수신 시각으로 덮어쓰지 않는다. 루트 `@timestamp`는 검증된 앱 시각과 같은 순간을 가리켜야 한다. 앱 시각은 UTC `YYYY-MM-DDTHH:MM:SS[.1~9자리]Z`만 허용한다. 기존 정규화 시각은 마이크로초 정밀도이며 원래 나노초 시각은 허용된 상세 필드 `timestamp`에 보존한다.
- JSONL 한 줄을 전용 `parse`로 먼저 검증한다(UTF-8 최대8192바이트). 중복 JSON 키, NaN/Infinity, 잘못된 JSON은 거부한다. 검증 후 앱 필드만 `security_mall.audit` **객체**로 저장한다. 정규화 연결은 JSON 문자열 값이나 `message`에서 이벤트를 복구하지 않는다. 구조화 저장 전 중복 키 검증을 생략하면 이후 파서는 덮어쓴 키를 감지할 수 없다.
- 원문 `message`, `event.original`, 비밀값, 쿠키/인증 헤더, 결제/개인정보를 원본 계약에 추가하지 않는다. 알려지지 않은 앱 필드는 파서 결과에서 버린다. 수집 단계의 원문 보관/권한 정책은 별도 인수가 필요하며 이번 단계에서 구성하지 않았다.

## 정규화 매핑

| 앱 필드 | 결과 |
| --- | --- |
| `@timestamp` | 정규화 `@timestamp`, `cloud_soc.detail.fields.timestamp` |
| `event_id` | `event.id` 및 상세 `event_id` (UUID 원문 보존) |
| `service_name` | `service.name` 및 상세 `service_name` |
| `event_action` | `event.action`, 상세 `action` |
| `event_outcome` | `event.outcome`, 상세 `outcome` |
| `source_ip` | `source.ip` 및 상세 `source_ip` (IP 표기만 정규화) |
| `schema_version`, `account_id`, `account_key_id` | `cloud_soc.security_mall`의 같은 이름 및 상세 필드 |
| `resource_type`, `authorization_reason` | 권한 이벤트의 `cloud_soc.security_mall` 및 상세 필드 |

로그인 `login`은 `event.category=["authentication"]`이다. 관리자 행동 `admin_view`, `item_create_form`, `item_create`, `item_edit_form`, `item_update`, `item_delete`, `user_delete`와 주문 `order_view`는 `event.category=["iam"]`이다. 원래 행동 이름을 바꾸거나 새 앱 이벤트를 만들어내지 않는다. 상품/회원 변경 이벤트도 **접근 허용/거부 판단**이며 CRUD의 실제 성공을 뜻하지 않는다.

관리자 resource_type은 화면 `admin`, 상품 `item`, 회원 삭제 `user`이며 허용 사유 `admin`/거부 `admin_required`다. 주문은 `order`이며 허용 `owner`/거부 `not_owner` 또는 `not_found`다. 모든 권한 이벤트는 `failure`+`unauthenticated`+`account_id=null` 조합도 허용한다. 다른 조합은 invalid다. 로그인은 account_id가 반드시 있어야 하고 권한 필드를 갖지 않는다.

event_id는 소문자 정규 UUID(영 UUID 제외), account_id는 소문자 16진수64자리 또는 위 비로그인 조건의 null, 서비스 이름과 키 버전은 `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`의 비민감 식별자다. 키 버전은 HMAC 키가 아니다. 미지원 스키마/행동은 unsupported, 타입/시각/식별자/사유 조합 오류는 invalid로 처리하며 고정 오류 코드만 남긴다. malformed 이벤트를 다른 파서로 재해석하지 않는다.

가명은 `user.name` 또는 범위 없는 `user.id`에 넣지 않는다. 계정 연관은 반드시 `(organization.id, service.name, account_key_id, account_id)`를 함께 사용하며 null은 계정 연관에서 제외한다. 서로 다른 키 버전을 같은 계정으로 추측하지 않는다. 조직 내 여러 환경이 같은 서비스 이름/키 버전으로 다른 키를 쓰는 경우 3-B에서 수집 범위 또는 서비스 이름을 분리해야 한다. IP는 관측된 소켓 peer만 의미하며 전달 헤더·최종 사용자·공격 여부를 추정하지 않는다.

## 참조·중복·조회 필드

`cloud_soc.provenance.raw={index,id}`와 처리 레코드의 raw 참조를 그대로 보존한다. 기존 방식대로 `SHA256(JSON([normalizer_version, raw_reference], sort_keys=True))`를 정규화/처리 문서 ID로 사용하고 create-only 재처리 충돌409를 중복으로 취급한다. 같은 원본 재처리는 같은 ID지만, 같은 event_id가 다른 원본 참조로 다시 들어오면 각 참조를 보존하는 별도 정규화 문서다. 원본 간 event_id만으로 합쳐 근거를 잃지 않는다. 3-B에서 재전송을 줄이려면 신뢰 수집 범위(조직/호스트), 서비스 및 event_id를 반영한 안정적 원본 `_id` 정책을 별도 확정해야 한다.

`DETAIL_FIELDS`에 `security_mall.audit.<허용 필드>` 11개를 명시한다. 기존 worker의 `READ_FIELDS`와 상세 조회의 선택 계약은 이 목록을 상속하므로 부모 객체/와일드카드/원문을 추가 요청하지 않고 필수 필드를 유지한다. 대시보드 UI와 원본 목록의 새 출처 표시/필터 확장은 이번 범위에 포함하지 않는다.

## 검증 범위와 남은 인수

관련 시험만 `pytest tests/test_security_mall.py tests/test_security_detail.py tests/test_processing.py::ProcessingTests`로 실행한다. 합성 이벤트와 모의 ES 클라이언트만 사용한다. 실제 Filebeat 구성·서버 로그/키/DB·운영 상태·실제 ES·SSH·전체 Python/UI/Docker 검사는 실행하지 않는다. 3-B에는 조직/호스트 바인딩, 로그 절대 경로와 읽기 권한, 회전/재전송/중복 키 거부, 위 구조화 envelope와 안전한 원본 ID, ES 필드 mapping/조회 권한 및 실수신 인수가 남는다. HMAC 비밀키는 수집/정규화기에 필요하지 않다.
