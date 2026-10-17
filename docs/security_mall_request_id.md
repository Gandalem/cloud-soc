# Security Mall 앱 request_id — 6-D-2 로컬 구현

2026-10-16의 6-D-2는 구현 및 격리 테스트까지 완료한 기록이다. 당시 VM 배포·실제 Filebeat/Painless·3종 실로그 연결은 미검증이었다. 후속 2026-10-17 **6-D-3에서 실제 배포·3요청/원본9/정규화9 연결을 완료**했으며 별도 [실제 인수 기록](security_mall_request_id_integration_validation.md)에 결과와 한계를 기록했다. 아래 로컬 설계/테스트 이력과 당시 미실행 절차는 유지한다.

## 전달과 신뢰 경계

기존 `deploy/security-mall/waf-lab/conf/proxy.conf`를 그대로 사용한다. Apache unique_id 모듈의 `UNIQUE_ID`를 웹 접근 로그·ModSecurity Native A와 백엔드 `X-Request-ID`에 사용한다. 클라이언트의 기존 `X-Request-ID`, `X-Correlation-ID`, Forwarded/XFF/Real-IP 주장은 프록시 전달 전에 제거한다. 예시 `atI3YyuokZgOiD33Gh3LxwAAAAI`처럼 실제 27자 `[A-Za-z0-9_-]{27}` 형식을 허용한다. UUID로 변환하거나 새 ID를 생성하지 않는다.

Spring Boot는 `server.forward-headers-strategy=NONE`을 유지하며 servlet의 실제 remoteAddr를 사용한다. 이번 실습의 허용 peer는 정확히 `127.0.0.1`, `::1`, `0:0:0:0:0:0:0:1`이다. DNS 조회나 XFF 신뢰는 없다. 이 제한은 수신 조건일 뿐 **Apache 인증이 아니다**. 같은 VM의 직접 18080 호출과 Apache 프록시 연결은 식별할 수 없다. 따라서 문법상 올바른 단일 헤더도 항상 **위조 가능한 참고용 상관 ID**다. request_id로 인증·권한 부여·계정 식별·공격 확정 판단을 하지 않는다. 다른 source_ip의 요청 ID, 누락/빈값/공백/개행/너무 긴 값/쉼표 결합/중복 헤더는 앱에서 필드를 생략한다. 직접 localhost 접근의 유효한 위조 ID는 참고값으로 남을 수 있으나 기존 권한 거부는 유지된다.

프록시가 인증된 출처라는 보장이 필요하면 후속 단계에서 직접 백엔드 접근 제한 또는 인증된 프록시 채널을 별도로 설계·검증해야 한다. 이번에는 공유 비밀이나 새 인증 체계를 만들지 않았다.

## 저장 및 하위 호환 계약

| 지점 | 선택 필드 | 처리 |
| --- | --- | --- |
| 앱 JSONL | `request_id` | 로그인 성공/실패 및 기존 모든 관리자·주문 권한 감사 공통 호출에서 기록 |
| Filebeat 앱 JS/allowlist | `security_mall.audit.request_id` | 단일 문자열 27자 검증, 누락/null 허용, 잘못된 값 또는 미허용 필드는 이벤트 취소 |
| ES 원본 예시 매핑 | `security_mall.audit.request_id` | keyword, final pipeline에서도 같은 검증 |
| Cloud SOC 정규화 | `http.request.id` | 웹/WAF와 같은 상관 필드, 누락/null이면 생성하지 않음 |
| 정규화 상세 한계 | `cloud_soc.detail.limitations` | 값이 있으면 `request_id_is_unverified_correlation_hint` 명시 |

schema_version=1 및 파서 `security-mall-audit-v1`을 유지하는 선택 필드 확장이다. 기존 로그인 9필드/권한 11필드와 request_id 없는 과거 이벤트는 그대로 처리한다. 선택값이 있으면 각각 10/12필드다. `event_id` UUID 생성, HMAC 입력·키/버전·가명, source_ip, 권한 로직, DB는 유지한다. 원본 문서 ID는 기존 조직·호스트·서비스·event_id fingerprint를 사용하며 request_id를 추가하지 않는다. 정규화 ID와 원본 index/id provenance 산정도 바꾸지 않는다. 원문 message/event.original/헤더/본문/쿼리를 새로 저장하지 않는다. 수집기와 중앙 검증은 잘못된 ID 이벤트를 거부하고, 앱은 잘못된 헤더만 생략하여 원래 감사 이벤트를 보존한다.

일치 후보 조회에는 항상 서버가 허용한 **organization.id + host.id + service.name + http.request.id**를 함께 사용한다. request_id 단독 또는 이벤트 시각 근접성으로 연결하지 않는다. 다른 조직/호스트/서비스의 같은 ID는 별도 범위다. 같은 범위에서 일치해도 앱의 ID는 참고값이며 직접 호출 위조 가능성이 남는다. 이번에는 자동 join 서비스나 새 경보를 구현하지 않았다.

## 로컬 검증

- 새 `RequestIdAuditTests` 16건 통과: 성공·실패, 주문 not_owner 403, 관리자 허용·삭제 거부/DB 불변, 과거 API/HMAC, 중복/잘못된/외부 peer 헤더, IPv4/IPv6 직접 접근과 위조 한계, 비로그인 401, 개인정보 미기록 및 고유 event_id.
- 새 `test_security_mall_request_id.py` 22건 통과: 실제 수집 JS를 Node VM에서 실행, 옵션/과거/null/비정상 필드, worker 필드 선택, ES 예시 매핑, 웹/WAF/앱 공통 필드와 조직·호스트 범위, event_id/provenance/재처리 ID, WEB-ACCESS-01/WEB-AUTH-01 및 중복 탐지 호환.
- Java는 기존 로컬 Oracle JDK21.0.7만 설치되어 있다. Git 제외 임시 init-script로 JDK21 + `JavaCompile.options.release=17`을 적용해 Java17 호환 바이트코드를 검사했다. Gradle 프로젝트의 기존 toolchain17 설정은 그대로다. 최초 init 적용 순서로 인한 JDK17 탐색 중단을 임시 스크립트에서 바로잡았으며 Java17 런타임 실행은 미검증이다. 기존 단위 테스트 전체는 실행하지 않았다.
- 메모리 H2 테스트 프로필만 사용했다. 기존 파일형 DB/trace는 전후 해시로 불변을 확인했다. Python 테스트는 합성 자료·모의 ES만 사용하며 Filebeat/Painless 네이티브 실행이나 실제 ES 인수로 간주하지 않는다.

증거와 상세 출력은 Git 제외 `state/security-mall-request-id-6d2-20261016/`에 보관한다. 두 저장소 브랜치 및 기존 변경의 baseline을 유지한다.

## 이번 변경 파일 (16개)

경로 기준은 `D:/cloud-soc`이며 mall 항목은 별도 저장소다.

| 구분 | 파일 |
| --- | --- |
| 앱 | `state/security-mall/src/main/java/com/security/securitymall/audit/LoginAuditLogger.java` |
| 앱 | `state/security-mall/src/main/java/com/security/securitymall/controller/HomeController.java` |
| 앱 새 테스트 | `state/security-mall/src/test/java/com/security/securitymall/RequestIdAuditTests.java` |
| 앱 문서 | `state/security-mall/docs/security-audit.md` |
| 파서 | `src/cloud_soc/parsers/security_mall.py` |
| 상세 한계 | `src/cloud_soc/portal/security_detail.py` |
| 정규화 | `src/cloud_soc/processing/contract.py` |
| 수집 | `filebeat/security-mall/security-mall-audit.js` |
| 수집 | `filebeat/security-mall/filebeat.example.yml` |
| ES 예시 | `deploy/security-mall/index-template.json` |
| ES 예시 | `deploy/security-mall/ingest-pipeline.yml` |
| 기존 테스트 모델 확장 | `tests/test_security_mall_collection.py` |
| 새 테스트 | `tests/test_security_mall_request_id.py` |
| 문서 | `docs/security_mall_collection.md` |
| 새 설계/인수 문서 | `docs/security_mall_request_id.md` |
| 작업 기록 | `docs/work_tracker.md` |

## 후속 VM 반영 (이번에는 실행하지 않음)

1. 기존 설정/HMAC/DB/로그를 보존하고 최신 mall JAR를 빌드·전송한 후 사용자가 승인한 절차로 앱만 재기동한다. 기존 Apache 전달 설정을 변경할 필요는 없다.
2. 실습의 실제 전용 설정에도 앱 JS와 include_fields를 반영한다. 실행 중인 기존 Filebeat를 자동 변경하지 않는다.
3. 새로운 시험 인덱스에서 선택 필드 매핑과 수정한 final pipeline을 실제 Painless `_simulate`로 검증한다. 과거 문서·운영 인덱스를 수정하거나 재색인하지 않는다. 템플릿은 기존 생성 인덱스의 매핑을 자동 확장하지 않는다.
4. 최신 정규화 코드를 독립 시험 프로세스에 반영한다. TLS·최소 create_doc 권한 및 기존 ID/provenance 계약을 유지한다.
5. 승인 후 무해한 프록시 요청으로 웹/WAF/앱 3종 ID·조직·호스트·서비스·원본 참조를 실제 대조한다. 직접 18080 위조 사례와 ID 없는 과거 이벤트도 구별한다. 검증 전에는 실제 3종 연결 완료로 표시하지 않는다.
