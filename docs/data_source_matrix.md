# Cloud SOC Telemetry Strategy and Data Source Matrix

2026-09-10 / 목표 제품에서 역산한 제안. 현재 확보한 로그나 OCI 접근 가능성은 **구현 가능성** 평가에만 반영한다. 어떤 소스도 이번에 활성화/배포하지 않았다.

## 1. 선택 원칙

먼저 보호할 업무/자산과 분석 질문을 정하고 도메인을 고른다. `데이터가 많다`, `지금 가지고 있다`, `그래프를 그리기 쉽다`는 단독 선정 이유가 아니다. 우선순위는 조사 가치, 독립적인 관측 시점, 안정 식별자, 개인정보/비용, 시험 가능성을 함께 평가한다.

가치/복잡도/비용의 H/M/L은 상대적 설계 판단이며 공급자 가격표/계측 결과가 아니다. Source별 비용은 로그 발생량, 전달/저장/보존, 라이선스, 파서 유지 비용에 따라 재산정한다.

## 2. 전체 Data Source Matrix

| ID / Security Domain | Log Source | 주요 Event | 필요한 주요 필드 | Detection 활용 | Investigation 활용 | MVP 우선순위 |
| --- | --- | --- | --- | --- | --- | --- |
| DS-01 Identity/Authentication | Linux auth/sshd/PAM | 성공/실패 인증, 세션, sudo 인증 | event ID/time, Host stable ID, user/account, source IP, auth method/outcome/session | 반복 실패, 실패 뒤 성공 후보 | 워크로드 접근과 전후 계정 활동 | MUST 후보 |
| DS-02 Identity/Authentication | Windows Security / IdP / VPN | 로그온, 실패, 토큰/MFA, 원격접속 | account SID/issuer, device ID, event code, src/dst, session | account abuse, spray, MFA 이상 | 실제 계정 범위/인증 방식 확인 | COULD, 환경 존재 시 |
| DS-03 Cloud Control Plane | OCI Audit / AWS CloudTrail / Azure Activity | API 호출, IAM/정책/자원 변경 | provider, tenant, principal, resource, operation, response, request/event ID, time, region | 민감 변경, 권한 추가, 감사 설정 변경 | 누가 어떤 자원을 어떻게 변경했는가 | MUST: 한 공급자 선택 |
| DS-04 Cloud Identity | OCI Identity domain audit / Entra sign-in 등 | 로그인 성공/실패, MFA, 신원 변경 | issuer/account ID, auth outcome/method, client, IP, correlation ID | cloud login/credential abuse | 제어면 호출 전 로그인 맥락 | SHOULD/별도 접근 확인 |
| DS-05 Network | VCN/VPC Flow | 허용/거부 흐름, bytes/packets, 수집 품질 | tenant/network/VNIC ID, src/dst IP/port, protocol, start/end, action, capture status | 스캔/egress burst의 후보 | 자원 간 통신, 거부/허용 범위 | COULD: 4번째 후보 |
| DS-06 Network | Firewall / IDS/IPS | 정책 허용/차단, 시그니처 경보 | observer ID, flow ID, signature/rule, endpoints, action | 네트워크 공격 징후/다중 신호 | 무엇이 차단됐고 어디에 도달했는가 | COULD |
| DS-07 Network | DNS / Proxy | 질의/응답, 도메인 접근 | client/resolver, query/rcode/answer, URL category, time | 새 도메인/주기성/IOC | IP만으로 설명 안 되는 외부 목적지 | COULD |
| DS-08 Application/Web | Nginx/Apache access + error | HTTP request/status/error | service/resource ID, request ID, trusted client IP, method/path/status, bytes/duration | 이상 요청/오류율, exploit 후보 | 사용자 요청과 서버 오류/후속 프로세스 | COULD; 웹 서비스 선택 시 우선 상승 |
| DS-09 Application/Web | WAF / application security events | WAF rule match, session/authz, 보안 예외 | request/session ID, rule/action, app/user, resource, outcome | 입력 공격/인가 위반 | 차단 요청과 실제 처리 구분 | COULD |
| DS-10 Host/Endpoint | Linux Audit (auditd) / process events | exec, euid 변화, 파일/설정 변경 | Host/boot ID, audit serial, auid/uid/euid, executable, args, PID/PPID, path, outcome | 특권 실행, 보안 설정 변경 | 로그인 뒤 무엇을 실행했는가 | SHOULD: 3번째 후보 |
| DS-11 Host/Endpoint | Sysmon/EDR telemetry | process tree, file/network activity | process GUID, parent, host/user, hash, destination | 행위/다단계 탐지 | root cause, 영향/지속성 | COULD; 수집 권한/라이선스 필요 |
| DS-12 Security/Threat Context | IOC / Threat Intelligence | indicator, validity, confidence | type/value, provider, retrieved/valid until, TLP/license | indicator match/우선 검토 후보 | 외부 평판/시점별 문맥 | COULD, 자동 악성 판정 금지 |
| DS-13 Asset Context | CMDB / cloud inventory / 수동 자산 등록 | 자산/소유자/중요도/노출 상태 | immutable resource ID, owner, business criticality, valid interval | 중요 자산 정책/우선순위 | IP/이름을 안정 자산에 대응 | MUST: 최소 수동 Registry |
| DS-14 Vulnerability Context | 승인된 스캔/패치 inventory | 취약점/설치 버전/보완 상태 | asset ID, CVE, observed/updated, scanner, confidence | exploit 관련성 보강 | 영향 가능성 검토 | COULD; 스캐너 개발 제외 |
| DS-15 Pipeline Operations | Collector heartbeat / poll / stage run | 성공/실패/0건/지연/드롭 | source/stage/run ID, times, counts, cursor, error | Absence/Health 정책 | 경보 부재가 데이터 장애인지 | MUST: 지원 메타데이터 |

DS-12~DS-15는 공격 로그와 성격이 다르다. 특히 Asset Registry와 Health 측정은 필수 지원 데이터지만 아래 `보안 Telemetry 2~4개` 개수에 포함해 소스 수를 부풀리지 않는다.

## 3. 가치와 비용 평가

| Source | Security Value | Detection Value | Investigation Value | Complexity | Cost | 평가 이유 |
| --- | --- | --- | --- | --- | --- | --- |
| DS-03 Cloud Audit | H | H | H | M | L~M | 클라우드 제어권/자원 변경 주체를 직접 관측. API/event별 필드 편차 |
| DS-01 Linux auth | H (Linux 노출 시) | M | H | L~M | L | 로그인 근거는 유용하나 명령/영향까지 보이지 않음 |
| DS-10 auditd | H | H | H | M~H | M | 침입 뒤 행위 연결. 다중 레코드 조립/수집 설정/민감 인자 처리 필요 |
| DS-05 Flow | M~H | M | H | M | M~H | 네트워크 범위 확인, 높은 볼륨/집계/유실 가능성, payload 없음 |
| DS-04 Cloud Identity | H | H | H | M | L~M | 로그인/토큰 맥락을 제어면과 연결, IdP별 접근/필드 검증 |
| DS-02 Windows/VPN | 환경 의존 H | H | H | M | M | 업무상 사용하는 환경일 때 가치, 이번에 새 환경까지 만들지는 않음 |
| DS-06 Firewall/IDS | H | H | H | M~H | M~H | 방화벽/센서 배치와 가시성 확보가 선행 |
| DS-07 DNS/Proxy | M~H | M | H | M | M | 외부 통신 설명, 암호화/경유 경로/개인정보 제약 |
| DS-08/09 Web/WAF | 웹 서비스 시 H | M~H | H | M | M | 실제 보호 대상이 웹일 때 우선. 빈 서비스로 데모 그래프만 만들지 않음 |
| DS-11 EDR | H | H | H | H | M~H | 라이선스/에이전트 운영/다양한 이벤트 모델 부담 |
| DS-12 IOC | M | M | M | M | 변동 | 오래된 평판/재할당 IP는 오판 위험, feed 신뢰성 관리 |
| DS-13 Inventory | H | M | H | L~M | L~M | 우선순위/Entity key에 필요한 기초 |
| DS-14 Vulnerability | M~H | M | H | M~H | M | 맥락 보강이지 공격 발생 증명 아님 |
| DS-15 Operations | H | 간접 H | H | M | L~M | 데이터 손실/탐지 미실행을 보안 무사고와 구분 |

## 4. Source Onboarding 계약

각 Source는 수집하기 전에 다음을 문서화한다.

| 영역 | 필수 계약 |
| --- | --- |
| 업무 | 보호 자산, 조사 질문, 승인자/소스 담당, 필요한 event class |
| 식별 | source_id, tenant/scope, native ID 또는 file/record identity, 중복 정책 |
| 시각 | event time/TZ, provider availability, local receipt, clock quality |
| 수집 | transport/auth, 최소 권한, schedule, paging, retry, limits, 완료 범위 |
| 형식 | parser/schema version, required/optional fields, unknown event 보존 |
| 품질 | parsed/normalized/rejected/filtered counts, field missing ratio, 이유 |
| 정상성 | continuous/sparse/batch, heartbeat 또는 성공 poll, 지연/실패 판정 |
| 보존/보안 | 개인정보, secrets redaction, 원본 접근, 보존/삭제/사건 보전 정책 |
| 검증 | 정상/비정상/미지원 형식/중복/시간 경계/재시작/지연 도착 시험 |

## 5. 권장 두 소스의 최소 필드

공통 최소: stable `event.id`, `@timestamp`, 중앙 수집 시각, `event.dataset/category/action/outcome`, `cloud_soc.source_id/scope_id/raw_ref`, parser/schema version, 품질 플래그. 의미/타입이 맞을 때 ECS를 사용하고 그렇지 않은 확장 값은 별도 namespace에 둔다.

| Source | 최소 Normalized Field | 보존할 원본/소스 값 | 확보되지 않으면 |
| --- | --- | --- | --- |
| Cloud Audit | `cloud.provider/account.id/region`, `user.id`, `event.action/outcome`, `cloud_soc.resource.id`, `source.ip` (제공 시), `event.id` | principal/tenant/resource ID, operation/eventName, request ID/method, response status, state change | IAM/Resource 관련 capability를 blocked로 표시. 이름/IP로 대체 병합 금지 |
| Linux auth | `host.id`, `user.id` 또는 unresolved name, `source.ip`, `event.action/outcome`, auth method, event time | hostname, sshd/PAM message, file identity/offset, session correlation 값 | Host ID는 inventory/agent에서 보강. 로그가 제공하지 않은 UID/세션을 발명하지 않음 |

Cloud API의 HTTP method와 operation 이름을 혼동하지 않는다. 예를 들어 여러 변경 작업이 모두 POST일 수 있으므로 `event.action`은 provider의 구체 작업 의미를 정규화하고 원래 method는 별도 보존한다. API 응답이 성공이어도 실제 자원 상태 변경 완료가 아닌 비동기 요청일 수 있다.

## 6. OCI 구현 가능성 확인 시 주의

- Audit는 지원되는 공개 API 호출의 제어면 관측이다. Object Storage의 bucket 관련 기록과 object-level 접근 기록의 범위를 구분해야 한다. [Overview of Audit](https://docs.oracle.com/en-us/iaas/Content/Audit/Concepts/auditoverview.htm).
- Audit v2의 principal/resource/request/response/stateChange는 이벤트별 가용성이 다르다. 실제 API 작업명을 샘플로 확인한 뒤 mapping을 정한다. [Audit event contents](https://docs.oracle.com/en-us/iaas/Content/Audit/Reference/logeventreference.htm).
- Audit 가시화는 보통 API 호출 후 15분 이내지만 변동 가능하다는 공급자 설명이 있다. 1분 동안 새 로그가 없다고 DOWN 처리하지 않는다. [Viewing Audit Log Events](https://docs.oracle.com/en-us/iaas/Content/Audit/Tasks/viewinglogevents.htm).
- Cloud 로그인은 Identity domain 감사 이벤트가 실제 환경에서 어떻게 제공되는지 별도로 확인한다. Linux username과 cloud principal을 문자열만으로 연결하지 않는다. [Identity Audit Log Report](https://docs.oracle.com/en-us/iaas/Content/Identity/reports/audit-log.htm).
- VCN Flow의 `NODATA`, `SKIPDATA`, 정상 캡처를 구분한다. Flow는 payload가 아니고 일부 infrastructure traffic이 제외되며 공인 IP 트래픽이 사설 IP로 기록될 수 있다. [VCN Flow details](https://docs.oracle.com/en-us/iaas/Content/Logging/Reference/details_for_vcn_flow_logs.htm).

위 URL 확인일: 2026-09-10. 가격/OCI 권한/실제 로그 제공 여부를 확인하거나 계정을 연결하지 않았다.

## 7. MVP 최종 추천: 2개 기본 + 최대 2개 확장

1. **Cloud Control Plane Audit 하나:** 기본 후보 OCI Audit. 클라우드 보안이라는 목적에 직접 맞고 계정/정책/자원 변경을 조사할 수 있다. OCI 접근 가능성은 동일 도메인의 AWS/Azure보다 구현이 쉬울 수 있는 이유일 뿐, 선정 가치 자체는 제어면 가시성이다.
2. **Workload Authentication 하나:** Linux auth. 제어면과 독립된 워크로드 접근 관측을 제공하고 정상/실패를 실제 검증할 수 있다. SSH 전체를 제품으로 삼지 않는다.
3. **SHOULD: Linux Audit:** 로그인 이후 프로세스/특권 활동을 조사할 때 추가한다. 다중 레코드 조립/키/민감 필드를 처리할 여유가 있을 때만 도입한다.
4. **COULD: VCN Flow:** 자원 간 통신/egress 조사가 시연에 필요하고 비용/유실 의미를 검증할 때 추가한다. 일정이 부족하면 제외한다.

두 소스가 있다고 자동 cross-source account-compromise detection이 가능한 것은 아니다. 공유된 안정적 자원/주체 관계가 있어야 한다. 연관성이 없는 실습 이벤트를 같은 사건으로 강제 병합하지 않는다. 실제 보호 대상이 웹 서비스로 확정되면 세 번째 소스를 auditd 대신 Web/WAF로 바꾸는 결정을 재검토한다.

현재 소스의 목표 구조상 위치는 [로드맵의 현재 구현 배치](implementation_roadmap_v2.md)에 별도로 기록한다.
