# 통합 로그 조회 계약 v1

P1-01 계약을 기준으로 P1-02 API와 P1-03 화면 연결까지 구현했다. 기준일: 2026-09-22. 격리 ES 및 합성 UI 검증은 완료했으나 AWS 배포·실제 에이전트 수신 검증은 별도다. 사용·업데이트 절차는 [통합 로그 안내](log_explorer.md)를 참고한다.

- 구현: [log_contract.py](../src/cloud_soc/portal/log_contract.py)
- 조회 API 구현: [log_query.py](../src/cloud_soc/portal/log_query.py), [포털 라우트](../src/cloud_soc/portal/app.py)
- 대표 문서: [합성 fixture 8건](../tests/fixtures/log_intake.json)
- 검증: [계약 테스트](../tests/test_log_contract.py)
- 진행 상태: [작업 목록](work_tracker.md)

## 1. 범위와 확인 근거

허용 대상은 `soc-host-raw-*`, `soc-network-*`, P4에서 추가한 `soc-cloud-aws-*`, `soc-cloud-oci-*`뿐이다. 클라우드 필드 계약은 아래 6절을 따른다. 기존 `raw-logs-*`, `normalized-events`, `security-alerts`, 시스템 인덱스는 섞지 않는다. 인덱스 전체를 임의로 선택하는 UI/API도 제공하지 않는다.

현재 저장소의 [호스트 매핑](../deploy/agents/index-template.json), [네트워크 매핑](../deploy/agents/network-index-template.json), [Packetbeat 필드 허용 목록](../deploy/agents/packetbeat.base.json), [수집 시각 파이프라인](../src/cloud_soc/portal/status_setup.py), Windows/Linux 탐색 스크립트를 비교했다. 운영 Elasticsearch 문서를 읽은 것은 아니다. fixture는 이 설정을 바탕으로 작성한 합성 문서로 실제 Beats 출력의 모든 필드를 보장하지 않는다.

| 대표 소스 | 확인 가능한 분류/위치 | 없는 경우 추측하지 않는 정보 |
| --- | --- | --- |
| Windows 이벤트 | `labels.log_source=windows_event`, `winlog.channel`, `event.code` | 4625 같은 코드만 보고 사용자·출발지·결과를 생성하지 않음 |
| Windows 파일 | `windows_file`, `log.file.path` | 본문의 IP·사용자를 조회 단계에서 임의 파싱하지 않음 |
| Linux 파일 | `linux_file`, `log.file.path` | auth.log라는 이유로 기존 SSH 파서가 실행됐다고 표시하지 않음 |
| Linux 저널 | `linux_journald` | 존재하지 않는 파일 경로나 채널을 만들지 않음 |
| Packetbeat 흐름 | `network_packetbeat`, `event.dataset`, `flow.final` | 문서 수를 연결 수로 표시하거나 누적 바이트를 모두 합산하지 않음 |
| Packetbeat DNS/TLS | `network.protocol`, 존재하는 IP 필드 | 상대 호스트·프로세스·유출 파일을 센서 정보로 대체하지 않음 |
| 과거/미분류 문서 | 원본 인덱스와 문서 ID | 없는 수신 시각·OS·수집기 ID를 보충하지 않음 |

## 2. 목록 행 계약

`project_hit()`는 입력을 변경하지 않고 고정된 메타데이터 필드만 반환한다. 아래 표의 경로 외에 임의 `_source` 필드를 복사하지 않는다. 이는 정규화/탐지 엔진이 아닌 **읽기 화면용 변환**이다.

| 응답 필드 | 근거/의미 |
| --- | --- |
| `reference.index`, `reference.id` | ES `_index`와 `_id`의 정확한 쌍. 표시용 가짜 ID를 만들거나 자르지 않음 |
| `stream`, `source_kind`, `source_label` | 허용 인덱스 그룹, 지원되는 소스 태그, 원래 태그. 미지원/그룹 불일치는 `unknown` |
| `received_at` | 서버 `event.ingested`. 누락 시 `null` |
| `event_at` | `@timestamp`. 반드시 원본 행위 발생 시각이라는 보장은 없음 |
| `organization`, `agent_id`, `collector` | `organization.id`, `agent.id`, `agent.type` |
| `host_name`, `host_ips` | 수집 호스트 정보. 네트워크 통신 상대의 정보가 아님 |
| `os`, `os_basis`, `os_name` | OS 분류, 분류에 쓴 필드 경로, 표시용 `host.os.name` |
| `channel`, `file_path`, `dataset` | `winlog.channel`, `log.file.path`, `event.dataset`. 각각 별도 보존 |
| `event_code`, `action`, `outcome`, `user` | 대응하는 명시적 ECS 필드만 사용. `winlog.event_data` 안의 사용자 역할을 임의 선택하지 않음 |
| `source_ip`, `destination_ip` | 유효한 단일 IP. 본문이나 `host.ip`에서 대신 채우지 않음 |
| `transport`, `protocol`, `flow_final` | 대응하는 network/flow 필드. `false`와 누락을 구분 |
| `parse_status` | 현재 항상 `not_evaluated`. 수집/JSON 해석만으로 보안 파싱 완료라 하지 않음 |
| `quality.invalid_fields`, `quality.truncated_fields` | 검사한 필드의 형식 문제/표시 길이 제한. 원문 변경이나 수집 손실을 뜻하지 않음 |

OS 우선순위는 지원되는 `host.os.type` → `labels.sensor_platform` → 지원되는 `labels.log_source` → `unknown`이다. Packetbeat 허용 목록에 `host.os.type`이 없으므로 센서 태그가 필요하다. 호스트명, 인덱스명, OS 이름 문자열을 추측해 분류하지 않는다. 이 태그는 인증된 OS 증명이 아닌 수집 메타데이터다.

문자열 결측은 `null`, IP 배열 결측은 `[]`, 분류/결과 결측은 `unknown`이다. 화면은 이를 `미관측`/`미확인`으로 표현한다. 문자열은 최대 512자, 호스트 IP는 최대 16개를 검사하며 중복을 제거한다. 잘못된 자료형을 JSON 문자열로 바꿔 표시하지 않는다. 부모 객체 자체가 손상되어 경로를 찾지 못한 경우도 결측이며, `quality`는 전체 문서 스키마 검증 결과가 아니다.

## 3. 시간과 검색 조건

`parse_filters(request.args.items(multi=True))`를 첫 페이지 API 입력 검증에 사용한다. 중복/미지원 파라미터는 조회 전에 400으로 처리한다. 다음 값만 받는다.

| 파라미터 | 규칙 |
| --- | --- |
| `start`, `end` | 함께 지정. 타임존이 있는 ISO 시각, UTC로 변환. `[start, end)` 구간, 양수이며 최대 30일. 생략하면 요청 시각 기준 최근 1시간 |
| `time_basis` | `ingested` 기본: `event.ingested`; `event`: `@timestamp`. 한 조회 안에서 대체/혼용하지 않음 |
| `page_size` | 10/25/50, 기본 25 |
| `host` | `host.name` 완전 일치, 최대 253자. Lucene/KQL/와일드카드 구문으로 해석하지 않음 |
| `os` | `windows`/`linux`/`unknown`. 표시와 동일한 분류 규칙으로 필터링 |
| `collector` | `filebeat`/`packetbeat` 완전 일치 |
| `ip` | IPv4/IPv6 단일 주소. CIDR/zone ID 제외. `host.ip`, `source.ip`, `destination.ip` 중 일치 |

과거 시점 조회는 허용하지만 한 번의 구간은 30일 이하다. 명시한 미래 구간도 허용하여 시계 오류가 있는 이벤트를 조사할 수 있다. `event_at`으로 `received_at`을 채우지 않는다. 수신 시각이 없는 과거 문서는 기본 수신 시간 조회에서 제외되며, 이벤트 기준 조회로 찾는다. 기존 문서를 일괄 재수집해 가짜 수신 시각을 붙이지 않는다.

`@timestamp`는 입력/파서별 의미가 다르다. 파일 본문 날짜를 아직 파싱하지 않았다면 수집기가 정한 시각일 수 있으므로 UI에서는 **로그 기준 시각**으로 표시한다. 원본 행위 시각 보장은 P5 소스별 파서에서 검증한다.

`q`, 임의 JSON 쿼리, 정렬 스크립트, 조직별 권한 파라미터는 v1에서 거부한다. 자유 본문 검색과 미지원 환경/플랫폼/파싱 상태 필터는 준비되기 전까지 비활성화한다.

## 4. 권한과 원문 접근

기존 포털의 관리자 인증·정확한 Host/Origin 검사·same-origin 정책을 그대로 적용한다. `organization.id`는 분류 태그이고 테넌트 권한이 아니다. v1 관리자는 허용된 두 인덱스 그룹 전체를 보는 단일 관리자 범위다. 다중 조직 서비스로 공개하면 안 된다.

기존 `cloud_soc_agent_monitor` 읽기 계정 범위가 두 그룹과 일치한다. P1-02는 해당 읽기 클라이언트만 재사용하고 발급 계정/elastic 계정으로 조회하지 않는다. 새로운 쓰기·키 발급 권한은 필요하지 않다. 계정 미설정은 503이며 성공한 빈 목록으로 숨기지 않는다.

원문 참조는 구체적인 인덱스명과 문서 ID로 제한한다. 이 검증은 권한 검사나 URL 인코딩을 대신하지 않는다. 이름 형태만으로 ES alias 여부는 알 수 없으므로 P1-02에서 실제 인덱스/반환된 `_index`까지 확인한다. 클라이언트의 원문 URL/인덱스 패턴을 그대로 ES 요청에 전달하지 않는다. 상세는 동일 관리자 인증과 서버 측 인덱스 검사 후 조회하며 삭제/만료된 참조는 404로 구분한다.

**이 단계의 목록 변환은 `message`, `event.original`, 명령 인자, Windows event_data 및 미승인 중첩 필드를 반환하지 않는다.** 메타데이터 자체도 개인정보일 수 있어 인증이 필요하다. P1-02/03은 우선 제한된 메타데이터 상세를 연결하고, 자유 텍스트·전체 원문 노출은 P2-01의 마스킹/접근 정책이 검증되기 전 기본 차단한다. UI에 제한 상태를 표시하며 제한된 필드를 전체 원문처럼 부르지 않는다. 이 순서는 위험한 원문 노출을 방지하기 위한 단계적 범위 제한이다.

모든 문자열은 비신뢰 데이터다. UI에서는 textContent 또는 동일 수준의 이스케이프를 사용한다. 로그 문자열을 HTML, 명령 또는 링크로 실행하지 않는다. 응답은 `no-store`; 인증정보, upstream 오류 본문, 실제 원문을 서버 오류 메시지나 테스트 기록에 남기지 않는다.

## 5. P1-02/03 구현과 검증 기준

아래 기준은 코드·모의 API·격리 ES·합성 UI로 검증했다. 운영 서버/실제 에이전트 검증을 대신하지 않는다. 기존 문서의 요구사항 표현은 유지하되 실제 동작 차이는 바로 아래에 명시한다.

- 목록 `GET /api/logs`, 상세 `GET /api/logs/detail`을 포털 보호 범위 안에 추가한다. 상세는 허용된 필드만 표시하며 원문 제한 상태를 함께 반환한다.
- 기본 시간 내림차순과 일관된 고유 tie-breaker를 사용한다. snapshot/PIT 방식과 변조 방지 커서를 구현·검증하여 새 로그 유입 중 중복/누락을 막는다. 단순 시간값만 커서로 사용하지 않는다.
- 커서는 최대 8192자, 조회 조건·관리자·만료와 결합한다. 후속 요청에 원래 필터를 바꾸면 거부한다. 커서는 `parse_filters`와 별도 검증하며 임의 PIT/정렬값을 통과시키지 않는다. 만료 시 410 및 첫 페이지 재조회 안내, 이전 화면 스택은 브라우저가 관리한다.
- ES 조회 제한 시간 4초, 각 클라이언트 요청 제한 시간 5초, 자동 재시도 0회. 페이지당 최대 50행, 직렬화 후 응답 최대 256 KiB, 상세 최대 64 KiB. 초과 시 413을 반환한다. 첫 페이지는 인덱스 확인·매핑 확인·PIT 열기·조회가 순차 실행되므로 전체 HTTP 처리 시간이 5초라는 뜻은 아니다.
- 부분 shard 실패, 조회 시간 초과, 매핑 충돌, 인증 실패는 성공한 빈 결과로 변환하지 않는다. 미지원 매핑/필터 조합도 안내하고 소스가 없는 것과 구분한다. 오류에 upstream 응답을 노출하지 않는다.
- 기존 호스트 매핑의 동적 문자열은 text/keyword 하위 필드가 될 수 있고 네트워크는 `dynamic:false`다. OS 필터는 명시 필드/태그의 우선순위와 동일해야 한다. 필드 이름만 같다고 같은 ES 타입/검색 가능성을 가정하지 않는다. P1-02의 격리 ES 테스트에서 실제 매핑별 검색을 검증한다.
- 목록은 `contract_version`, 고정 조회 범위, 행, `next_cursor`를 반환한다. 전체 건수를 계산하지 않았다면 숫자 0이나 추정 전체 페이지를 만들지 않는다. 받은 행 수와 실제 전체 집계를 구분한다.
- 사용자에게 보이는 데모 숫자·샘플 자동 대체를 제거하고 미지원/없음/오류/로딩을 구분한다. 공통 데모 스크립트 대신 독립된 실데이터 조회 화면을 사용한다. HTML의 CSP를 `connect-src 'self'`로 변경하고 인라인 스크립트/스타일 허용을 추가하지 않았다.

실제 페이지는 PIT + 시간 내림차순/`_shard_doc` 오름차순을 사용한다. 마지막 페이지와 오류 시 PIT를 닫고, 이탈/요청 중단 시 남은 PIT는 90초 유휴 만료로 회수한다. 커서에는 고정 필터·관리자·PIT·정렬값·10분 만료가 HMAC 서명으로 결합된다. 후속 요청은 `cursor` 하나만 받는다. 서버 프로세스 간 동일 관리자 해시를 사용하여 서명을 공유하며 비밀번호 해시 변경 시 기존 커서는 무효가 된다.

호스트/수집기는 고정 keyword 매핑을 확인하고, OS/IP는 고정 runtime 스크립트로 기존 동적 매핑 차이를 처리한다. 부분 조회·지원하지 않는 매핑·비용 제한으로 runtime 쿼리가 거부되는 경우 모두 실패로 표시한다. 클러스터 정책을 자동 변경하지 않는다.

## 6. 현재 검증과 남은 일

OCI 추가 계약: `soc-cloud-oci-*`, `collector=oci-audit`, `os=cloud`를 지원합니다. `cloud_provider=oci`로 AWS와 구분하며 `cloud_account`는 수집 테넌시, `cloud_region`은 조회 리전입니다. 상세는 구획·주체·자원·API·HTTP 결과 등 명시적 허용 필드만 읽습니다. 전체 `oci.audit`나 원본 요청/응답은 요청하지 않습니다. AWS/OCI에 없는 호스트 정보를 만들지 않습니다. [OCI 범위·설치 안내](oci_audit.md).

P4 추가 계약: `soc-cloud-aws-*`를 조회/상세 허용 목록에 추가했습니다. `collector=cloudtrail`, `os=cloud`는 AWS 관리 API 영역이며 호스트 OS가 아닙니다. 행에는 `cloud_account`, `cloud_region`, `cloud_service`, `actor_id`가 추가됩니다. 별도 AWS 허용 필드만 상세에서 조회하며 전체 CloudTrailEvent/requestParameters/responseElements는 요청하지 않습니다. 계정/자원을 `host.name`으로 바꾸지 않고 호스트 필터도 AWS 계정 필터로 재해석하지 않습니다. 중앙 읽기 역할/템플릿 갱신 후 사용하며 [AWS 가이드](aws_cloudtrail.md)를 따릅니다.

P3 추가 계약: 상세 응답에 선택적 `security` 객체(version 1)를 제공합니다. Windows 공급자/채널/ID를 확인하여 명시된 event_data 하위 필드만 해석하고, Packetbeat 메타데이터를 표시합니다. `message`, 전체 event_data, 명령줄/작업 XML은 조회하지 않습니다. 목록 계약과 `row.parse_status=not_evaluated`는 그대로이며 별도 해석을 전체 파싱/공격 판정으로 취급하지 않습니다. 누락/미지원·감사 설정 미확인·연관 한계는 [P3 계약](host_security_audit.md)에 명시합니다.

로컬 계약 테스트는 합성 Windows 이벤트/파일, Linux 파일/저널, 흐름/DNS/TLS, 과거 문서를 사용한다. 필드 결측·시각·잘못된 타입·표시 제한·본문 비노출·인덱스 참조·조회 제한·기존 수집 설정과의 정합성을 검사한다. 서비스나 에이전트를 설치하지 않고 ES/운영 로그에도 접근하지 않는다.

P1-02 실제 격리 ES 쿼리/페이지 검증과 P1-03 화면 연결 검증은 [통합 로그 안내](log_explorer.md)에 기록했다. P1-04/P0의 승인된 실제 서버 수신 시험은 남아 있다. 합성 테스트 통과로 운영 수신을 완료 처리하지 않는다.

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_log_contract.py -v
```
