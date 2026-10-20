# 보안 중심 수집 정책과 통합 로그 종류

2026-10-20 사용자 승인 초안의 구현이다. LOG-COLLECTION-POLICY-02로 관리한다.
구현 중에는 테스트·린트·빌드·실행 검사를 하지 않는다. 구현 작성 100% 뒤 집중 검수와 영향 수정만 수행한다.
이번 작업은 **재부팅과 재부팅 검증을 제외**한다. 구현·코드 검사·실습 배포·실장치 수집 결과는 별도 기록한다.

## 범위와 기본 정책

운영체제 로그 생성 자체를 끄거나 기존 원본/경보/정규화 문서를 삭제하지 않는다.
필수 이벤트를 먼저 보존하고 새로운 불필요한 기록의 중앙 전송을 제한한다.
키·조직 권한·큐·registry·입력 ID·기존 체크포인트·event_hash 의미를 변경하지 않는다.
수집 종류는 출처/이벤트 해석이며 공격 확정·탐지 규칙 지원과 다르다.

단일 원본 카탈로그는 `deploy/agents/security-catalog.json`이다.
`tools/sync_collection_policy.py`는 Windows PS/C# 채널 정의와 Linux 경로 선택자를 생성한다.
카탈로그는 설치 묶음에도 포함한다. 런타임에 임의 원격 목록/코드를 받지 않는다.

Windows는 활성 채널 전체를 선택하던 동작에서 Security/System과 보안 제품·실행 제어·원격 접속 채널로 좁힌다.
카탈로그의 중요한 ID는 항상 보존한다. 로그인 성공/실패·계정/그룹·감사 정책·로그 삭제·지속성 이벤트를 정보 등급이라는 이유로 버리지 않는다.
이벤트 필터는 검토된 반복/대량 ID만 제외하며, 처음 보는 ID와 실패·경고·오류는 보존한다. 카탈로그 목록 밖이라고 전부 삭제하지 않는다.
Sysmon의 네트워크·일부 파일/DNS 반복 이벤트와 허용 연결 감사 등은 기본 제외 목록이다. 필요한 네트워크 수집은 명시적 sysmon_network 역할로 추가한다.
PowerShell 4103/4104도 기존 privacy.js가 스크립트 본문·명령줄·rendered message를 제거한다. 스크립트 내용 분석까지 지원한다고 표시하지 않는다.
긴 네이티브 이벤트 쿼리를 추가하지 않고 input processor에서 선별해 input ID와 북마크를 유지한다.
새 설치의 필수 채널은 Security/System이며 기존 required_channels/AdditionalChannel은 명시적 선택으로 보존한다.
파일 기본 경로와 이름은 Windows Firewall 디렉터리의 pfirewall 로그로 제한한다. 임의 Windows Logs/ProgramData 텍스트 파일은 자동 선택하지 않는다.
필수 채널 부재/권한 오류는 기존 설정을 보존한 실패이며 수집 0건 성공으로 바꾸지 않는다.

Linux는 auth.log/secure, audit/audit.log, ufw.log, fail2ban.log와 숫자 회전 파일만 기본 선택한다.
packages 역할에서는 dpkg.log/apt/history.log/dnf.rpm.log/yum.log를 추가한다.
임의 텍스트·syslog/messages 전체·설치 상세 출력은 자동 선택하지 않는다. 발견 단계에서도 관련 없는 하위 디렉터리를 순회하지 않는다.
일반 journald 전체 대신 인증 제공자·감사·예약 작업과 커널 보안 메시지를 선택한다. 커널 일반 부팅 메시지는 전송하지 않는다.
처음 선택한 인증/audit/UFW의 file 또는 journal 경로는 보호된 `security-source-preference.json`에 고정한다.
나중에 파일이 생겨도 journal에서 file로 조용히 바꾸지 않는다. 고정한 파일이 없어지거나 상태가 손상되면 마지막 정상 입력을 보존하고 실패한다.
운영자가 출처를 전환하려면 미전송 범위와 기존 cursor를 확인하는 명시적 절차가 필요하다. 고정 상태 삭제로 전환을 숨기지 않는다.
회전·미전송 큐·registry·기존 읽기 위치는 초기화하지 않는다. 압축 파일은 이 텍스트 발견 기능의 지원 범위 밖이다.

보호된 설치 루트의 선택 파일 `security-roles.json` 예:

```json
{"schema":1,"roles":["packages","sysmon_network"]}
```

허용 역할은 packages/sysmon_network/directory_service/application이며 기본값은 빈 목록이다.
실제로 설치된 출처만 사용하며 Linux 역할/출처 고정 파일은 소유자 전용 권한이어야 한다.
AD·DB·VPN·컨테이너의 제품별 감사나 새 앱 계측을 자동 설치한 것으로 간주하지 않는다.

## 웹 제외의 전제

앱 인증/권한/관리 감사와 WAF 탐지는 보존한다. 서비스별 중요 거래/민감 기능은 앱의 명시적 감사 출처를 선택해야 한다.
일반 combined access 기록에는 해당 요청의 최종 WAF 판단이 없다. 경로/확장자/200만 보고 버리지 않는다.
이 경우 보호된 접근 메타데이터는 보존하며 collection_status=retained_missing_security_context다.
WAF 전용 입력은 접근 제외와 독립적이고 모든 실제 탐지 기록을 기존 보호 계약으로 처리한다.

선택된 서버 소유 로그가 다음 추가 계약을 생산하면 정상 정적/아이콘/상태 확인을 제외할 수 있다.
이 필드는 클라이언트 헤더/쿼리를 복사해서 채우면 안 된다. WAF/앱 검사를 마친 서버가 최종값을 생산해야 한다.

```json
{"schema":"cloud-soc-web-security-v1","timestamp":"2026-10-20T12:00:00Z","request_id":"opaque-server-request-id","source_ip":"192.0.2.1","method":"GET","status":200,"route_kind":"static","has_query":false,"security_checked":true,"security_matched":false}
```

정확한 키·형식만 허용한다. security_checked=true, security_matched=false, query 없음,
GET/HEAD, 200/204/304, route_kind가 static/favicon/health를 **모두** 만족할 때만 제외한다.
다른 상태·민감/미분류 경로·검사 미완료·쿼리·POST·오류는 보존한다.
본문·Cookie·Authorization·전체 URI/쿼리·스크립트/명령 인자를 새로 추가하지 않는다.
request_id는 HTTP의 제한된 식별 필드로만 전달하며 기존 event.id를 바꾸지 않는다.
고전 access 형식과 기존 스키마는 계속 지원한다.
공개 페이지/AJAX 전량 제외는 요청량/오류율 집계와 보안 문맥이 갖춰질 때까지 활성화하지 않는다.
정규화/탐지 capability가 없는 새 출처를 정상 분석 완료로 표시하지 않는다.

## 현재 실습의 실제 적용 경계

`deploy/lab/apply_collection_policy.py --root /home/kopo/soc-mall-lab --apply`는 정확한 현재 실습만 허용한다.
기존 private proxy/after-crs를 별도 backup하고 Apache syntax를 마지막 검수 단계에서 확인한 뒤 graceful reload한다.
CustomLog 형식 8열/경로/request ID와 기존 projector/spool/checkpoint는 유지한다.
CRS/custom phase 5 뒤의 비기록 메타데이터 규칙 10003이 검사 완료와HIGHEST_SEVERITY를 전달한다.
최종 값255, 검사 완료, 쿼리/요청 body없음, GET/HEAD, 200/304, 제한된 정상 정적/아이콘 경로일 때만
중앙 수집 출처access.tsv의 새 레코드 생성을 제외한다. WAF native 감사 출처는 변경하지 않는다.
제어 표식이 없거나 알 수 없으면 접근 기록을 유지한다. 미검토 custom SecRule이 있으면 적용을 거부한다.
HIGHEST_SEVERITY 255는 알려진 severity가 없다는 뜻이지 모든 공격 부재의 보장이 아니다.
현재 고정 CRS/메타데이터 파서가 인정하는severity 기반 WAF 탐지의 보존을 실제 검수한다.
Custom 탐지 규칙 추가/CRS변경 시 이 전제와 분류 정책도 다시 검토해야 한다.

`--apply --rollback`은 적용 후 hash가 일치하는 이번 파일만 원복한다. 이후 운영자 변경을 덮어쓰지 않는다.
실패 시 기존 구성을 복원하고 성공 처리하지 않는다. 설치 도구가 source/중앙 기존 문서를 다시 쓰지 않는다.
일반 Windows/Linux 설치 패키지 수정과 현재 쇼핑몰의 전용 수집기 적용은 서로 다른 배포다.
등록된 다른 실장치/운영 서버에 자동 업데이트하지 않는다.

## 통합 로그

서버가 허용된 출처·채널·이벤트 코드·검증된 보호 스키마를 해석해 로그 종류를 제공한다.
예: Windows 인증/감사 정책/실행 제어, Linux 인증·권한/보안 감사/커널 보안,
쇼핑몰 로그인 감사/웹 접근/WAF 탐지, 에이전트 수집 상태, 네트워크·클라우드 감사.
원본에 임의 log_type을 넣어 신뢰 분류를 얻을 수 없다. 정보가 부족하면 종류 미확인/기타 기록이다.
종류 표시는 공격 판정이나 지원 탐지 규칙의 존재를 의미하지 않는다.

LOG-COLLECTION-VIEW-03은 사용자가 보낸 화면의 반복 미관측 열과 2720px 최소 폭을 보완한다.
목록은 **로그 종류 / 시각 / 출처 / IP·주체 / 주요 내용 / 상세**의 여섯 열이다.
Windows 전용 OS·이벤트 공급자·문서 ID 등을 웹 로그의 공통 열로 강제하지 않는다.
웹 접근은 검증된 HTTP 메서드·응답 코드·보호된 경로 분류를 표시하고, WAF DetectionOnly는 탐지 전용·차단 안함으로 구분한다.
HTTP 200을 공격 없음이나 실제 작업 성공으로 판정하지 않는다. 가명 계정은 실제 사용자명으로 바꾸지 않는다.
선택한 조회 시간 기준을 유지하며 대체 시각을 사용할 때는 수신/로그 시각이 없다는 근거를 표시한다.
상세에는 관측된 출처 필드와 정확한 인덱스/문서 ID를 남긴다. 해석 미지원·필수 필드 누락·보호 제한은 유지하되 무관한 빈 항목을 나열하지 않는다.
가로 폭은 데스크톱 화면 안에 맞추고 작은 화면은 표 내부에서만 스크롤한다.
조직 범위·원본 권한·PIT/페이지/취소·AJAX 입력 보존 계약은 변경하지 않는다.

## 검수와 남은 경계

구현 작성 100% 뒤 한 번의 집중 검수로 관련 Python/JS·Windows native/PS·Linux 선택자와 실제 Filebeat 구성을 검사했다.
최초 검사에서 확인한 이전 fixture 기대와 패키지 이름 충돌을 수정하고 영향 항목만 재검사했다. 전체 반복 검수는 하지 않았다.
실습에서는 정상 정적 요청 제외, SQLi 쿼리/공격 헤더/일반 페이지 보존, 기존 수집→정규화→경보→정확한 근거 연결을 확인했다.
실제 화면에서 시험 규칙 생성·승인·적용·경보와 로그 종류·상세 조회·삭제를 확인했다. 이후 사용자 화면 보완은 영향 조회/레이아웃만 확인한다.
개별 검사 결과·배포 파일 대조·정리는 작업 목록에 기록한다. **이번 작업에서는 재부팅하지 않는다.**
일반 Windows/Linux는 합성 fixture/네이티브 실행/구성 검사를 한 것이며 다른 실제 장치에 배포하거나 실제 보안 로그를 수집한 결과가 아니다.
현재 실습 웹 경로의 실제 Filebeat 수집과 일반 에이전트의 배포 완료를 혼동하지 않는다.
이벤트별 영속 제외 사유 카운터와 수집 감소율/SLA, 모든 공격 보존 보장은 이번 범위 밖이다.
원본 ES 참조와 기존 정규화 event_hash 의미를 보존한다. 독립 WORM 원본 바이트 저장까지 구현했다고 선언하지 않는다.

공식 근거:
[Microsoft 감사권고](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations),
[Filebeat winlog](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-winlog),
[Filebeat journal 선별](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-journald),
[Apache 조건부로그](https://httpd.apache.org/docs/2.4/mod/mod_log_config.html),
[ModSecurity 변수](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v2.x%29-Variables),
[OWASP 로그지침](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
기존 고정 Beats 9.5.2/Python/ES 의존성을 유지했고 새 런타임 의존성은 추가하지 않았다.

최종 결과: LOG-COLLECTION-POLICY-02와 LOG-COLLECTION-VIEW-03의 승인된 코드·현재 실습 범위 인수를 완료했다. 상세 검사 수와 수정 이력, 실제 장치 배포의 남은 경계는 docs/work_tracker.md에 기록했다.
