# P5-03 공격 행위 기반 탐지 명세

2026-10-12 / `pack` / 로컬 구현·합성 검증. 운영 배포·AWS 접근·공격 실행 없음.

## 범위와 데이터 적합성

기존 Python/YAML 엔진·정규화·create-only 경보·정확한 근거·SQLite 상태를 유지한다.
`AUTH-001`, `AUTH-SEQ-001`, AWS/OCI Single 규칙은 변경하지 않는다.
외부 엔진·데이터베이스·규칙 변환·WAF 설치는 없다. OCI 신규 개발은 범위 밖이다.

| 시나리오 | 개발 전 | 이번 결과 | 실제 자료 검증 |
| --- | --- | --- | --- |
| ATTACK-01 SSH 실패→성공→sudo | 앞 2단계는 기존 규칙 재사용 가능, 후속 맥락 추가 개발 필요 | 메타데이터 순서형 규칙 구현. 동일 세션/비정상 권한 상승은 미판정 | 미실행 |
| ATTACK-02 AWS 열거 | 투영/정규화 가능, 고유 API 수 집계 추가 개발 필요 | 명시적 서비스/API 쌍 + 호출 수/종류 수 집계 구현 | 실제 계정에서 API별 기록/수신 확인 필요 |
| ATTACK-03 IAM→Trail | 각각의 Single 규칙 존재, 연결 엔진 필요 | 순서형 규칙 구현. 동일 계정·principal ID·ARN 필수 | 미실행 |
| ATTACK-04 웹 SQLi | 요청 URL/쿼리/본문 제외, 독립 공격 신호 없음 | 명세만 작성, 실행 규칙 없음 | 필수 관측 신호 부족 |
| ATTACK-05 웹 명령어 삽입/실행 | 프로세스 일부 메타데이터는 있으나 요청→실행 연결 없음 | 명세만 작성, 실행 규칙 없음 | 필수 관측 신호 부족 |

코드의 필드 존재는 실제 수신 완료를 뜻하지 않는다. 이번 AWS 자료는 공개 문서 형식에
맞춘 합성 자료이며, 연결된 AWS 계정/실제 CloudTrail 유입량을 확인하지 않았다.
T-Pot 로그가 CloudTrail 계정 행위의 대체 근거가 되는 것도 아니다.

검토 근거: `detection/{engine,sequence,registry,rule_loader,worker,incremental,telemetry}.py`,
`processing/{contract,worker}.py`, `parsers/{linux_security,linux_operational,linux_auth}.py`,
`aws/{cloudtrail,collector}.py`, `portal/{security_detail,operations}.py`, `pipeline/alerts.py`,
기존 `detection_coverage.md`, `cloud_detection.md`, `incremental_detection.md`,
`data_source_matrix.md`, `host_security_audit.md`.
기존 문서의 날짜가 붙은 과거 현황은 삭제하지 않는다. 아래 내용이 이번 범위의 최신 대조다.

## 실행·선택·상태 계약

기본 CLI는 여전히 AUTH-001만 선택한다. 새 파일의 `enabled: true`는 **선택한 시험 프로필
안에서만** 유효하다. 아래 명령은 규칙 검증만 하고 네트워크/쓰기/상태 파일 생성이 없다.

```powershell
$env:PYTHONPATH = 'src'
.\.venv\Scripts\python.exe -m cloud_soc.detection --include-attacks
```

`--include-cloud`/`--include-sequence`는 기존 선택 옵션이다. `--include-attacks`가 기존
클라우드 Single/SSH Sequence 전체를 자동 활성화하지 않는다. 세 옵션을 함께 주면
기존 6개 + 신규 3개 = 9개다. 운영 `--run`/Compose 변경은 이번에 실행하지 않는다.

규칙 집합·버전·시작점·endpoint는 기존 SQLite identity에 고정된다. 기존 상태 파일에
옵션을 추가하거나 규칙을 바꾸면 거부하며 자동 초기화/마이그레이션하지 않는다.
전환 시 상태/근거 백업, 승인된 시작점·과거 평가 범위, 별도 상태 파일을 먼저 결정한다.
규칙 내용이 달라지면 새 경보 ID가 될 수 있으므로 과거 경보 중복 영향도 검토한다.

## 공통 필드와 판정

- 필수: 시간대 있는 `@timestamp`, `organization.id`, 정확한 정규화 인덱스/ID와
  `cloud_soc.provenance.raw.index/id`. 증분에는 `cloud_soc.normalized_at`도 필요하다.
- 문자열 식별자는 비어 있거나 배열/객체/마스킹 값이면 평가 불가로 처리한다.
  IP/이름만으로 누락된 계정·호스트·principal을 추정하지 않는다.
- 정규화 AWS 이벤트 ID는 **`cloud_soc.detail.fields.event_id`**이다.
  원본의 `event.id`가 정규화 최상위에도 있다고 가정하지 않는다.
- AWS 중복 단위는 조직·AWS 계정·CloudTrail event ID다. 동일 API를 실제로 여러 번
  호출한 서로 다른 ID는 별도 관측이다. SSH는 조직·정확한 원본 참조 단위다.
  서로 다른 SSH 원문이 동일 인증 시도를 중복 표현하는지는 식별할 수 없으므로
  로그인 시도 수가 아니라 일치 로그 관측 수라고 설명한다.
- `attack_indicator`/`attack_correlation`과 severity는 별개다. 확률 점수는 만들지 않는다.
  모든 신규 경보는 `attack_success: not_established`를 남긴다.
- 설명은 `cloud_soc.provenance.assessment`에 저장하고 기존 상세 API/화면에 표시한다.
  API 다양성 수와 순서 단계별 근거 위치, 제한사항을 제공한다. 원문 대신 주변 로그로
  대체하지 않고 정규화/원본 참조와 기존 event hash 검사를 재사용한다.
- 참조를 만들 수 없으면 회차 실패다. 실제 문서 만료·삭제·내용 불일치는 기존 조사 API의
  missing/expired/hash mismatch 상태로 표시하며 정상으로 간주하지 않는다.
- 늦은 도착은 기존 기본 900초 버퍼로 정렬한다. 확정 frontier 이전 자료는 제외 이력에
  `late_event`로 남기며 자동 backfill하지 않는다. 상태/조회 상한과 15분 수신 중첩 제한도 유지한다.
- 경보 쓰기·상태 게시 실패 시 로컬 체크포인트는 유지한다. 재시도는 동일 근거 ID와
  create-only 저장을 사용한다. ES/SQLite 분산 트랜잭션이나 정확히 한 번 보장은 아니다.

## ATTACK-01: SSH 인증 이후 권한 관련 활동 맥락

**Rule ID/명칭:** ATTACK-01 / SSH 인증 공격 이후 권한 관련 활동 의심 / high.

**로그/필드:** 지원 RFC3164 sshd 성공·실패와 PAM sudo session-open 로그.
`linux_ssh_v1`/`linux_sudo_session_v1`, `host.id`, `user.name`, `network.protocol`,
`event.category/outcome/action`, SSH `source.ip`, sudo `cloud_soc.detail.fields.target_user/target_uid`.
명시된 PAM actor/actor UID와 target/target UID만 파싱하며 user.name은 actor다.
지원 형식은 `pam_unix(sudo:session): session opened for user root(uid=0) by fixture(uid=1000)`이다.
기존 일반 sudo 명령 로그는 `PWD=` 때문에 개인정보 필터에서 마스킹된다. 그 보호는 유지하고
해당 명령 로그로 ATTACK-01을 생성하지 않는다. actor/UID가 없는 세션 로그도 사용하지 않는다.
새 어댑터는 `linux-sudo-session-v1` 정규화 ID를 사용하고 기존 어댑터/자료를 덮어쓰지 않는다.

**조건/그룹:** 동일 조직·host.id·user.name(비-root)에서:

1. 동일 IP의 SSH 실패 로그 5건 이상.
2. 해당 IP의 성공 로그가 모든 선택 실패 이후이며 실패→성공 300초 이내.
3. 가장 최근 관측한 성공 이후 600초 이내에 같은 계정의 root(uid=0) 대상
   `sudo_session_opened` 관측. 전체 최대 창 900초, 후속 경보 cooldown 600초.

첫 2단계의 조건/5건·300초는 현재 AUTH-SEQ-001을 기준으로 한다. 기존 AUTH-001은
그대로 10건/300초이며 조직/IP 집계 의미를 승인 없이 호스트별로 바꾸지 않는다.
선행 성공은 같은 IP의 이전 실패 집합을 초기화한다. 새로운 성공에 해당하는 실패가
없다면 이전 성공을 되찾아 연결하지 않는다. 시간 경계는 포함하되 같은 시각의 단계는
순서를 증명하지 못하므로 연결하지 않는다. 경보에는 최근 실패 5건+성공+sudo, 총 7개
정확한 근거와 단계별 참조 위치를 남긴다.

**한계/오탐:** sudo에는 SSH IP·공통 세션 ID가 없다. 이것은 호스트·계정·시간의 조사 맥락이지
동일 SSH 세션의 sudo로 확정한 경보가 아니다. 동시 세션·정상 재시도 후 관리 작업이
오탐 후보다. 명령 본문/인자를 추가 수집하지 않으며 sudo의 기록은 명령 실행 성공·권한 상승
성공·계정 탈취의 증거가 아니다. audit 세션/로그인 UID 등 검증된 연결을 확보하기 전
완전한 침해/후속 권한 상승 탐지라고 표시하지 않는다.

**시험:** 실패 4/5/6건, 성공 없음/먼저/동시각, 다른 IP/호스트/계정/조직, 300/301초와
600/601초, sudo 단독/비-root 대상, 두 번째 정상 성공, 원문 재전송, 재시작.

## ATTACK-02: AWS API 열거 빈도와 다양성

**Rule ID/명칭:** ATTACK-02 / AWS 비정상 API 열거 및 정찰 의심 / medium.

**로그/필드:** CloudTrail 관리 이벤트 투영/정규화.
`event.dataset=aws.cloudtrail`, `cloud.provider=aws`, `event.provider/action`,
`cloud.account.id`, `user.id`, `cloud_soc.detail.fields.{identity_type,identity_arn,event_id}`.
IAMUser/AssumedRole/FederatedUser/Root만 후보이며 AWSService 등의 식별 불충분 주체는
지원 대상으로 추정하지 않는다. user.id와 ARN을 함께 요구하고 role issuer ARN이나
user.name만으로 서로 다른 주체를 합치지 않는다.

**조건/그룹:** 동일 조직·AWS 계정·principal ID·identity ARN의 300초 내 관측 20건 이상
AND 서로 다른 API 이름 4개 이상. cooldown 300초. 둘 다 초기 가설이다.
리전은 그룹 키가 아니므로 같은 계정·주체의 여러 리전 자료를 포함할 수 있다.
실제 중복 관리 이벤트 노출/수집 범위와 리전 경유 의미는 운영에서 확인해야 한다.

**명시적 provider/API 쌍:**

| provider | 지원 API |
| --- | --- |
| ec2.amazonaws.com | DescribeInstances, DescribeSecurityGroups, DescribeVpcs, DescribeSubnets |
| iam.amazonaws.com | ListUsers, ListRoles, ListPolicies, ListAttachedUserPolicies, ListAttachedRolePolicies |
| s3.amazonaws.com | ListBuckets |
| lambda.amazonaws.com | ListFunctions |
| ecs.amazonaws.com | DescribeServices, ListClusters, ListServices |

`List*` 등 접두사만 보지 않는다. 다른 provider의 같은 API 이름도 제외한다.
성공·AccessDenied 등의 호출 시도를 함께 세되 열거 성공·정보 접근 성공으로 설명하지 않는다.
정확한 이벤트 ID가 없으면 집계하지 않고 unknown/제외 기록을 남긴다.

**한계/오탐:** 정상 관리 조회/SDK/인벤토리도 임계값을 넘을 수 있다. 현재 userAgent와 정상
활동 기준선은 수집·구현하지 않았으며 이 규칙은 그 이상을 판정하지 않는다. API별 실제
Event History 기록 여부와 수집 권한은 계정에서 확인해야 한다. 호출 20건은 공격 20회 또는
공격자 20명이라는 뜻이 아니다.

**시험:** 19/20/21건, API 3/4종, 한 종류 30건, 300/301초, provider 불일치, denied,
중복 ID·다른 문서 참조, 누락/잘못된 principal/ARN, 조직/계정 분리, 정상 소량 조회·명시 예외.

## ATTACK-03: IAM 변경 이후 Trail 중지/삭제

**Rule ID/명칭:** ATTACK-03 / AWS 권한 변경 이후 감사 기능 비활성화 의심 / high.

**로그/필드:** ATTACK-02의 조직·계정·주체·정확한 event ID와
`event.outcome=success`, `cloud_soc.detail.fields.target_policy_arn`, provider/action.

**조건/그룹:** 같은 조직·AWS 계정·principal ID·identity ARN에서:

1. iam.amazonaws.com AttachUserPolicy/AttachRolePolicy/AttachGroupPolicy에 AWS 관리형
   AdministratorAccess 또는 PowerUserAccess ARN이 관측되고 성공 응답.
2. 그 이후 900초 이내 cloudtrail.amazonaws.com StopLogging/DeleteTrail 성공 응답.

기존 AWS-IAM-001/AWS-AUDIT-001의 조건을 기반으로 별도 연계한다. 두 Single은 유지한다.
같은 시각/역순/실패 API는 연계하지 않는다. cooldown 0이며 별도 Trail 중지/삭제 이벤트는
독립 경보다. 여러 선행 변경 중 최신 유효 1건과 후속 1건의 정확한 근거를 선택한다.

**한계/오탐:** principal ID+ARN도 재사용된 assumed-role 세션 이름이면 정확한 자격 증명
세션을 보장하지 않는다. 정책 대상이 actor인지 추정하지 않는다. API 응답만으로 실제
권한 상승, 모든 감사 로그 제거, 공격 성공을 판정하지 않는다. 정상 정책/Trail 마이그레이션도
일치할 수 있으므로 승인·대상·다른 Trail·독립 수집 상태를 확인한다.

**시험:** 고권한 아닌 정책/실패 API, 서로 다른 조직/계정/주체/ARN, 900/901초, 같은 시각/역순,
같은 역할 다른 세션 이름, 여러 후속 이벤트, 정상 승인 예외, 저장 실패/재시도/상태 복원.

## ATTACK-04: 웹 SQLi 시도 (비활성 명세)

**후보 ID/명칭:** ATTACK-04 / 웹 SQL Injection 공격 시도 의심. 실행 YAML 없음.
현재 Nginx/Apache access 파서는 method/status/client IP/time만 유지하고 URL·헤더·본문은
제외한다. Packetbeat도 요청 내용이 없다. 400/500, 반복 요청, 프로세스만으로 SQLi를 생성하지 않는다.

필수 후보: 조직·host/service ID·관측 시각·고유 request ID·검증된 공격 유형/규칙 ID·
센서 및 판정 버전·차단/통과 결과. HTTP 요청의 어느 요소를 평가했는지와 인코딩 처리 근거가
필요하지만 민감 요청 내용을 중앙으로 추가 수집하지 않는다. 향후 승인된 기존 애플리케이션의
개인정보 보호형 보안 신호를 검토할 수 있다. 이번에는 WAF/CRS 엔진을 설치·연동하지 않는다.

조건/창/심각도는 데이터 계약 확인 전 미정이다. 독립 SQLi 신호가 실제로 존재하고
정상 검색문/인코딩·우회·중복·요청 ID·조직 분리 반증 시험을 통과해야 활성화할 수 있다.
센서 신호의 단순 재표시와 Cloud SOC 자체 탐지는 구분하며 SQL 실행 성공으로 해석하지 않는다.

## ATTACK-05: 웹 명령어 삽입·실행 (비활성 명세)

**후보 ID/명칭:** ATTACK-05 / 웹 명령어 삽입 및 서버 실행 행위 연계 의심. 실행 YAML 없음.
Sysmon 프로세스 GUID/부모 GUID 등의 일부 관측은 존재하지만 HTTP 요청과 연결되지 않는다.
Linux Audit 다중 레코드 정규화 결합도 미완료다. PID만으로 동일성을 만들거나 가까운 시간의
프로세스 실행을 웹 요청의 결과로 추정하지 않는다.

필수 후보: 조직·호스트/부팅 범위·서비스·검증된 웹 공격 신호·request/trace ID,
실제 서비스 실행 주체·안정 프로세스 ID/부모 관계와 정확한 관측 시각·원문 참조.
command line/argv/요청 본문을 새로 수집하지 않는다. 요청→실행 귀속과 정상 서비스 자식
프로세스 기준을 확보하기 전 상관분석 불가다. 조건/창/심각도는 미정이다.
정상 서비스 실행/서로 다른 요청·호스트/재사용 PID/순서·중복·누락을 반증해야 한다.

## 정상 활동과 예외

`falsepositives`는 문서 메타데이터일 뿐 자동 필터가 아니다. 기본 `exclusions: []`다.
예외는 실제 AND 조건으로 평가하며 모든 group_by 필드와 조직을 exact equals로 지정해야 한다.
event-time `[start,end)` 구간은 시간대가 필요하고 최대 24시간이다. 영구 관리자/공용 IP
화이트리스트는 지원하지 않는다. 예외도 규칙 snapshot/version/상태 identity에 포함되므로
변경 시 기존 SQLite를 자동 전환하지 않는다. 증분은 `approved_policy_exception` 참조 이력과
`policy_excluded` 계측을 남긴다. 과거 snapshot 평가에는 증분 제외 이력 기록이 없다.

예외 도입은 새로운 운영 승인 작업이며 이번 기본 파일에는 실제 예외가 없다. 승인된
주체도 탈취될 수 있으므로 장시간/일괄 예외는 위험하다. 정상 위험 설정 변경의 기존 Single
경보가 유지되는 것은 의도된 동작이며 모든 정상 사례가 반드시 0건일 필요는 없다.

## 외부 참고 (2026-10-12 확인)

- [MITRE DET0402 / AN1127](https://attack.mitre.org/detectionstrategies/DET0402/): 열거 빈도·주체 맥락·정상 인벤토리 구분을 참고. 전체 analytic 구현을 주장하지 않는다.
- [MITRE Brute Force](https://attack.mitre.org/techniques/T1110/), [Sudo](https://attack.mitre.org/techniques/T1548/003/): 로컬 인증/특권 행위의 의미 참고. 단계 연결은 자체 설계다.
- [Sigma Rules](https://sigmahq.io/docs/basics/rules.html): 로그소스/조건/오탐 메타데이터의 구분 참고. 규칙 복제·변환·엔진 도입 없음.
- [OWASP CRS](https://coreruleset.org/): 웹 패턴 연구 범위 참고. 현재 웹 규칙은 미구현이며 WAF 실행 없음.
- [AWS Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html): 관리 이벤트의 지역·조회 범위와 실제 이벤트 기록 확인 필요.
- [Linux-PAM 세션 로그 형식](https://github.com/linux-pam/linux-pam/blob/master/modules/pam_unix/pam_unix_sess.c): 공개 로그 형식·주체/대상 UID 의미만 참고했다. 외부 코드 복사 없음.

세부 실행 결과 및 미검증 사항: [검증 기록](archive/validation/p5_03_attack_detection_validation.md).
