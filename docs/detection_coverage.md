# Cloud SOC Detection Capability and Coverage

2026-09-10 / 제품 설계 제안. 순서: 분석가 질문 -> 필요한 탐지 기능 -> Telemetry/필드 -> 로컬 규칙 -> 검증 -> 조사 화면. 새 Rule을 작성/배포하지 않았다.

## 1. 탐지 기능부터 정의

필요성/예시는 목표 제품 기준이다. 현재 엔진 지원 대조는 문서 마지막에 별도로 기록한다.

| Capability | 필요성 / SOC 활용 | 필요한 데이터/실행 계약 | MVP |
| --- | --- | --- | --- |
| Single Event Rule | 의미가 강한 민감 설정/권한 변경을 즉시 검토 | 검증된 action/outcome/주체/대상, rule version, 이유/근거 | MUST |
| Threshold Detection | 반복/대량 행동을 개별 경보 대신 집계 | counting unit, 필터, threshold, 중복 이벤트 정책 | MUST |
| Time Window | 탐지 범위를 명확히 설명 | event time/TZ, 경계 포함 여부, 허용 지연, watermark | MUST, 독립 시나리오가 아닌 실행 기능 |
| Grouped Threshold | 다른 자산/계정의 정상 활동을 잘못 합산하지 않음 | scope+Host/Account/Source 같은 그룹 키, 결측/고 cardinality 처리 | MUST |
| Sequence Detection | 실패 뒤 성공, 변경 뒤 실행 등 순서를 확인 | stable join key, stage order, maxspan, late/out-of-order, state persistence | SHOULD: 하나의 검증된 사례 |
| Correlation Detection | 여러 신호/소스에서 하나의 조사 가설 구성 | 관계의 증거, 시간, entity scope, correlation reason/version | Target; MVP는 **수동 Incident 연결**, 자동 엔진 아님 |
| Absence Detection | 기대되는 활동/수집이 사라졌는지 확인 | 기대 schedule, heartbeat/poll/완료 범위, grace period | Health 정책은 MUST; 보안 이벤트 부재 탐지는 SHOULD |
| Rare/New Behavior | 처음 보는 principal/resource 동작을 후보화 | 보존된 baseline, first_seen 정확성, warmup/retention, 최소 표본 | COULD; 데이터 수집 첫날을 전부 공격으로 표시 금지 |
| Risk-based Correlation | 약한 여러 신호를 자산 중요도와 합쳐 우선화 | calibrated weights, decay, Entity resolution, 근거 추적, 정답 평가 | OUT OF SCOPE for first MVP |
| Indicator Match | 유효한 CTI 지표와 관측 연결 | indicator source/validity/TLP, observed time, normalized value | COULD, match가 악성 확정은 아님 |

상용 제품의 다양한 rule type은 기능 분리의 근거이며 구현 우선순위 자체는 프로젝트 제안이다. [Elastic Rule type guides](https://www.elastic.co/docs/solutions/security/detect-and-alert/rule-types), [연구/제품 비교](siem_reference_research.md).

## 2. Alert 품질 계약

모든 탐지는 `rule_id/version/hash`, `run_id`, 목적/설명, domain, severity, required_sources/fields, group/count semantics, window, allowed lateness, suppress/dedup policy, evidence refs를 제공한다.

- 탐지 이유는 규칙 제목 복사가 아니라 **어떤 값이 어떤 조건을 충족했는지**다.
- `match_count`는 실제 정의된 단위를 센다. auth.log 여러 줄을 로그인 시도 한 번으로 환산하려면 별도 세션/시도 식별 계약이 필요하다.
- single-event는 정확한 원본 1건, threshold는 실제 일치 집합, sequence는 순서별 근거와 join key를 보존한다.
- 탐지 창과 근거의 earliest/latest를 구분한다. 5분 규칙의 이벤트 간격이 20초일 수 있다.
- 파싱/Source 결측으로 조건을 평가하지 못하면 no match가 아니라 unsupported/partial/failed 상태다.
- 일치하지만 억제한 경우 count와 정책 이유를 남긴다. Suppression은 데이터 삭제 또는 정탐/오탐 판정이 아니다.

## 3. ATT&CK 기준과 버전 정책

기준: **ATT&CK Enterprise v19.2**, 확인일 2026-09-10. [Version History](https://attack.mitre.org/resources/versions/), [2026-08-06 release](https://attack.mitre.org/resources/updates/updates-august-2026/).

v18에서 legacy Data Sources가 deprecated되었다. 새 설계의 `data_source_matrix.md`는 프로젝트의 실제 수집 소스 목록이지 deprecated ATT&CK DS 객체를 새로 구현하는 것이 아니다. [공식 안내](https://attack.mitre.org/datasources/).

```text
Security Domain / Analyst question
                 |
Technique (catalog version, object version, revoked/deprecated flag)
                 |
Detection Strategy --> platform-specific Analytic
                 |
Data Component + Log Source / channel requirements
                 |
Local telemetry + field mapping + engine capability
                 |
Local Rule/version + test evidence + current run/source health
                 |
Alert / Incident / Investigation / Coverage workspace
```

ATT&CK 객체 버전과 전체 catalog 버전은 다르다. 로컬 Rule version도 별개다. 구 ID가 변경/폐기되면 이전 경보의 매핑을 덮어쓰지 않고 mapping revision으로 보존한다. v19의 Defense Impairment 등 새 tactic 구조를 사용하며 예전 Matrix 크기를 하드코딩하지 않는다.

## 4. 도메인별 탐지/조사 연결

`후보`는 미구현 로컬 설계다. `부분 관측`은 Technique/Analytic 전체 구현이 아니라는 뜻이다. 아래 표에 없는 도메인이 안전하다는 뜻도 아니다.

| Domain / 질문 | ATT&CK / 공식 Strategy·Analytic | Required Telemetry / Data Component | Detection Type / 로컬 후보 | Investigation / Workspace | 범위/검증 주의 |
| --- | --- | --- | --- | --- | --- |
| Cloud IAM / 미승인 권한 추가인가 | T1098.003 / DET0277 / AN0771 | Cloud Audit, principal/role/policy/resource; DC0010 User Account Modification | single event + 승인/중요도 context; 이후 sequence | MC -> IW 변경 원문 -> EN Account/Resource | 공식 AN0771의 AWS 등 의미를 OCI로 **자체 매핑**. 같은 API명 복사 금지 |
| Cloud Visibility / 기록이 의도적으로 꺼졌는가 | T1685.002 / DET0289 / AN0801 | logging configuration API + 독립 Health, 설정 대상/변경자/응답 | single + absence corroboration | IW 이유/설정 -> PH 영향 소스 -> DC 영향 Rule | 로그 없음만으로 방해 공격 확정 금지. OCI Audit 자체 비활성 API가 있다고 가정하지 않음 |
| Authentication / 반복 실패와 후속 접근은 | T1110.001 / DET0551 / AN1522 | Linux auth, DC0002 User Account Authentication | grouped threshold; sequence는 후속 | IW exact matches -> EN Host/Account -> HT 성공/후속 검색 | threshold만 있으면 AN1522 전체 충족 표시 금지 |
| Host / sudo가 악용됐는가 | T1548.003 / DET0052 / AN0142 | auditd exec/command + uid/euid + sudo 정책; Process Creation/Command Execution 계열 | 조건 일치 single + sequence | IW command timeline -> EN Host/Account | 정상 sudo는 기본 악성 아님. 설정/권한/명령 맥락 필요 |
| Network / 서비스 탐색이 있었는가 | T1046 / DET0376 / AN1058 | auditd Process Creation DC0032 + Network Traffic Flow DC0078 | grouped distinct count + optional sequence | EN 자산 간 흐름 -> IW 프로세스 근거 | VCN Flow만이면 process 부분 관측 불가, authorised scanner 구분 |
| Web / 요청이 침해로 이어졌는가 | T1190 / DET0080 / AN0220 | Web/Application Log DC0038 + Process Creation DC0032 + network egress | multi-signal sequence/correlation | IW request/error/process/egress timeline | 404/500 증가만으로 exploit 성공 확정 금지 |

공식 대응 관계 확인 URL: [DET0277](https://attack.mitre.org/detectionstrategies/DET0277/), [DET0289](https://attack.mitre.org/detectionstrategies/DET0289/), [DET0551](https://attack.mitre.org/detectionstrategies/DET0551/), [DET0052](https://attack.mitre.org/detectionstrategies/DET0052/), [DET0376](https://attack.mitre.org/detectionstrategies/DET0376/), [DET0080](https://attack.mitre.org/detectionstrategies/DET0080/). 확인일 2026-09-10. 위 로컬 매핑/필드/우선순위는 공식 분석 로직의 완전한 복제가 아니라 제안이다.

T1685.002는 현행 `Disable or Modify Cloud Log`다. 과거 T1562.008을 그대로 신규 매핑에 사용하지 않는다. [현재 Technique](https://attack.mitre.org/techniques/T1685/002/). DC ID를 확인하지 못한 행은 계열 이름/로컬 필드 요구만 썼고 임의 ID를 만들지 않았다.

## 5. Coverage의 다섯 축

하나의 녹색/빨강 Matrix나 coverage %로 합치지 않는다.

| 축 | 가능한 값 | 근거 |
| --- | --- | --- |
| 매핑 | unmapped / proposed / reviewed | ATT&CK catalog/object/mapping version와 검토자 |
| Telemetry readiness | missing / partial / ready | 실제 Source+필드 계약, 마지막 검증, 수집 범위 |
| Rule implementation | not implemented / disabled / enabled | 실제 배포 Rule revision, 기능 지원 여부 |
| Validation | untested / failed / passed / stale | 정상/이상/반증 시험, 일시/데이터/환경/결과 |
| Operational health | unknown / healthy / delayed / down / idle / not configured | 최근 detector run과 필요한 source 상태; 비활성/미설정을 장애와 구분 |

`enabled + mapped`만으로 validated coverage가 아니다. 테스트 통과도 모든 공격 변형/속도/플랫폼을 탐지한다는 뜻이 아니다. 분모가 정의된 선택 use case 집합에서만 `검증된 use case X/Y`를 표시하고 전 세계 Technique 전체에 대한 방어율로 표현하지 않는다.

## 6. 검증 기준과 Fatigue 통제

| 시험 | 확인해야 할 결과 |
| --- | --- |
| 정상/승인된 활동 | benign 또는 no alert가 정책과 일치; 실제 정답/근거 보존 |
| 정확히 임계값 전/도달/초과 | counting unit과 경계가 문서와 일치 |
| 창 경계/UTC/TZ/동일 타임스탬프 | 누락/이중 집계 없이 결정적 결과 |
| 서로 다른 Host/tenant의 같은 IP/username | 그룹이 의도치 않게 합쳐지지 않음 |
| 재전송/재실행/재시작 | 동일 근거의 경보 중복 억제, 처리 진행 복원 |
| 늦은/순서 뒤바뀐 이벤트 | lateness 정책에 따른 재평가/미지원 표시 |
| source/필드 누락, Rule failure | no threat/0건이 아닌 실패/결측 상태 |
| Evidence 보존기간/삭제 | expired/missing 상태와 조사 제한 표시 |
| Suppression/cooldown | 적용 사유/범위/개수 가시성, 새로운 독립 활동 누락 검토 |
| 자동 correlation 후보 | 사람이 검토한 묶기/분리 정답과 비교, 오연결률 확인 |

MVP에서 고급 ML/risk-based correlation보다 single/threshold의 설명 가능성, 범위 정확성, 재시작 안정성을 먼저 확보한다. 연구(P2/P6/P8)의 해석 가능성/원래 신호 보존 원칙을 적용한 우선순위다. [연구 검토](siem_reference_research.md).

## 7. 현재 구현 대조

외부 조사/목표 설계 후 2026-09-10 작업 트리를 읽기 전용으로 확인했다. 실행 시험이나 새 Rule 배포는 하지 않았다. `지원`은 코드 존재이며 운영 검증 완료를 뜻하지 않는다. 상세 코드 근거와 신뢰성 Gap은 [로드맵 §3~4](implementation_roadmap_v2.md)에 있다.

| Capability | 현재 지원 여부 / 코드 근거 | 부족한 계약 | MVP 도입 순서 |
| --- | --- | --- | --- |
| Single Event Rule | 독립 유형 미지원. engine의 threshold=1로 일부 조건을 흉내 낼 수 있음 | rule_loader가 group/window/threshold를 필수 요구하고 cooldown 의미가 남음 | MUST, Phase C에서 명시적 유형/근거 계약 추가 |
| Threshold Detection | 지원: engine.py의 detect_rule, deque 길이와 count 비교 | unique event/attempt 구분, 재처리/영속 상태/시험 | MUST, 현재 기반 재사용 |
| Time Window | 지원: event-time 정렬, 차이 300초 이하는 창에 포함 | 늦은 도착, durable watermark, timezone 품질 | MUST, B/C에서 신뢰성 보강 |
| Grouped Threshold | 지원: group_by 목록의 tuple key | 조직/네트워크 범위 자동 격리 없음, 결측/배열/대량 그룹 계약 | MUST, 기존 AUTH-001의 cross-host 의미는 승인 없이 변경 금지 |
| Sequence | 미지원: AND는 한 이벤트 안의 조건이며 순서 단계가 아님 | stage/join/maxspan/복원/반증 | SHOULD, F에서 한 사례 |
| Correlation | 자동 엔진 미지원 | 여러 Alert/Event/Source 간 관계 근거 | D에서 수동 사건 연결 MUST, 자동 엔진 후속 |
| Absence | 보안 부재 탐지/Source health evaluator 모두 미지원 | 기대 schedule, poll/heartbeat 성공 여부 | B/C의 Health MUST, 보안 부재 탐지는 SHOULD |
| Rare/New | 미지원 | baseline/최초 관측/보존 경계 | COULD, F 이후 |
| Risk-based | 미지원. rule severity는 risk score가 아님 | 설명 가능한 결합/정답 검증 | 첫 MVP OUT OF SCOPE |
| Indicator Match | 전용 지표 저장소/유효기간/매칭 미지원 | 단순 equals/in 연산자만으로 CTI capability 충족 불가 | COULD, F 이후 |

현재 AND 연산자는 `equals/not_equals/contains/in/greater_than`이다. 필드 결측에서 `not_equals`가 참이 될 수 있고, 결측 group/time은 제외되며 통계가 남지 않는다. 타입별 평가 불가와 실제 조건 불일치를 분리해야 한다. Rule loader의 safe_load/필수값 검증은 유지할 기반이다.

Cooldown은 구현되어 있다. YAML의 미구현을 암시하는 TODO 주석보다 engine.py 327~430행을 근거로 판정했다. 다만 **한 detect_rule 호출 내 그룹별 상태**이며 프로세스/증분 배치 사이의 영속 suppression은 아니다. 같은 입력을 다시 계산한 뒤 Alert ID로 재저장하는 효과와 suppression 상태 보존을 혼동하지 않는다.

### AUTH-001의 위치

```text
Authentication domain
  -> Linux auth telemetry (classic sshd subset)
  -> event.category contains authentication
     AND event.outcome equals failure
     AND network.protocol equals ssh
  -> group by source.ip
  -> >=10 matched log events within 300s, 300s in-call cooldown
  -> security-alerts (high, T1110 metadata)
  -> read-only Kibana alert overview
```

[현재 규칙](../rules/authentication.yml)은 상위 Technique **T1110 Brute Force**를 기록한다. 위 §4의 **T1110.001/DET0551/AN1522/DC0002는 검토할 세부 대응 후보**이며 기존 규칙을 변경했다는 뜻이 아니다. 반복 실패를 관측하지만 후속 성공/정상 사용자 맥락/전체 플랫폼 analytic을 구현하지 않았으므로 `AN1522 완전 구현` 또는 `ATT&CK 전체 방어`로 표시하지 않는다.

현재 기능의 의미는 일치 로그 수 기반 인증 이상 신호다. 공격자 개인, 로그인 시도 횟수, 계정 탈취 성공을 확정하지 않는다. 여러 Host를 향한 동일 IP도 합산되며 scope는 자동 분리되지 않는다. 향후 조직 격리는 필수지만 Host별로 규칙 의미를 바꿀지는 별도 결정이다.

현황 판정: mapping=기존 T1110 태그/세부 후보 proposed, telemetry=SSH 부분 관측, implementation=YAML enabled, validation=이번 정적 검토로 passed 판정 불가, operational health=UNKNOWN. 10,000건 조회 한도와 exact evidence 누락을 해결하기 전 최신 로그 전체 탐지나 근거 재현을 보장하지 않는다.
