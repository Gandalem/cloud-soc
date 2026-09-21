# Cloud SOC Analyst Workflow

2026-09-10 / 목표 업무와 MVP 제안. 실제 경보를 생성하거나 사건을 변경하는 실행 지침이 아니다. 역할은 Analyst, Lead, Data/Detection Engineer로 구분하지만 학생 팀원이 겸임할 수 있다.

근거: [외부 조사](siem_reference_research.md)의 Elastic Timeline/Case(E2/E3), Sentinel Incident(M2), Splunk Queue(S2), Google Investigation(G2/G4)와 구조화된 Triage/설명 가능성 연구(P2/P3/P8)를 종합한 자체 업무 흐름이다. 특정 제품의 절차를 그대로 복사하지 않는다.

## 1. 업무 흐름

```text
Start shift / scope & handover
           |
Check PH source/pipeline confidence
           | degraded -> record limitation / notify engineer
           v
MC: Incident queue + untriaged Alert queue
           |
Claim work / explain priority
           |
IW: read detection reason + exact evidence
           |
Timeline <--> EN: stable entity / related activity
           |
HT: hypothesis / query / supporting & contradicting evidence
           |
Record verdict + rationale + scope + uncertainty
           |
Escalate / recommend response / verify authorized manual action
           |
Close or keep open -> handover -> rule/data improvement request
```

모든 경보를 반드시 Incident로 만드는 것은 아니다. 단일 경보에서 정상 업무가 명확히 설명되면 AlertReview에 근거를 기록하고 종결한다. 여러 신호/영향 범위를 조사하거나 인계할 필요가 있으면 Incident를 만든다. Hunt에서도 경보 없이 사건을 시작할 수 있도록 Target 모델을 둔다.

## 2. 단계별 작업과 데이터

| 단계 | 담당/상황 | 화면과 필요한 데이터 | 실제 행동 | 저장/종료 조건 |
| --- | --- | --- | --- | --- |
| W01 범위·인계 | 근무 시작 Analyst | MC/IW: scope, 미처리 업무, 전 교대 메모, 담당 | 오늘 볼 환경/계정과 인계 대상을 확인 | scope와 인수 업무가 명확 |
| W02 신뢰도 확인 | 업무 시작/경보 급감 | PH: heartbeat/poll, Stage 결과, 지연, 마지막 검사 | UNKNOWN/DELAYED/DOWN을 구분하고 영향을 받는 도메인 확인 | 사건 판단에 사용한 데이터 한계를 기록 |
| W03 Triage | 새 Alert/Incident 도착 | MC: priority_reason, severity, asset criticality, queue_entered_at, owner | 먼저 처리할 이유를 보고 인수; 같은 업무 중복 인수 방지 | 담당 저장 확인, 버전 충돌 시 다시 읽기 |
| W04 대상 정의 | 경보가 실제 조사 대상인가 | IW-S/IW-R: rule version, reason, window, match count, scope | 규칙의 의도와 관측이 일치하는지 확인 | 조사 가설과 우선 확인할 사항 |
| W05 근거 검토 | 탐지 조건 재현 | IW-E: 당시 event refs, Raw, 파서/시간 품질 | 원본과 정규화 값을 비교, 누락/중복 여부 확인 | supports/refutes/context와 이유 |
| W06 시간 맥락 | 전후 활동/실제 영향 불명 | IW-T: 원래 탐지 창 및 전후 30분, 이벤트/TZ | 실패 뒤 성공, 변경 뒤 실행 등 순서를 검토 | 인과는 추정인지 확인인지 표시 |
| W07 Entity pivot | 영향 자산/계정 확장 | EN: stable key, scope, alias validity, 관련 활동 | Host/Account/Resource를 확인하고 IP-only 연관을 검증 | 새 관련 대상과 증거/불확실성 |
| W08 Hunting | 규칙 밖의 활동 확인 | HT: 가설, source/time/entity filters, 결과/누락 | 검색 범위를 명시하고 반증도 찾음 | query snapshot, 실행 시각, 결과 refs, 결론 |
| W09 Incident 구성 | 여러 경보/이벤트 공동 조사 | IW: incident links, 묶는 이유, 시간/대상 | 수동 생성/연결. 중복 사건 여부 확인 | 사건 ID와 링크/작성자/이유 |
| W10 판단 | 판단에 필요한 근거 확보 | IW-W: verdict, confidence/limitations, notes | malicious/benign/false_positive/inconclusive 구분 | rationale과 근거, 미해결 질문 |
| W11 인계/대응 | 권한/전문성 밖 또는 위험 큼 | IW-W: 영향, 조치 제안, 담당/승인 | Lead/대응 담당에게 전달, 승인 없는 차단 금지 | 인계 받는 사람과 수락/추가 요청 |
| W12 종료/재개 | 조치·조사 완료 또는 보류 | IW-W: 확인 결과, 최종 판정, 잔여 위험 | 종결 기준 점검. 미해결 고위험은 유지/상향 | closed_at, close_reason, audit; 재개 사유 |
| W13 개선 | 정상 반복/필드 누락/검증 부족 | DC/PH: rule/source/test와 사건 refs | 튜닝·소스·파서 개선 작업 제안 | 담당/검증 기준, 자동 규칙 변경 금지 |

## 3. 분류와 상태는 서로 다른 축

| 값 | 의미 | 필요한 근거 |
| --- | --- | --- |
| malicious | 실제 악성 활동으로 판단 | 관측 근거, 영향 범위, 공격 시도와 성공 여부 구분 |
| benign | 규칙이 관측한 현상은 맞지만 정당한 업무 | 변경 승인/운영자 확인/서비스 맥락 등의 근거 |
| false_positive | 탐지 의도가 성립하지 않음 | 파서 오해석, 집계 오류, 잘못된 조건 등 반증 |
| inconclusive | 자료/권한/시간 범위 부족으로 판정 불가 | 부족한 정보, 요청할 담당/자료, 다음 확인 조건 |

`new/investigating/escalated/closed`는 처리 상태다. `high`는 severity 또는 priority 등급이다. `false_positive`는 상태가 아니라 verdict다. 공격이 차단되었다고 benign은 아니며, 실제 악성 시도라도 피해가 없을 수 있다. 대응 성공이나 계정 침해 여부는 별도 기록한다.

MVP에서는 Verdict 대신 표시되는 임의 `risk score`나 LLM 자동 결론을 만들지 않는다. 재현 가능한 텍스트 이유와 evidence 링크를 우선한다.

## 4. 표준 조사 기록 템플릿

```text
Object: Alert/Incident ID, scope, reviewer, server time
Question: What is being investigated, and why now?
Reason: Rule version, condition, window, grouping key, matched count
Evidence: Exact references checked; supports/refutes/context
Timeline: Relevant before/after activity and timezone
Entities: Stable IDs, uncertain aliases/relationships
Hypothesis: Alternatives considered; hunt query/time/results
Decision: Verdict, rationale, impact/attempt/success distinction
Limitations: Missing source, retention, permission, clock, parser
Action: Requested/approved/executed/verified separately
Handover: Owner, next action, remaining question, review condition
```

일괄 자동 생성된 긴 메모가 아니라 각 질문에 답하는 간결한 기록을 요구한다. 원본 전체를 메모에 복사해 개인정보/용량을 늘리지 않고 접근 통제된 참조를 쓴다.

## 5. 우선순위 정책 제안

초기 Incident priority는 연결 Alert의 최고 severity에서 시작하되 `rule severity based`라고 출처를 표시한다. Alert 없는 Hunt 사건은 Analyst가 이유와 함께 등급을 정한다. 자산 중요도, 권한 수준, 지속 활동, 검증된 악성 근거를 보고 사람이 조정한다. 미등록 자산을 낮은 중요도로 가정하지 않는다.

기본 큐는 priority 높은 순, queue_entered_at 오래된 순이다. 업무 등록 후 경과 시간과 이벤트 first_seen을 구분한다. `unassigned`, `owned by me`, `escalated`, `oldest` 보기를 제공한다. 대기 시간/SLA는 승인된 운영 기준이 있을 때만 위반으로 표시하며 평가용 시간을 운영 의무로 오기하지 않는다.

## 6. 실패/불확실성 처리

- Raw 만료/삭제: `evidence expired/missing` 표시, 사건에 제한 기록, 관련 로그를 원래 근거라고 대체하지 않는다.
- 소스 미연동: 그 도메인을 `NOT CONFIGURED`로 표시하고 해당 활동의 부재를 부정 증거로 쓰지 않는다.
- 수집 오류: 사건 조사 자체는 가능한 데이터로 계속할 수 있지만 결론의 범위를 제한한다. 오류를 경보 0건으로 표시하지 않는다.
- 같은 IP, 다른 계정/Host: 자동 사건 병합을 중지하고 관계 근거를 요구한다.
- 동시 편집: 저장 충돌을 알리고 새 상태/차이를 확인한 뒤 다시 저장한다. 조사 메모를 잃지 않게 한다.
- 브라우저/서버 오류: 저장 성공 응답이 없으면 저장된 것으로 표시하지 않는다. 안전한 idempotency/retry가 필요하다.

## 7. MVP 업무 시연과 평가

시연은 허가받은 실습 환경에서 실제 생성/수집한 데이터로 한다. 이번 설계 작업에서는 데이터를 생성하지 않았다.

| 시연 경로 | 재현할 핵심 업무 | 합격 증거 |
| --- | --- | --- |
| Cloud API 변경 조사 | MC -> IW -> Cloud Account/Resource -> Raw -> 판정 | 변경 주체/대상/결과, 승인 맥락, 판정 메모 |
| 인증 이상 조사 | Alert -> IW -> Host/Account -> 전후 정상/이상 활동 | 탐지 일치 이벤트와 related activity의 구별 |
| 정상 업무/오류 구분 | 같은 규칙 경보에서 benign과 false_positive 이유 비교 | 두 verdict가 다른 근거로 기록됨 |
| 데이터 장애 | PH -> 영향 Rule 확인 -> 조사 제한 기록 -> 복구 확인 | 0건, IDLE, UNKNOWN, DOWN의 구분 |
| 협업 인계 | 담당 변경 -> 추가 조사 -> 종료 -> 재시작/재조회 | 이력/근거/판정이 보존됨 |

초기 평가는 2~3명의 팀원으로도 가능하지만 통계적 일반화를 하지 않는다. 정확한 근거 확인과 업무 완료를 1순위, 조사 시간과 클릭 수를 보조 지표로 삼는다.
