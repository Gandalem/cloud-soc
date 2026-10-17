# Security Mall 7-B 증거 기반 조사 우선순위

2026-10-17 최신 상태: **7-A/B 실제 ES 읽기 통합 검증 완료, 7-C 실제 Portal 고정 스냅샷 인수 완료**. 근거는 approved-20261017T105455Z-c289b4ba의 summary/lifecycle(exit0) 및 [실제 검증 기록](security_mall_ab_approved_console.md)이다. 6인덱스211문서·3종묶음8·원본/정규화105대조·증거해시1·격리SQLite12검사를 확인했다. 이번 정정은 저장 증거 대조만 수행했으며 ES 검증을 반복하지 않았다. 실제 AUTH60/반복 가산·실시간 발행·장애/재부팅 복구는 이 완료에서 추정하지 않는다.

로컬 구현 당시: 2026-10-17: **로컬 구현·관련 테스트 완료**. VM 배포·실ES 조회/쓰기·서비스 변경·Portal/API/UI 활성화는 미실행이다. Mall systemd 전환 및 장애·재부팅 검증은 보류를 유지한다.

## 기존 위험도·사건 모델과의 관계

기존 `detection/risk.py`의 triage-v1은 경보 위험도를 계산한다. low 기본20, medium 기본45에 sequence 가산15로 AUTH60/high가 된다. 이 계산과 규칙 severity, 경보 ID·증거 해시·중복 차단은 수정하지 않았다. 기존 CaseStore의 priority는 분석가가 수동 지정하는 사건 작업 값이므로 덮어쓰지 않는다.

새 버전은 `mall-triage-v1`이다. 7-A 결과와 기존 경보를 사용해 **별도 조사 큐**를 계산한다. 경보를 새로 탐지하거나 사건을 자동 생성하지 않는다. 동일 경보가 여러 요청 묶음을 참조해도 한 조사 항목이며 위험 점수를 합산하지 않는다.

추가 파일: `src/cloud_soc/triage/{__init__,policy,engine,store}.py`, `tests/test_security_mall_triage.py`, 이 문서. 변경 파일: 7-A `correlation/store.py`·`security_mall.py`, 해당 계약 회귀 테스트, 7-A 문서 및 작업 기록이다.

## 점수·가중치·구간

모든 조정값은 `triage/policy.py`의 불변 `Policy`에 모았다. 정책 내용 해시를 결과와 저장소 binding에 포함한다. 기존 위험도 수식과 별개다.

| 요소 | 기본 규칙 |
|---|---|
| 기본 점수 | 해당 기존 경보 risk_score 그대로 사용; 여러 경보의 합계 아님 |
| 독립 반복 가산 | WEB-ACCESS-01의 검증된 not_owner 증거에 한함 |
| 반복 범위 | 같은 scope·가명 account_id·account_key_id·관측 source.ip, 현재 경보 이전300초(양 끝 포함) |
| 독립 요청 근거 | ambiguous/unlinked가 아닌 묶음의 고유 웹 접근 event key; 같은 요청의 웹/WAF/앱은1건 |
| 반복 임계값/가산 | 독립 요청3건 이상이면 `(요청수-1)*5`, 최대15점 |
| AUTH 다중 요청 | 기존 sequence 위험도에 이미 반영됨. 다시 가산하지 않음 |
| 로그 종류·완전성·성공·WAF rule 개수 | 점수 가산0. 신뢰도·설명만 변경 |
| 증거 누락·검증 불일치 | 점수 차감0. 고위험 경보를 제외하지 않음 |
| 최종 점수 | `min(100, 기존 위험도 + 반복 가산)` |
| 구간 | critical80 이상 / high60 이상 / medium30 이상 / low30 미만 |
| 지연 표시 | 수신 시각이 발생 시각보다120초 초과 늦으면 delayed_evidence |

단일 실제 ACCESS형 경보는20/low, AUTH형 경보는60/high를 유지한다. 동일 계정/키/관측IP의 독립 ACCESS 요청3개가 확인된 가장 늦은 경보는20+10=30/medium이다. 앞선 경보에 미래 요청을 소급 가산하지 않는다. 같은 요청을 참조하는 경보가 둘이어도 반복 요청은1건이다. 웹 근거가 없는 앱 ID들만으로 독립 요청 수를 추정하지 않는다.

미경보 요청도 조사용 관측으로 유지하지만 새 경보를 만들지 않는다. 이 경우 `review_kind=unalerted_observation`, `base_risk_score=null`, 조사점수0/low다. 실제 행동의 위험도가0으로 평가됐다는 의미가 아니다.

## 위험도와 증거 신뢰도

| 필드 | 의미 |
|---|---|
| base_risk_score / original_severity / original_risk_level | 기존 경보 값, 불변 |
| triage_score / triage_priority | 새 조사 큐 정책의 값 |
| evidence_confidence=corroborated_metadata | 모든 경보 참조가 해시로 연결되고 해당 묶음의3종 증거가 존재 |
| limited | 참조는 연결됐지만 일부 종류 누락·unlinked/ambiguous 등 한계가 존재 |
| unverified | 경보 증거 누락·해시 미확인/불일치 또는 연결 근거 없음 |
| evidence_completeness | complete/partial/missing/ambiguous, 묶음 수·누락 종류·고유 검증/미검증 참조 수 |

confidence는 공격 성공 확률이 아니다. 원본 ES 문서를 다시 읽거나 원본 바이트 해시를 검사하지 않으므로 `raw_contents_not_reverified_by_triage`를 항상 남긴다. 7-A의 검증된 정규화 증거 메타데이터와 경보 해시 사이의 일치를 의미한다.

각 결과에는 앱 not_owner 등 권한 거부, HTTP403 원인 후보, WAF DetectionOnly 관측, 로그인 실패/성공을 별도로 표시한다. rule의 block action을 실제 차단으로 해석하지 않는다. WAF 증거가 없으면 차단 여부null, 현재 지원하는 DetectionOnly면false다. 로그인 성공·request_id·프록시 IP로 계정 탈취나 출처 인증을 확정하지 않는다. `origin_authenticated=false`, `compromise_confirmed=false`를 유지한다.

## 7-A 최소 계약 보완

7-A의 내용 해시 revision만으로는 순서를 알 수 없어 다음을 추가했다.

```json
{"revision_order":{"publisher_id":"발행 저장소의 고정 UUID hex",
                   "sequence":1,"binding_id":"서버 scope/정책 binding SHA-256"}}
```

`CorrelationStore`의 새 `revision_state`는 같은 SQLite 트랜잭션에서 실제 관측/경보 병합이 있을 때만 sequence를1 증가시킨다. 중복/no-op은 증가하지 않고 실패 배치는 sequence까지 롤백된다. snapshot의 데이터와 순번은 같은 읽기 트랜잭션에서 가져온다. 재개 시 publisher/순번을 유지한다.

기존7-A 전용4테이블 DB만 검증 후5테이블로 최소 업그레이드할 수 있다. 기존 증거는 유지하며 처음 publisher를 만들고 순번0부터 시작한다. 이번에는 **임시 테스트 DB에서만 업그레이드를 검증**했다. 실제 저장소를 변경하지 않았다. 다른 DB·다른binding은 사전에 거부한다. 경보 링크에는 기존 허용된 `evidence` 참조 목록도 포함해 7-B가 참조/해시 일치를 다시 확인할 수 있도록 했다.

내용 revision은 순서 메타데이터를 제외한 결정적 내용 해시다. 순서 메타데이터 없는 과거 snapshot을 7-B가 추측해서 수용하지 않는다. publisher/sequence는 전자서명이 아니며 **신뢰하는 로컬 7-A 처리 경로 전용 계약**이다. 브라우저·외부 입력이 이 값을 지정할 수 있는 API를 만들면 안 된다.

7-B는 기존 파서/7-A correlate로 snapshot을 재구성해 원래 scope·내용 revision·연결·허용 메타데이터와 일치하는지 확인한다. 이 검증은 기존 전체 ES _source의 hash를 새로 계산했다는 뜻이 아니다.

## revision 저장·교체

`TriageStore`는 별도 비공개 SQLite 파일의 settings/frames만 사용한다. 기존 CaseStore/Portal/7-A DB를 결과 저장용으로 열지 않는다. 다른 DB·손상·symlink/hardlink를 거부하고, Linux 소유권/비공개 모드를 요구한다. Windows ACL 및 Linux 권한 분기 실환경 시험은 별도다.

- 범위 키는 동일 organization/site/host/service 및 UTC `[start,end)`다. 최대30일 범위, 저장 frame 기본128개이며 한도 초과 시 실패한다. 자동 삭제/정리는 하지 않는다.
- source binding과 policy_id를 고정한다. 첫 정상 적용에서 publisher를 고정하고 이후 변경은 거부한다. 백업 복원/DB 재생성으로 publisher가 바뀌면 별도 검토·재설정이 필요하며 우회 옵션은 없다.
- 같은 순번/내용은 no-op, 작은 순번은 stale 거부, 같은 순번의 다른 내용은 conflict 거부다. 큰 순번의 새 snapshot만 해당 frame 전체를 교체한다. 다른 frame/다른 조직 저장소를 변경하지 않는다.
- BEGIN IMMEDIATE 안에서 발행자 검사·순번 검사·큐 JSON·revision 갱신을 처리한다. DB 오류 시 이전 큐와 순번을 함께 보존한다. 생성 시각이나 수신 순서로 최신을 추측하지 않는다.
- 경보 기반 조사 항목 ID는 scope+기존 경보 index/id로 산정한다. 지연 증거로 요청 묶음 ID가 바뀌어도 항목과 기존 사건의 경보 참조는 유지한다. 미경보 관측 항목은 임시 증거 기반 ID이므로 재분할 시 달라질 수 있다.

조회 범위는 경보 발생 시각으로 선택한다. AUTH가 참조하는 앞선 요청이나 반복성300초 lookback의 증거는 범위 밖이어도 같은 scope에서 보강 근거로 사용한다. 세 로그나 여러 요청을 단일 공격 횟수로 합산하지 않는다. `independent_request_count`는 확인된 웹 관측 하한이며 0이면 실제 요청이0건이라는 뜻이 아니다.

## 7-C 제공 인터페이스와 데이터

이번에는 HTTP route를 추가하지 않았다. 향후 기존 Portal 경보/사건 읽기 API에 다음 로컬 인터페이스를 연결할 수 있다.

```python
# 신뢰하는 처리기 전용. snapshot은 같은 서버의 CorrelationStore.snapshot(principal) 결과.
queue.replace(snapshot, start, end)
# 서버가 인증 후 만든 기존 LogPrincipal만 사용. 클라이언트가 Scope/index/principal을 지정하지 않음.
result = queue.queue(start, end, principal)
item = queue.item(item_id, start, end, principal)
```

`queue()`는 점수 내림차순→발생 시각 오름차순→고정ID 순으로 정렬한다. 타 조직/저장되지 않은 범위는 items빈목록, 타 조직/존재하지 않는 항목은 같은 `triage_not_found`다. 원문 증거 조회는 기존 Operations의 조직·원문 권한 검사를 그대로 거쳐야 한다.

루트: schema_version1, version, scope, range, correlation_revision, revision_order, policy_id, items.

| items 필드 | 계약 |
|---|---|
| id / review_kind | 기존 경보 기반 고정ID 또는 미경보 관측ID / alert 또는 unalerted_observation |
| triage_score / triage_priority | 0~100 / critical·high·medium·low |
| base_risk_score / original_severity / original_risk_level | 원 경보 값, 없으면null |
| rule_ids / linked_alert_ids | 기존 규칙 ID 및 경보 index/id; 기존 사건 참조를 대체하지 않음 |
| evidence_confidence / evidence_completeness | 신뢰도·완전성, 공격 성공 확률 아님 |
| contributing_factors / uncertainty_factors | 고정 코드와 점수/요청 수/참조, 누락·모호성·지연·출처/시계 한계 |
| linked_request_ids / linked_request_bundle_ids | 실제 상관 ID / 현재 revision의 묶음 ID, 별도 개념 |
| independent_request_count / repeated_independent_request_count | 웹 증거 하한 / 시간·가명·키·IP 일치 반복 관측 수 |
| evidence_references | 원본/정규화 index/id, event_id(미확인null), event_hash, ingested_at, 검증 상태 |
| behavior | 로그인/앱 거부/403/WAF 진단과탐지 관측 수, 권한거부 사유·403 원인 후보, DetectionOnly/차단/출처 한계 |
| correlation_revision / range / occurred_at / explanation | 추적·범위·정렬 시각·고정 템플릿 설명 |

비밀번호·계정명·쿠키·원본 공격 문자열·원문 message/rule msg·임의 설명 입력을 복사하지 않는다. 설명은 고정 문구·규칙 ID·숫자로만 작성한다. 정책 변경은 기존 결과를 조용히 재해석하지 않고 새policy binding의 검토된 저장소/재처리 계획을 요구한다.

## 검증과 미완료 사항

7-B 전용43건 통과, 이후 미경보 위험도null 표현에 영향받는3건만 재확인해 통과했다. 7-A 순서/증거 계약 관련 기존10건도 통과했다. 합계 고유53사례이며 기존전체49건/전체Python·UI/VM 시험은 반복하지 않았다. 실제 normalize·detector·경보 생성 계약을 재사용한 합성 이벤트와 임시 SQLite를 사용했다.

변경 대상 Python8파일의 Pyflakes 진단0이다. 기존main152파일/mall11파일 해시를 대조해 승인된 기존5파일 변경만 확인했고 두 Git 브랜치를 유지했다. 비밀 없는 검사·코드SHA 기록은 Git 제외 `state/security-mall-triage-7b-20261017/verification.json`에 있다.

다음은 로컬 구현 당시 남은 항목 기록이며 실제 ES 미실행이라는 과거 상태는 위 최신 결과로 대체한다. 당시 후속 단계에서 exact site/index binding, 전체 정규화 _source 증거 hash 일치, 실제 경보 위험도 불변, 최신 snapshot 발행/재개·백업복원 정책, publisher 인계, 서비스별 권한/CA, ES 증거 보존기간 만료·지연, 실제 큐 비용과 Portal 조직 API/원문 권한을 확인해야 한다. 정책 점수는 초기 실습 설정이며 운영 효과·공격 성공 확률을 검증한 모델이 아니다.
