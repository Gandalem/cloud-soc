# Cloud SOC SIEM Reference Research

확인일: **2026-09-10 (KST)**. 목적: 현재 SSH 데이터에서 기능을 역산하지 않고 SOC 업무와 외부 근거로 제품을 설계한다. 아래는 제품 구매 평가나 성능 벤치마크가 아니라 공개 문서 기반 기능/업무 비교다.

## 1. 조사 방법과 근거의 강도

조사 순서: SOC 업무 자료 -> 제품 공식 문서 -> NIST/ATT&CK -> 학술 연구 -> 목표 업무/화면/모델/탐지/Telemetry 정의 -> 저장소 대조. 현재 구현의 대조 결과는 [로드맵](implementation_roadmap_v2.md)에 별도 기록한다.

- 공식 문서는 **제품이 문서화한 기능**의 근거이지 효과가 실증되었다는 근거가 아니다. 라이선스, 배포 방식, 버전, 연동 범위가 다르다.
- 논문은 목적/방법/관측 결과/한계를 분리했다. 논문의 실험 수치를 Cloud SOC 예상 성능으로 사용하지 않는다.
- 본 문서의 `적용`과 다른 새 문서의 요구사항은 **조사에서 도출한 Cloud SOC 설계 제안**이다. 표준이 특정 화면이나 DB를 의무화한다고 주장하지 않는다.
- 검색 요약만으로 논문 결론을 확장하지 않았다. P1은 학회 초록, P2~P8은 본문 또는 본문의 관련 절까지 확인했다. P8은 저자 공개본이며 DIMVA 2026 accepted 표시는 저자 메타데이터 기준이다.
- IBM 일부 문서의 직접 본문 열기가 실패했다. Q1~Q5는 공식 검색 색인에 제공된 본문 발췌와 공개 문서 정보 범위만 사용했다. 설치 실험, 영상 전체 시청, 유료 기능 검증은 하지 않았다.
- 일반 블로그/커뮤니티 주장을 설계의 핵심 근거로 사용하지 않았다. 모든 아래 URL의 확인일은 위 날짜다.

## 2. SOC 업무에서 출발한 공통 문제

SOC 분석은 경보의 존재 확인으로 끝나지 않는다. 고객/자산에 대한 관련성, 실제 이벤트, 전후 맥락, 공격 영향에 대한 근거를 모아 판단하고 인계해야 한다. 구조화된 T1 분석을 평가한 연구와 사건 관리 문서는 그 흐름을 뒷받침한다. [P3], [M2]

경보 품질 문제에는 잘못 탐지한 경우뿐 아니라 규칙은 맞았지만 정상 업무였던 경우가 섞인다. 이를 모두 오탐으로 묶으면 튜닝 피드백도 왜곡된다. [P2]

**Cloud SOC에 대한 추론:** 작업 큐, 탐지 이유, 근거 원본, Entity pivot, 조사 기록을 연결하고, 데이터가 없거나 수집 상태를 모를 때 결론을 강요하지 않는다. 번아웃은 도구 외 조직/인력 요인도 있으므로 UI만으로 해결했다고 주장하지 않는다. [P1]

## 3. 상용 제품 조사

### 3.1 Elastic Security

| 조사 영역 | 확인한 구조 | Cloud SOC에 적용할 점 |
| --- | --- | --- |
| Security Overview / Dashboards / Alerts | 개요와 Alerts를 구분하고 이벤트 맥락으로 조사한다. [E1], [E5] | 집계 화면과 실제 업무 큐를 구분 |
| Investigations / Timeline | Alert, Host, Network 등의 필드로 Timeline 검색을 구성하고 원본 이벤트와 경보를 함께 조사한다. [E3] | 시간/Entity 조건을 유지하는 pivot |
| Cases | 경보, 이벤트, Timeline, 조사 기록을 사건에 연결한다. [E2] | 탐지 결과와 업무 기록의 수명 분리 |
| Hosts / Users / Entity Analytics | Host/User 탐색과 Entity 위험 분석은 구별된다. 위험 점수 활성화 및 구독 조건이 있다. [E4], [E5] | Entity 목록을 위험 점수 엔진으로 가장하지 않음 |
| Detection Rules | Query, Threshold, EQL, New terms, ML, Indicator match 등 탐지 유형을 구분한다. [E6] | 범용 엔진 capability부터 정의 |
| Ingestion / Integrations / Data Quality | 다양한 소스를 연동하고 ECS 호환성을 검사한다. [E1], [E7] | 수집 성공, 매핑 호환, 최신성은 다른 상태 |

흐름은 `Alert -> Timeline/Entity 조사 -> Case 기록`으로 구성할 수 있지만 고정된 단방향 마법사가 아니다. 사건에서 이벤트/Entity로 다시 이동할 수 있다. **Kibana 사용자 정의 인덱스의 경보가 Elastic Security 네이티브 Alert/Cases로 자동 호환되는 것은 아니다.** 이식성은 별도 스키마/권한 검증이 필요하다. 마지막 문장은 Cloud SOC 통합에 대한 설계 제약이다.

### 3.2 Microsoft Sentinel

| 조사 영역 | 확인한 구조 | Cloud SOC에 적용할 점 |
| --- | --- | --- |
| Incidents / Alerts / Triage | Incident 안에 Alerts, Entities, 활동 이력을 모아 분류/조사한다. [M1], [M2] | Incident와 Alert ID/상태를 독립 모델로 둠 |
| Investigation / Entities | 사건 맥락에서 Timeline, Entity 정보, 관련 검색으로 이동한다. [M2] | 조사 중 필터/근거를 잃지 않는 이동 |
| Workbooks / Hunting | 시각 보고용 Workbook과 능동 검색/Hunt는 별개다. [M3], [M5] | 차트를 Hunting 대체물로 사용하지 않음 |
| Analytics Rules / Automation | 탐지와 사건 자동화 규칙, Logic Apps Playbook을 구분한다. [M1] | 탐지의 사실과 대응 실행 결과 분리 |
| Data Connectors / Health / Audit | 연결 상태/탐지 실행 상태와 변경 감사를 별도로 수집한다. 일부 Health는 지원 Connector에 한정된다. [M4], [M6] | 성공적으로 실행된 0건과 실행 실패 구별 |

Azure portal 조사 문서와 Defender portal 문서를 혼동하지 않는다. 공식 개요는 Azure portal 지원 종료를 **2027-03-31 이후**로 안내한다. 본 설계는 이동 경로나 메뉴 명칭을 복제하지 않고 Triage -> Investigation -> Response -> Incident Management의 의미를 사용한다. [M1]

### 3.3 Splunk Enterprise Security

| 조사 영역 | 확인한 구조 | Cloud SOC에 적용할 점 |
| --- | --- | --- |
| Mission Control / Analyst Queue | Findings, Finding Groups, Investigations를 큐에서 다룬다. Intermediate Finding은 직접 큐에 표시하지 않는다. [S1], [S2] | 모든 탐지 신호를 즉시 업무로 만들지 않음 |
| Findings / Notable / Detection | 8.x 문서의 Finding 용어와 구버전 Notable 중심 문서를 구분한다. [S2], [S5] | 제품 용어에 독립적인 내부 모델 |
| Prioritization / Risk | 담당/미배정/위험 점수 등의 뷰와 정렬을 제공한다. [S3] | 근거 있는 우선순위, 담당자, 오래된 미처리 항목 |
| Investigations / Workflow | Finding을 조사에 넣고 할당·억제·Playbook 실행을 한다. [S2] | 묶기와 억제를 구분하고 이력 보존 |
| Assets / Identities / Data Models / Security Posture | 자산/신원 문맥과 도메인별/운영 감사 대시보드가 별도로 존재한다. CIM/Data Model 계층을 사용한다. [S4], [S6] | 정규화/문맥 계층을 화면에서 분리 |

8.4 관리 문서, 8.5 Mission Control 개요, 8.1 정렬/대시보드 자료를 구분해 참고했다. Finding Group은 관련 신호의 묶음이며 Investigation과 동의어가 아니다. Splunk 점수의 숫자를 가져와 Cloud SOC의 위험 확률로 사용할 근거는 없다.

### 3.4 IBM QRadar

| 조사 영역 | 확인한 구조 | Cloud SOC에 적용할 점 |
| --- | --- | --- |
| Event Collector | 수집/정규화/동일 이벤트 coalescing 후 전달한다. [Q1] | 수집 어댑터와 downstream 처리의 책임 분리 |
| Event Processor / Console | Processor의 이벤트 처리와 Console의 조사/운영 기능을 구분한다. All-in-One 배치도 있다. [Q1], [Q2] | 논리 계층 분리와 물리 마이크로서비스 분리는 다름 |
| Offenses / Events / Flows / Rules | 규칙으로 관련 이벤트/흐름을 Offense에 연결하고 세부 이벤트 및 payload를 조사한다. [Q4] | 원본 없이 요약만 남기지 않음 |
| Asset information / Priority | Magnitude는 relevance, severity, credibility와 자산 등 맥락을 반영한다. [Q3] | 심각도와 업무 우선순위는 별도 |
| Coverage | Use Case Manager는 규칙과 로그 소스/ATT&CK 매핑을 다룬다. [Q5] | 수집한 로그와 실제 탐지 가능성을 연결 |

Offense는 사건과 비슷한 조사 단위지만 일반 Case 모델과 동일하지 않다. Full packet capture/Forensics, SOAR, 앱 기능을 기본 Event/Flow 저장과 동일시하지 않는다. Q4의 오래된 UI 예시는 조사 의미만 참고하며 현재 메뉴를 보장하지 않는다.

### 3.5 Google Security Operations

| 조사 영역 | 확인한 구조 | Cloud SOC에 적용할 점 |
| --- | --- | --- |
| UDM / Raw | 원본 로그와 구조화된 UDM 표현을 구별한다. [G1] | 원본 참조 및 파서 버전 유지 |
| Detection / Alerts / Investigation | 규칙, 관련 이벤트, Entity 그래프, 변경 이력을 조사한다. [G2] | 탐지 이유와 근거의 명시적 연결 |
| Search / Hunting / Timeline | UDM 검색에서 이벤트와 관련 Entity를 탐색한다. [G3] | 탐지되지 않은 이벤트 검색도 보장 |
| Cases / Grouping | 관련 Finding을 Case로 다룬다. Enhanced Cases는 Alert, 비경보 Detection, Event를 구분한다. [G4] | 업무 단위와 신호 유형을 분리 |
| Data Health | Health Hub는 수집/파싱/지연 정보를 제공한다. [G5] | Health를 경보 건수에서 추정하지 않음 |

**G4 Enhanced Cases와 G5 Health Hub는 확인 당시 Pre-GA 문서**다. 모든 고객에게 이미 동일하게 제공되는 GA 기능으로 취급하지 않는다. G4의 `Detection=alerting off signal`은 Google 제품 용어다. Cloud SOC의 Detection 실행/일치 결과 정의와 억지로 동일시하지 않는다.

## 4. Capability 비교

`별도`는 별도 화면/앱/설정 또는 연동, `부분 확인`은 공개 근거 범위를 뜻한다. 체크 표시를 이용한 기능 동등성/우열 점수는 사용하지 않는다. 각 열은 위 제품 절의 출처를 따른다.

| Capability | Elastic | Sentinel | Splunk ES | QRadar | Google SecOps | Cloud SOC 적용 제안 |
| --- | --- | --- | --- | --- | --- | --- |
| Alert | Detection Alert E1 | Alert M1 | Finding/Intermediate S2 | CRE 관련 이벤트 Q4 | Alert/Detection G2/G4 | 신호와 업무 상태 분리 |
| Incident/Case | Case E2 | Incident M2 | Investigation S1 | Offense Q4 | Case G4 | 수동 Incident부터 |
| Analyst Queue | Alerts/Cases E1/E2 | Incidents M2 | 혼합 객체 큐 S2 | Offenses Q3 | Cases queue G4 | Incident/미분류 Alert 탭 |
| Investigation | Timeline/Cases E2/E3 | Incident context M2 | Investigation S1 | Offense Summary Q4 | Alert/Case G2/G4 | 근거 우선 Workbench |
| Entity | Host/User/Service E4 | Entity M2 | Asset/Identity S4 | Asset/IP Q1/Q3 | UDM Entity G1/G2 | scope가 있는 ID |
| Timeline | 전용 workspace E3 | 사건 chronology M2 | Queue timeline S1 | 시작/마지막/이벤트 Q4 | 검색/Case history G2/G3 | 발생·수집·업무 시각 분리 |
| Raw Evidence | Timeline events E3 | 로그 pivot M2 | 도메인 원시검색 S4 | Payload Q4 | Raw/UDM G1 | 불변 참조+조회 권한 |
| Hunting | Timeline/query E3 | Hunting M3 | SPL/domain search S4 | Event/Flow search Q4 | UDM search G3 | Discover 재사용 |
| Detection Rules | 다양한 rule type E6 | Analytics M1 | Event/Finding detection S1/S5 | CRE Q4 | Detection rules G2 | capability 계약 |
| Correlation | EQL/기타 E6 | Alert->Incident M1 | Finding Group S2 | Offense 연결 Q4 | Alert grouping G4 | 자동 묶기 후순위 |
| ATT&CK | Rule metadata E1/E6 | Coverage M1 | Finding metadata S5 | Use Case Manager Q5 | 본 조사에서 coverage UI 미확인 | 데이터/시험 연결표 |
| Asset/User Context | Hosts/Users E4/E5 | Entities/watchlists M1/M2 | Asset/Identity S4 | Asset weight Q3 | Entity enrichment G2 | 명시된 중요도/출처 |
| Data Health | ECS 검사 E7 | Health/Audit M4/M6 | 운영/모델 감사 S4 | 수집/관리 계층 Q1, 상세 알림 미확인 | Health Hub G5 Pre-GA | 6상태+실패 원인 |
| Workflow | Case/notes E2 | Owner/tasks/history M2 | Assign/investigate S2 | Offense 조사 Q4 | Case history G4 | 상태/판정/담당/감사 |
| Automation | Case workflows E2 | Rules/Playbooks M1 | Playbooks S2 | 별도 앱, 기본 범위 미평가 | Case Playbooks G4 | 수동 승인 없는 차단 제외 |

공통점: 다중 소스 정규화, 검색, 탐지 신호, 관련 문맥, 조사 기록이 연결된다. 차이점: Case/Incident/Offense/Investigation의 생성·묶기·종료 정책, 신호의 중간 계층, 위험 점수 방식, 배포/라이선스가 다르다. 따라서 제품들의 명칭을 1:1 복제하지 않는다.

## 5. NIST 검토

- **SP 800-92 (2006 Final)**: 로그 인프라, 수집/분석/보존/운영 프로세스의 기반 자료다. 오래된 암호/프로토콜 예시는 현재 구현 권장값으로 복사하지 않는다. [N1]
- **SP 800-92 Rev.1 (2023 Initial Public Draft)**: 확인한 발행 페이지는 여전히 초안이며 NIST 프로젝트 페이지는 의견 처리 중이라고 설명한다. 최종판으로 오기하지 않는다. 계획 중심 자료로 사용한다. [N2], [N3]
- **SP 800-61 Rev.3 (2025 Final)**: Rev.2를 대체하며 CSF 2.0 관점으로 사고대응을 위험 관리에 연결한다. 화면의 사건 처리 완료를 복구 완료와 동일시하지 않는다. [N4]

| 로그 수명 단계 | 확인한 방향 | Cloud SOC에서 제안하는 검증 가능한 계약 |
| --- | --- | --- |
| 생성/수집 | 필요한 로그와 책임을 계획 N1/N2 | Source Registry에 목적·관리자·이벤트/필드 계약 |
| 전송 | 기밀성/무결성/가용성 고려 N1 | 인증된 전송, 재시도, durable checkpoint, 드롭 계수 |
| 저장/보존 | 순환/보관/폐기 정책 N1/N2 | 승인된 기간, 용량 예산, incident evidence 보존 충돌 처리 |
| 검색/분석 | 접근·분석 절차 N1 | 시간/소스/Entity 검색, 원본 pivot, 부분 결과 표시 |
| 무결성 | 변조/삭제 위험 관리 N1 | 원본 해시+권한+버전+감사. 해시만으로 진본성 보장 불가 |
| 운영 상태 | 지속적인 운영/검증 N1 | backlog/오류/마지막 성공/측정 누락을 분리 |
| 사고 처리 | 탐지·대응·복구 연결 N4 | 판단 근거, 인계, 조치·복구 확인 및 학습 항목 |

보존 일수나 업무 SLA를 법적 의무처럼 임의 지정하지 않는다. 졸업작품의 수치는 시험 조건과 운영 정책 제안으로만 사용한다.

## 6. MITRE ATT&CK 최신 구조

확인한 현행 콘텐츠는 **v19.2**, 2026-08-06 Agile release다. v19에서는 기존 Defense Evasion 분류가 Stealth와 Defense Impairment로 분리되었다. 버전 고정 없이 예전 tactic 수나 technique ID를 복사하면 잘못된 coverage가 된다. [A1], [A2], [A8]

Data Sources는 v18에서 **deprecated**되었으며 역사 자료로 남는다. 현재 설계는 `Technique -> Detection Strategy -> platform Analytic -> Data Component/Log Source -> 로컬 Rule/필드/시험`으로 이어진다. Data Component까지 폐기되었다고 해석하지 않는다. [A3], [A4], [A5]

예를 들어 T1110.001에는 DET0551/AN1522와 DC0002 인증 데이터가 연결된다. 클라우드 권한 추가는 T1098.003/DET0277/AN0771을 참고할 수 있지만 AWS 등의 구체 API를 OCI에 그대로 적용할 수 없다. OCI 매핑은 자체 검증이 필요한 **로컬 해석**이다. [A6], [A7]

`Rule에 Technique 태그가 있음`은 `Technique 전체 탐지가 검증됨`이 아니다. [Coverage 설계](detection_coverage.md)에서 매핑·Telemetry·구현·시험·현재 건강도를 각각 표시한다.

## 7. 학술 자료 검토

아래 8개는 서로 다른 연구다. 제목 속 숫자나 제한된 실험 결과를 전체 SOC의 일반적인 비율로 사용하지 않는다.

| ID / 제목 / 연도 / 매체 | 목적과 확인 범위 | 활용 가능한 결과 | 설계 반영 및 한계 |
| --- | --- | --- | --- |
| P1. A Human Capital Model for Mitigating Security Analyst Burnout (2015, SOUPS) | 6개월 현장 연구 및 다른 SOC fieldnotes 검토. 학회 초록 확인 | 번아웃에 인력·기술·관리 요인의 순환 관계가 관여 | 인계 기록·반복작업 감소. UI 개선만으로 번아웃 해소 주장 금지 |
| P2. 99% False Positives: A Qualitative Study of SOC Analysts' Perspectives on Security Alarms (2022, USENIX Security) | 설문 n=20, 질적 연구 n=21. 본문 §5~7 확인 | false alarm과 benign trigger 구분, REACT 품질 속성 제안 | 탐지 이유/원본/문맥/재현 가능 판단. 제목의 99%는 모든 SOC 측정값 아님 |
| P3. 'Give Me Structure': Synthesis and Evaluation of a (Network) Threat Analysis Process Supporting Tier 1 Investigations in a Security Operation Center (2023, SOUPS) | 상용 SOC와 과정 설계, T1 10명 평가. 본문 §4~8 확인 | 구조화한 관련성·문맥·공격 근거 분석이 해당 실험의 판단 정확도에 도움 | Workbench 조사 체크포인트/인계 템플릿. 소규모 특정 환경 결과, 자체 효과 검증 필요 |
| P4. Cybersecurity knowledge graphs (2023, Knowledge and Information Systems) | 지식 표현·시각화·데이터 융합 검토. 본문 §6~7 확인 | 관계는 조사 맥락에 유용하지만 큰 그래프는 가독성을 해칠 수 있음 | 기본은 관계 테이블, 명시적 edge와 시간 범위, 그래프는 선택. Graph DB 필수라는 결론 아님 |
| P5. Evolving techniques in cyber threat hunting: A systematic review (2024, Journal of Network and Computer Applications 232, 104004) | 117개 선정 논문, 본문 §3/§7~8 확인 | 가설 수립·반복 조사 중요성, 데이터/라벨/전문인력 제약 | Saved Hunt에 가설·쿼리·기간·결과·반증/한계. ML부터 도입하지 않음 |
| P6. An approach to the correlation of security events based on machine learning techniques (2013, Journal of Internet Services and Applications) | 정규화/분류/융합 후 meta-alert 평가. §3.3/§4/결론 확인 | 시간·의미 조건을 가진 묶기와 원래 경보의 보존이 해석을 지원 | grouping 이유/정책 버전/해제 이력. 논문도 복합 다단계 공격 지원 한계 명시, 최신 클라우드 효과로 일반화 금지 |
| P7. Intrusion detection and Big Heterogeneous Data: a Survey (2015, Journal of Big Data) | 이종 탐지 데이터와 규모 문제 검토. SIEM/분산 구조 절 확인 | 다중 소스 활용과 중앙 처리 병목/신뢰성 문제가 함께 존재 | 파서/정규화 계약과 backpressure 관측. 졸업작품에 분산 클러스터 의무화하지 않음 |
| P8. Can SOC Operators Explain their Decisions while Triaging Alarms? A Real-World Study (2026, DIMVA accepted 저자 공개본) | 문헌 검토와 실제 SOC n=12. 공개 HTML 본문 확인 | 올바른 분류와 올바른 이유 설명이 일치하지 않을 수 있음 | Verdict와 rationale/evidence를 별도로 평가. 저자본 상태를 명시하고 보편적 정확도 수치 주장 금지 |

주제 연결: SIEM architecture=P7/P6, SOC workflow=P1/P3, security visualization/cyber situational awareness=P4, alert fatigue=P1/P2, triage/prioritization=P2/P3/P8, correlation=P6, hunting=P5, explainable alerts=P2/P8. 자동 순위 모델의 우월성이나 상용 SIEM 전체 성능을 입증한 조사로 취급하지 않는다.

## 8. 설계 결정으로 연결

| 결정 | 왜 필요한가 | 근거 | 후속 문서/결과 |
| --- | --- | --- | --- |
| D01 Queue 중심, 경보/사건 분리 | 업무와 신호 수 혼동 방지 | E2/M2/S2/G4 | MC-Q, Incident/Alert 모델 |
| D02 Reason/Evidence 우선 | 맞는 판단뿐 아니라 설명 가능해야 함 | P2/P3/P8 | IW-R/IW-E, immutable evidence refs |
| D03 Context 보존 pivot | 화면 이동마다 조사 재시작 방지 | E3/M2/G3 | QueryContext 계약 |
| D04 투명한 수동 우선순위 | 출처 없는 위험 점수 방지 | S3/Q3/P2 | severity/criticality/age/reason 분리 |
| D05 데이터·탐지 건강도 독립 | 0건/미실행/누락 구분 | M4/M6/G5/N1 | Health 6상태와 coverage 운영 상태 |
| D06 검색 재사용 | Query UI 재개발보다 업무 연결에 집중 | E3/M3/G3/P5 | Kibana Discover + Hunt metadata |
| D07 계층은 넓게, 배포는 작게 | 모든 제품 기능의 복제는 일정 위험 | Q1/Q2/P7 | Target/MVP 별도 구성 |
| D08 클라우드 제어면 포함 | 서버 인증만으로 IAM/API 변경 조사 불가 | O1/O2 | 최소 두 도메인 Telemetry 검증 |

## 9. 출처 목록

각 ID는 본문의 주장 바로 옆에서 사용한다. 아래 URL은 모두 2026-09-10 확인. 제목은 식별용이며 긴 원문 인용은 포함하지 않는다.

### 제품 공식 자료

- E1: [Elastic Security solution & project type overview][E1]
- E2: [Cases for Elastic Security][E2]
- E3: [Timeline][E3]
- E4: [Entity Analytics dashboard][E4]
- E5: [Elastic Security UI][E5] (구 guide 경로의 공개 UI 설명)
- E6: [Rule type guides][E6]
- E7: [Data Quality dashboard][E7]
- M1: [What is Microsoft Sentinel SIEM?][M1]
- M2: [Microsoft Sentinel incident investigation in the Azure portal][M2]
- M3: [Hunting capabilities in Microsoft Sentinel][M3]
- M4: [Auditing and health monitoring in Microsoft Sentinel][M4]
- M5: [Visualize your data using workbooks][M5]
- M6: [Monitor the health of your data connectors][M6]
- S1: [Overview of Mission Control in Splunk Enterprise Security][S1] (8.5)
- S2: [Manage analyst workflows using the analyst queue][S2] (8.4)
- S3: [Sort and filter findings and investigations for triage][S3] (8.1, 공식 색인 발췌)
- S4: [Available dashboards in Splunk Enterprise Security][S4] (8.1)
- S5: [Monitor your SOC with findings][S5] (8.1, 공식 색인 발췌)
- S6: [About the architecture][S6] (Splunk Developer)
- Q1: [QRadar components][Q1] (7.5.0, 공식 색인 발췌)
- Q2: [Overview of supported virtual appliances][Q2] (7.5.0, 공식 색인 발췌)
- Q3: [Offense prioritization][Q3] (7.5, 공식 색인 발췌)
- Q4: [Investigating threats in QRadar][Q4] (7.3.3, 역사적 조사 예시)
- Q5: [QRadar Use Case Manager app][Q5] (별도 앱, 공식 색인 발췌)
- G1: [UDM overview][G1]
- G2: [Investigate alerts][G2]
- G3: [Understand search][G3]
- G4: [Investigation and case management overview][G4] (Enhanced Cases, Pre-GA)
- G5: [Monitor health of data sources][G5] (Health Hub, Pre-GA)

### 표준/ATT&CK/Telemetry

- N1: [NIST SP 800-92, Guide to Computer Security Log Management][N1] (2006 Final, PDF §2~5도 확인)
- N2: [NIST SP 800-92 Rev.1, Cybersecurity Log Management Planning Guide][N2] (2023 IPD)
- N3: [NIST Log Management project][N3] (개정 진행 상태)
- N4: [NIST SP 800-61 Rev.3][N4] (2025 Final)
- A1: [ATT&CK Version History][A1]
- A2: [ATT&CK Updates - August 2026][A2]
- A3: [ATT&CK Data Sources deprecation notice][A3]
- A4: [ATT&CK Detection Strategies][A4]
- A5: [ATT&CK Analytics][A5]
- A6: [DET0551 Password Guessing via Multi-Source Authentication Failure Correlation][A6]
- A7: [DET0277 Detection Strategy for Role Addition to Cloud Accounts][A7]
- A8: [ATT&CK Updates - April 2026][A8] (v19 tactic 구조 변경)
- E8: [ECS Event fields][E8] (발생/관측/중앙 수신 시각 의미, Architecture에 적용)
- O1: [OCI Overview of Audit][O1]
- O2: [Contents of an Audit Log Event][O2]
- O3: [Details for VCN Flow Logs][O3]
- O4: [Viewing Audit Log Events][O4]
- O5: [OCI Identity Audit Log Report][O5] (인증 이벤트 별도 확인 필요)

### 학술 자료 원문/학회 페이지

- P1: [Sundaramurthy et al., A Human Capital Model for Mitigating Security Analyst Burnout][P1], SOUPS 2015, pp.347-359.
- P2: [Alahmadi, Axon, Martinovic, 99% False Positives][P2], USENIX Security 2022, pp.2783-2800. [PDF](https://www.usenix.org/system/files/sec22-alahmadi.pdf).
- P3: [Kersten et al., 'Give Me Structure'][P3], SOUPS 2023, pp.97-111. [PDF](https://www.usenix.org/system/files/soups2023-kersten.pdf).
- P4: [Sikos, Cybersecurity knowledge graphs][P4], 2023. DOI: 10.1007/s10115-023-01860-3.
- P5: [Mahboubi et al., Evolving techniques in cyber threat hunting][P5], 2024. DOI: 10.1016/j.jnca.2024.104004. [대학 저장소의 출판본 PDF](https://researchoutput.csu.edu.au/ws/portalfiles/portal/526139166/526056422_Published_article.pdf).
- P6: [Stroeh, Madeira, Goldenstein, An approach to the correlation of security events based on machine learning techniques][P6], 2013. DOI: 10.1186/1869-0238-4-7.
- P7: [Zuech, Khoshgoftaar, Wald, Intrusion detection and Big Heterogeneous Data: a Survey][P7], 2015. DOI: 10.1186/s40537-015-0013-4.
- P8: [Moosmann, Pekaric, Apruzzese, Can SOC Operators Explain their Decisions while Triaging Alarms? A Real-World Study][P8], 2026. arXiv:2604.22001v1, 저자 페이지에 DIMVA accepted 명시. [공개 본문](https://arxiv.org/html/2604.22001v1).

[E1]: https://www.elastic.co/docs/solutions/security
[E2]: https://www.elastic.co/docs/solutions/security/investigate/security-cases
[E3]: https://www.elastic.co/docs/solutions/security/investigate/timeline
[E4]: https://www.elastic.co/docs/solutions/security/dashboards/entity-analytics-dashboard
[E5]: https://www.elastic.co/guide/en/security/current/es-ui-overview.html
[E6]: https://www.elastic.co/docs/solutions/security/detect-and-alert/rule-types
[E7]: https://www.elastic.co/guide/en/security/current/data-quality-dash.html
[E8]: https://www.elastic.co/docs/reference/ecs/ecs-event
[M1]: https://learn.microsoft.com/en-us/azure/sentinel/overview
[M2]: https://learn.microsoft.com/en-us/azure/sentinel/incident-investigation
[M3]: https://learn.microsoft.com/en-us/azure/sentinel/hunting
[M4]: https://learn.microsoft.com/en-us/azure/sentinel/health-audit
[M5]: https://learn.microsoft.com/en-us/azure/sentinel/monitor-your-data
[M6]: https://learn.microsoft.com/en-us/azure/sentinel/monitor-data-connector-health
[S1]: https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.5/mission-control/overview-of-mission-control-in-splunk-enterprise-security
[S2]: https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.4/mission-control/manage-analyst-workflows-using-the-analyst-queue-in-splunk-enterprise-security
[S3]: https://docs.splunk.com/Documentation/ES/8.1.0/Admin/FilterFindings
[S4]: https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.1/analytics/available-dashboards-in-splunk-enterprise-security
[S5]: https://docs.splunk.com/Documentation/ES/8.1.0/Admin/UsingFindingsIntermediateFindings
[S6]: https://dev.splunk.com/enterprise/docs/devtools/enterprisesecurity/abouttheessolution
[Q1]: https://www.ibm.com/docs/en/qsip/7.5.0?topic=overview-qradar-components
[Q2]: https://www.ibm.com/docs/en/qsip/7.5.0?topic=vai-overview-supported-virtual-appliances
[Q3]: https://www.ibm.com/docs/en/qsip/7.5?topic=management-offense-prioritization
[Q4]: https://www.ibm.com/docs/en/qsip/7.3.3?topic=app-investigating-threats-in-qradar
[Q5]: https://www.ibm.com/docs/en/qradar-on-cloud?topic=apps-qradar-use-case-manager-app
[G1]: https://docs.cloud.google.com/chronicle/docs/event-processing/udm-overview
[G2]: https://docs.cloud.google.com/chronicle/docs/investigation/investigate-alert
[G3]: https://docs.cloud.google.com/chronicle/docs/investigation/udm-search
[G4]: https://docs.cloud.google.com/chronicle/docs/secops/investigate/investigation-management/investigation-management-overview
[G5]: https://docs.cloud.google.com/chronicle/docs/reports/data-health-monitoring-and-troubleshooting-dashboard
[N1]: https://csrc.nist.gov/pubs/sp/800/92/final
[N2]: https://csrc.nist.gov/pubs/sp/800/92/r1/ipd
[N3]: https://csrc.nist.gov/projects/log-management
[N4]: https://csrc.nist.gov/pubs/sp/800/61/r3/final
[A1]: https://attack.mitre.org/resources/versions/
[A2]: https://attack.mitre.org/resources/updates/updates-august-2026/
[A3]: https://attack.mitre.org/datasources/
[A4]: https://attack.mitre.org/detectionstrategies/
[A5]: https://attack.mitre.org/analytics/
[A6]: https://attack.mitre.org/detectionstrategies/DET0551/
[A7]: https://attack.mitre.org/detectionstrategies/DET0277/
[A8]: https://attack.mitre.org/resources/updates/updates-april-2026/
[O1]: https://docs.oracle.com/en-us/iaas/Content/Audit/Concepts/auditoverview.htm
[O2]: https://docs.oracle.com/en-us/iaas/Content/Audit/Reference/logeventreference.htm
[O3]: https://docs.oracle.com/en-us/iaas/Content/Logging/Reference/details_for_vcn_flow_logs.htm
[O4]: https://docs.oracle.com/en-us/iaas/Content/Audit/Tasks/viewinglogevents.htm
[O5]: https://docs.oracle.com/en-us/iaas/Content/Identity/reports/audit-log.htm
[P1]: https://www.usenix.org/conference/soups2015/proceedings/presentation/sundaramurthy
[P2]: https://www.usenix.org/conference/usenixsecurity22/presentation/alahmadi
[P3]: https://www.usenix.org/conference/soups2023/presentation/kersten
[P4]: https://link.springer.com/article/10.1007/s10115-023-01860-3
[P5]: https://www.sciencedirect.com/science/article/pii/S1084804524001814
[P6]: https://link.springer.com/article/10.1186/1869-0238-4-7
[P7]: https://link.springer.com/article/10.1186/s40537-015-0013-4
[P8]: https://arxiv.org/abs/2604.22001
