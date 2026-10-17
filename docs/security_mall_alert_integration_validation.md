# Security Mall 4-C 실제 경보 통합 검증

2026-10-16, 실행 식별자 `20261016-f56deb49`. **실제 경보 저장 및 재조회 인수 완료.**
실습 VM의 Elasticsearch 9.5.2(`https://127.0.0.1:19200`, `soc-mall-es-lab`)만 사용했다.
쇼핑몰 빌드·3-C 수집·Filebeat 검증·기존 49건 테스트는 반복하지 않았다.

## 실행 경로와 격리

실제 `rules/security_mall.yml`을 기존 규칙 로더로 읽고 `detection.engine.detect_events`/
`detect_rule`, `pipeline.alerts.build_security_alert`, `elastic.repository.save_security_alert`를
독립 시험 프로세스에서 호출했다. 경보 저장은 기존 create-only 계약을 사용했다.
운영 Worker/Detector와 통지 프로세스는 실행하지 않았다.

Windows에 있던 프로젝트 모듈·규칙과 공식 Python 클라이언트(elasticsearch 9.5.1,
elastic-transport 9.4.2)의 실행 의존 파일을 격리 디렉터리로 복사하고 SHA256을 검증했다.
VM에 패키지 설치나 다운로드를 하지 않았다. TLS CA 및 호스트 검증을 유지했다.
관리자 인증은 새 인덱스·매핑·키 준비에만 사용했다. 실제 처리는 유효기간 2시간의 별도 키로
수행했다. 실제 데이터 키는 기존 원본·정규화 인덱스의 읽기와 새 경보 인덱스의
`create_doc`/읽기/메타데이터 조회만 허용했다. 합성 키는 새 합성 저장소에만 제한했다.
`index`/`write`/삭제/관리 권한으로 create-only 제약을 우회하지 않았다.

| 용도 | 인덱스 | 검증 후 문서 수 |
| --- | --- | ---: |
| 기존 3-C 원본(읽기 전용) | `soc-host-raw-mall-isolated-20261016-8a070063` | 4 |
| 기존 3-C 정규화(읽기 전용) | `soc-normalized-mall-isolated-20261016-8a070063` | 4 |
| 실제 입력의 경보 | `soc-mall-alerts-lab-live-20261016-f56deb49` | 1 |
| 합성 원본 | `soc-host-raw-mall-4c-synthetic-20261016-f56deb49` | 37 |
| 합성 정규화 | `soc-normalized-mall-4c-synthetic-20261016-f56deb49` | 37 |
| 합성 입력의 경보 | `soc-mall-alerts-lab-synthetic-20261016-f56deb49` | 1 |

경보 인덱스는 운영 초기 통지 대상과 분리했다. 이번에 만든 네 인덱스 외의 문서는 쓰지 않았다.

## 실제 Elasticsearch 검증 결과

| 검증 | 결과 |
| --- | --- |
| 실제 정규화 4건 처리 | WEB-ACCESS-01 1건, WEB-AUTH-01 0건 |
| 실제 경보 저장·조회 | create 성공 후 GET 본문 일치, 1건 |
| 합성 로그인 시퀀스 | WEB-AUTH-01 저장·조회 1건, WEB-ACCESS-01 0건 |
| 일반 HTTP 403 | 경보 0건 |
| 조직·계정·키 버전·IP 불일치 | 각 혼합 그룹 경보 0건 |
| cooldown | 각각 단독으로 유효한 두 시퀀스의 성공 간격 899초에서 두 번째 억제(설정 900초) |
| 동일 입력 재처리 | 실제·합성 경보 모두 기존 ID의 create 충돌 처리, 증가 0건 |
| 기존 경보 보존 | 재처리 전후 본문·문서 ID·버전·seq_no·primary_term 동일 |
| 기존 3-C 데이터 보존 | 원본·정규화 4건씩 본문·버전·seq_no·primary_term 동일 |

합성 37건은 유효 로그인 시퀀스 2개(12건), 서로 다른 그룹 경계를 시험하는 4개 묶음(24건),
일반 403 음성 사례(1건)다. Mall 합성 입력은 기존 정규화 함수를 재사용했다.
cooldown 상태를 JSON으로 저장·복원해 두 번째 시퀀스 억제를 확인했다.
이 결과는 실제 ES와 독립 실행 엔진의 통합 검증이며, 운영 증분 워커의 배포·장기 운용 검증은 아니다.

## 증거와 시각 계약

실제 경보의 증거 1개와 합성 경보의 증거 6개를 실제 ES에서 역조회했다.
`cloud_soc.provenance.evidence`의 normalized/raw index/id, 정규화 이벤트 해시,
정규화 문서의 raw 참조를 대조했다. 원본 UUID와 `event.id`, 조직·서비스,
가명 `account_id`·`account_key_id` 및 source IP의 일치를 확인했다.
규칙 ID·버전·스냅샷, 고정 탐지 사유, severity 및 계산 위험도도 저장 후 재조회했다.
접근 거부는 유출 성공, 로그인 시퀀스는 계정 탈취 확정으로 해석하지 않는다.

기존 경보 계약에서 서비스·계정 가명·키 버전·원본 이벤트 UUID는 경보의 독립 평면 필드가 아니다.
증거 참조를 통해 정규화 및 원본 문서에서 읽는다. 이 계약을 변경하거나 개인정보를 경보로 복사하지 않았다.

경보 `@timestamp`는 `detection.window_end`, 즉 조건을 충족한 **이벤트 시각**이다.
저장된 경보의 시각을 실제 증거 이벤트의 마지막 시각과 대조했다.
실행 평가 시각은 별도의 검증 보고서 `results/live.json`의 `evaluated_at`에 기록했다.
경보 시각을 실행 시각이나 중앙 수신 시각으로 간주하면 안 된다.

## Rule severity와 계산 위험도

| 의미 | 저장 필드 | WEB-ACCESS-01 | WEB-AUTH-01 |
| --- | --- | --- | --- |
| 규칙 severity | `cloud_soc.severity` | low | medium |
| 계산 점수 | `cloud_soc.risk_score` | 20 | 60 |
| 계산 등급 | `cloud_soc.risk_level` | low | high |

기존 `src/cloud_soc/detection/risk.py`의 `triage-v1`은 medium 기본 45점에 sequence 15점을
더하고 60점 이상을 high로 분류한다. 따라서 medium 규칙의 60/high는 기존 구조와 일치한다.
`cloud_soc.risk_factors` 및 규칙 스냅샷과 대조했으며 수식·등급 매핑은 변경하지 않았다.
위험 점수는 대응 우선순위이며 침해 확률을 의미하지 않는다.

## 증적과 보존

VM 증적 경로: `/home/kopo/soc-mall-lab/detection-4c/results/`.
`live.json`, `live-alert.json`, `synthetic.json`, `synthetic-alert.json`, `summary.json`에
실행·조회·검증 결과를 보관했다. 로컬 안전 요약은
`state/security-mall-alerts-4c-20261016/summary.json`이다. 실행 자료는 Git에서 제외했다.
인증 파일은 VM의 보호된 파일(0600)에만 보관하고 결과 파일에 인증 비밀값이 없는지 확인했다.
보고서에는 비밀번호·API Key·개인키·로그 원문을 싣지 않았다.

기존 Filebeat/Packetbeat 서비스는 inactive 상태 그대로였으며 쇼핑몰 PID 55637도 유지됐다.
Docker/서비스 변경, Slack 발송, UI 변경, Git commit/push/PR/merge를 수행하지 않았다.
이번 추적 대상 변경은 이 문서와 작업 추적 기록이다. 작업 추적 기록을 제외한 기존 변경 파일
35개가 사전 백업 SHA256과 모두 일치했고, diff 공백 검사도 통과했다.

## 대시보드 연동 시 필요한 사항

- 조회 대상 인덱스를 명시적으로 허용하고 조직별 읽기 권한·필터를 적용한다. 실습 경보 인덱스를 운영 대상으로 자동 확장하지 않는다.
- rule severity와 계산 점수·등급을 별도 항목으로 표시하고, 사건 시각과 수신·평가 시각의 의미를 구분한다.
- 증거 index/id 조회 시 조직 경계와 이벤트 해시를 확인하고 서비스·계정 가명·키 버전·원본 이벤트 UUID를 연결한다.
- 통지·운영 워커 활성화 및 UI 개발은 별도 단계다. 이번 검증에서는 실행하지 않았다.
