# Security Mall 탐지 규칙 4단계

2026-10-16 로컬 구현·격리 검증 완료. 기존 single/sequence 엔진, 규칙 로더, 증분 상태/지연 처리, 경보 ID 및 create-only 저장 계약을 재사용한다. 실습/운영 ES에 경보를 쓰거나 탐지 워커를 배포하지 않았다.

## 규칙과 초기 설정

`rules/security_mall.yml`에서 임계값을 관리한다.

| 규칙 | 조건 | 초기 severity |
| --- | --- | --- |
| WEB-ACCESS-01 | security-mall의 인식된 감사 이벤트, order_view/failure/order/not_owner | low |
| WEB-AUTH-01 | 동일 organization/service/account_id/account_key_id/source.ip의 실패군5건/300초 후 해당 실패군 마지막 시각으로부터600초 안의 성공 | medium |

일반 HTTP403, 다른 자원·사유·서비스·어댑터는 WEB-ACCESS-01 대상이 아니다. 접근 차단은 데이터 유출 성공으로 표현하지 않는다. 각 별도 원본 거부 이벤트는 low로 기록하며 반복에 따른 자동 상향은 이번 범위에 넣지 않았다. 현 감사 이벤트에는 주문 ID가 없으므로 같은 주문을 추정해 묶지 않는다.

WEB-AUTH-01의 `threshold.count`, `time_window.seconds`, `success_window.seconds`, `cooldown.seconds` 기본값은 각각5/300/600/900이다. 성공 시각은 증거 실패들보다 엄격히 뒤여야 하며 경계300/600초는 포함한다. 여러 실패군이 있으면 성공 전 유효한 가장 최근 실패군을 증거로 선택한다. 이후의 단독 실패가 유효한 앞선 실패군을 지우지 않는다. 성공은 실패 상태를 초기화하고, 같은 그룹의 경보 후900초 동안 후속 시퀀스 경보를 억제한다. 가명/키 버전이 없으면 계정을 추정하지 않는다.

`severity`와 기존 위험도 계산은 별도다. 기존 triage 수식을 수정하지 않아 WEB-ACCESS-01은20/low, WEB-AUTH-01은 medium severity에 sequence 요소15점이 더해져60/high risk band다. 계정 탈취 확정으로 표현하지 않는다.

## 기존 엔진 연결 및 중복

- 기존 sequence의 전체300초 의미는 그대로다. 명시적인 `success_window` 설정이 있는 규칙만 failure-success-v3로 실행하며 실패300초+성공 대기600초 동안 상태를 유지한다. 기존 SSH AUTH-SEQ-001은 v2/기존 의미를 유지한다.
- Mall 원본 관측 식별자는 organization/host/service/원본 event.id를 해시한다. 재수집 인덱스·정규화 문서·처리 시각이 바뀌어도 같은 원본을 실패 횟수에 중복 합산하지 않는다. 서로 다른 원본 UUID는 별도 시도다.
- 기존 `make_alert_id`에 선택적 관측 anchor를 연결했다. WEB-ACCESS-01은 거부 이벤트, WEB-AUTH-01은 성공 이벤트의 원본 관측이 anchor다. 같은 설정에서 증거가 다시 정규화되거나 추가 실패가 뒤늦게 포함돼도 해당 성공의 경보 ID는 같다. 기존 경보 create-only 저장은 최초 본문/증거를 보존한다. 다른 기존 규칙의 ID 계산은 유지한다.
- 경보 증거는 기존 normalized index/id와 `cloud_soc.provenance.raw` index/id, event_hash/complete 상태를 보존한다. 원문 비밀번호·쿠키·세션은 규칙이나 증거 본문으로 복사하지 않는다.
- 기본 AUTH-001 프로필은 바꾸지 않는다. 고정 규칙 카탈로그에 두 규칙을 등록했고 기존 `--additional-rules WEB-ACCESS-01,WEB-AUTH-01` 선택 경로를 사용할 수 있다. 별도 상태/status의 추가 워커는 AUTH-001 초기 통지를 소유하지 않는다. 이번에는 워커를 실행하지 않았다.

향후 실행하려면 기존 detector CLI에 두 ID와 새 전용 state를 명시해야 한다. 규칙/임계값·지연 설정 변경 시 기존 상태의 식별 검증이 새 상태 파일을 요구한다. 운영 체크포인트를 재사용·초기화하지 않는다. isolated_all 선택에는 새 두 규칙도 포함되므로 기존 isolated_all 상태를 임의 재사용하지 않는다.

## 수집 지연과 순서

배치 입력은 사건 시각으로 정렬한다. 증분 실행은 기존 normalized_at 기반 읽기/15분 overlap과 기본900초 lateness 버퍼를 재사용해 역순 수신을 사건 순서로 확정한다. 이미 확정된 frontier보다 늦게 도착한 사건은 late_event 제외 이력으로 남기며, 자동으로 이전 경보를 다시 쓰거나 계정 시퀀스를 추측하지 않는다. 이 범위를 넘는 지연까지 실시간 탐지를 보장하지 않는다.

## 검증 결과

- 3-C의 보호된 `normalized-search.json`을 읽기 전용 복사하여 먼저 검사했다. 실제 정규화4건 → WEB-ACCESS-01 **1**, WEB-AUTH-01 **0**, 완전한 원본 참조와 low severity를 확인했다. 3-C 빌드/수집/정규화/설치는 재실행하지 않았다.
- 합성 입력과 관련 회귀는 고유 시험 **49 passed**, 최종 failures/errors0이다. 실패1~4건/5건,300/600초 경계·초과, 계정/IP/조직/서비스/키 버전 분리, null 계정, 사건 역순·동일 시각, 성공 초기화,15분 cooldown과 SQLite 재시작/만료, 지연 역순 버퍼/late 기록, 정규화 재처리·create-only 최초 증거 보존, 기본 AUTH-001·SSH sequence·초기 통지/카탈로그 연결을 검증했다.
- 첫 실행38건은 통과했고10건은 기본 Windows pytest 임시 폴더 접근 거부로 setup에서 시작하지 못했다. 제품 코드를 바꾸지 않고 프로젝트의 새 전용 basetemp에서 해당10건만 실행해 통과했다. 추가로 cooldown 재시작/만료1건을 실행했다. 이미 성공한 시험은 반복하지 않았다.
- 신규 fixture는3-A normalize로 가상 감사를 정규화한다. 기존 전체 카탈로그 fixture도 새 규칙을 생성할 수 있도록 연결했다. 테스트 ES IO는 기존 대역, 상태는 임시 SQLite이며 실제 VM/운영 DB에는 쓰지 않는다. 전체 Python/UI/성능 시험은 실행하지 않았다.
- 이전 미커밋 파일은 Git 제외 `state/security-mall-detection-20261016/baseline` 및 해시 목록으로 보존했다. 실제4건 사본/검증 요약·JUnit은 같은 Git 제외 경로에만 있다. 실제 가명·계정 정보/인증 자료를 시험 fixture나 문서에 넣지 않았다. Git commit/push/PR/merge와 다음 단계 개발은 수행하지 않았다.
