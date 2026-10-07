# P2-03 수집 품질 계측

## 현재 범위

2026-10-07: Linux Filebeat와 Windows/Linux Packetbeat의 큐·전송 통계 판독 및 상태 보고/API 계약을 로컬에서 구현했다. **배포·실제 새 통계의 중앙 수신·Packetbeat 화면 표시는 아직 검증하지 않았다.** P2-03 전체는 진행 중이다. P2-02 백업 저장소 대기는 유지한다.

팀원 통합 중인 `app.py`, 탐지/인증/공통 화면/CI는 변경하지 않았다. `packages.py`의 Ubuntu 파일 허용 목록과 `collection_health.py`의 추가 응답 필드는 통합 시 보존해야 한다.

## 무엇을 보고하는가

| 항목 | 의미 |
| --- | --- |
| `collector_metrics` | 해당 호스트 Filebeat의 마지막 완전한 구간 통계 |
| `network_collector_metrics` | 같은 PC/서버의 Packetbeat 구간 통계, 호스트 통계와 별도 |
| 큐 bytes/events/pct/max_bytes | 해당 표본에서 보고한 큐 게이지. 큐 파일 크기를 직접 재거나 큐를 변경하지 않음 |
| output total/acked/failed/dropped 등 | Beat가 통계 로그에 남긴 구간 변화량. 평생 누적 유실량이나 전체 패킷 수가 아님 |
| `last_problem_at` | 읽은 범위 내 최근 30분의 양수 오류 표본 시각. 원문 오류 내용은 전송하지 않음 |
| `scan_partial` | 판독 크기/개수 제한, 읽기 실패, 잘린 행 등의 제한이 존재함 |

지원하는 통계는 `monitoring` 로거, 일치하는 `service.name`, `Non-zero metrics in the last Ns` 형식뿐이다. 종료 시 `Total metrics` 누적 총계는 제외한다. 수치 누락/형식 오류는 `null`이며 0으로 추정하지 않는다. 보고하지 않은 오류가 없었다거나 무손실이라고 해석하면 안 된다.

서버 API는 표본이 5분 초과면 `stale`, 미래/보고 시각 불일치면 `clock_warning`으로 구분한다. 이때 현재 큐/전송 상태는 `unknown`이다. 최근 큐 사용률 80% 이상은 `high`이다. `observed`는 관측했다는 뜻이지 정상 인증·수신·캡처 또는 소스별 수신 성공이 아니다.

## 권한과 개인정보

- 기존 호스트 Filebeat가 `health.ndjson`을 읽어 기존 `soc-agent-health-*` 경로로 전송한다. Packetbeat 키에 상태 조회/쓰기나 원문 조회 권한을 추가하지 않는다.
- Packetbeat 설치 경로는 Linux `/opt/cloud-soc-network`, Windows `%ProgramFiles%\Cloud-SOC-Network`로 고정한다. 서버 주소·조직·CA가 호스트 설정과 일치하고 보호된 경로일 때만 함께 보고한다. 불일치/확인 불가는 미측정이다.
- 연결 정보 비교 과정에서 보호된 설정과 CA를 읽지만 키·주소·파일 경로·로그 메시지·ephemeral ID는 통계에 담지 않는다. CA 개인키/keystore/패킷 본문은 읽지 않는다.
- 일반 통계 로그의 최근 최대 4개, 각 마지막 1MiB만 읽는다. Linux는 디렉터리 항목 128개, Windows는 일치하는 파일 후보 128개에서 중단한다. 단일 행 제한은 Linux 512KiB, Windows 512K 문자이며 모두 1MiB 파일 꼬리 안에서 읽는다. 미완성 마지막 행과 `*-events-data-*` 진단 파일은 제외한다.
- Linux는 링크·하드링크·특수 파일·비신뢰 쓰기 권한을 거부한다. Windows는 연결 경로/하드링크를 거부하고 Packetbeat 연결 대상의 관리자/SYSTEM 소유·ACL을 확인한다.
- `network_identity=agent_reported_co_located_not_attested`: 인증된 호스트가 보고한 동위치 통계이지 독립 Packetbeat 신원 증명은 아니다. 두 수집기의 이벤트 수신 현황과 구분한다.

호스트 Filebeat/Discovery가 없거나 멈추면 이 상태 보고도 중앙에 도착하지 않는다. 네트워크 전용 설치를 위한 별도 보고기나 heartbeat 구현은 포함하지 않는다. 수집 서비스·NIC·키·큐·Windows 정책은 이 판독기가 바꾸지 않는다.

## 설치와 기존 에이전트

새 Ubuntu 묶음은 `collector-metrics.py`를 포함하고 설치 전 Python 3/보조 파일을 확인한다. 매분 Discovery가 제한된 읽기 작업을 수행하며 helper 누락/실패/15초 제한 시 기본 미측정 보고를 유지한다. Python `-I`로 사용자 모듈 경로와 환경의 영향을 차단한다.

Windows 새 native Discovery는 같은 작업에서 Filebeat와 Packetbeat를 따로 읽는다. 기존 Windows는 이미 지원하는 **Discovery-only 갱신 절차**로 새 작업자를 적용해야 한다. 기존 Linux의 보존형 자동 갱신은 별도 P2-04 범위이며 설치기를 재실행해 덮어쓰면 안 된다. 이번 커밋 자체가 기존 에이전트를 갱신하거나 웹의 기존 다운로드 묶음을 다시 만드는 것은 아니다.

## 팀원 화면 통합 계약

`GET /api/agents/health`의 각 기존 행과 `collector_metrics` 의미는 유지한다. 추가 `network_collector_metrics`는 동일 검증/상태 규칙을 사용한다. 구버전 보고에 필드가 없으면 `unavailable`로 반환한다. 잘못된 네트워크 표본이 정상 소스 목록이나 호스트 통계를 지우지 않는다.

화면은 **호스트 로그 통계 / 네트워크 통계**를 분리하고 각각 표본 시각·구간·지연/미측정·큐/전송 표본·읽기 제한을 표시해야 한다. 호스트의 `agent.id` 행을 실제 Packetbeat 수집기 행으로 바꾸거나 두 수치를 더하면 안 된다. 현재 공통 화면은 기존 Filebeat 필드만 사용하므로 추가 표시를 팀원 UI 통합에서 연결해야 한다.

## 완료 전 검증

### 로컬 검증 결과

2026-10-07 신규 16건 중 15건 통과/실제 Linux 권한 1건 생략, 기존 품질 포함 23건 통과/1건 생략이다. Windows .NET 실제 합성 빌드·실행과 기존 native worker 회귀, Linux 보고의 성공/실패 fallback, 생성 Ubuntu 묶음의 파일/해시를 확인했다. 정책/Enrollment/개인정보 포함 관련 35건 통과/1건 생략, Node 기존 설치기·네트워크·품질 화면 61건 통과다.

전체 Python 회귀는 OCI 전용 17건 제외 후 397건 실행: 386 통과/9 조건부 생략/기존 Windows Restricted 정책 실패 2건이다. 이 실패를 이번 계측 오류로 처리하거나 전역 정책을 낮춰 숨기지 않는다. 마지막 시각 정규화 보완 후 관련 35건 재통과했다. 실제 Python 3.10/Linux 권한·SYSTEM 실행·중앙 수신 및 새 UI 표시는 후속 검증이다.

### 운영 검증 순서

1. 대표 Ubuntu의 실제 일반 Filebeat/Packetbeat 통계 형식과 수치, root 보호 경로 및 Discovery timer를 대조한다.
2. 대표 Windows에서 실제 SYSTEM 작업자의 Packetbeat ACL/설정 연결·표본 판독을 확인한다.
3. 새 보고의 생성 시각→인증된 health 수신→API의 각 숫자/null/지연을 별도 읽기 전용 조회로 대조한다.
4. 팀원 통합 화면의 두 표본과 API를 대조하고 구버전·중지·오래된 표본·읽기 제한·오류 경우를 확인한다.
5. 기존 키/큐/registry/NIC/서비스와 실행 정책 보존을 확인한 뒤에만 P2-03 완료 표시한다.

로컬 회귀 명령:

```powershell
python -m unittest discover -s tests -p test_collector_metrics_p2.py -v
python -m unittest discover -s tests -p test_collection_health.py -v
node --test deploy/agents/tests/installers.test.cjs deploy/agents/tests/network.test.cjs prototype/tests/collection-health.test.cjs
```

`src`와 `tests`를 Python 모듈 경로에 준비한다. Windows의 Git Bash 테스트는 보고 렌더링만 검증하며 실제 Linux 권한/systemd 실행 증명은 아니다. Linux 파일 권한 시험은 Windows에서 생략된다. Windows C# 시험은 실제 컴파일한 합성 작업자로 검증하지만 실제 SYSTEM/실제 Packetbeat/중앙 서버 수신은 아니다.
