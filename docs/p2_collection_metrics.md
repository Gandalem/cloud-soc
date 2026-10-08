# P2-03 수집 품질 계측

## 현재 범위

2026-10-08: Linux Filebeat와 Windows/Linux Packetbeat의 큐·전송 통계 판독 및 상태 보고/API 계약을 구현했다. **지정 Ubuntu와 Windows 시험 VM의 실제 SYSTEM/Discovery 보고 → 중앙 수신 → API 숫자 대조 및 배포 화면 검증을 마쳤다.** Windows 신규 통합 설치는 10-07 통과했다. 10-08 부팅 직후의 시작 시간 초과/1053 후속은 보호 백업·서비스별 지연 자동 시작·실제 정상 재부팅으로 검증했다(아래 P0C-02R-01). 팀원 정식 소스 통합·배포와 과거 Linux 상태 spool 비정상 행 조사가 남아 P2-03 전체는 진행 중이다. P2-02 백업 저장소 대기는 유지한다.

### P0C-02R-01 실제 부팅 후속

- 2026-10-08 시험 Windows VM만 정상 재부팅했다. 부팅 `01:30:30.5000000Z`, Filebeat 프로세스 시작 `01:32:40.0663566Z`, Packetbeat `01:32:40.8938770Z`. 수동 시작 없이 두 서비스의 지연 자동 실행/Npcap System·Running, SYSTEM 작업 결과 0과 새 보고를 확인했고 이번 부팅 SCM 7000/7009 재발은 없었다.
- 두 보호 백업 1,492/157개 파일의 해시 검증과 데이터 파일 포함을 확인했다. 설정/CA/keystore 및 `data/meta.json` 해시와 작업 XML은 불변, 기존 diskqueue는 유지했다. 큐 복원·초기화·재설치·키 재발급·전역 서비스 시간 제한/정책 변경은 하지 않았다.
- SYSTEM 생성 `01:33:27.0402711Z` → ES 수신 `01:33:33.861030213Z`의 목록/개수/해시/두 수집기 통계를 독립 monitor ES와 인증 API에 대조했다. 동일 시험 조직·호스트에서 발생 시각과 서버 수신 시각 모두 부팅 이후인 호스트 735건·TCP 흐름 745건을 확인했다. 원문 본문은 읽거나 기록하지 않았다.
- Filebeat 표본 큐 898,958 bytes/558건·시도/ACK 564/563, Packetbeat 79,875 bytes/77건·131/131이다. 읽기 오류 2와 scan_partial은 주의/판독 제한으로 유지하며 모든 오류 해결·전체 무손실을 주장하지 않는다. 이전 화면 증거/배포 파일 해시 대조는 별개로 보존하며 이번에 브라우저를 다시 열었다고 주장하지 않는다.
- 임시 접속 키만 제거해 다른 키 bytes/ACL 보존 및 해당 키 인증 거절을 확인했다. 중앙 서비스/기존 ZIP은 변경하지 않았다. 지연 시작 적용을 전체 VM/PC 갱신이나 수정 설치기의 포털 배포 완료로 간주하지 않는다. 부팅 후 시작 전 패킷은 소급 수집되지 않는다. 자원 경합의 세부 원인은 확정하지 않았고, 확인된 부팅 단계 1053과 서비스별 완화의 대표 재부팅 결과로 한정한다.

비민감 증거는 Git 제외 `state/p2-collection-20261007/windows-boot-{local,api,central}-evidence.json`에 보관한다. 순서대로 SHA256 `e98f5d382bfe9ad7cda86ebf8fff4f91ce52283ed99fb60f13c99a18cb935ba8`, `4480a03d7e2a5e5225b0e68a8ffe8843a4f6358534651d570ad53ab112084808`, `ea3a6122b2f72d693fc31ce50871e95953d39500e1b7740b1e943001e19f2832`이다. 시작 설정과 새 ZIP 적용 제한은 [Windows 복구 안내](windows_install_recovery.md)를 참고한다.

팀원 통합 중인 `app.py`, 탐지/인증/공통 shell/CI는 변경하지 않았다. 사용자 요청으로 수집 품질 전용 화면의 네트워크 컬럼과 해당 화면에 한정된 CSS·회귀를 추가했다. `packages.py`의 Ubuntu 파일 허용 목록과 `collection_health.py`의 추가 응답 필드는 통합 시 보존해야 한다.

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

실제 Beats 전송에서는 `null`인 잎 필드가 생략될 수 있다. 중앙/API는 필드 없음과 `null` 모두 미보고로 다루며, 숫자가 보고된 필드는 그대로 보존·대조한다. 이는 값이 0인 표본과 다르다.

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

수집 품질 전용 화면은 **호스트 로그 통계 / 네트워크 통계**를 분리하고 각각 표본 시각·구간·지연/미측정·큐/전송 표본·읽기 제한을 표시한다. 호스트의 `agent.id` 행을 실제 Packetbeat 수집기 행으로 바꾸거나 두 수치를 더하면 안 된다. 팀원 UI 통합에서도 이 구분과 미보고 의미를 유지해야 한다.

## 완료 전 검증

### 실제 Ubuntu 검증

학교 시험 서버의 기존 DB backup/verify/격리 restore·이미지 보관 후 포털과 Linux Discovery만 갱신했다. 기존 수집기 PID, 설정/CA/keystore 및 DB 전체 행/BLOB(패키지 15개·키 이력 24개)이 유지됐다. 보고 생성 `2026-10-07T05:50:57Z`와 중앙 수신 `05:51:00.693595377Z`를 독립 읽기 권한으로 대조해 두 통계·소스 목록의 보존을 확인했다.

실제 gateway HTTPS API의 별도 조회 표본도 중앙 원문과 일치했다. 해당 표본에서 Filebeat 큐 13,919,433 bytes/10,029건·시도/ACK 28/28, Packetbeat 큐 35,804,237 bytes/32,381건·88/88이었다. 읽기 오류 2/3은 화면에 주의로 표시하며 전체 정상이나 누적 유실량으로 해석하지 않는다. 전용 화면 1920px/390px과 구버전 미측정 표시, 모바일 표 내부 스크롤, 실행 오류/경고 0을 확인했다. 브라우저는 실제 배포 응답만 사용하는 읽기 전용 relay로 검증했으며 배포 파일 해시와 일치했다. CA·내부 IP 이름 검증을 유지했고 Windows 전역 신뢰 설정은 바꾸지 않았다. 외부 ngrok tunnel의 동작 검증은 별도다.

이번 서버의 기존 체크아웃/이미지는 최신 main보다 오래되어 최소 호환 overlay를 사용했다. 기존 인증/조회/개인정보 코드·수집 정책·Compose/ngrok를 덮어쓰지 않았으며 최신 main 전체를 배포했다는 의미가 아니다. **그 구버전 체크아웃에서 이미지를 다시 빌드하면 overlay가 없어질 수 있다.** 보호 이미지/DB 백업과 배포 overlay는 서버의 `~/p2-collection-20261007` 작업 경로에 보존했다. 팀원 통합 후 정식 소스 배포로 전환해야 한다. 같은 서버 디스크에 만든 배포 백업은 독립 재해 복구 저장소가 아니다.

Ubuntu 격리 회귀 25건 중 24 통과/Windows 컴파일 1 생략, Windows 로컬 회귀 25건 중 24 통과/Linux 권한 1 생략, 화면 10건 통과다. 마지막 설치기·네트워크·화면 통합 Node 회귀 63건도 모두 통과했다. 실제 Linux 권한·FIFO·하드링크 보호를 확인했다. 이 Ubuntu 검증 단계 당시 Windows 새 작업자의 SYSTEM 실행은 미검증이고 해당 VM의 `sshd` 준비가 필요했으며, 아래 후속 Windows 단계에서 실제 검증했다. 기존 Linux 상태 spool의 배포 전 비정상 1행은 삭제하지 않고 후속 조사로 남겼다. 이는 업무 로그 전체의 유실 증거가 아니다.

### 실제 Windows 검증 및 10-08 재개

사용자 설치 전 스냅샷/Npcap 준비 후 Windows 10 Education x64 시험 VM에 새 네트워크 묶음을 설치했다. ZIP SHA-256 `24fd4189637e6e9c68e2a3042e0ebf935974b254e6eb3bfd6b7442e7c6bfe90c`와 내부 21개 파일을 전송 전후 대조했다. 실제 학교 서버의 구버전 Compose는 패키지 수신 주소를 ngrok 이름에서 만들고 있었으므로, 승인 후 포털의 `SOC_ELASTIC_ENDPOINT` 한 줄만 기존 `SOC_AGENT_ENDPOINT`를 사용하도록 수정했다. 수신 주소는 `https://192.168.32.60:9200`, 외부 포털 설정은 그대로다. 포털 이미지는 기존 P2 overlay와 동일하며 최신 main/팀원 코드로 덮어쓴 것이 아니다.

서버 온라인/중지 DB backup·verify 및 이전 Compose 보호 보관 후 포털만 재생성했다. 최종 재개 검사에서도 기존 패키지 15개의 행/BLOB·키 이력 24개·사건 전체 행이 그대로였다. 이번 시험 패키지 1개와 호스트/네트워크 키 2개만 추가돼 총 16개/26개이며 두 키의 제한 역할·활성 상태·기한을 확인했다. **이번 시험 키는 2026-10-14 15:50:23 KST 만료**이며 운영용 장기 자격 증명으로 간주하지 않는다. Linux 설정/CA/keystore, 수집기 PID와 다른 중앙 컨테이너의 이미지·설정·시작 시각·재시작 수도 보존했다.

Windows에서는 승인된 HP 사용자에게만 CurrentUser RemoteSigned를 적용했다. 사설 CA 폐기 정보 조회 불가에 대해 승인된 `-AllowUnavailableRevocation`을 중앙 사전 검사에만 사용했으며 전역 인증서 저장소/정책은 바꾸지 않았다. 이 옵션은 폐기 여부를 확인하지 못한 인증서를 받아들일 위험을 남긴다. 별도 소유 임시 SYSTEM 작업으로 실제 유효 정책 Restricted/모든 저장 범위 Undefined를 확인하고 작업·폴더를 정리했다. 본 Discovery는 SYSTEM의 native EXE이며 최종 결과 0이다. 두 수집기는 LocalSystem/Automatic/Running, 설치 pending 없음과 새 native 소스 해시 일치를 확인했다.

10-07 독립 대조: 보고 생성 `2026-10-07T06:56:26.0812687Z` → 수신 `06:56:29.393427082Z`. 선택 379/제외 901/탐색 오류 0 및 첫 200개 소스 해시/상태가 보존됐다. Filebeat 큐 81,476,000 bytes/70,825건·전송/ACK 98/98, Packetbeat 큐 728,128 bytes/703건·131/131이다. 두 통계의 읽기 오류 3/3과 판독 제한도 숨기지 않는다. `.NET` 시각의 7자리 소수는 API에서 마이크로초로 투영되므로 시각을 정규화해 동일 보고를 대조했으며 숫자/소스는 정확히 일치했다. 별도 monitor 조회로 실제 Windows 호스트 문서 147,402건과 TCP 흐름 문서 1,208건을 해당 시험 조직·설치 후 수신 구간에서 확인했다. 이는 고유 활동 수/전체 로그/전체 패킷 수 또는 무손실 증명이 아니다.

화면은 실제 HTTPS 배포 응답만 전달하는 읽기 전용 중계로 검증했다. 배포 파일 해시와 API/독립 ES 숫자가 일치했고 Windows 행의 호스트/네트워크 4개 통계 컬럼을 확인했다. 1920px 데스크톱과 390px 모바일에서 페이지 전체 넘침 없이 표 내부만 스크롤됐으며 구버전 네트워크 미측정/오래된 표본도 유지됐다. JS 실행 오류는 없었고 중계에서 제공하지 않은 favicon 요청 404 한 건은 별도로 기록했다. 외부 ngrok tunnel 자체 검증은 아니다.

10-08 재개: Windows가 `00:14:15Z`에 부팅한 뒤 두 서비스에 SCM 7009/7000, 45,000ms 시작 시간 초과/1053이 발생해 정지한 상태였다. Discovery의 새 보고에 담긴 통계는 전날 표본이었으며 현재 정상으로 간주하지 않았다. 같은 서비스/활성 NIC/Npcap을 확인하고 두 서비스만 다시 시작했다. 설정·CA·keystore 해시 불변, 큐 초기화/키 교체/재설치/전역 서비스 시간 제한/정책 변경 없음이다. 새 보고 `2026-10-08T00:23:26.9487656Z` → 수신 `00:23:27.484960980Z`를 독립 ES/API와 대조했다. Filebeat 큐 5,364,034 bytes/3,841건·3,842/3,842, Packetbeat 큐 50,766 bytes/49건·56/56이며 읽기 오류 2/3은 주의로 유지했다. 재개 검사 시점 최근 15분의 실제 호스트 문서 4,001건·UDP 흐름 문서 867건도 메타데이터만 확인했다. 수동 재시작 성공은 부팅 자동 시작 문제 해결이 아니다.

정리: 어제 정리 도구의 숨김 ProgramData 읽기·빈 백업 경로 파일 교체와 검증 도구의 시각 정밀도/주기적 healthcheck 이력 비교 문제를 각각 보완했다. 제품 정책을 낮추거나 이 실패를 수신 실패로 숨기지 않았다. 소유 SSH 공개 키 한 줄만 제거하고 다른 키의 바이트·ACL 보존, 제거 후 해당 키 인증 거절을 확인했다. 수집용 키·큐·실행 서비스는 유지한다. 인증 중계/검증 브라우저가 남아 있지 않음을 확인했고 증거는 Git 제외 `state/p2-collection-20261007`에 보관한다. 10-07 Node 63건 통과, 10-08 Python 25건 중 24 통과/Linux 권한 1 생략이다. 기존 사용자 Word/JSON과 과거 이력을 보존하며 새 커밋·푸시는 하지 않았다.

후속은 **시험 VM 부팅 시작 시간 초과의 원인 보완·재부팅 재검증**, 팀원 정식 소스 통합·배포, 과거 Linux 상태 spool 비정상 행 조사다. 10-01의 P0C-02 완료는 당시 대표 시험의 이력이며 이번 새 VM의 비정상 종료 후 부팅에서도 항상 동작함을 보장하지 않는다.

### 로컬 검증 결과 (초기 구현 당시)

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
