# P3 호스트 보안 감사

2026-09-22 기준 **1차 로컬 구현**입니다. AWS 배포, Sysmon/auditd 설치, 감사 정책/SACL 변경, 민감 파일 접근 시험은 실행하지 않았습니다. 에이전트가 설치되었다고 모든 보안 이벤트가 생성되는 것은 아닙니다.

## 1. 이번 구현 범위

| 항목 | 현재 동작 | 아직 안 되는 것 |
| --- | --- | --- |
| Windows 보안 이벤트 | 통합 로그의 문서 ID를 누르면 공급자·채널·이벤트 ID를 함께 확인하여 선택된 필드를 해석 | OS 감사 자동 활성화, 전체 이벤트 종류 지원 |
| Sysmon | 이미 수신된 1/3/11/26 이벤트의 실행·부모·GUID·해시·접근 대상·통신 메타데이터 표시 | Sysmon 자동 설치/설정, 모든 프로세스 추적 |
| Linux SSH | 제한된 RFC3164 sshd 성공/실패 로그의 메타데이터 파서 및 합성 테스트 | 신규 수집 인덱스에서 자동 파싱하여 화면에 표시하는 처리 경로 |
| Linux Audit | x86_64 SYSCALL/PATH 묶음의 UID·프로세스·경로·결과 파서 및 합성 테스트 | auditd 설치, 규칙 배포, 실시간 다중 문서 결합/정규화 저장 |
| 네트워크 | Packetbeat IP/포트·DNS·TLS·통신량·흐름 시작/종료 시각 상세 | PID 추정, 호스트/네트워크 문서 자동 상관분석, 유출 파일 판정 |
| 보호 | 수집 전 privacy v2, 상세 필드 허용 목록, 표시 단계 마스킹 | 기존 에이전트/큐/과거 ES 데이터 자동 교체·재처리 |

**목록의 `미평가`는 그대로입니다.** 목록 전체를 파싱하거나 공격 탐지를 실행한 것이 아니라, 선택한 문서의 제한된 보안 메타데이터만 별도로 해석합니다. 상세에는 `지원 형식 확인`, `부분 해석`, `미지원 형식 또는 근거 부족`이 표시됩니다. 공격/정상 판정과는 다릅니다.

포털은 `message`, `event.original`, 전체 `winlog.event_data`, 명령줄, 작업 XML, 파일 본문을 ES에서 요청하지 않습니다. 명시된 `winlog.event_data.TargetUserName` 등의 하위 필드와 네트워크 메타데이터만 상세 조회에 추가합니다. 목록 허용 필드는 변경하지 않습니다. 문서 인덱스/ID와 서버 수신·로그 기준 시각은 기존 상세에 함께 남습니다.

## 2. Windows 지원표

Security 채널의 `Microsoft-Windows-Security-Auditing` 공급자를 기준으로 합니다. 동일 번호라도 공급자/채널이 다르거나 `event.code`와 `winlog.event_id`가 충돌하면 해석하지 않습니다. 필드 없는 이벤트는 누락 정보를 표시합니다.

| ID | 표시 내용 | 주의 |
| --- | --- | --- |
| 4624 / 4625 | 로그인 성공/실패, 대상 계정, 로그온 유형, 관측된 IP/포트 | 로그인 실패가 곧 공격은 아님. 유형 3과 10을 구별 |
| 4672 | 로그온에 특수 권한 할당 | 실제 권한 사용을 의미하지 않음 |
| 4720 / 4726 | 계정 생성/삭제, 실행 주체와 대상 | 없는 주체는 추정하지 않음 |
| 4732 / 4733 | 로컬 보안 그룹 구성원 추가/제거, 그룹과 구성원 SID | 도메인 그룹 변경 이벤트 전체 지원 아님 |
| 4688 | 프로세스 생성, 실행 경로·PID, 관측된 부모 경로·PID | PID 재사용 가능. 명령 인자는 표시하지 않음 |
| 4663 | 객체 접근 권한 사용, 접근 마스크·경로·주체 | File 객체가 디렉터리일 수도 있음. 읽기 권한 사용과 유출/삭제 완료는 다름 |
| 4670 | 객체 권한 변경 | 변경 전후 보안 설명자 본문은 표시하지 않음 |
| 4697 | 서비스 설치 | 시작 인자/서비스 실행 명령은 표시하지 않음 |
| 4698 / 4702 | 예약 작업 생성/갱신, 작업 이름 | XML·실행 인자는 제외 |
| 4719 | 감사 정책 변경 | 감사 전체 중지로 판정하지 않음 |

Sysmon은 `Microsoft-Windows-Sysmon/Operational` 채널과 `Microsoft-Windows-Sysmon` 공급자를 함께 확인합니다. 1은 프로세스 생성, 3은 연결 관측, 11은 파일 생성/덮어쓰기, 26은 파일 삭제 관측입니다. 11/26은 파일 읽기 감사가 아닙니다. 삭제 파일을 보관하는 Sysmon 23은 미지원이며 새로 활성화하지 않습니다.

GUID·조직·호스트 ID가 모두 있으면 **같은 이벤트 안의 프로세스 식별 근거**를 보여줍니다. 다른 이벤트와 자동 연결하지 않습니다. GUID 없이 PID만으로 동일성을 만들지 않습니다. 공급자/호스트 필드는 수집된 값이며, 침해 호스트가 보내는 문서의 무결성을 증명하는 전자서명이 아닙니다.

근거: [Microsoft 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624), [4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672), [4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688), [4663](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663), [감사 정책](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration), [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

## 3. Linux 파서 계약과 제한

구현: [linux_security.py](../src/cloud_soc/parsers/linux_security.py). 순수 함수로 OS·파일·ES에 접근하지 않습니다. 현재 포털 상세는 본문을 읽지 않으므로 Linux 텍스트 로그에 이 파서를 호출하지 않습니다. `main.py`의 기존 처리 대상을 자동 확대하지 않았습니다.

- SSH는 연도/시간대 없는 RFC3164 형식만 지원합니다. 기준 연도/시간대 결합은 기존 시간 정책과 함께 후속 처리기에서 해야 하며 현재 시각으로 덮어쓰지 않습니다. journald 본문만 있는 형식, sudo·PAM·계정/그룹 변경은 미지원입니다.
- Audit 입력은 `{organization, host_id, line}` 배열입니다. 조직·호스트·전체 `audit(초.소수:일련번호)`가 같은 묶음만 받습니다. PID/일련번호만으로 묶지 않습니다. 최대 64행, 행당 8,192자, 총 128 KiB입니다.
- SYSCALL의 `items`와 PATH의 `item`을 대조합니다. 경로 누락/중복, 다른 호스트/사건 혼입, 알 수 없는 아키텍처는 정상 완료로 표시하지 않습니다. 지원하지 않는 필드 형식은 거부합니다.
- syscall 해석은 `arch=c000003e`의 read/write/open/openat/execve/execveat/unlink/unlinkat/chmod/fchmod/fchmodat로 제한합니다. ARM·32비트 번호를 x86_64로 해석하지 않습니다. 파일 open 성공을 파일 내용 읽기 성공으로 바꾸지 않습니다.
- `auid`는 로그인 UID, `uid/euid`는 호출 UID/실효 UID로 분리합니다. `auid=4294967295`는 미설정입니다. 상대/hex 경로는 임의 복원하지 않으며 argv/PROCTITLE은 출력하지 않습니다.
- 후속 처리기에는 제한 시간/미완성 묶음, 재시작과 중복 처리, 각 원문 인덱스/ID 배열, 타임존, 체크포인트가 필요합니다. 이 기능과 신규 인덱스의 `normalized-events` 저장·탐지 연결은 미구현입니다.

근거: [Linux Audit 이벤트 묶음](https://github.com/linux-audit/audit-userspace/blob/master/docs/ausearch.8), [Linux x86_64 syscall 표](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl).

## 4. 감사 사전 확인

아래는 사용자가 승인한 시험 호스트에서 수행할 **읽기 전용 확인**입니다. 비밀번호·개인키·실제 민감 로그를 공유하지 마세요. 결과가 없는 항목은 계속 `미확인`입니다. 이벤트가 없다는 이유로 `비활성` 또는 `안전`이라고 표시하지 않습니다.

관리자 PowerShell:

```powershell
Get-WinEvent -ListLog Security | Select-Object LogName, IsEnabled, RecordCount
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Select-Object LogName, IsEnabled, RecordCount
Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object Name, Status
auditpol /get /category:*
```

Windows 민감 경로 접근 감사에는 File System 감사 정책과 **해당 경로의 SACL**이 필요합니다. 활성화는 별도 승인 후 테스트 디렉터리부터 수행합니다. 개인 문서·인증서·개인키 경로를 Filebeat 본문 수집 루트에 추가하지 않습니다. 4656 요청만 관측하고 실제 읽기가 수행되었다고 표시하지 않습니다.

Ubuntu (설치된 도구가 있을 때만):

```bash
systemctl is-active auditd
command -v auditctl
sudo auditctl -s
sudo auditctl -l
```

`auditctl`이 없으면 미설치로 기록하고 중단합니다. 설치/규칙 추가·삭제·재기동은 이 확인 절차에서 수행하지 않습니다. auditd와 Filebeat의 경로 접근·회전도 별도 확인해야 합니다. 모든 파일/모든 syscall 감시는 폭증 위험이 있으므로 승인된 소수 경로와 행위부터 시작합니다.

## 5. privacy v2 및 배포 주의

- Windows 렌더링 `message`는 명령줄/XML을 다시 포함할 수 있어 수집 전 제거합니다. `CommandLine`, `ParentCommandLine`, `TaskContent`, `NewTaskContent`, `ScriptBlockText` 등도 제거합니다. 기존 v1 보호 규칙은 유지합니다.
- `linux_*` 소스에서 네이티브 `type=EXECVE`, `PROCTITLE`, `USER_CMD`로 시작하는 레코드는 인코딩 인자 누출을 막기 위해 전송하지 않습니다. SYSCALL/PATH는 유지합니다. 그 외 포맷/본문의 비밀값까지 탐지하는 일반 DLP는 아닙니다.
- 새 이벤트에 `labels.privacy_policy=v2`를 기록합니다. 옛 패키지나 실행 중인 에이전트의 스크립트는 자동 갱신되지 않습니다. 경로 정책 도구는 수집기 전체 업그레이드 도구가 아닙니다.
- 포털 업데이트 후 기존 문서의 제한된 Windows/네트워크 상세를 조회할 수 있습니다. 필드가 없으면 부분/미지원으로 표시합니다. ES 역할 확대, 재색인·삭제, 수집 키 교체는 필요하지 않습니다.
- 새 수집기는 승인한 시험 호스트에서 검증합니다. 기존 서비스 위에 설치기를 재실행하거나 registry·큐·키를 삭제하지 마세요. 구버전 이행은 P2-04 후속 작업입니다.

## 6. 검증과 다음 순서

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests
node --test deploy/agents/tests/*.test.cjs prototype/tests/*.test.cjs
```

실제 로컬 Docker ES 시험도 포함하려면 `$env:SOC_TEST_AGENT_STATUS_ES='1'`을 지정합니다. 임시 합성 전용 컨테이너를 사용하고 종료 시 정리하며 운영 ES에는 접근하지 않습니다.

다음은 **Linux 처리 경로·원문 참조 결합 → 승인된 시험 호스트의 감사 범위 결정/활성화 → 실제 중앙 수신 확인 → P5 처리·탐지 연결** 순서입니다. Linux 계정/권한 변경, cron/SSH 설정 변경, 로그 삭제/보안 도구 중지 해석도 남았습니다. 탐지 규칙은 별도로 정하며 이번 작업에서 추가/활성화하지 않았습니다.
