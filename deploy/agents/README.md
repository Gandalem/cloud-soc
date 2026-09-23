# 서버별 자동 로그 수집 에이전트

신규 서버에서 설치 명령 한 번과 API 키 입력으로 Filebeat 9.5.2를 설치합니다. **고정된 몇 개 로그만 수집하지 않고, 지원하는 소스를 자동 발견하고 1분마다 다시 탐색**합니다. 중앙 원격 배포나 Fleet 관리 서버는 아닙니다.

**웹 화면에서 설치 파일을 만들려면 [Ubuntu 중앙 서버 가이드](../server/README.md)를 먼저 진행합니다.** OS별 ZIP/tar.gz에 설치 스크립트와 CA 공개 인증서를 묶으며 API 키는 별도로 발급합니다. 네트워크를 선택한 묶음은 Filebeat와 Packetbeat 설치를 순서대로 실행합니다. 아래는 개별 스크립트를 직접 사용할 때의 안내입니다.

| OS | 자동 수집 범위 | 별도 앱 경로 |
| --- | --- | --- |
| Ubuntu 22.04 + systemd, x86_64/ARM64 | 시스템 journald + `/var/log` 하위 텍스트 파일 | `--log-root /srv/app/logs` |
| Windows x86_64, 관리자 PowerShell | 모든 활성 지원 이벤트 채널 + 표준 로그 디렉터리의 텍스트 파일 | `-AdditionalLogRoot 'D:\App\logs'` |

**전체 디스크의 모든 데이터를 전송하는 기능은 아닙니다.** 수집 범위, 인코딩, 제외 사유, 중복 가능성은 [자동 수집 계약](COLLECTION.md)에 설명합니다. 비활성 감사 정책을 자동으로 켜거나 Sysmon을 설치하지 않습니다.

**네트워크 통신도 수집하려면 [Packetbeat 추가 설치 가이드](NETWORK.md)를 진행합니다.** 기존 Filebeat를 변경하지 않고 별도 서비스로 통신 흐름·DNS·TLS 메타데이터를 `soc-network-*`에 전송합니다. 네트워크 전용 템플릿·API 키와 명시적인 수집 NIC가 필요하며, 원본 PCAP은 저장하지 않습니다. Windows는 승인된 Npcap 사전 설치가 필요합니다.

## 사전 준비

1. 실제 수신 서버의 HTTPS Elasticsearch 주소, 일치하는 인증서 SAN, 신뢰하는 CA PEM이 필요합니다. 로컬 개발용 HTTP·인증 비활성 Compose를 외부에 공개하지 않습니다.
2. 중앙 관리자가 `index-template.json`을 인덱스 템플릿으로 등록하고 `soc-host-raw-*` 자동 생성을 허용합니다. 보존 기간과 디스크 경보도 먼저 결정합니다.
3. 서버마다 전용 API 키를 발급합니다. `publisher-role.json`의 `monitor` 및 `soc-host-raw-*`에 대한 `auto_configure`, `create_doc` 범위를 사용합니다. 조회·삭제·템플릿 관리 권한은 수집기에 주지 않습니다.
4. 검토한 저장소의 `deploy/agents` 폴더를 함께 전달합니다. **설치 스크립트만 복사하면 안 됩니다.** 각 OS의 `discover-*.sh/ps1` 보조 파일도 필요합니다. 서명이 필요한 환경에서는 PowerShell 보조 스크립트도 승인된 서명이 필요합니다.

`organization.id`는 분류 태그이며 테넌트 인증이나 접근 통제를 대신하지 않습니다. 여러 조직은 조직별 인덱스·키 범위·서버 측 검증이 필요합니다.

API 키는 설치 중 Beat keystore 프롬프트에 `id:api_key` 형식으로 입력합니다. `encoded` 값이 아니며 명령 인자·Git·설정 파일에 평문을 넣지 않습니다. CA 개인키도 전달하지 않습니다.

## Ubuntu 설치

필수 도구: Bash, `curl`, `tar`, `sha512sum`, `sha256sum`, `timeout`, `realpath`, `pgrep`, `systemctl`, `find`, `file`, `flock`, `sort`, `cmp`, `journalctl`. 누락된 패키지는 자동 설치하지 않습니다.

```bash
sudo bash deploy/agents/install-ubuntu.sh --endpoint https://soc.example.invalid:9200 --ca /etc/cloud-soc-ca.crt --organization school
```

예시 주소와 CA 경로는 실제 값으로 바꿉니다. `auth.log`·`syslog`가 없더라도 journald 수집을 구성합니다. 별도 서비스 로그 디렉터리가 있으면 같은 명령에 `--log-root /srv/myapp/logs`를 추가합니다. 로그 루트 경로 자체에는 공백·와일드카드·부모 경로 이동을 허용하지 않습니다. 하위 파일명에는 공백을 허용합니다.

기존 `--log-file /var/log/app.log`는 호환용이며 해당 파일은 이미 자동 탐색 범위에 있습니다. 파일명별 등록은 더 이상 필요하지 않습니다.

`--dry-run`은 설치용 기본 설정만 출력하며 서버의 파일 목록을 읽거나 수정하지 않습니다. 실제 발견 목록은 설치 시 생성됩니다.

## Windows 설치

신규 Windows 패키지는 [설치 실패 예방 1차 가이드](../../docs/windows_install_recovery.md)의 SYSTEM 사전 검사·보호 staging·준비 단계 롤백을 적용합니다. NIC는 확인 후 선택할 수 있습니다. 두 수집기의 원자적 설치, `-Repair`, Enrollment, 실제 수신 자동 확인은 아직 미완료입니다.

64비트 관리자 PowerShell에서 실행합니다. Windows 시스템 `curl.exe`와 설치기 옆의 `download-windows.ps1`이 필요합니다. 조직의 기존 실행 정책을 따르고 정책이나 인증서 검증을 우회하지 않습니다. 다운로드는 1회 300초·최대 2회로 제한하며, 60초 동안 초당 16KiB 미만이면 중단합니다. SHA-512 검증 후에만 압축을 풉니다.

```powershell
.\deploy\agents\install-windows.ps1 -Endpoint https://soc.example.invalid:9200 -CaPath C:\certs\cloud-soc-ca.crt -Organization school
```

`Get-WinEvent -ListLog * -Force`로 발견한 활성 지원 채널을 모두 입력에 추가합니다. PowerShell·Defender·Sysmon 채널도 설치·활성화되어 있으면 자동 포함합니다. `-AdditionalChannel`은 지정 채널을 반드시 사용할 수 있는지 검증하는 옵션이며 수집 목록을 그 채널들로 제한하지 않습니다.

파일 로그는 다음 디렉터리를 재귀 탐색합니다.

- `%SystemRoot%\Logs`
- `%SystemRoot%\System32\LogFiles`
- `%SystemDrive%\inetpub\logs`
- `%ProgramData%\logs`

다른 서비스 경로는 설치 명령에 `-AdditionalLogRoot 'D:\MyApp\logs'`로 추가합니다. 파일명은 나열할 필요가 없습니다. `-DryRun`은 설치기 기본 설정만 표시하고 실제 목록은 설치 시 구성합니다.

신규 설치는 Filebeat의 `winlog`·`filestream` 입력을 함께 사용합니다. 이전 버전의 Winlogbeat를 자동 교체하지 않습니다. 기존 `cloud-soc-winlogbeat`, Filebeat, Elastic Agent 또는 설치 흔적이 있으면 중단합니다.

## 설치와 재탐색 동작

- 공식 아카이브 버전과 SHA-512를 고정하고 검증한 후 압축 해제합니다. HTTPS·CA 검증·API 키 keystore·관리자 전용 디렉터리를 유지합니다.
- 신규 파일이나 채널은 Linux systemd timer 또는 Windows 예약 작업으로 1분마다 재탐색합니다. Filebeat는 외부 입력 설정을 10초마다 재로딩합니다. 탐색 시간과 이벤트 처리량에 따라 실제 반영 지연이 더 길어질 수 있습니다.
- 입력 ID를 안정적으로 유지하고 변경된 설정만 원자적으로 교체합니다. 탐색 전체 실패나 필수 채널 누락은 기존 입력 설정을 덮어쓰지 않습니다. 개별 소스 접근 실패는 보고서로 확인합니다.
- 기본 로컬 디스크 큐는 최대 1GB입니다. 전체 로그를 처음 읽으므로 과거 데이터 유입, 저장량 증가, 개인정보 포함 가능성을 먼저 검토해야 합니다.
- 수집기 자체 로그는 수집 루트 외부에 기록하고 journald에서 Filebeat 서비스 로그를 제외합니다. 소스 로그를 삭제하지 않습니다.

| OS | 위치 | 서비스 / 자동 탐색 |
| --- | --- | --- |
| Ubuntu | `/opt/cloud-soc-agent` | `cloud-soc-filebeat`, `cloud-soc-discovery.timer` |
| Windows | `%ProgramFiles%\Cloud-SOC-Agent` | `cloud-soc-filebeat`, 예약 작업 `Cloud-SOC-Discovery` |

공통 파일: `filebeat.yml`, `inputs/discovered.yml`, `discovery-report.json`, `data`, `logs`, `ca.crt`. 탐색 루트는 Ubuntu의 `discovery-roots.txt`, Windows의 `discovery-settings.json`에 보관합니다. 관리자만 수정합니다.

설치 후 명령 재실행으로 덮어쓰거나 업그레이드하지 않습니다. 새 Windows 설치기는 서비스 시작 전 자기 staging만 정리할 수 있습니다. 구버전 잔존 상태와 서비스 시작 이후의 registry·대기 큐는 자동 삭제하지 않습니다.

## 검증

```bash
sudo systemctl status cloud-soc-filebeat cloud-soc-discovery.timer --no-pager
sudo journalctl -u cloud-soc-discovery.service -n 30 --no-pager
```

```powershell
Get-Service cloud-soc-filebeat
Get-ScheduledTaskInfo -TaskName Cloud-SOC-Discovery
Get-Content "$env:ProgramFiles\Cloud-SOC-Agent\discovery-report.json" -Raw
```

보고서의 선택 목록은 **설정에 넣은 소스 목록**입니다. 실제 전송 성공이나 모든 소스의 접근 가능성을 보장하지 않습니다. 보고서 갱신 시각, 예약 작업 종료 코드, Filebeat 로그의 개별 입력 오류도 확인합니다. 실행 정책으로 예약 작업이 차단된 경우 승인된 서명 절차를 사용하고 정책을 우회하지 않습니다.

Kibana에서 `soc-host-raw-*` Data View를 만들고 새 테스트 이벤트의 호스트·시각·본문을 원본과 비교합니다. `labels.log_source`는 `linux_file`, `linux_journald`, `windows_file`, `windows_event`로 구분합니다. 기존 SSH 파서는 `raw-logs-*`만 처리하므로 자동 연결되지 않습니다.

## 개발 테스트

```powershell
node --test deploy/agents/tests/installers.test.cjs
```

테스트는 실제 설치나 네트워크 전송 없이 구문·보안 검증·자동 탐색·깊은 폴더·중복 경로·새 파일·인코딩·제외 사유·실패 시 설정 보존을 확인합니다. Windows에서는 Git Bash와 PowerShell 7이 필요합니다. PowerShell 5.1 문법도 별도 검사합니다.

고정된 공식 Windows Filebeat를 별도로 검증하여 확보했다면 다음 추가 테스트를 실행할 수 있습니다.

```powershell
pwsh -NoProfile -File deploy/agents/tests/validate-filebeat.ps1 -FilebeatPath 'D:\검증용경로\filebeat.exe'
```

이 테스트는 합성 파일과 존재하지 않는 가짜 이벤트 채널만 사용하고, 출력은 로컬 콘솔로 제한합니다. Windows Filebeat 9.5.2에서 설정 해석·입력 생성·UTF-8/UTF-16 합성 파일 수집·재탐색 후 실시간 설정 반영을 확인했습니다. 실제 Ubuntu/systemd, Windows 서비스/예약 작업/LocalSystem, CA/API 키, Elasticsearch 저장 및 재부팅 검증은 별도입니다.

공식 기준: [Filebeat winlog](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-winlog), [journald](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-journald), [설정 재로딩](https://www.elastic.co/docs/reference/beats/filebeat/_live_reloading). 체크섬: [Windows x86_64](https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-9.5.2-windows-x86_64.zip.sha512), [Linux x86_64](https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-9.5.2-linux-x86_64.tar.gz.sha512), [Linux ARM64](https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-9.5.2-linux-arm64.tar.gz.sha512).
