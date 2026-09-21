# 서버별 한 번 실행하는 에이전트 설치

이 디렉터리는 **신규 서버에 수집기를 설치하는 v1 도구**다. 중앙에서 모든 서버에 원격 명령을 내리는 기능이나 Fleet 관리 서버는 아니다. 설치 파일과 CA 인증서를 서버에 전달한 뒤 명령 한 번을 실행하면, API 키 입력을 받아 다운로드·설정·연결 검사·서비스 등록을 진행한다.

기존 Python 백엔드, `compose.yaml`, 현재 Filebeat 설정, 대시보드는 변경하지 않는다. **현재 개발용 HTTP/인증 비활성 Elasticsearch에는 설치할 수 없다.** HTTPS 수신 주소와 API 키는 중앙 환경에서 먼저 준비해야 한다.

## 지원 범위

| 대상 | 에이전트 | 기본 수집 | 추가 지정 |
| --- | --- | --- | --- |
| Ubuntu 22.04, systemd, x86_64/ARM64 | Filebeat 9.5.2 | `/var/log/auth.log`, `/var/log/syslog` | `--log-file /var/log/서비스/파일.log`, 여러 번 사용 가능 |
| Windows x86_64, 관리자 PowerShell | Winlogbeat 9.5.2 | Application, Security, System | `-AdditionalChannel`에 활성 이벤트 채널 이름 지정 |

- "모든 로그" 자동 발견 기능은 아니다. 명시한 소스의 이벤트를 필터 없이 수집하는 출발점이다. 기존 데이터도 처음부터 유입될 수 있으므로 전송량과 개인정보를 먼저 확인한다.
- Ubuntu는 읽을 수 있는 일반 텍스트 파일만 지원한다. journald 직접 수집, 바이너리/압축 로그, 재귀 와일드카드, 멀티라인 파싱, 회전된 과거 파일 전체 복구는 이 버전에 포함하지 않는다. 등록한 파일의 줄 단위 메시지를 전송한다.
- Windows는 활성 이벤트 채널만 지원한다. Sysmon 설치, 감사 정책 변경, 채널 활성화, 일반 텍스트 파일/IIS 파일 수집은 하지 않는다. Windows 파일 수집용 Filebeat는 후속 범위다.
- CloudTrail·OCI Audit 같은 클라우드 API 로그는 별도 커넥터가 필요하다.
- 설치된 에이전트의 중앙 목록, heartbeat 대시보드, 업그레이드, 재설치, 키 교체, 제거 자동화는 아직 없다.

## 중앙 서버에서 먼저 준비할 것

1. 원격 서버가 접근 가능한 Elasticsearch HTTPS 주소와 해당 서버 인증서를 검증할 CA PEM 파일을 준비한다. DNS/IP가 인증서 SAN과 일치해야 한다. 사설망/VPN 및 필요한 송신 서버만 허용하는 방화벽 정책을 사용한다. 개발용 9200 포트를 그대로 인터넷에 공개하지 않는다.
2. 관리자 계정으로 `PUT /_index_template/cloud-soc-host-raw-v1`에 `index-template.json`을 등록한다. 기존 템플릿 우선순위 충돌과 최종 매핑은 `POST /_index_template/_simulate_index/soc-host-raw-linux-9.5.2-2099.01.01` 등으로 검토한다. 파일은 최소 공통 필드 예제이며 완전한 ECS 템플릿이 아니다. 복제본 1개를 사용하므로 단일 노드 실습 환경은 미할당 복제본이 생긴다.
3. 각 서버마다 만료 기간이 있는 전용 API 키를 발급한다. `publisher-role.json`은 `POST /_security/api_key` 요청의 `role_descriptors.cloud_soc_publisher` 값으로 사용하는 권한 예제다. `monitor`와 `soc-host-raw-*`에 대한 `auto_configure`, `create_doc`만 부여한다. API 키 생성자는 이 권한을 실제로 보유해야 한다. 키에는 조회·삭제·템플릿 관리 권한을 주지 않는다. [Elastic 게시 권한 문서](https://www.elastic.co/docs/reference/beats/filebeat/privileges-to-publish-events)를 기준으로 ILM과 ingest pipeline을 사용하지 않는 구성이다.
4. 중앙 서버의 인덱스 자동 생성 정책이 `soc-host-raw-*`를 허용하는지 확인한다. 날짜별 일반 인덱스를 사용하며 data stream이 아니다. 보존 기간/삭제 정책, 디스크 사용량 경보, 조회 전용 역할을 별도로 구성한다. 설치기가 수명주기나 삭제 정책을 만들지는 않는다.
5. 신뢰 가능한 경로로 검토된 설치 스크립트와 CA 인증서만 전달한다. API 키·인증서 개인키는 저장소에 넣지 않는다. 저장소 복제와 전체 설치 순서는 [루트 설치 가이드](../../README.md)를 따른다. 배포에는 검토한 커밋의 스크립트를 사용하며, 별도 서명된 설치 패키지나 릴리스는 아직 제공하지 않는다.

API 키 생성 요청의 형태는 다음과 같다. `role_descriptors`에는 파일의 **내용을 객체로** 넣어야 하며 파일 이름을 문자열로 넣는 것이 아니다.

```json
{
  "name": "cloud-soc-ubuntu-01",
  "expiration": "30d",
  "role_descriptors": {
    "cloud_soc_publisher": {
      "cluster": ["monitor"],
      "indices": [{ "names": ["soc-host-raw-*"], "privileges": ["auto_configure", "create_doc"] }]
    }
  }
}
```

`organization.id`는 분류용 태그일 뿐 인증된 테넌트 경계가 아니다. 현재 키 권한은 공통 수신 인덱스에 쓰기를 허용한다. 여러 조직을 운영하려면 조직별 인덱스/키 범위와 서버 측 조직 검증을 별도로 설계해야 한다.

## Ubuntu에서 실행

서버에 `curl`, `tar`, `sha512sum`, `sha256sum`, `timeout`, `realpath`, `pgrep`, systemd가 있어야 한다. 누락된 패키지를 자동 설치하거나 저장소 설정을 바꾸지 않는다. `auth.log`, `syslog`가 없다면 먼저 rsyslog 등 현재 서버의 로깅 구성을 점검한다.

저장소 루트에서 실행하는 예시다. `soc.example.invalid`는 실제로 연결되지 않는 예시 주소이므로 실제 주소로 바꿔야 한다. CA 경로는 서버에 전달한 파일의 절대 경로다.

```bash
sudo bash deploy/agents/install-ubuntu.sh --endpoint https://soc.example.invalid:9200 --ca /etc/cloud-soc-ca.crt --organization school
```

서비스 로그도 수집하려면 같은 명령에 `--log-file /var/log/nginx/access.log` 등을 추가한다. 경로에 공백·특수문자·와일드카드는 허용하지 않는다. 기존 Filebeat/Elastic Agent 또는 설치 흔적이 있으면 중단한다. 기존 OCI Filebeat가 실행 중인 서버에는 곧바로 병행 설치하지 말고 전환 계획을 먼저 세운다.

설치 전 미리보기는 `sudo` 없이 위 명령 끝에 `--dry-run`을 붙인다. 네트워크 요청·파일 쓰기·서비스 변경·API 키 입력이 없으며, 실제 OS·CA·로그 파일·설치 여부는 검사하지 않는다.

## Windows에서 실행

검토된 스크립트를 실행할 수 있는 **기존 조직 실행 정책** 아래에서 64비트 관리자 PowerShell을 사용한다. 스크립트가 정책에 의해 차단되면 서명 등 조직이 승인한 배포 절차를 사용한다. 이 도구는 실행 정책을 변경하거나 우회하지 않는다. 실제 OS의 Winlogbeat 지원 여부도 배포 전에 확인한다.

```powershell
.\deploy\agents\install-windows.ps1 -Endpoint https://soc.example.invalid:9200 -CaPath C:\certs\cloud-soc-ca.crt -Organization school
```

추가 채널은 `-AdditionalChannel 'Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational'`처럼 지정한다. 실제 존재하고 활성화되어 있어야 한다. 없으면 무시하지 않고 설치를 중단한다. 채널에 이벤트가 생성되는지는 해당 감사/로깅 정책에 달려 있다.

설치 전 미리보기는 관리자 권한 없이 `-DryRun`을 붙인다. Ubuntu 미리보기와 같은 제한이 있다.

## 설치 동작과 보안

1. 인자·플랫폼·기존 설치·로그 소스를 검사한다. URL은 HTTPS DNS/IPv4 주소만 허용하며 IPv6 리터럴·프록시 경로·URL 내 계정정보는 v1에서 지원하지 않는다.
2. 관리자 전용 디렉터리를 새로 만들고 Elastic 공식 아카이브를 내려받는다. 버전은 9.5.2로 고정하고 **저장소에 고정한 SHA-512 값**이 일치해야 압축 해제한다. 자동 최신 버전 설치는 하지 않는다.
3. API 키는 Beat의 keystore 입력 프롬프트에서 `id:api_key` 형식으로 입력한다. 명령 인자나 YAML에 평문으로 넣지 않는다. `encoded` 값을 입력하지 않는다. [Elastic API 키 형식](https://www.elastic.co/docs/reference/beats/winlogbeat/beats-api-keys).
4. 생성되는 `.yml`은 JSON 표현의 YAML 호환 설정이다. 키 대신 `${CLOUD_SOC_API_KEY}`를 참조하고 CA와 호스트 이름을 모두 검증한다. 설정 검사 및 Elasticsearch 연결 검사가 성공해야 서비스 등록으로 넘어간다.
5. Ubuntu는 root systemd 서비스, Windows는 LocalSystem 서비스로 실행한다. 상태 디렉터리와 keystore 경로는 사전 검사와 서비스에서 동일하게 사용한다. 저장 디렉터리는 Linux root 전용, Windows SYSTEM/Administrators 전용으로 제한한다. keystore는 난독화 저장이며 root/관리자에게 비밀을 숨겨 주는 보안 경계가 아니다. [Filebeat keystore](https://www.elastic.co/docs/reference/beats/filebeat/keystore).
6. 시작 직후 서비스가 유지되는지 검사한다. 실패 시 성공 메시지를 출력하지 않고 0이 아닌 코드로 종료한다. 생성한 서비스의 시작이 실패하면 중지/비활성화를 시도한다. 실패 원인 분석과 로그 유실 방지를 위해 부분 설치 디렉터리와 registry는 자동 삭제하지 않는다.

Elastic 공식 Windows 설치 스크립트는 기존 서비스를 삭제할 수 있으므로 직접 실행하지 않는다. 필요한 서비스 인자만 참고하여 별도 `cloud-soc-winlogbeat` 서비스를 생성한다. [공식 서비스 템플릿](https://github.com/elastic/beats/blob/main/dev-tools/packaging/templates/windows/install-service.ps1.tmpl).

로컬 디스크 큐는 최대 1GB로 설정한다. 이것이 전달 성공이나 무손실 수집을 보장하지는 않는다. 장기 연결 장애·로그 회전·디스크 고갈·매핑 오류를 별도로 감시해야 한다.

| 대상 | 설치/설정/상태 위치 | 서비스 이름 |
| --- | --- | --- |
| Ubuntu | `/opt/cloud-soc-agent` 아래 `filebeat.yml`, `data`, `logs`, `ca.crt` | `cloud-soc-filebeat` |
| Windows | `%ProgramFiles%\Cloud-SOC-Agent` 아래 `winlogbeat.yml`, `data`, `logs`, `ca.crt` | `cloud-soc-winlogbeat` |

재실행은 기존 파일이나 서비스를 덮어쓰지 않고 실패한다. 실패한 설치는 표시된 위치와 서비스 상태를 먼저 점검하고, 등록된 API 키의 폐기 여부를 판단한 뒤 관리자가 복구해야 한다. registry/data 디렉터리를 무작정 지우면 재수집·중복·대기 로그 유실이 발생할 수 있다.

## 실제 전송 검증

**서비스 실행 및 `test output` 통과는 실제 문서 저장 성공과 다르다.** 최소 다음 항목을 확인한 뒤 배포 완료로 판단한다.

1. Ubuntu의 `systemctl status cloud-soc-filebeat`, `journalctl -u cloud-soc-filebeat` 또는 Windows의 `Get-Service cloud-soc-winlogbeat`와 설치 경로의 `logs`를 확인한다. 특히 서비스 계정에서 keystore/CA를 읽는지 확인한다.
2. 테스트 서버에서 승인된 정상 로그인 등으로 새 이벤트를 한 건 발생시킨다. 과거 데이터 유입만으로 실시간 수집을 판정하지 않는다.
3. 조회 전용 계정으로 Kibana에 `soc-host-raw-*` Data View를 만들고 시간 필드를 `@timestamp`로 선택한다. `host.name`, `agent.id`, `organization.id`, `labels.log_source`, `message`, Windows의 `winlog.channel`·`event.code`를 확인한다.
4. 새 이벤트의 시간·호스트·내용이 실제 원본과 같은지 확인한다. 401/403, TLS 검증 오류, bulk 매핑 실패, 인덱스 자동 생성 거부가 없는지 에이전트 로그를 확인한다.
5. 재부팅 후 서비스 자동 시작, 일시 연결 장애 후 재전송, 수집량/용량을 테스트한다. 로그 보존·조회 권한과 키 만료/교체 절차까지 확인한다.

기존 Python은 `raw-logs-*`를 읽고 Linux SSH 형식만 정규화한다. 신규 수집은 의도적으로 `soc-host-raw-linux-*`, `soc-host-raw-windows-*`에 분리했다. **새 로그가 기존 탐지나 정적 대시보드에 자동으로 표시되지는 않는다.** 수집 검증 후 소스 라우팅·파서·조회 API를 연결하는 별도 단계가 필요하다.

## 개발 검증과 남은 검증

```powershell
node --test deploy/agents/tests/installers.test.cjs
```

Node.js, Bash, Windows 테스트에는 PowerShell 7(`pwsh`)이 필요하다. `BASH_EXE`, `POWERSHELL_EXE`로 이미 설치된 실행 파일 경로를 지정할 수 있다. 테스트를 위해 실행 정책을 변경하지 않는다.

- 로컬 검증: Bash 구문, PowerShell 5.1 구문 호환 파싱, PowerShell 7 실행, 양쪽 미리보기 출력, HTTPS/인자 검증, 추가 소스, 중복 소스, 체크섬 실패, 기존 설치 거부, 네이티브 명령의 실패 전달. 테스트는 실제 설치를 실행하지 않는다.
- 공식 다운로드 서버에서 9.5.2 Linux x86_64/ARM64 및 Windows x86_64의 `.sha512` 값을 확인했다. 스크립트의 버전과 해시는 함께 검토해서 변경해야 한다.
- 미검증: 실제 Ubuntu/systemd 설치, Windows 서비스·ACL·LocalSystem keystore 접근, 실제 Beat 바이너리의 설정 해석, CA/API 키 연결, 인덱스 템플릿 등록과 실제 문서 유입. 중앙 보안 수신 환경이 준비되면 별도 테스트 서버에서 검증해야 한다.

체크섬 출처: [Linux x86_64](https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-9.5.2-linux-x86_64.tar.gz.sha512), [Linux ARM64](https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-9.5.2-linux-arm64.tar.gz.sha512), [Windows x86_64](https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-9.5.2-windows-x86_64.zip.sha512).
