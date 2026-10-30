# Cloud SOC

Windows·Ubuntu 로그를 중앙에 수집하고 경보의 근거 확인·사건 조사로 연결하는 Mini SIEM입니다. **Security Mall 없이 사용할 수 있습니다.** 일반 웹과 ModSecurity WAF는 사이트별 선택 수집이며 Mall 앱 감사는 별도 확장입니다.

범용 사이트·ModSecurity의 명시적 개발 프로필, 전환 시점·상태 보존, WSL 실제 요청 인수는 [운영 연결과 검증 기록](docs/operational_acceptance.md)을 확인하세요. 기존 배포의 활성 규칙은 자동 변경하지 않습니다.

처음 설치한다면 아래 순서로 진행하세요. 세부 수동 설정·CA 준비·패키지 검증은 [설치 참고](docs/installation_reference.md)를 따릅니다.

새 장치의 설치 묶음·Windows EXE·관리/제거는 [장치 설치와 배포](docs/device_installation.md), 토큰·키·수신 확인은 [에이전트 운영](docs/agent_management.md)을 따릅니다. 완료 기록과 지원 제한은 [현재 상태](docs/project_status.md)에 모았습니다.

## 1. 설치 전 준비

- 중앙 서버: 새 Ubuntu Server 22.04/24.04/26.04 LTS, systemd, amd64/arm64, sudo 권한.
- 자원: RAM 8GiB 이상 권장, 여유 디스크 10GiB 이상과 로그 저장 공간, 2 vCPU부터.
- 기존 Docker: CLI/Engine 24.0.0 이상, Compose 2.24.0 이상과 필요한 명령 지원을 검사합니다. 호환되면 재사용하며, 낮거나 기능이 없으면 업데이트 안내 후 중단합니다. 기존 프로그램을 자동 업그레이드하지 않습니다.
- 수집 대상: Windows 64비트 또는 Ubuntu 22.04/24.04. 네트워크 수집은 선택이며 Windows Npcap은 별도 준비합니다.
- 접속 주소: 관리자와 수집 대상이 실제 접속할 DNS/IP 및 서버 NIC에 실제 할당된 바인딩 IPv4.
- 방화벽: 443(Portal)·5601(Kibana)은 관리자 IP/VPN, 9200(수신)은 승인된 수집 대상/VPN에만 허용합니다. 설치기는 방화벽·클라우드 보안그룹을 자동 변경하지 않습니다.

`127.0.0.1`은 접속한 PC 자신입니다. 다른 PC에서는 실제 중앙 서버 주소를 사용하세요. AWS의 바인딩 주소는 공인 NAT 주소 대신 서버에 할당된 프라이빗 IPv4를 사용합니다.

## 2. Ubuntu 중앙 서버 최초 설치

**새 서버의 Ubuntu 터미널**에서 실행합니다. 기존 서버에는 최초 설치기를 다시 실행하지 마세요.

```bash
sudo apt-get update
sudo apt-get install -y git
git clone --branch main https://github.com/Gandalem/cloud-soc.git
cd cloud-soc
ip -4 -brief addr

# 10.0.0.10을 해당 서버의 실제 IPv4로 교체
sudo sh deploy/server/install-ubuntu.sh --host 10.0.0.10 --bind-ip 10.0.0.10
```

설치 중 Portal 관리자 비밀번호를 터미널의 보안 입력으로 설정합니다. 비밀번호·API 키를 명령 인자나 저장소에 넣지 마세요. DNS와 수집 주소를 다르게 사용하는 `--agent-host` 예시는 [설치 전체 안내](docs/device_installation.md#장치-설치)를 참고하세요.

Ubuntu의 `sudo` 비밀번호와 새 Portal 관리자 비밀번호는 별개입니다. Portal 비밀번호 입력과 확인에서는 글자나 별표가 표시되지 않습니다. 설치 확인은 `y` 또는 `yes`로 응답할 수 있습니다.

설치기는 필수 프로그램·Docker 준비 → 인증서 생성 → Cloud SOC 이미지 빌드 → Elasticsearch·Kibana·Caddy의 누락 이미지 준비 → 계정·워커 구성 → HTTPS 기동 확인 순서로 진행합니다. 안내는 한국어이며 빌드·다운로드의 외부 도구 출력은 원문으로 표시합니다. 이미 있는 검증 버전 이미지는 재사용하고 다른 버전으로 임의 대체하지 않습니다.

```bash
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml ps -a
```

Portal·Elasticsearch·Kibana·gateway와 필수 워커 상태를 확인합니다. 정상 종료한 bootstrap의 `Exited (0)`은 오류가 아닙니다. 기동 성공은 실제 에이전트 수신·탐지 완료를 의미하지 않습니다.

`runtime_ready: true`는 서버 실행 준비 확인 통과, `existing_keys_replaced: false`는 기존 키 보존을 뜻합니다. `live_acceptance: not_verified`는 아직 실제 수집·탐지 인수를 하지 않았다는 뜻이며 서버 기동 실패와 구분합니다.

| 목적 | 접속 주소 | 인증 |
| --- | --- | --- |
| Portal | `https://중앙-서버-주소/` | admin / 설치 중 설정한 비밀번호 |
| Kibana | `https://중앙-서버-주소:5601` | cloud_soc_analyst / 생성된 분석가 비밀번호 |
| 에이전트 수신 | `https://수신-주소:9200` | 전용 수집 API Key |

사설 CA를 사용하면 공개 CA의 SHA256을 대조하고 브라우저에 신뢰 등록해야 합니다. [Windows CA 등록 명령](docs/device_installation.md#장치-설치)을 사용하세요. TLS 검증을 끄거나 CA/서버 개인키를 에이전트에 전달하지 않습니다. 인증 없이 9200에 접속했을 때 HTTP 401은 정상입니다.

<a id="2-에이전트-설치"></a>

## 3. Portal에서 에이전트 패키지 생성

1. Portal에 로그인해 **에이전트 설치 파일 → 설치 파일 추가**를 엽니다.
2. OS·패키지 이름·조직·수집 항목을 선택합니다. 시스템 로그가 기본이며 웹 로그·네트워크는 선택입니다. 웹 수집에는 사이트와 로그 경로가 필요합니다.
3. ZIP(Windows) 또는 tar.gz(Ubuntu)을 받고 Portal의 SHA256과 대조합니다.
4. 대상별 로그 수집 키를 발급합니다. 네트워크 수집 키는 별도입니다. 키는 설치 도중 보안 프롬프트에 입력합니다.

설치 토큰 방식을 선택했다면 Portal의 **설치 토큰** 화면에 표시되는 명령과 입력 안내를 따르세요. 토큰과 수집 API 키는 서로 다른 값입니다. 토큰은 15분 이내 한 번 사용하며 패키지 해시와 대상 OS의 인증서 검증 조건을 확인해야 합니다. 신규 중앙 설정은 토큰 기능을 켜지만 기존 서버 설정은 자동 변경하지 않습니다. 자세한 조건은 [설치 토큰 안내](docs/agent_management.md#enrollment)를 참고하세요.

패키지의 모든 파일을 같은 폴더에 풉니다. 바이너리는 설치 중 공식 배포처에서 다운로드·검증하므로 인터넷 접속이 필요합니다.

웹 수집은 Apache·Nginx 등의 실제 로그 경로와 사이트를 지정합니다. **ModSecurity·OWASP CRS는 중앙 또는 에이전트 설치기가 자동 설치하지 않습니다.** 웹 서버에서 별도로 설치·설정한 WAF의 JSON 감사 로그를 선택 수집하는 기능입니다.

## 4. 수집할 장치에 설치

### Ubuntu

패키지를 대상 서버에 전달하고 아래 파일명을 실제 다운로드 파일명으로 바꿉니다.

```bash
PACKAGE="$HOME/설치파일명-setup.tar.gz"
sha256sum "$PACKAGE"
mkdir "$HOME/cloud-soc-agent-package"
tar -xzf "$PACKAGE" -C "$HOME/cloud-soc-agent-package"
cd "$HOME/cloud-soc-agent-package"
sha256sum -c SHA256SUMS
sudo bash install.sh
```

### Windows

다운로드한 ZIP의 SHA256을 대조하고 모든 파일을 푼 뒤 **관리자 PowerShell**에서 실행합니다.

```powershell
$package = Join-Path $env:USERPROFILE 'Downloads\실제패키지명-setup.zip'
Get-FileHash -LiteralPath $package -Algorithm SHA256
Expand-Archive -LiteralPath $package -DestinationPath 'C:\Cloud-SOC-Agent-Package'
Set-Location 'C:\Cloud-SOC-Agent-Package'
.\install.ps1
```

네트워크 수집을 선택한 경우 NIC·Npcap·추가 설치 인자는 [전체 설치 안내](docs/device_installation.md#장치-설치)와 [네트워크 안내](deploy/agents/NETWORK.md)를 따릅니다. 기존 설치와 충돌하면 덮어쓰기 전에 [설치 복구](docs/windows_agents.md#repair)를 확인합니다.

<a id="7-설치-후-실제-로그-확인"></a>

## 5. 새 로그부터 첫 경보까지 확인

1. Portal **에이전트 접속 현황**에서 대상의 마지막 중앙 수신 시각을 확인합니다.
2. **통합 로그**에서 최근 기간·장치·조직을 선택하고 직접 생성한 승인된 시험 이벤트를 대조합니다.
3. **관제 상세 → 분석 상태 → 실제 워커의 규칙·버전 확인**에서 실행 보고·revision·마지막 성공·처리 위치를 확인합니다.
4. 새 최종 경보의 상세·정확한 원본/정규화 근거를 확인합니다. [독립 SOC 첫 경보 인수](docs/operational_acceptance.md)의 읽기 전용 검사로 저장 근거를 대조하고 실제 브라우저·Slack 채널 수신을 각각 기록합니다.

로그 재탐색은 약 1분이며 전송·정규화·탐지에는 추가 시간이 필요합니다. 초기 통지는 최종 경보와 다릅니다. 로그가 수집됐다고 모든 이벤트가 경보가 되지는 않습니다. 경보 0건은 위험 없음의 증명이 아닙니다.

## 6. 화면 사용

| 화면 | 주소 | 확인 내용 |
| --- | --- | --- |
| 홈 | `/index.html` | 최근 경보·수신·사건 요약 |
| 내 대시보드 | `/dashboard.html` | 개인 위젯·기간 |
| 통합 로그 | `/logs.html` | 수집 로그·보호된 상세 |
| 관제 상세 | `/operations.html` | 집계·규칙 실행 보고·경보 근거 |
| 사건 조사 | `/workbench.html` | 연결된 경보·조사·사건 |

홈은 최근 24시간, 관제 상세는 최근 1시간이 기본입니다. 과거 경보는 기간을 늘려 조회하세요. 경보는 공격 성공이나 WAF 차단 성공을 확정하지 않습니다.

## 7. 문제 해결·기존 설치

- 접속 실패: 주소·바인딩 IP·443/5601 허용 IP·CA 신뢰·컨테이너 상태를 확인합니다.
- 수신 없음: 대상에서 9200 도달·API Key 만료·CA·Filebeat 로그를 확인합니다.
- 설치 중단: 기존 state·큐·키를 보존하고 [설치 상세 참고](docs/installation_reference.md)와 [Windows 복구](docs/windows_agents.md#repair)를 확인합니다.
- 기존 중앙 서버는 [공통 업데이트·복구](docs/runtime_deployment.md), 기존 Windows는 [에이전트 갱신](docs/windows_agents.md#discovery-update)을 따릅니다.

최초 설치에서 인증서와 `state/server/compose.env` 생성 후 이미지 준비·기동 단계가 실패했다면, 소스를 갱신한 뒤 기존 인증서·비밀번호로 설치를 이어갑니다.

```bash
git pull --ff-only origin main
sudo python3 deploy/server/manage.py recover
sudo python3 deploy/server/manage.py install --build
sudo python3 deploy/server/manage.py verify --startup-only
```

이 명령은 완료된 운영 서버의 일반 업데이트 절차가 아닙니다. 운영 서버는 위의 공통 업데이트 가이드를 따르세요. `compose.env` 생성 전 실패했거나 Git 갱신이 충돌하면 현재 상태를 보존하고 원인을 먼저 확인합니다.

`state/server`와 에이전트 상태는 보호해야 합니다. 문제 해결을 위해 `docker compose down -v`로 저장 데이터를 삭제하지 마세요.

## 8. 제거

중앙 서버의 저장소 폴더에서 실행합니다. 옵션 없이 실행하면 제거 계획만 표시합니다.

```bash
# 미리보기: 실제 삭제 없음
sudo sh deploy/server/uninstall-ubuntu.sh

# 중앙 실행 구성 제거: 데이터·인증서·비밀번호 보존
sudo sh deploy/server/uninstall-ubuntu.sh --apply

# 중앙 데이터와 공통 이미지까지 제거: 새 설치를 위한 초기화
sudo sh deploy/server/uninstall-ubuntu.sh --purge-data --remove-images --apply
```

실제 제거 시 표시된 계획을 확인하고 `y` 또는 `yes`를 입력합니다. 대소문자는 구분하지 않으며 빈 입력이나 다른 답은 취소합니다. `--yes`는 이 확인 입력만 생략합니다.

| 항목 | 기본 제거 `--apply` | 데이터·이미지 제거 옵션 추가 |
| --- | --- | --- |
| 중앙 Cloud SOC 컨테이너·전용 네트워크 | 삭제 | 삭제 |
| 수집 로그·경보·Portal 설정·인증서·비밀번호 | 보존 | 삭제 |
| Cloud SOC 공통 이미지 태그 | 보존 | 삭제 |
| Git으로 내려받은 소스·공식 이미지·빌드 캐시 | 보존 | 보존 |
| Docker 프로그램·Apache·Nginx·ModSecurity·다른 프로젝트 | 보존 | 보존 |
| 다른 VM의 에이전트·웹사이트 | 보존 | 보존 |

`--remove-docker`를 추가하면 다른 컨테이너·볼륨·사용자 네트워크가 없는 경우에만 공식 Docker CE 패키지를 추가 제거합니다. Docker 공용 저장 폴더와 캐시는 자동 삭제하지 않습니다. 같은 호스트의 Ubuntu 에이전트 제거는 `--component agent --purge-data --apply`, 중앙과 에이전트 동시 제거는 `--component all`을 사용합니다. 에이전트 발급 키는 중앙 Portal에서 별도 폐기하세요.

데이터 제거는 변경되지 않은 Cloud SOC 전용 커널 설정 파일도 정리하지만 실행 중인 커널 값은 낮추지 않습니다. 공유 리소스·다른 설치·변경된 설정이 발견되면 중단합니다. 자세한 대상과 제한은 [중앙 제거 안내](deploy/server/README.md#제거)를 참고하세요.

## 9. 선택 실습과 개발

서버·애플리케이션·네트워크의 수집 배치와 선택형 상관분석 규칙은 [통합 수집·분석 시나리오](docs/unified_collection_scenario.md)를 참고하세요.
인증·HTTP 접근 거부·Packetbeat 흐름 외의 환경별 3종 추가 규칙과 구조화 감사 수집은 [추가 보안 시나리오 9종](docs/security_scenarios.md)에 있습니다.

Security Mall·ModSecurity WAF는 일반 SOC 설치에 포함되지 않습니다. 현재 범위와 과거 계약/검증 압축본은 [선택 실습·참고](docs/optional_integrations.md)를 따릅니다. 별도 실험 성공을 새 중앙 서버의 상주 작동으로 해석하지 않습니다.

[로컬 개발](docs/local_development.md) · [중앙 서버 상세](deploy/server/README.md) · [전체 문서 색인](docs/README.md) · [작업 상태·남은 인수](docs/work_tracker.md)
