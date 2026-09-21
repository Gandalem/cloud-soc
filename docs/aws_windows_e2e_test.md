# AWS Ubuntu 중앙 서버 + Windows PC 실제 수집 테스트

목표는 **내 Windows PC의 새 로그가 AWS 인스턴스의 Elasticsearch에 저장되고 Kibana에서 검색되는 것**입니다. 먼저 로그만 검증하고, 성공한 다음 네트워크 수집을 추가합니다.

> 이 문서는 실행 절차이며 실제 AWS 배포 성공 보고서가 아닙니다. 인스턴스 생성·비용 발생·인증서 신뢰 등록·에이전트 설치는 사용자가 각 단계를 확인하고 진행합니다. 이전 `http://127.0.0.1:8766` 미리보기와 `preview-*` 패키지는 사용하지 않습니다.

## 0. 어디에서 무엇을 실행하는가

| 표시 | 실행 위치 | 할 일 |
| --- | --- | --- |
| AWS 콘솔 | 현재 PC의 브라우저 | EC2·보안그룹·IP 준비 |
| Ubuntu SSH | EC2에 접속한 터미널 | Docker·중앙 서버 설치 |
| Windows PowerShell | 현재 PC | 인증서 확인·에이전트 설치·테스트 로그 생성 |
| AWS 포털/Kibana | 현재 PC의 브라우저 | 패키지 다운로드·키 발급·실제 수신 확인 |

```text
Windows PC
  Filebeat ---------------- HTTPS 9200 --> AWS Ubuntu / Elasticsearch
  Packetbeat (2차 테스트) -- HTTPS 9200 -->           |
  브라우저 ---------------- HTTPS 443  --> 설치 파일 관리 포털
  브라우저 ---------------- HTTPS 5601 --> Kibana / 실제 로그 검색
```

현재 PC의 `localhost:9200`, `localhost:5601`은 기존 개발용 컨테이너입니다. 이번 테스트에서는 **AWS 주소**로 접속합니다. PC의 기존 개발 컨테이너를 지울 필요는 없습니다.

**관제 메인·조사·통합 로그 화면은 아직 샘플 데이터입니다.** 이번에 실제로 연결되는 부분은 에이전트 배포 포털과 Elasticsearch/Kibana입니다. 실데이터 판정에 데모 화면을 사용하지 않습니다. 탐지 규칙 연동은 이번 테스트 범위가 아닙니다.

## 1. AWS EC2 준비

### 인스턴스

AWS 콘솔에서 다음 조건의 신규 실습 인스턴스를 만듭니다. 기존 운영 인스턴스를 초기화해서 사용하지 않습니다.

| 설정 | 이번 테스트 기준 |
| --- | --- |
| 이름 | `cloud-soc-lab` |
| OS | Canonical의 Ubuntu Server **22.04·24.04·26.04 LTS 중 하나**, x86_64/amd64 |
| 메모리/CPU | 시작 구성으로 8GiB / 2vCPU, 예: `t3.large` |
| 디스크 | 암호화된 gp3 50GiB를 실습 시작점으로 사용, 수집량에 따라 조정 |
| 네트워크 | 인터넷 게이트웨이 경로가 있는 퍼블릭 서브넷, 접속 가능한 공인 IPv4 |
| SSH | 자신이 보관하는 키 페어 `.pem`, 사용자 `ubuntu` |
| IAM | 이 구성은 AWS API를 사용하지 않으므로 별도 관리자 IAM 역할·Access Key 불필요 |

공식 Ubuntu 이미지의 게시자는 Canonical입니다. [Ubuntu AMI 확인](https://documentation.ubuntu.com/aws/aws-how-to/instances/launch-ubuntu-ec2-instance/)

`t3.large`는 2vCPU/8GiB이며, 여기서의 선택은 소규모 실습 제안이지 성능 보장이 아닙니다. **무료 사용을 보장하지 않습니다.** EC2·EBS·공인 IPv4·트래픽과 T3 CPU 크레딧 관련 비용을 콘솔에서 확인하고 예산 알림을 설정하세요. [AWS T3 사양](https://aws.amazon.com/ec2/instance-types/t3/)

시험 도중 주소가 바뀌면 인증서와 이미 배포한 설정이 어긋납니다. 주소를 고정하려면 Elastic IP를 연결하거나 관리 가능한 고정 도메인 구성을 준비합니다. 일반 자동 할당 공인 IPv4는 중지 후 재시작 시 바뀔 수 있습니다. Elastic IP를 나중에 연결할 예정이라면 **인증서 생성 전에** 연결합니다. 공인 IPv4/Elastic IP는 사용 중에도 비용이 발생할 수 있습니다. [주소 동작](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html), [Elastic IP 비용·특성](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html)

### 보안그룹

이번에는 관리자와 에이전트가 같은 PC이므로 아래 네 포트 모두 소스를 **현재 PC가 인터넷으로 나가는 공인 IP `/32`**로 제한합니다. AWS 콘솔의 `내 IP / My IP`를 출발점으로 쓰고 학교망·VPN·프록시 환경에서는 실제 경로를 확인합니다. PC의 `192.168.*` 주소를 넣는 것이 아닙니다. [AWS 보안그룹 소스 설정](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/changing-security-group.html)

| 인바운드 TCP | 소스 | 목적 |
| --- | --- | --- |
| 22 | 내 공인 IP/32 | SSH·SCP |
| 443 | 내 공인 IP/32 | 중앙 관리 포털 |
| 5601 | 내 공인 IP/32 | Kibana |
| 9200 | 내 공인 IP/32 | PC 에이전트의 HTTPS 전송 |

**`0.0.0.0/0`, `::/0`, 모든 트래픽 허용으로 바꾸지 않습니다.** 이미 붙어 있는 다른 보안그룹에도 전체 공개 규칙이 없는지 확인합니다. 8000·8766·9300은 외부에 열지 않습니다. Windows PC에 인바운드 포트를 열 필요도 없습니다.

서버의 패키지·이미지 설치에는 DNS와 외부 저장소 접근이 필요합니다. 아웃바운드를 제한한 환경은 Docker/Elastic/PyPI/GitHub의 HTTPS 및 Ubuntu APT 저장소에 필요한 통신을 관리자가 허용해야 합니다. IP가 바뀌면 허용 목록을 갱신하고, 문제 해결을 위해 전체 공개하지 않습니다. Docker 게시 포트는 UFW만으로 제한되지 않을 수 있으므로 AWS 보안그룹과 실제 패킷 필터를 함께 확인합니다. [Docker 방화벽 주의사항](https://docs.docker.com/engine/install/ubuntu/)

## 2. Windows에서 EC2에 SSH 접속

**Windows PowerShell**에서 실제 값을 입력합니다. `$Host`는 PowerShell 예약 변수이므로 아래처럼 `$ServerHost`를 사용합니다.

```powershell
$ServerHost = Read-Host 'EC2의 실제 공인 IPv4 또는 연결된 도메인 (https://와 포트 제외)'
$KeyPath = Read-Host '다운로드한 SSH .pem 키의 절대 경로'
Test-NetConnection -ComputerName $ServerHost -Port 22
ssh -i $KeyPath "ubuntu@$ServerHost"
```

최초 SSH 접속의 호스트 키 지문은 AWS 콘솔의 신뢰할 수 있는 인스턴스 정보/시스템 로그와 비교한 뒤 승인합니다. SSH 호스트 키 검증을 끄지 않습니다. `.pem`은 SSH 접속용 **개인키**이며 아래 CA 공개 인증서와 다릅니다. Git·채팅·설치 묶음에 넣지 마세요. Windows 키 파일 권한 오류가 있으면 해당 파일에 대한 다른 사용자의 접근을 검토합니다. [AWS SSH 접속 안내](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-linux-inst-ssh.html)

이후 Ubuntu 명령은 SSH 안에서, Windows 명령은 PC의 별도 PowerShell에서 실행합니다.

## 3. Git + sh 자동 설치 (권장)

**Ubuntu SSH**, 신규 Ubuntu 22.04·24.04·26.04 LTS 서버에서 실행합니다. 위 보안그룹을 먼저 제한하세요. Git으로 받은 파일을 검토하고 `sh` 스크립트가 누락된 패키지와 Docker·Compose를 설치하도록 합니다. 저장소 복제 자체에 필요한 Git만 먼저 준비합니다.

```bash
cd /home/ubuntu
# git이 없을 때만 아래 두 줄을 실행
sudo apt-get update
sudo apt-get install -y --no-remove --no-upgrade git
git clone https://github.com/Gandalem/cloud-soc.git
cd /home/ubuntu/cloud-soc
git rev-parse HEAD
less deploy/server/install-ubuntu.sh
sh deploy/server/install-ubuntu.sh --dry-run
sudo sh deploy/server/install-ubuntu.sh
```

이미 체크아웃이 있다면 새로 복제하지 말고 기존 변경을 보존하세요. `less`는 확인 후 `q`로 닫습니다. `git rev-parse HEAD` 결과는 실제 테스트한 버전으로 기록합니다. 예전 커밋으로 전환하면 새 설치기가 없을 수 있습니다.

예전 설치기의 `Only Ubuntu 22.04 is supported` 오류만 발생했다면 사전 검사에서 멈춘 것입니다. [중앙 서버의 버전별 안내](../deploy/server/README.md#ubuntu-버전-범위)에 따라 `git status --short`로 변경을 확인하고 `git pull --ff-only origin main`으로 수정본을 받으세요. `/etc/os-release`에서 버전·코드명을 확인해 22.04=`jammy`, 24.04=`noble`, 26.04=`resolute` 저장소를 선택합니다. 임의로 버전 검사만 삭제하거나 다른 배포판의 저장소를 사용하지 않습니다.

| 입력 순서 | 넣을 값 |
| --- | --- |
| `Public DNS/IPv4` | Windows PC에서 접근하는 고정 공인 IPv4 또는 도메인. `https://`·포트 제외 |
| `Local bind IPv4` | EC2의 기본 **프라이빗 IPv4**. 직전에 출력되는 인터페이스 주소에도 존재해야 함 |
| 변경 승인 | 보안그룹과 설치 계획 확인 후 `INSTALL` |
| 관리자 비밀번호 | 포털 `admin`용 16자 이상 비밀번호를 두 번 입력 |

EC2 공인 IP는 보통 NAT 주소라서 바인딩 값으로 사용할 수 없습니다. 바인딩을 공란으로 두면 `127.0.0.1`만 사용하여 원격 접속이 안 됩니다. 이후 에이전트 패키지의 관리 서버 주소는 이때 정한 공개 주소로 자동 설정됩니다.

스크립트는 최소 6GiB RAM·10GiB 여유 디스크를 검사하고, 누락된 필수 패키지 설치, Docker·Compose 준비, 커널 설정, 인증서 생성, 중앙 컨테이너 기동, bootstrap 및 로컬 TLS/HTTP 확인까지 수행합니다. **8GiB 이상 메모리를 권장하며 다운로드·보관에는 추가 디스크가 필요합니다.** 다운로드에는 시간이 걸리므로 SSH 연결을 유지합니다.

기존 중앙 상태·컨테이너·볼륨·다른 Docker 저장소/충돌 패키지·사용 중인 포트가 있으면 덮어쓰거나 제거하지 않고 중단합니다. `--dry-run`은 계획 출력만 합니다. `--prepare-only`는 의존성·인증서까지만 준비하며 SOC 컨테이너는 시작하지 않습니다. 자동 설치기는 원격 접속 성공이나 에이전트 수신까지 보장하지 않습니다.

**성공하면 아래 수동 3-A·4·5절을 건너뛰고 6절로 이동합니다.** 실패하면 출력된 첫 오류를 확인하세요. `state/server/compose.env` 생성 이후의 기동 실패는 상태를 보존한 채 5절 Compose 명령으로 재시도합니다. 준비 단계의 부분 실패는 [중앙 설치기의 실패·재시도 안내](../deploy/server/README.md#실패재시도)를 먼저 확인합니다.

### 3-A. Docker와 필수 도구 수동 설치 (대안)

이하 3-A·4·5절은 자동 설치를 사용하지 않는 경우에만 실행합니다. 두 경로를 연속으로 실행하지 않습니다.

**Ubuntu SSH**, 위 지원 목록의 신규 Ubuntu LTS 기준입니다. Docker가 이미 있으면 먼저 버전과 기존 컨테이너를 확인하고 재설치 부분은 건너뜁니다. 충돌 패키지나 기존 데이터를 자동 삭제하지 않습니다.

```bash
lsb_release -ds
uname -m
free -h
df -h /
sudo apt-get update
sudo apt-get install -y ca-certificates curl git python3 openssl
```

Docker가 없는 경우 [공식 APT 설치 방식](https://docs.docker.com/engine/install/ubuntu/)으로 설치합니다. 기존 `docker.sources` 또는 다른 Docker 저장소 설정이 있다면 먼저 확인하고 아래 파일을 덮어쓰지 않습니다.

```bash
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
sudo tee /etc/apt/sources.list.d/docker.sources > /dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && printf '%s' "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker version
sudo docker compose version
```

Elasticsearch용 커널 설정을 확인합니다. 현재 값이 `1048576` 이상이면 유지합니다. 부족한 경우에만 아래 파일을 추가하며 같은 파일이 이미 있으면 먼저 검토합니다. [Elastic Docker 운영 설정](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-prod)

```bash
sysctl vm.max_map_count
printf 'vm.max_map_count=1048576\n' | sudo tee /etc/sysctl.d/90-cloud-soc.conf
sudo sysctl -p /etc/sysctl.d/90-cloud-soc.conf
```

## 4. 중앙 서버 인증서·주소 준비 (수동 경로)

**Ubuntu SSH**에서 저장소를 내려받습니다. 아래는 신규 디렉터리 기준이며 이미 있으면 기존 변경을 보존하고 해당 디렉터리를 사용합니다.

```bash
cd /home/ubuntu
git clone https://github.com/Gandalem/cloud-soc.git
cd /home/ubuntu/cloud-soc
git rev-parse HEAD
ip -4 -brief address
```

`git rev-parse HEAD` 결과를 실제 테스트 버전으로 기록합니다. 재현 시 해당 버전의 문서·설정·스크립트를 함께 사용하세요.

다음 두 값은 서로 다릅니다.

| 값 | 넣을 주소 |
| --- | --- |
| `PUBLIC_HOST` | Windows에서 접근하는 EC2 공인 IPv4 또는 고정 도메인 |
| `BIND_IP` | EC2 콘솔의 기본 프라이빗 IPv4. 위 `ip` 출력에도 실제로 존재하는 주소 |

EC2 공인 IP는 보통 NAT로 연결되므로 Ubuntu 인터페이스에 직접 붙어 있지 않습니다. 공인 IP를 `BIND_IP`로 넣지 마세요. `BIND_IP`를 생략하면 기본값 `127.0.0.1` 때문에 원격 PC가 접속하지 못합니다.

```bash
read -r -p 'Windows에서 접근할 실제 공인 IPv4 또는 도메인: ' PUBLIC_HOST
read -r -p '이 EC2 인터페이스에 있는 기본 프라이빗 IPv4: ' BIND_IP
sudo python3 deploy/server/prepare.py --host "$PUBLIC_HOST" --bind-ip "$BIND_IP"
```

여기서 **포털 `admin` 비밀번호를 16자 이상으로 두 번 입력**합니다. `https://`, 포트, 경로는 주소 입력에 넣지 않습니다. 이후 에이전트 설치 파일에는 `https://PUBLIC_HOST:9200`이 자동으로 포함됩니다. 패키지를 만들 때 주소를 다시 입력하는 방식이 아닙니다.

`state/server/`가 이미 있으면 준비 명령은 중단합니다. 오류가 났다고 상태 폴더를 지우거나 CA를 새로 만들지 말고, 처음 실패한 단계를 확인합니다. 이미 사용 중인 CA·계정·DB를 재생성하면 기존 설치가 깨질 수 있습니다.

## 5. 중앙 서버 기동 (수동 경로·실패 후 복구)

**Ubuntu SSH**, 반드시 `/home/ubuntu/cloud-soc`에서 실행합니다. 루트의 개발용 `docker compose up -d`가 아니라 아래 전용 Compose를 사용합니다.

```bash
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml config --quiet
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml up -d --build
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml ps -a
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml logs --tail 80 bootstrap portal gateway
```

| 서비스 | 다음 단계로 가기 위한 상태 |
| --- | --- |
| elasticsearch | `Up`, healthcheck `healthy` |
| bootstrap | **Exited (0)**. 계정·템플릿 준비가 끝나면 종료되는 것이 정상 |
| portal | `Up` |
| kibana | `Up`, 브라우저 접속 준비 완료 |
| gateway | `Up` |

이미지 다운로드와 최초 기동에는 시간이 걸립니다. `Up`만으로 모든 기능이 검증된 것은 아닙니다. `Exited (1)`이나 재시작 반복이면 진행을 멈추고 다음 로그를 봅니다. 특히 1GB/2GB 인스턴스에서 메모리 부족을 의심해야 합니다.

```bash
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml logs --tail 100 elasticsearch bootstrap kibana portal gateway
sudo docker stats --no-stream
df -h /
```

SSH를 닫아도 `-d`로 실행한 중앙 컨테이너는 유지됩니다. 테스트용 Python 미리보기 프로세스와 다릅니다.

## 6. Windows에 CA 공개 인증서 전달·신뢰

브라우저와 서버 사이에 HTTPS가 필요합니다. 사설 CA는 Windows가 원래 신뢰하지 않으므로 **자신이 만든 CA인지 확인한 다음** 신뢰 등록합니다. 등록하면 이 CA가 발급한 인증서를 해당 Windows 사용자가 신뢰하게 되므로, 다른 사람이 준 CA를 확인 없이 등록하지 않습니다.

### Ubuntu SSH: 공개 인증서만 내보내기

```bash
cd /home/ubuntu/cloud-soc
sudo openssl x509 -in state/server/tls/ca.crt -outform DER -out /home/ubuntu/cloud-soc-lab-ca.cer
sudo chmod 0644 /home/ubuntu/cloud-soc-lab-ca.cer
sha256sum /home/ubuntu/cloud-soc-lab-ca.cer
```

SHA-256 값을 기록합니다. 이 값은 **DER 내보내기 파일**의 해시이며, `prepare.py`가 출력한 PEM 파일 해시와 다릅니다. 자동 설치기는 `state/server/tls/ca.cer`의 DER 해시도 출력하므로 동일 CA라면 여기서 내보낸 파일과 같아야 합니다. `private/ca.key`, `tls/server.key`, `secrets/`, `kibana.yml`은 복사하지 않습니다.

### Windows PowerShell: SCP와 해시 비교

SSH 접속에 사용한 것과 같은 검증된 서버를 사용합니다. 이전 PowerShell을 닫았으면 `$ServerHost`, `$KeyPath`를 다시 입력합니다.

```powershell
$ServerHost = Read-Host '앞에서 지정한 실제 EC2 공인 IPv4 또는 도메인'
$KeyPath = Read-Host 'SSH .pem 키의 절대 경로'
$Work = Join-Path $env:USERPROFILE 'Downloads\cloud-soc-aws-lab'
New-Item -ItemType Directory -Path $Work -ErrorAction Stop
$CaFile = Join-Path $Work 'cloud-soc-lab-ca.cer'
scp -i $KeyPath "ubuntu@${ServerHost}:/home/ubuntu/cloud-soc-lab-ca.cer" $CaFile
if ($LASTEXITCODE -ne 0) { throw 'CA download failed.' }
```

`$Work`가 이미 있으면 먼저 기존 파일을 검토하고 다른 새 폴더를 지정하세요. 아래 **전체 블록**은 해시가 다르면 인증서 등록 전에 중단합니다.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $ExpectedCaHash = (Read-Host 'Ubuntu sha256sum에 나온 DER 파일 해시 64자리').Trim()
    if ($ExpectedCaHash -notmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid SHA-256.' }
    if ((Get-FileHash -LiteralPath $CaFile -Algorithm SHA256).Hash -ine $ExpectedCaHash) {
        throw 'CA hash mismatch. Do not trust this certificate.'
    }
    Import-Certificate -FilePath $CaFile -CertStoreLocation 'Cert:\CurrentUser\Root' -Confirm |
        Select-Object Subject, Thumbprint, NotAfter
}
```

승인 프롬프트에서 확인 후 진행하고 출력된 인증서 Thumbprint를 기록합니다. 현재 사용자 저장소만 사용하며, 에이전트 서비스는 별도로 설치 묶음의 CA 파일을 읽습니다. 브라우저를 사용하는 계정과 인증서를 등록한 계정이 같아야 합니다. [Microsoft 인증서 가져오기](https://learn.microsoft.com/en-us/powershell/module/pki/import-certificate?view=windowsserver2025-ps)

**인증서 경고를 무시해서 접속하거나 TLS 검증을 끄지 않습니다.** 인증서 등록 후 필요하면 브라우저를 다시 시작합니다. 회사·학교 관리 PC에서는 먼저 관리자 승인을 받습니다.

## 7. 실제 포털과 Kibana 접속

**Windows PowerShell**에서 포트 접근부터 확인합니다.

```powershell
Test-NetConnection -ComputerName $ServerHost -Port 443
Test-NetConnection -ComputerName $ServerHost -Port 5601
Test-NetConnection -ComputerName $ServerHost -Port 9200
"Portal: https://$ServerHost"
"Kibana: https://${ServerHost}:5601"
"Receiver: https://${ServerHost}:9200"
```

`TcpTestSucceeded : True`는 TCP 접근만 뜻하며 TLS·로그인·저장 성공까지 보장하지 않습니다.

| 주소 | 로그인 |
| --- | --- |
| 위 `Portal` 주소 | `admin` / 자동 설치 또는 수동 4절에서 직접 정한 비밀번호 |
| 위 `Kibana` 주소 | `cloud_soc_analyst` / 서버의 분석가 비밀번호 |
| 위 `Receiver` 주소 | 인증 없이 열면 401이 정상. 공개 조회 서버가 아님 |

분석가 비밀번호는 **Ubuntu SSH**에서 다음처럼 읽습니다. 명령은 비밀번호를 화면에 출력하므로 화면 공유·녹화 중에는 실행하지 말고, 값을 채팅이나 Git에 올리지 않습니다.

```bash
cd /home/ubuntu/cloud-soc
sudo head -c 256 state/server/secrets/analyst_password
printf '\n'
```

포털에서 **Elasticsearch: 연결 확인**과 실제 `https://내-AWS-주소:9200`이 보이면 다음으로 진행합니다. `soc.example.invalid`가 보이면 잘못된 테스트 페이지입니다. `/api/portal` 연결만 확인되었다고 실제 에이전트 수신이 완료된 것은 아닙니다.

## 8. Windows 로그 전용 패키지 설치

### 실제 AWS 포털: 패키지 생성

1. **설치 파일 추가**를 누릅니다.
2. OS는 Windows, 파일 이름은 `win-pc-logs`, 조직 ID는 `school-lab`을 입력합니다.
3. 첫 테스트에서는 **네트워크 수집 체크를 해제**합니다.
4. 생성된 `win-pc-logs-setup.zip`을 다운로드합니다. 실제 AWS 서버 주소가 포함되어야 합니다.
5. **키 발급**에서 1일 또는 7일을 선택하고 Filebeat 키를 안전하게 보관합니다. 화면에 표시되는 `id:api_key` 그대로 입력할 것이며, 포털 관리자 비밀번호와 다릅니다.

### Windows: 설치 전 확인

본인에게 수집 권한이 있는 PC에서만 실행합니다. 설치 후에는 테스트 로그 한 건뿐 아니라 **기존 활성 이벤트 채널과 지원 로그 파일도 전송**되므로 회사·학교 PC는 데이터 수집 승인을 먼저 받으세요. 수집 범위는 [로그 수집 계약](../deploy/agents/COLLECTION.md)에 있습니다. 처음에는 과거 로그도 유입되어 디스크 사용량이 늘 수 있습니다.

**64비트 Windows PowerShell을 관리자 권한으로** 열고 확인합니다.

```powershell
[Environment]::Is64BitOperatingSystem
[Environment]::Is64BitProcess
$env:PROCESSOR_ARCHITECTURE
Get-ExecutionPolicy -List
Get-Service -Name cloud-soc-filebeat,cloud-soc-winlogbeat,filebeat,winlogbeat,elastic-agent -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName Cloud-SOC-Discovery -ErrorAction SilentlyContinue
Test-Path "$env:ProgramFiles\Cloud-SOC-Agent"
```

기대값은 `True`, `True`, `AMD64`입니다. 기존 수집 서비스·예약 작업·설치 흔적이 있으면 새 설치를 멈추고 검토합니다. 설치기는 덮어쓰기를 거부하며 무조건 제거하면 이전 설정·미전송 데이터가 손실될 수 있습니다.

### Windows: 해시 검증·압축 해제

다운로드 위치가 다른 경우 `$Zip`을 실제 위치로 바꿉니다. 관리자 터미널이 다른 계정으로 실행되었다면 Downloads 경로도 확인합니다. 아래 전체 블록을 실행합니다. 같은 추출 폴더가 있으면 새 이름을 사용하고 덮어쓰지 않습니다.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $Zip = Join-Path $env:USERPROFILE 'Downloads\win-pc-logs-setup.zip'
    $ExpectedHash = (Read-Host '실제 AWS 포털의 패키지 상세 SHA-256 64자리').Trim()
    if ($ExpectedHash -notmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid SHA-256.' }
    if ((Get-FileHash -LiteralPath $Zip -Algorithm SHA256).Hash -ine $ExpectedHash) {
        throw 'Package hash mismatch. Stop installation.'
    }
    $Destination = Join-Path $env:USERPROFILE 'Downloads\win-pc-logs-agent'
    if (Test-Path -LiteralPath $Destination) { throw 'Destination already exists. Review it first.' }
    Expand-Archive -LiteralPath $Zip -DestinationPath $Destination
    Set-Location -LiteralPath $Destination
    Get-Content .\package.json
}
```

`package.json`에서 OS·조직·실제 AWS 수신 주소와 `network: false`를 확인합니다. `ca.crt`, `install.ps1`, `install-windows.ps1`, `discover-windows.ps1`을 함께 유지합니다.

### 다운로드 파일의 실행 정책

인터넷에서 받은 파일은 `RemoteSigned`에서도 출처 표시 때문에 차단될 수 있습니다. 전역 정책을 `Bypass`/`Unrestricted`로 변경하거나 `-ExecutionPolicy Bypass`를 사용하지 않습니다. `AllSigned`나 조직 정책이 요구하면 모든 관련 스크립트에 승인된 코드 서명을 적용해야 합니다.

개인 실습 PC에서 유효 정책이 `RemoteSigned`이고 **자신의 실제 AWS 서버에서 받은 ZIP 해시와 스크립트 내용을 검토하고 실행을 승인한 경우에만**, 이 세 파일의 다운로드 차단 표시를 해제할 수 있습니다. 전체 Downloads 폴더를 재귀 해제하지 않습니다. 이는 실행 정책 자체를 바꾸지 않습니다. [Microsoft의 검토 후 파일 차단 해제 안내](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.5)

```powershell
Get-AuthenticodeSignature .\install.ps1, .\install-windows.ps1, .\discover-windows.ps1
# 본인이 내용을 검토하고 실행을 승인한 RemoteSigned 환경에서만 진행
Unblock-File -LiteralPath .\install.ps1
Unblock-File -LiteralPath .\install-windows.ps1
Unblock-File -LiteralPath .\discover-windows.ps1
```

### 설정 미리보기 후 실제 설치

```powershell
.\install.ps1 -DryRun
$LASTEXITCODE
```

`0`과 올바른 HTTPS AWS 주소를 확인합니다. 이 단계는 실제 연결·설치 성공을 뜻하지 않습니다.

**다음 명령부터 실제 다운로드·서비스 등록·로그 전송이 시작됩니다.** 관리자 터미널에서 실행하고 프롬프트에 Filebeat용 `id:api_key`를 입력합니다. 키를 명령 뒤에 붙이지 않습니다.

```powershell
.\install.ps1
$LASTEXITCODE
Get-Service cloud-soc-filebeat
Get-ScheduledTaskInfo -TaskName Cloud-SOC-Discovery
```

종료 코드 `0`, 서비스 `Running`, 완료된 탐색 작업의 `LastTaskResult = 0`을 확인합니다. 이 상태만으로 문서 저장이 검증된 것은 아닙니다. 설치 실패 시 보호된 부분 상태가 남을 수 있으므로 같은 명령을 무조건 반복하지 않습니다.

## 9. 고유 로그를 만들어 Kibana에서 찾기

### Windows: 이벤트 로그 생성

**관리자 PowerShell**에서 합성 테스트 이벤트 하나를 Application 채널에 만듭니다. Security 채널을 조작하거나 로그인 실패 공격을 수행할 필요가 없습니다. [Microsoft eventcreate 설명](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/eventcreate)

```powershell
$TestId = 'CLOUD_SOC_E2E_' + [guid]::NewGuid().ToString('N')
eventcreate.exe /L APPLICATION /T INFORMATION /SO CloudSOCTest /ID 1000 /D "$TestId Filebeat to AWS"
if ($LASTEXITCODE -ne 0) { throw 'Test event creation failed.' }
Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='CloudSOCTest'; Id=1000; StartTime=(Get-Date).AddMinutes(-5) } |
    Where-Object { $_.Message -like "*$TestId*" } |
    Select-Object TimeCreated, Id, ProviderName, Message
"PC: $env:COMPUTERNAME"
'KQL: organization.id : "school-lab" and winlog.channel : "Application" and message : "' + $TestId + '"'
```

### AWS Kibana: 실제 저장 확인

1. **AWS 주소의 Kibana**에 분석가 계정으로 접속합니다.
2. `Discover`에서 Data View를 만듭니다. 필요하면 Stack Management의 Data Views로 이동합니다.
3. 패턴은 `soc-host-raw-*`, 시간 필드는 `@timestamp`를 선택합니다. 아직 인덱스가 없으면 서비스 로그와 TLS·키 권한을 먼저 확인합니다.
4. 시간 범위를 **최근 1시간**으로 설정하고, PowerShell이 출력한 `KQL:` 뒤의 검색식을 붙여 넣습니다.
5. 새로고침해 고유 `$TestId`가 들어간 문서의 시간·호스트·조직·채널을 로컬 이벤트와 비교합니다.

확인 필드: `@timestamp`, `host.name`, `organization.id`, `winlog.channel`, `event.code`, `message`. 처음 과거 로그가 많이 쌓이면 새 이벤트가 보일 때까지 지연될 수 있습니다. 서비스 로그의 인덱싱 오류도 같이 봅니다.

**이 문서가 실제 AWS Kibana에서 보이면 Windows 이벤트 로그 → Filebeat → HTTPS → Elasticsearch → Kibana 경로가 검증된 것입니다.** 이것이 탐지 규칙 실행이나 모든 종류의 로그 수집 성공까지 뜻하지는 않습니다.

### 선택: 새 파일 자동 탐색도 검증

같은 관리자 PowerShell에서 자동 탐색 대상인 `%ProgramData%\logs` 하위에 고유 파일을 만듭니다. 개인정보가 없는 합성 내용만 넣습니다.

```powershell
$FileTestId = 'CLOUD_SOC_FILE_E2E_' + [guid]::NewGuid().ToString('N')
$LogDir = Join-Path $env:ProgramData 'logs\cloud-soc-e2e'
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$TestFile = Join-Path $LogDir "$FileTestId.log"
Set-Content -LiteralPath $TestFile -Value ("$FileTestId " + ('x' * 2048)) -Encoding UTF8
'KQL: organization.id : "school-lab" and labels.log_source : "windows_file" and message : "' + $FileTestId + '"'
```

재탐색은 1분, 입력 재로딩은 10초 주기입니다. 실제 지연은 부하에 따라 더 길 수 있으므로 1~2분 후 같은 Data View에서 출력된 KQL로 확인합니다. 계속 없다면 `discovery-report.json`의 파일 경로와 제외 사유부터 봅니다.

## 10. 로그 성공 후 네트워크 수집 추가

이 단계는 선택한 NIC에서 **실제 통신 메타데이터 수집**을 시작합니다. 원본 PCAP은 저장하지 않지만 IP·DNS 이름·SNI도 민감할 수 있습니다. 본인에게 승인된 NIC에서만 진행합니다. 먼저 [네트워크 수집 범위](../deploy/agents/NETWORK.md)를 확인합니다.

### Npcap과 NIC 확인

**관리자 PowerShell**에서 확인합니다. 2026-09-21 조회 시 현재 PC의 Npcap은 `Running`이었지만, 설치 시 다시 확인해야 합니다. 새 Npcap을 자동으로 설치·교체하지 않습니다. 필요한 경우 [공식 Npcap 배포처](https://npcap.com/#download)의 라이선스·학교 정책을 확인하고 승인된 설치를 진행합니다.

```powershell
Get-Service npcap
Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll"
Get-NetAdapter -IncludeHidden | Select-Object Name, Status, InterfaceGuid
```

AWS로 나가는 실제 `Up` 상태의 Ethernet/Wi-Fi/VPN 인터페이스를 선택합니다. Docker·VMware 가상 어댑터를 이름만 보고 선택하지 않습니다. VPN에서는 물리 NIC에 VPN 암호화만 보일 수 있어 DNS/TLS를 기대하는 지점을 구분해야 합니다. GUID는 중괄호 없이 입력합니다.

### 포털 패키지에서 네트워크 설치기만 실행

1. 실제 AWS 포털에서 Windows, 파일 이름 `win-pc-network`, 조직 `school-lab`, 네트워크 수집 **체크**로 새 패키지를 만듭니다.
2. 다운로드한 `win-pc-network-setup.zip`도 8절과 동일하게 포털 SHA-256 대조 후 **새 폴더**에 풉니다. `$Zip`과 `$Destination`만 해당 파일명으로 바꿉니다.
3. 새로 발급된 두 키 중 **Packetbeat 네트워크 키**를 사용합니다. 이때 같이 발급된 새 Filebeat 키는 사용하지 않으므로, ID를 정확히 확인해 발급 키 관리에서 폐기합니다. 8절에서 실제 사용 중인 Filebeat 키와 혼동하지 마세요.
4. 기존 Filebeat가 설치되어 있으므로 **새 묶음의 `install.ps1`을 실행하지 않습니다.** 아래 개별 네트워크 설치기만 실행합니다. 통합 설치기는 기존 로그 수집기를 덮어쓰지 않고 중단하도록 되어 있습니다.

새로 푼 `win-pc-network` 폴더에서 실행합니다. 실행 정책 절차는 8절과 동일하며, `RemoteSigned`에서 검토·승인이 끝난 경우에만 `install-network-windows.ps1` 한 파일에 대해 `Unblock-File`을 사용합니다.

```powershell
$Spec = Get-Content .\package.json -Raw | ConvertFrom-Json
$Spec | Select-Object name, os, organization, endpoint, network
$NicGuid = Read-Host '선택한 실제 Up NIC의 InterfaceGuid (중괄호 제외)'
$CaPath = (Resolve-Path .\ca.crt).Path
.\install-network-windows.ps1 -Endpoint $Spec.endpoint -CaPath $CaPath -Organization $Spec.organization -InterfaceGuid $NicGuid -DryRun
$LASTEXITCODE
```

실제 AWS 주소·조직·NIC 설정을 확인한 뒤 `-DryRun` 없이 설치합니다. 프롬프트에는 새 **네트워크 키**를 입력합니다.

```powershell
.\install-network-windows.ps1 -Endpoint $Spec.endpoint -CaPath $CaPath -Organization $Spec.organization -InterfaceGuid $NicGuid
$LASTEXITCODE
Get-Service cloud-soc-filebeat,cloud-soc-packetbeat,npcap
```

### 통신을 생성하고 확인

**Windows PowerShell**에서 실제 AWS 포털에 TLS 요청을 보냅니다. 인증정보 없이 요청하므로 HTTP **401**이면 서버 접근 제한이 동작하는 정상 결과입니다. `-k`를 넣지 않습니다.

```powershell
$ServerHost = Read-Host '인증서에 지정한 실제 AWS 공인 IPv4 또는 도메인'
curl.exe --silent --show-error --output NUL --write-out "%{http_code}\n" "https://$ServerHost/"
$LASTEXITCODE
```

DNS도 확인하려면 EC2 콘솔에서 자신의 **Public IPv4 DNS**를 확인한 뒤 질의합니다. 해당 이름이 없다면 소유·승인한 테스트 도메인을 준비하고 이 부분은 나중에 확인합니다.

```powershell
$DnsTestName = Read-Host '자신의 EC2 Public IPv4 DNS 이름'
nslookup.exe $DnsTestName
```

AWS Kibana에서 `soc-network-*`, 시간 필드 `@timestamp`의 Data View를 만듭니다. 최근 15분으로 조회하고 다음 KQL을 각각 사용합니다. 여러 PC가 있으면 확인한 `host.name`을 추가 필터로 지정합니다.

```kql
organization.id : "school-lab" and labels.log_source : "network_packetbeat" and event.dataset : "flow" and flow.final : true
```

```kql
organization.id : "school-lab" and type : "dns"
```

```kql
organization.id : "school-lab" and type : "tls"
```

최종 흐름은 해당 통신이 끝나고 비활성 타임아웃(30초)을 지난 뒤 확인합니다. TLS 요청의 목적지 IP·443 포트, DNS 질의 이름·시각과 맞춰 봅니다. IP로 접속하면 SNI가 없을 수 있으며, DNS가 다른 NIC·암호화 경로로 지나가면 DNS 이벤트가 없을 수 있습니다. **흐름 성공과 DNS/TLS 세부 이벤트 성공을 각각 기록**합니다. 흐름의 중간 누적값과 최종값을 모두 합산하지 않습니다.

## 11. 실패했을 때 확인 순서

| 증상 | 먼저 확인할 것 |
| --- | --- |
| `Only Ubuntu 22.04 is supported` | 구버전 중앙 설치기. 로컬 변경 확인 후 Git 갱신, 실제 OS는 `cat /etc/os-release`로 확인 |
| `Ubuntu ... is not supported by this installer` 또는 코드명 불일치 | 22.04·24.04·26.04 LTS와 올바른 코드명인지 확인. 검사 우회·`jammy` 강제 지정 금지 |
| `127.0.0.1:8766`, `preview-*`, `soc.example.invalid`가 보임 | 옛 미리보기. 실제 AWS HTTPS 포털과 거기서 만든 새 패키지 사용 |
| 포털에서 `Failed to fetch` | 동일 AWS 주소의 포털/gateway 상태, 클라이언트 네트워크, 인증서, 서버 로그. 임시 Python 서버 재실행으로 해결하지 않음 |
| 모든 `Test-NetConnection`이 실패 | 현재 공인 IP/32, 보안그룹·다른 그룹의 규칙, 서브넷/IGW, NACL, 인스턴스 실행 여부 |
| `cannot assign requested address` | `BIND_IP`에 NAT 공인 IP를 넣었는지 확인. 실제 EC2 프라이빗 IP 필요 |
| 브라우저 인증서 오류 | 정확한 CA·해시·사용자 저장소, 인증서 SAN과 접속 주소, 만료·시계. 검증을 끄지 않음 |
| ES 주소를 그냥 열었더니 401 | 인증을 요구하는 정상 동작. 에이전트는 별도의 수집 키 사용 |
| 포털의 ES 연결 확인 실패 | `bootstrap` 종료 코드, issuer 비밀번호·CA, 내부 ES 상태 |
| bootstrap가 Exited (0) | 정상. 준비 작업 후 종료되는 서비스 |
| 설치 중 Existing service/partial state | 기존 설치 보존. 자동 삭제·덮어쓰기 금지, 처음 실패한 단계부터 분석 |
| 설치 스크립트 실행 차단 | 현재·조직 실행 정책, 파일 출처/해시 검토, 승인된 서명 또는 허용된 파일별 차단 해제 |
| 서비스는 Running인데 로그가 없음 | 실제 AWS Kibana인지, Data View·시간 범위·고유 TestId·큐/색인 오류·키 권한 확인 |
| 네트워크 인덱스에 403 | Filebeat 키를 Packetbeat에 넣었는지, 네트워크 키 만료·권한 확인 |
| 패킷 문서 없음 | Npcap·Up NIC·실제 통신 경로·VPN·프로토콜·전송 오류를 구분 |
| 컨테이너 재시작/OOM | EC2와 개별 컨테이너 메모리, 디스크 용량 확인. 상태 볼륨 삭제는 해결책이 아님 |

Windows 수집기 로그는 관리자 PowerShell에서 확인합니다. 네트워크를 아직 설치하지 않았다면 두 번째 경로는 없습니다.

```powershell
Get-ChildItem "$env:ProgramFiles\Cloud-SOC-Agent\logs" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 5 Name,LastWriteTime,Length
Get-Content "$env:ProgramFiles\Cloud-SOC-Agent\discovery-report.json" -Raw
Get-ChildItem "$env:ProgramFiles\Cloud-SOC-Network\logs" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 5 Name,LastWriteTime,Length
```

목록에서 실제 로그 파일을 선택해 마지막 오류 부분만 읽습니다. 보고서에는 PC 파일 경로·채널 이름이 포함됩니다. 지원을 요청할 때는 API 키·비밀번호·개인키·개인정보를 빼고 서비스 상태, 오류 문구, 시간, 커밋, 테스트 ID만 전달하세요. `test output` 성공도 실제 인덱싱 성공과 별개입니다.

## 12. 완료 판정과 시험 종료

| 항목 | 성공 증거 | 결과 기록 |
| --- | --- | --- |
| 중앙 서버 | ES healthy, bootstrap Exited (0), 포털·Kibana HTTPS 로그인 | 미실행 / 성공 / 실패 |
| 실제 패키지 | AWS 주소·정확한 CA·해시 검증·설치 종료 코드 0 | 미실행 / 성공 / 실패 |
| 이벤트 로그 | 로컬 Application 이벤트와 AWS 문서의 고유 TestId 일치 | 미실행 / 성공 / 실패 |
| 파일 로그 (선택) | 새 고유 파일과 windows_file 문서 일치 | 미실행 / 성공 / 실패 |
| 네트워크 흐름 (선택) | 선택 NIC의 테스트 목적지·시각·포트와 flow 문서 일치 | 미실행 / 성공 / 실패 |
| DNS/TLS (선택) | 실제 질의/연결과 해당 프로토콜 문서 일치 | 미실행 / 성공 / 실패 |

**이 표를 직접 채우기 전에는 실제 E2E 검증 완료로 간주하지 않습니다.** 기존 자동 테스트는 이 원격 배포 시험을 대신하지 않습니다.

계속 수집할 계획이 없다면 먼저 PC에서 시험 수집기를 중지합니다. Filebeat만 설치한 경우 Packetbeat 명령은 생략합니다. 다른 제품의 서비스나 Npcap 자체를 중지하지 않습니다.

```powershell
# 네트워크를 설치한 경우에만
Stop-Service cloud-soc-packetbeat
Set-Service cloud-soc-packetbeat -StartupType Manual
# 로그 수집 중단 및 재부팅 시 자동 전송 방지
Stop-Service cloud-soc-filebeat
Set-Service cloud-soc-filebeat -StartupType Manual
Disable-ScheduledTask -TaskName Cloud-SOC-Discovery
```

필요한 증거를 보존한 뒤 포털에서 **이번 PC용 키 ID만** 확인해 폐기합니다. 키 폐기만으로 로컬 수집·큐 기록이 멈추지는 않으므로 위 서비스 중지가 먼저입니다. 제거·키 교체 자동화는 아직 없습니다. 설정·큐·데이터 폴더를 임의로 지우지 않습니다.

중앙 서버를 중지하려면 Ubuntu SSH에서 다음을 실행합니다. `down -v`로 증거 데이터를 지우지 않습니다.

```bash
cd /home/ubuntu/cloud-soc
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml stop
```

컨테이너 중지는 EC2 과금을 끝내지 않습니다. EC2 중지/종료, EBS 보존, Elastic IP 할당 상태와 잔여 비용은 AWS 콘솔에서 따로 확인합니다. 삭제는 필요한 데이터 백업과 사용자 판단 후 진행합니다. 실습이 완전히 끝나 더 이상 필요 없는 경우에만 Windows의 사용자 인증서 관리에서 **6절에 기록한 Thumbprint와 일치하는 실습 CA**를 확인해 제거합니다. 다른 CA는 건드리지 않습니다.

장기 실행 전에 보존 기간·디스크 경보·백업·키 만료 갱신을 정해야 합니다. 현재 구성은 단일 노드이고 중앙 로그 자동 삭제 정책이 없습니다. 자세한 제약은 [중앙 서버 안내](../deploy/server/README.md)를 참고하세요.
