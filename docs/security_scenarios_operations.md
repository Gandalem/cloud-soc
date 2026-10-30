# Ubuntu 9종 운영 탐지 시작

대상은 사용자 지정 Ubuntu 192.168.1.159와 ~/security-mall이다. 기존 쇼핑몰 로그인 워커와 중앙 기본 워커는 계속 유지한다. 이 절차는 합성 로그, 자동 공격, 테스트, 린트, 검증을 수행하지 않는다. 탐지 프로세스는 실제 정규화 로그를 읽어 조건에 맞는 경보와 실행 상태를 기록한다.

## 전용 워커 실행

기존 쇼핑몰 탐지에 사용한 .venv-mall-detector와 Python 의존성을 사용한다. 아래 명령은 새 보호 상태 경로에 CA 사본과 30일 전용 탐지 키를 준비하고 9종 규칙을 실행한다. 서버 CA·키·회원 DB·기존 SQLite·체크포인트는 교체하지 않는다. 새 키 설정에는 기존 관리자 비밀번호 파일을 내부적으로 사용하며 출력하지 않는다. 준비 단계에서 오류가 나면 자동 삭제·재발급하지 않는다.

```bash
cd ~/cloud-soc-local
bash deploy/security-scenarios/start-detector.sh
```

별도 터미널에서 계속 실행한다. 중지는 Ctrl+C다. 재시작도 같은 명령이며 전용 잠금은 중복 프로세스를 거부한다. detector-security-scenarios는 정확히 9개 SCENARIO 규칙에만 허용하는 상태 ID다. 기존 detector-additional 및 detector-mall-login 상태를 덮어쓰지 않는다. 이 워커는 호스트 프로세스이며 systemd 자동 시작 등록은 하지 않는다.

## 실제 생산자 연결 계획

워커 실행과 생산자 연결은 별개다. 쇼핑몰 로그인 감사는 아래 앱 세 종류의 대체 입력이 아니다. 현재 코드만으로 9종의 실제 로그가 모두 수집되거나 경보가 발생한다고 간주하지 않는다.

| 규칙 | Ubuntu/쇼핑몰 연결 대상 | 추가 작업 |
| --- | --- | --- |
| SCENARIO-SERVER-FILE-001 | Linux auditd의 중요 파일 쓰기/권한 변경 | 감시 대상 지정, audit 원본 해석기 |
| SCENARIO-SERVER-PERSIST-001 | systemd·cron 구성 변경 감사 | 실제 생성/변경 증거 및 수행자 연결 |
| SCENARIO-SERVER-DEFENSE-001 | 보안 서비스 중지·설정 변경 감사 | 실제 서비스/정책 변경 증거 연결 |
| SCENARIO-APP-ROLE-001 | security-mall의 실제 권한 변경 | 권한 관리 기능, 변경 전후 감사 |
| SCENARIO-APP-EXPORT-001 | security-mall의 실제 데이터 내보내기 | 실제 처리 건수 기록; 작업당 1000건 이상 |
| SCENARIO-APP-UPLOAD-001 | security-mall의 실제 파일 업로드 | 저장/거부 결과와 확장자·MIME 등 위험 근거 |
| SCENARIO-NET-DNS-001 | Ubuntu 네트워크 센서 DNS 응답 | Suricata EVE 등 실제 NXDOMAIN 응답 해석 |
| SCENARIO-NET-FIREWALL-001 | Ubuntu 방화벽 차단 기록 | 실제 차단 기록 해석; 기존 방화벽 정책 보존 |
| SCENARIO-NET-IDS-001 | Ubuntu Suricata EVE alert | IDS 설치·수집 NIC·탐지 규칙·실제 시그니처 증거 |

공통 전송은 docs/security_scenarios.md의 구조화 내보내기 계약 → 별도 스풀/Filebeat → 중앙 정규화다. 원문을 임의 kind로 표시하거나 로그인 로그를 역할/업로드 이벤트로 변환해서는 안 된다. 생산자 연결 없이 기록을 만들어 경보를 충족시키지 않는다. 모든 규칙은 15분 내 서로 다른 조건 충족 원본 3건 이상이 필요하다. 앱 내보내기는 각 작업당 1000건 이상이라는 추가 조건이 있다.

## 현재 인수 범위

2026-10-28: 전용 상태 분리 코드와 시작 스크립트 작성. 사용자 지시에 따라 테스트·시험·검수·검사·구문 확인을 실행하지 않았다. 사용자 Ubuntu에서 워커를 직접 시작하거나 생산자/센서를 설치하지 않았다. 실제 9종 원본 수신·정규화·경보 생성은 미완료다. 기존 쇼핑몰 WEB-AUTH-01은 사용자 제공 결과에서 원본38건/정규화38건/경보1건이 확인됐으며 9종과 별개다.

## 실제 생산자 연결 명령 — 2026-10-28

아래는 사용자 로컬에서 실행할 설치·운영 명령이다. 코드 작성 환경에서는 실행하지 않았다. 이미 실행 중인 9종 탐지와 쇼핑몰 로그인 탐지 터미널은 유지한다. 각 단계에서 오류가 발생하면 그 단계에서 멈추고 원문/키를 제외한 오류를 공유한다. 서버 CA·키·DB를 초기화하거나 체크포인트를 삭제하지 않는다.

### 1. 전용 실제 원본 수신 경로 준비 — 한 번만

```bash
cd ~/cloud-soc-local
umask 077
SCENARIO_STATE="$HOME/.local/state/cloud-soc/security-scenarios"
sudo python3 deploy/security-scenarios/prepare-intake.py \
  --es-url https://192.168.1.159:9200 \
  --ca-file "$SCENARIO_STATE/ca.crt" \
  --password-file "$PWD/state/server/secrets/elastic_password" \
  --key-file "$SCENARIO_STATE/writer.key"
```

성공 메시지 이후에만 소유권을 새 writer.key 하나에 적용한다.

```bash
sudo chown "$(id -u):$(id -g)" "$SCENARIO_STATE/writer.key"
chmod 600 "$SCENARIO_STATE/writer.key"
```

새 인덱스는 `soc-host-raw-security-scenarios-local-v1`, 수신 파이프라인은 `soc-security-scenarios-local-receipt-v1`이다. 키는 이 인덱스의 create_doc만 허용하며 30일 만료다. 기존 동명 설정이 다르면 덮어쓰지 않는다. 준비 실패 시 예약된 키 파일이 남을 수 있다. 자동 삭제·재발급하지 않으므로 출력 오류에 따라 복구해야 한다. 기존 쇼핑몰 Filebeat와 전용 로그인 인덱스에는 손대지 않는다. 직접 HTTPS 전송으로 이 경로에는 새 Filebeat가 필요 없다.

### 2. Ubuntu 감사와 센서 설치

```bash
sudo apt-get update
sudo apt-get install -y auditd audispd-plugins suricata suricata-update nftables
sudo service auditd start
cd ~/cloud-soc-local
sudo bash deploy/security-scenarios/install-audit-rules.sh
```

기존 감사 규칙을 flush하지 않고 `70-cloud-soc-scenarios.rules`를 새로 추가한다. 같은 이름이 있으면 보존하고 중단하므로 반복 설치하지 않는다. immutable 감사 정책 때문에 로드가 거부되면 자동 재부팅/해제하지 않는다. 이미 적용된 일부 규칙도 자동 삭제하지 않는다.

| 실제 감사 대상 | 연결되는 kind |
| --- | --- |
| /etc/hosts, /etc/passwd, /etc/group | server_file |
| /etc/systemd/system, /etc/cron.d, /etc/cron.hourly, /var/spool/cron/crontabs | server_persistence |
| /etc/audit, /etc/ufw, /etc/apparmor.d | server_defense |

성공한 write/attribute 접근 감사만 사용한다. 파일 내용·명령줄·EXECVE 인자는 중앙에 보내지 않는다. 감사 watch는 바이트 전후 해시 비교가 아니므로 모든 modified 기록이 내용 변경을 증명하는 것은 아니다. 서비스 구성 변경이 서비스 실행 성공을 뜻하지 않는다. 현재 server_defense 연결은 정책 파일 변경이며 서비스 중지 성공을 추정하지 않는다.

별도 터미널 **A**:

```bash
cd ~/cloud-soc-local
sudo -v
bash deploy/security-scenarios/run-collector.sh auditd
```

### 3. 네트워크 DNS·IDS 센서

실제 수집 NIC는 사용자가 앞서 지정한 ens33을 사용한다. 아래 명령은 규칙 설치 후 별도 센서를 foreground로 실행한다. 규칙 업데이트의 자체 시험과 서비스 reload를 끈다. 기존 Suricata 설정·다른 서비스는 덮어쓰거나 중지하지 않는다.

```bash
sudo suricata-update --no-test --no-reload
mkdir -p "$HOME/.local/state/cloud-soc/suricata"
sudo suricata -c /etc/suricata/suricata.yaml -i ens33 \
  --pidfile /run/cloud-soc-scenarios-suricata.pid \
  --set unix-command.enabled=no \
  -l "$HOME/.local/state/cloud-soc/suricata"
```

Ubuntu 패키지 기본 EVE의 dns/alert 출력을 사용한다. 관리자가 이를 꺼 둔 기존 설정은 자동으로 바꾸지 않는다. 센서는 실행 중인 터미널을 유지한다. 이 NIC에서 관측된 트래픽만 분석하며 다른 장비의 전체 트래픽을 보장하지 않는다. 기본 규칙 업데이트가 차단되거나 기존 설정/룰 오류가 나면 해당 오류에서 멈춘다. 가짜 IDS 경보·자동 트래픽·탐지 시험은 생성하지 않는다.

별도 터미널 **B**:

```bash
cd ~/cloud-soc-local
sudo -v
bash deploy/security-scenarios/run-collector.sh eve
```

EVE의 실제 NXDOMAIN 응답은 `network_dns`, 실제 alert는 `network_ids`로 변환한다. DNS 응답의 목적지 IP를 요청 클라이언트로 사용한다. 질의 이름이 없는 집계 응답은 제외한다.

### 4. 방화벽 차단 기록

별도 터미널 **C**:

```bash
cd ~/cloud-soc-local
sudo -v
bash deploy/security-scenarios/run-collector.sh kernel
```

기존 `[UFW BLOCK]` 기록이 있으면 그대로 `network_firewall`에 연결한다. 수집기는 방화벽을 켜거나 정책을 바꾸지 않는다. 차단 정책이 없으면 기록이 없는 것이 정상이다.

현재 별도 방화벽 정책이 없는 로컬 실습에서는 다음 **선택 단계**로 loopback TCP 18081만 격리 포트로 예약할 수 있다. 이 포트를 사용하는 기존 업무가 없어야 한다. 새 테이블만 추가하고 SSH·포털·8080·기존 테이블은 변경하지 않는다. 실제 해당 포트 접근이 발생하면 커널에 SOC_DROP이 기록된다. 이 문서는 접근 요청을 자동 발생시키지 않는다.

```bash
cd ~/cloud-soc-local
sudo nft -f deploy/security-scenarios/loopback-firewall.nft
```

같은 테이블이 있으면 자동 교체하지 않는다. 이 정책은 재부팅 후 자동 복원하도록 기존 nftables 설정에 저장하지 않는다. 추가한 정책만 해제하려면 `sudo nft delete table inet cloud_soc_scenarios`를 사용한다.

### 5. 쇼핑몰 실제 업무 기능 추가

기존 로그인 감사 키가 있는 같은 소스/같은 사용자로 실행한다. 새 Java 파일 두 개만 추가하며 같은 경로에 다른 파일이 있으면 거부한다. 회원·상품을 만들거나 초기화하지 않는다.

```bash
cd ~/cloud-soc-local
python3 deploy/security-scenarios/install-business.py --mall "$HOME/security-mall"
python3 deploy/security-scenarios/restart-business.py --mall "$HOME/security-mall"
```

재시작 명령은 현재 mall.pid의 소유자·Java 인자·작업 디렉터리가 같은 앱인지 확인해 다른 프로세스를 중지하지 않도록 한다. 기존 JAR을 audit 아래 보호 사본으로 보존한 뒤 앱을 정상 종료하고 bootJar를 만든다. 이 과정에 앱 중단 시간이 있다. Gradle test를 제외하며 HTTP 준비 상태 확인이나 자동 로그인은 하지 않는다. 빌드 실패 시 이전 JAR의 실행을 요청하고 기존 DB·키는 유지한다. Java 실행 요청은 앱 시작 성공 확인이 아니다. 이전 런처가 아닌 프로세스이거나 mall.pid가 없으면 멈춘다. 앱 종료 거부 시 강제 kill하지 않는다.

브라우저에서 기존 관리자 계정으로 로그인 후 다음을 연다.

`http://127.0.0.1:8080/soc-business`

- 권한 관리: 기존 다른 계정의 USER/ADMIN 역할을 실제 변경한다. 같은 역할 저장은 변경 사건으로 기록하지 않는다. 자기 계정은 변경할 수 없다. actor/target_user는 기존 HMAC 키를 이용한 가명 값이며 로그인용 가명과는 용도가 다르다.
- 상품 CSV: DB에서 실제 읽은 상품의 ID·상품명·분류·가격·재고를 CSV로 생성한다. 실제 row 수를 기록하며 회원 개인정보나 비밀번호를 내보내지 않는다. 로그의 exported는 CSV 응답 생성이며 브라우저 저장 완료를 증명하지 않는다.
- 파일 격리 보관: 최대 5MiB를 UUID 파일명/0600 권한으로 저장한다. 실행형 확장자 또는 명시된 PNG/JPEG MIME과 매직바이트의 불일치를 위험 근거로 기록한다. 백신 악성 판정을 만들어 내지 않으며 위험 근거 없는 업로드는 이 위험 업로드 시나리오 로그에 포함하지 않는다. 원래 파일명·본문은 중앙에 전송하지 않는다.

업무 페이지는 loopback 소켓의 로그인한 관리자만 사용하며 DB에서 현재 권한을 다시 읽는다. POST에는 세션 CSRF 토큰을 요구한다. 기존 쇼핑몰 전체 취약점을 보완한 것은 아니므로 공개 서비스로 확대하지 않는다. 실제 권한 변경/파일 저장 이후 감사 파일 쓰기가 실패하면 HTTP 오류가 날 수 있으며 업무 변경은 이미 반영됐을 수 있다. 이 경우 같은 작업을 반복해 성공으로 추정하지 말고 앱 오류를 공유한다.

별도 터미널 **D**:

```bash
cd ~/cloud-soc-local
bash deploy/security-scenarios/run-collector.sh business
```

첫 실제 업무 감사 파일이 아직 없으면 tail이 파일 생성을 기다린다. 실제 동작 후 `audit/business-audit.jsonl`에 기록되며 중앙으로 전달한다. 앱 외부에서 JSON 이벤트를 작성하지 않는다.

### 6. 운영 범위와 경보 조건

이 브리지의 `received_by_central: 1`은 원본 저장 성공이며 정규화·경보 생성 완료가 아니다. 9종 탐지 워커의 created가 실제 경보 생성 수다. 원본 참조는 새 전용 인덱스에 연결된다. 일반 수집 worker가 이미 security_scenarios_v1 어댑터를 포함한 이미지여야 중앙 정규화가 가능하다. 사용자 기존 이미지 버전은 이 코드 작성만으로 변경/확인하지 않았다.

수집 bridge는 metadata를 전용 SQLite inbox에 먼저 기록하고 ES create 성공 후 완료 처리한다. 전송 실패 재시도와 동일 원본 재독 시 중복 방지를 제공한다. 각 소스별 SQLite/잠금을 유지한다. auditd는 시각+serial로 syscall 한 건을 한 사건으로 센다. 원본 전체 로그를 중앙으로 복사하지 않는다. 시작 시 현재 audit/EVE/업무 파일을 다시 읽고 커널은 최근 15분부터 읽는다. 재시작 중 회전돼 사라진 이전 파일이나 15분 밖의 커널 기록은 자동 복구하지 않으므로 원본 보존과 상시 운영이 필요하다. 과거 로그가 늦게 도착하면 기존 탐지 규칙의 지연 허용 범위 밖에서 제외될 수 있으며 체크포인트를 되감지 않는다. foreground 프로세스는 터미널 종료/재부팅 때 중지되며 부팅 자동 시작은 아직 등록하지 않는다.

각 규칙은 15분 안에 고유 조건 충족 원본 3건 이상이다. 대량 내보내기는 **매 작업 실제 상품 1,000건 이상인 작업 3건**이 필요하다. 기본 쇼핑몰의 몇 개 상품만 내보내면 수집은 되지만 해당 경보가 생기지 않는다. 임계값을 낮추거나 상품/로그를 자동 생성하지 않았다. DNS NXDOMAIN·방화벽 차단·IDS 시그니처가 실제로 발생하지 않으면 해당 경보가 없는 것이 정상이다. 보안 기능을 끄거나 중요 파일을 훼손해 경보를 만들지 않는다.

실제 검증/수신 조회 명령은 사용자의 별도 지시 전까지 실행하지 않는다. 이 변경은 코드·운영 절차 작성이며 실제 사용자 적용·9종 경보 성공과 구분한다.
