# 기존 서버와 분리한 쇼핑몰 로그인 탐지

전제: 실제 쇼핑몰 원본이 정규화됐고 기존 기본 워커가 실행 중이다. 기본 배포 정책·이미지·컨테이너·체크포인트를 수정하지 않고, 호스트 Python 프로세스에 전용 탐지 키·SQLite·상태 ID를 사용한다. 이 안내는 현재 사용자의 새 중앙 설치192.168.1.159와~/cloud-soc-local 기준이다.

## 최초 준비

```bash
cd ~/cloud-soc-local
python3.12 -m venv .venv-mall-detector
.venv-mall-detector/bin/python -m pip install \
  -r requirements.txt -r deploy/server/requirements.txt \
  -r deploy/aws/requirements.txt -r deploy/oci/requirements.txt
umask 077
mkdir -p state/mall-login-detector
# 한 번만 생성. 이미 있으면 기존 시작 시각과 상태를 유지한다.
(set -o noclobber; date -u -d '2 minutes ago' +%Y-%m-%dT%H:%M:%SZ \
  > state/mall-login-detector/start.txt)
sudo install -o "$(id -u)" -g "$(id -g)" -m 644 \
  state/server/tls/ca.crt state/mall-login-detector/ca.crt
```

## 전용 키 발급

이미 있는 키를 덮어쓰지 않는다. 실패 시 기존 파일/키를 지우거나 자동 재발급하지 않는다. 중앙 Elasticsearch 관리자 비밀번호 파일을 내부에서 사용하고 값은 출력하지 않는다. 기존 소유자 계정에서 sudo로 설정 명령만 수행한 뒤 새 키 파일을 해당 사용자에게 돌려준다. 기존 서버 키·비밀번호·계정은 교체하지 않는다.

```bash
sudo env PYTHONPATH="$PWD/src" \
  "$PWD/.venv-mall-detector/bin/python" -m cloud_soc.detection.setup \
  --es-url https://192.168.1.159:9200 \
  --ca-file "$PWD/state/mall-login-detector/ca.crt" \
  --password-file "$PWD/state/server/secrets/elastic_password" \
  --worker detector \
  --key-file "$PWD/state/mall-login-detector/detector.key"
```

성공한 경우에만 다음을 실행한다.

```bash
sudo chown "$(id -u):$(id -g)" state/mall-login-detector/detector.key
chmod 600 state/mall-login-detector/detector.key
```

키는30일 만료이며 만료 시 명시적 교체가 필요하다. 기존 API 키 파일이 이미 있으면 발급 단계를 반복하지 않는다.

## 실행

별도 터미널에서 아래 프로세스를 계속 실행한다. 재시작에도 같은 시작 시각·상태·키를 유지하고 동시에 두 번 실행하지 않는다.

```bash
cd ~/cloud-soc-local
PYTHONPATH="$PWD/src" .venv-mall-detector/bin/python -m cloud_soc.detection \
  --run --additional-rules WEB-AUTH-01 \
  --status-id detector-mall-login \
  --state "$PWD/state/mall-login-detector/runtime.sqlite" \
  --start "$(cat state/mall-login-detector/start.txt)" \
  --interval 10 --lateness-seconds 180 \
  --es-url https://192.168.1.159:9200 \
  --ca-file "$PWD/state/mall-login-detector/ca.crt" \
  --api-key-file "$PWD/state/mall-login-detector/detector.key"
```

`detector-mall-login` 상태 ID는 정확히 WEB-AUTH-01만 선택하는 별도 워커에 허용한다. 기존 detector-additional 상태를 덮어쓰지 않는다. 이 프로세스는 soc-normalized-v1을 읽고 선택 규칙의 경보·처리 이력을 중앙에 기록한다. 전용 키는 정상 기존 탐지 역할을 사용하며 별도 조직 필터를 적용한 키는 아니다. 실제 규칙은 서비스/가명 계정/IP 등으로 그룹화한다.

이 별도 워커는 지연 허용180초를 사용하므로 마지막 성공 로그 발생 후 정규화/검색 지연을 포함해 약4분 이상 기다려야 할 수 있다. 기존 워커들의900초 설정은 변경하지 않는다. 늦게 도착한 기록·필수 필드 누락은 경보 없음과 함께 제외 이력을 봐야 한다. 기존10건을 소급해 탐지 완료했다고 해석하지 않는다.

## 실제 활동과 확인

새 워커 시작 후 localhost:8080의 쇼핑몰에서 같은 고유 실습 계정으로5분 안에 잘못된 비밀번호5회, 이어 올바른 비밀번호1회를 직접 입력한다. 기존 로그에 없는 공격 결과를 만들거나 계정 탈취 성공으로 표현하지 않는다.

다른 터미널에서 다음을 조회한다.

```bash
cd ~/cloud-soc-local
sudo -v
python3 deploy/security-mall/login-audit/connect.py \
  --mall "$HOME/security-mall" --sudo-docker --analysis-status
```

목표는 detector-mall-login의reported_rules에WEB-AUTH-01, 원본/정규화 참조 일치, exact-source 경보에WEB-AUTH-01 표시다. 이 문서 작성 중 사용자 서버에 워커를 실행하거나 실제 경보를 생성하지 않았다. 검사 결과는 격리된 모의ES/SQLite 경로26건이며 실제 적용 인수와 구분한다. 종료는 워커 터미널에서Ctrl+C이며 상태·키·로그를 지우지 않는다.
