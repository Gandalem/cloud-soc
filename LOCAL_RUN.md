# 로컬 병합본 실행 안내

이 폴더는 main `5759c8d`와 JEONGRIM-SEO `f2e8260`의 통합 소스입니다.
로컬 검증 후 사용자 요청으로 JEONGRIM-SEO에 커밋·push하는 통합본입니다. 기존 서버의 state·키·DB는 포함하지 않습니다.

## Ubuntu / Linux 개발용 실행

Python 3.12 이상과 Docker Compose가 필요합니다. 명령은 이 파일이 있는 저장소 루트에서 실행합니다.
기본 Python이 3.10인 Ubuntu 22.04에서는 별도로 준비한 Python 3.12를 사용하세요.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -c constraints.txt -r deploy/server/requirements.txt
export PYTHONPATH="$PWD/src"
```

Elasticsearch·Kibana 개발 인스턴스가 필요한 경우에만 다음을 실행합니다.
같은 이름의 개발 컨테이너나 9200·5601 포트를 사용하는 서비스가 있으면 먼저 구성을 확인하세요.

```bash
docker compose -f compose.yaml -f compose.dev.yaml config --quiet
docker compose -f compose.yaml -f compose.dev.yaml up -d
docker compose -f compose.yaml -f compose.dev.yaml ps
```

개발 Elasticsearch는 `http://127.0.0.1:9200`, Kibana는 `http://127.0.0.1:5601`입니다.
이 구성은 인증 없는 loopback 개발용 ES·Kibana만 실행합니다.
Portal·상주 정규화·탐지·에이전트 수집 전체 기능에는 아래 중앙 런타임 구성이 필요합니다.

연결 설정은 `.env.example`을 참고하며 기존 `.env`가 있으면 보존하세요.

```bash
.venv/bin/python -m cloud_soc.elastic.client
```

정적 화면 배치만 보려면 다음을 실행하고 `http://127.0.0.1:8765`를 엽니다.

```bash
.venv/bin/python -m http.server 8765 --bind 127.0.0.1 --directory prototype
```

정적 미리보기에는 중앙 API가 없어 로그 조회·로그인·사건 저장이 동작하지 않습니다.

## Portal·수집·탐지를 포함한 실행

- 새 Ubuntu 실습 서버/VM: [README](README.md)의 신규 설치와 [전체 설치 안내](docs/first_install_walkthrough.md)를 따릅니다. 이 병합 폴더나 JEONGRIM-SEO 브랜치를 사용하세요. main을 다시 clone/pull하면 별도 main 코드가 됩니다.
- 기존 중앙 서버: [공통 런타임 안내](docs/runtime_deployment.md)의 plan/apply/verify 절차로 기존 상태를 보존합니다. 최초 설치기를 재실행하지 않습니다.
- 로그인 감사 연동: [패키지 안내](deploy/security-mall/login-audit/README.md). 별도의 `~/security-mall`, Java 17, HTTPS 중앙 Elasticsearch가 필요합니다. 인증 없는 개발 ES 구성과 연결 절차를 혼용하지 않습니다.
- Windows 개발: [PowerShell 안내](docs/local_development.md).

이 통합 작업에서는 기존 서비스 배포·쇼핑몰 재시작·실제 로그 수집을 실행하지 않았습니다.

## 회귀 검사

```bash
.venv/bin/python -m pip install -c constraints.txt -r requirements-dev.txt
npm ci --prefix prototype/tests --ignore-scripts --no-audit --no-fund
.venv/bin/python -m pytest -q
node --test prototype/tests/*.test.cjs
```

Node는 22 이상을 권장합니다. 서버 문서/일부 에이전트 검사는 PowerShell(pwsh)이 필요하며,
Windows 전용·명시적 live 검사는 별도의 OS/실습 자원이 있어야 합니다.
테스트용 임시 디렉터리의 상위 경로가 신뢰할 수 없는 소유자이거나 group-writable이면
수집 지표 보안 검사가 의도적으로 거부합니다. 해당 검사는 정상 소유권의 격리 환경에서 수행하세요.
