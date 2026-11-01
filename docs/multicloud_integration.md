# JEONGRIM-SEO 멀티 클라우드 통합

2026-11-01. 기준 c87e9cae471547108917997130207366a767ee78. 채팅에서 작성한 수집/정규화/포털과 후속 연결 스크립트를 같은 저장소에 포함한다. 초기에는 검증을 제외했으며, 후속 사용자 요청으로 테스트·검수·린트·구문검사·빌드·실행 점검을 진행했다. 운영 배포는 일반 Ubuntu 터미널에서 실행할 보존형 절차로 준비했으며 아직 적용 전이다. 이 문서는 코드에 구현한 동작과 사용자가 나중에 실행할 적용 명령을 구분한다.

## 이번 변경

- `portal/multicloud.py` blueprint와 인증/RBAC/메뉴/정적 파일을 함께 반영한다. 비로그인 `/multicloud` 문서 요청은 로그인 화면으로 이동한다. API는 기존 인증/조직 필터를 사용한다.
- `portal/status_setup.reader_role()`에 `soc-multicloud-*` 읽기 범위를 추가한다. 기존 사용자에 대해 `configure_reader()`는 추가 역할·metadata·활성 상태·비밀번호를 보존하고 필요한 기본 역할만 추가한다. 초기 생성에만 전달된 비밀번호를 사용한다. 기존 role의 제한 scope가 있으면 additive_grants가 자동 확장을 거부한다.
- 새 설치 bootstrap과 기존 version2 prerequisites migration이 멀티 클라우드 템플릿을 준비한다. worker policy 버전/DB identity/키/체크포인트/시작 시각은 바꾸지 않는다. `runtime/migrations.json`의 독립 `features.multicloud-v1` receipt로 기록한다.
- 배포 plan preflight는 기존 템플릿을 읽어 새 기능 준비 상태를 포함하고 호환되지 않는 정의는 변경 전에 거부한다. 이전 채팅 템플릿은 동일 mapping을 가진 legacy 정의로 수용한다. 이미 저장된 인덱스의 문서나 설정은 변경하지 않는다. 새 일별 인덱스의 replica 기본은 단일 중앙 노드용0이다.
- deploy/multicloud와 requirements-multicloud.txt를 중앙 release source manifest 및 Docker 이미지 복사 범위에 포함한다. 중앙 이미지는 여전히 포털/기존 워커용이고 collector SDK는 별도 이미지/선택 extra다.
- 기본 Compose의 AWS source는 Oregon 예시와 일치시켰고 환경변수로 바꿀 수 있다. connect.py의 특정 AWS 계정·리전 하드코딩은 제거했다. Naver helper의 workspace/home/state 기본값은 현재 소스·실행 사용자·실제 중앙 CA mount에서 가져온다. 기존 명시적 플래그도 유지한다.
- 용량/스토리지 조회에 새 인덱스 패턴과 이름 allowlist를 함께 추가한다. 기존 retention/ILM 삭제 정책은 새 데이터에 자동 적용하지 않는다.
- poll 상태는 waiting/processed/failed를 구분하고 watermark가 전진한 경우에만 last_success를 갱신한다. 기존 SQLite scope와 state는 유지한다. Azure actor의 일반 objectidentifier claim도 투영한다.
- *.env, config/multicloud.json, .venv-multicloud는 Git/이미지 context에서 제외한다. 예시 JSON은 포함하되 실제 계정/키를 코드에 채워 넣지 않는다.

## 독립 collector 배포 계약

중앙의 기존 `ALL_WORKERS`에 collector를 무조건 추가하지 않는다. 중앙 워커 version2 계약을 바꾸면 기존 운영 state identity를 손상할 수 있으므로 독립 관리 명령 `deploy/multicloud/manage.py`를 제공한다.

feature state 아래의 `collectors.json`에는 provider별 Compose/config 지문, 이미지 ID, checkpoint 경로, secret 파일 경로, 네트워크와 관리 스크립트 지문을 기록한다. secret 값은 기록하지 않는다. start/stop/recreate/status/backup-plan은 등록 지문과 다른 설정을 자동 채택하지 않는다. prepare/adopt가 명시적인 등록/갱신 작업이다. env 파일의 값은 인증 갱신을 허용하기 위해 해시 고정하지 않으며, 새 env 반영에는 recreate가 필요하다.

AWS와 Naver는 기존 실행 프로젝트 이름·state 디렉터리·키 파일을 그대로 사용한다. 기본 이미지 태그가 기존 태그인 것은 이전 사용자 명령과의 호환용이다. 이 통합 코드로 collector 동작까지 바꾸려면 새 이미지를 별도로 빌드하고 prepare의 --image로 지정해야 한다. 코드 pull만으로 실행 이미지는 바뀌지 않는다.

### 이미 실행 중인 AWS/Naver 등록(서비스 변경 없음)

아래 명령은 사용자가 실행할 때 기존 생성 파일을 지문으로 등록한다. 작성 과정에서는 실행하지 않았다. 실제 소스 루트에서 실행한다.

```bash
sudo python3 deploy/multicloud/manage.py adopt --provider aws \
  --state /home/yoonji/cloud-soc-local/state/server
sudo python3 deploy/multicloud/manage.py adopt --provider naver \
  --state /home/yoonji/cloud-soc-local/state/server
```

collector는 기존 상태 경로의 aws-state/naver-state와 snapshot source JSON을 유지한다. 원본 config/multicloud.json의 start/account/id를 바꾸고 기존 state를 재사용하는 작업은 자동 마이그레이션 범위가 아니다.

### 새 이미지 준비/갱신 예시

이것은 향후 배포 명령이며 이번에 빌드/실행하지 않았다.

```bash
sudo docker build -f deploy/multicloud/Dockerfile \
  -t cloud-soc-multicloud:integrated-20261101 .
sudo python3 deploy/multicloud/manage.py prepare --provider aws \
  --state /home/yoonji/cloud-soc-local/state/server \
  --workspace "$PWD" --source aws-audit-oregon \
  --env /home/yoonji/.config/cloud-soc/aws.env \
  --image cloud-soc-multicloud:integrated-20261101
sudo python3 deploy/multicloud/manage.py prepare --provider naver \
  --state /home/yoonji/cloud-soc-local/state/server \
  --workspace "$PWD" --source naver-audit \
  --env /home/yoonji/.config/cloud-soc/naver.env \
  --image cloud-soc-multicloud:integrated-20261101
```

prepare는 설정/권한 준비와 collector receipt만 기록한다. 기존 collector를 자동 재시작하지 않는다. 기존에 실행 중인 서비스를 새 설정으로 바꿀 때는 recreate를 사용한다.

```bash
sudo python3 deploy/multicloud/manage.py recreate --provider aws \
  --state /home/yoonji/cloud-soc-local/state/server
sudo python3 deploy/multicloud/manage.py recreate --provider naver \
  --state /home/yoonji/cloud-soc-local/state/server
```

`stop`은 해당 collector 하나만 중지한다. `status`는 Compose process 상태만 읽으며 실제 수신을 증명하지 않는다. `backup-plan`은 암호화할 키/인증/설정 파일 목록, SQLite 일관성 보존 방법과 soc-multicloud-* snapshot 필요성을 비공개 파일로 작성한다. 실제 백업을 실행하거나 비밀 파일을 평문 archive로 내보내지 않는다. 백업 실행·보존·격리 복구와 Azure 수집기 lifecycle 통합은 별도 작업이다.

## 포털이 제한 API 키를 사용하는 경우

reader_role 갱신은 네이티브 monitor role의 권한을 준비한다. 이미 발급된 제한 API 키의 role_descriptors/limited_by를 자동으로 넓히거나 교체하지 않는다. `SOC_PORTAL_READ_API_KEY_FILE` 구성이면 기존 helper가 변경 전에 거부하는 동작을 유지한다. 필요한 최소 읽기 범위와 키 소유자를 확인한 별도 키 갱신 절차가 필요하다. 사용자 현재 운영 결과는 네이티브 monitor 경로와 구분해 기록한다.

## 의도적으로 분리한 범위

- `/multicloud` 저장/조회와 기존 `/logs`·soc-normalized-v1·규칙 탐지는 아직 별도다. raw provenance와 adapter 없는 문서를 기존 탐지 입력에 무작정 추가하지 않았다. 신규 경보 규칙·분류·근거 연결은 추가 구현 범위다.
- 중앙 runtime_ready와 collector receipt는 실수신/연속성 인수 결과가 아니다. 사용자 화면의 기존 AWS88건은 당시 조회 결과이며 이번 통합 이미지의 검증 결과가 아니다. Naver는 poll 진행까지 사용자 출력이 있었으며 새 대시보드 실수신 결과는 아직 제공되지 않았다. Azure는 권한 부족으로 보류 상태다.
- AWS 임시 env는 자동 갱신되지 않고 ES writer는90일 만료다. 키 자동 교체/광범위 권한 부여는 하지 않는다.
- SDK 의존성 중 AWS는 기존 aws requirements와 같은1.43.99로 맞췄다. Azure/portalocker 범위의 완전 lock과 collector 별도 CI 실행은 남아 있다. 기존 pipeline의 source 검사와 Bandit 경계는 코드에 반영했지만 실제 통과 여부는 주장하지 않는다.

## 기존 중앙 서버 적용

Git 반영은 실행 서비스 변경이 아니다. 이 소스로 새 중앙 이미지를 만들고 기존 state를 사용하는 plan/apply를 새로 생성해야 한다. 지난 배포 계획을 재사용하지 않는다. 기존 bootstrap/신규 설치기를 운영 서버에 다시 실행하지 않는다. 이 작업에서는 실제 사용자의 Docker/Elasticsearch/클라우드에 접근하거나 키를 읽고 변경하지 않았다.

## 2026-11-01 후속 검증 및 지연 로그 보완

최신 사용자 지시로 이전 검사 제외를 해제하고 검증을 수행했다. 린트·구문검사·dependency check·중고위험 Bandit·알려진 의존성 취약점 검사를 수행했다. 새 기능18건과 영향 회귀를 별도 확인했으며 전체 최초 실행의 환경 의존 실패/기대값 차이는 원인별 재검사로 구분했다. 결과 수치는 outputs의 검증 보고서에 기록한다.

Naver는 사용자 제공24시간 공개 대기 조건에 대비해 `naver_late_watermark_v1` 재조회 커서를 추가한다. 기존 live `watermark`와 state fingerprint를 변경/삭제하지 않는다. 기본5분 lag 수집은 유지하고, 별도 경로가 최초 start부터 현재보다24시간5분 이전 구간을15분 단위로 재조회한다. 재조회 실패 시 그 커서를 전진시키지 않으며 기존 결정적 이벤트 ID/create가 중복 저장을 막는다. 이는 공식24시간 SLA를 주장하는 것이 아니라 사용자 운영 조건에 맞춘 보완이다. 기존 운영 이미지에는 자동 적용되지 않는다.

일반 Ubuntu 터미널은 사용자 출력상 NoNewPrivs0/sudo 성공이며 Codex 명령은 sandbox NoNewPrivs1로 분리돼 있다. sandbox 자체를 변경하거나 우회하지 않는다. `deploy/multicloud/deploy-local.sh`는 일반 터미널에서 root로 실행할 보존형 중앙/collector 배포 절차다. state·원본scopeconfig·AWSenv·Naverenv의 네 경로를 인자로 받는다. 원본 구성과 다른 기존 target config는 덮어쓰지 않으며, 이전 collector Compose/config를 별도 release 폴더에 보존한다. 새 plan/apply 후 collector prepare/recreate와 startup-only 확인을 수행한다. 새 로그 실수신 인수와 별개다.
