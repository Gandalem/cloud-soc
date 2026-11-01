> 2026-11-01 통합 후 안내: 이 파일의 초기 설치 예시보다 docs/multicloud_integration.md의 feature migration 및 manage.py 절차를 우선 사용한다. 기존 실행 상태를 이전/재설정하지 않는다.

# 기존 중앙 Elasticsearch 및 AWS Docker 수집기 연결

2026-11-01. 사용자 요청에 따라 코드만 작성했다. 테스트·검수·구문검사·빌드·실행·실서비스 권한 변경은 이 작성 작업에서 수행하지 않았다. 아래 명령은 사용자가 실제 Ubuntu 중앙 서버에서 실행하는 적용 절차다.

## 적용 범위

- 소스: /home/yoonji/cloud-soc-multicloud/cloud-soc
- 중앙 상태: /home/yoonji/cloud-soc-local/state/server
- AWS 계정: 897722691159 / 리전 us-west-2
- 소스 ID: aws-audit-oregon
- 기존 이미지 cloud-soc-multicloud:20261101을 사용하며 다시 빌드하지 않는다. 연결 스크립트는 별도로 마운트해 일회성 설정 컨테이너에서 실행한다.
- 중앙 컨테이너의 실제 CA/관리 비밀번호 bind mount와 상태 경로를 대조한다. 관리 비밀번호는 일회성 설정 컨테이너에만 읽기 전용 마운트하며 출력하지 않는다.
- 기존 인덱스 템플릿 soc-multicloud-v1을 생성/갱신한다. 기존 원본 인덱스·데이터·워커 체크포인트는 변경하지 않는다.
- 기존 cloud_soc_agent_monitor 네이티브 사용자에 새 전용 read/view_index_metadata 역할을 추가한다. 기존 역할·비밀번호·metadata·enabled 상태를 보존한다. 기존 역할 자체를 교체하지 않는다.
- 포털이 제한된 API 키를 쓰는 구성이라면 native user 역할 추가만으로 조회 권한이 늘지 않으므로, 변경 전에 중단한다. 이 경우 별도 reader API 키 구성 작업이 필요하다.
- 신규 writer 키는 soc-multicloud-*에 create_doc/auto_configure만 가지며 90일 만료다. 키 값은 root 전용 상태 경로에 저장하고, 키 파일 자체는 컨테이너 uid10001만 읽을 수 있게 한다. 기존 키의 교체/폐기는 하지 않는다.
- 쓰기 키를 생성한 뒤 파일 저장이 실패하면 방금 생성한 키만 무효화한다. 이미 성공한 템플릿/역할 추가는 남을 수 있다. 재실행 시 보존된 같은 writer 키를 재사용한다. 파일 일부만 남으면 자동 덮어쓰기 없이 중단한다.
- 새 Compose 프로젝트 cloud-soc-multicloud는 aws 서비스 하나만 만든다. 기존 중앙 Docker 네트워크를 공유하고 내부 HTTPS 주소 elasticsearch:9200으로 연결하므로 새 공개 포트를 열지 않는다.
- 연결 스크립트는 포털/중앙 서비스를 재시작하거나 수집기를 자동 시작하지 않는다. 권한 반영은 Elasticsearch의 역할/사용자 API로 처리한다.

## 전제

config/multicloud.json에 AWS 항목이 aws-audit-oregon / account897722691159 / region us-west-2로 저장되어 있어야 한다. AWS 항목의 profile 속성은 환경 자격 증명 사용과 충돌하므로 제거한다. organization/start도 실제 운영 범위에 맞게 지정한다.

AWS 로그인이 완료된 yoonji 사용자 터미널에서 아래 명령을 실행한다. sudo를 사용하지 않는다. 파일을 만든 적이 없다면 먼저 디렉터리를 생성한다.

```bash
mkdir -p /home/yoonji/.config/cloud-soc
chmod 700 /home/yoonji/.config/cloud-soc
(
  umask 077
  aws configure export-credentials --profile cloud-soc --format env-no-export \
    > /home/yoonji/.config/cloud-soc/aws.env
)
```

내보내기에 실패하면 다음 설정/시작 명령을 실행하지 않는다. 파일 내용은 공개하지 않는다. export-credentials는 로그인한 프로필이 읽은 임시 인증을 파일로 전달하는 절차이며, 기능 테스트가 아니다.

## ES 권한·Compose 파일 준비

이 ZIP을 새 소스 루트에 풀면 deploy/multicloud/connect.py 및 configure_es.py가 추가된다. 기존 중앙 소스 폴더에 풀지 않는다.

```bash
cd /home/yoonji/cloud-soc-multicloud/cloud-soc
sudo python3 deploy/multicloud/connect.py \
  --workspace /home/yoonji/cloud-soc-multicloud/cloud-soc \
  --state /home/yoonji/cloud-soc-local/state/server \
  --aws-env /home/yoonji/.config/cloud-soc/aws.env
```

이 명령은 ES 설정을 실제 변경한다. configured:true와 prepared:true가 모두 출력되어야 다음 시작 명령으로 진행한다. 오류 발생 시 자동 rollback이나 기존 상태 삭제를 하지 않는다. 출력의 error_type/reason만 공유하고 상태 파일/키 원문은 공유하지 않는다.

보호 파일은 /home/yoonji/cloud-soc-local/state/server/multicloud에 저장된다. monitor-before.json은 최초 native monitor 사용자 설정의 보존 사본이며 비밀번호는 포함하지 않는다. writer-api-key, writer.json은 신규 키와 식별/만료 정보, aws-state는 전용 체크포인트, aws-config.json은 AWS 소스 설정 사본이다. 원본 JSON을 수정한 뒤 사본에 반영하려면 설정 명령을 다시 실행하고 수집기를 재생성한다. 기존 체크포인트와 설정 scope가 달라지면 수집기는 자동 되감기를 하지 않고 중단하므로 account/start/id 변경 시 별도 상태 경로가 필요하다.

## 수집 시작

```bash
sudo docker compose \
  -f /home/yoonji/cloud-soc-local/state/server/multicloud/aws.compose.json \
  up -d aws
```

이 명령은 새 AWS 수집기만 시작한다. 이미지 ID는 설정 시점의 로컬 이미지 ID로 고정된다. 기존 포털 주소의 /multicloud 또는 보안 관제 메뉴에서 접근한다. 실제 수신 여부는 명령 성공만으로 판단하지 않는다. 합성 이벤트 생성이나 자동 인수 검사는 수행하지 않는다.

## 인증 갱신과 중지

AWS 임시 세션을 파일로 내보내므로 자동 갱신되지 않는다. 세션이 만료되면 로그인 갱신 후 같은 export 명령으로 aws.env를 다시 저장하고 다음 명령으로 컨테이너 환경을 다시 읽힌다. restart만으로는 env_file 변경이 반영되지 않는다.

```bash
sudo docker compose \
  -f /home/yoonji/cloud-soc-local/state/server/multicloud/aws.compose.json \
  up -d --force-recreate aws
```

중지하려면 아래를 사용한다. 중앙 서버와 체크포인트/키는 유지된다.

```bash
sudo docker compose \
  -f /home/yoonji/cloud-soc-local/state/server/multicloud/aws.compose.json \
  stop aws
```

신규 ES writer 키도 90일 후 명시적 재발급이 필요하다. 만료 키를 자동 교체하지 않는다. 연결 스크립트는 만료 시 중단한다. 기존 배포 관리자의 오래된 plan은 권한 변경 전 지문을 사용하므로 다시 적용하지 말고 향후 중앙 업데이트 시 새 계획을 생성한다. 향후 bootstrap/사용자 초기화 작업은 추가 역할을 제거할 수 있으므로 기존 중앙 서버에서 초기 설치기를 재실행하지 않는다.

AWS 초기화가 실패하면 수집기는 Docker 재시작 정책에 따라 재시도한다. AWS/Naver 조회 워커 내부의 ES 쓰기 오류도 재시도하지만, 일부 성공 단계 이후 발생한 오류가 수집 완료를 뜻하지 않는다. Azure/Naver 연결은 이번 실행 Compose에 포함하지 않았으며 별도 준비 후 확장한다.
