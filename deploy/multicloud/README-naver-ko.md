> 2026-11-01 통합 후 안내: 이 파일의 초기 설치 예시보다 docs/multicloud_integration.md의 feature migration 및 manage.py 절차를 우선 사용한다. 기존 실행 상태를 이전/재설정하지 않는다.

# Naver Cloud Public 연결

2026-11-01. 기존 AWS 수집기는 유지하고 Naver Cloud Activity Tracer 조회 API만 별도 수집기로 연결한다. Azure는 권한 부족으로 보류한다. 이번 파일 작성 시 테스트·검수·린트·구문검사·빌드·스크립트 실행·실수집/클라우드 변경은 수행하지 않았다.

## Naver 준비

일반 상용 Public 계정용이다. Cloud Activity Tracer는 계정 활동을 자동 수집하므로 이 API 조회를 위해 VM/버킷/Tracer를 새로 만들 필요는 없다. Tracer는 장기 Object Storage 내보내기 용도이며 이번 API 수집과 구분한다.

관리자가 Sub Account 서비스에서 cloud-soc-collector 같은 수집 전용 Sub Account를 만들고 API Gateway 접근을 허용한다. 정책 탭에서 시스템 관리형 NCP_CLOUD_ACTIVITY_TRACER_VIEWER를 연결한다. Access Key 탭에서 키를 생성한다. 관리자 권한의 키를 수집기에 전달하지 않고 전용 읽기 계정 키를 사용한다. API 접근 출발지 IP 제한을 적용한다면 로컬 PC가 인터넷으로 나갈 때 사용하는 공인 IP가 포함되어야 한다.

Cloud Activity Tracer > Activities > 실제 활동 상세의 NRN 예: nrn:PUB:Account::1234567:Customer/static. 콜론으로 나눈 다섯 번째 값 1234567이 설정의 account다. 이메일/서브계정 번호/Access Key ID를 account에 넣지 않는다. NRN 전체나 상세 productData를 채팅에 보낼 필요는 없다.

## 로컬 설정

ZIP을 /home/yoonji/cloud-soc-multicloud/cloud-soc 아래에 풀면 deploy/multicloud/connect_naver.py가 추가된다. 기존 이미지 cloud-soc-multicloud:20261101을 그대로 사용한다.

config/multicloud.json의 provider:naver 항목만 실제 member 번호로 수정한다. 예시:

```json
{
  "id": "naver-audit",
  "provider": "naver",
  "organization": "team-a",
  "account": "실제member번호",
  "start": "2026-11-01T00:00:00Z",
  "access_key_env": "SOC_NAVER_ACCESS_KEY",
  "secret_key_env": "SOC_NAVER_SECRET_KEY"
}
```

start는 실제 수집 시작 시각으로 명시한다. 현재 수집기의 정책은 30일 초과 과거 시작을 거부한다. 콘솔 보존 기간과 이 수집기의 초기 조회 제한은 서로 다르다. organization을 기존 AWS와 같게 두면 같은 조직 권한으로 조회할 수 있다. 키는 구성 JSON에 넣지 않는다.

키 입력 명령은 sudo 없이 실행한다. 입력은 화면에 표시되지 않으며 명령 인자/쉘 히스토리에 키를 넣지 않는다. 기존 naver.env가 있으면 보존하고 중단한다.

```bash
cd /home/yoonji/cloud-soc-multicloud/cloud-soc
python3 deploy/multicloud/connect_naver.py credentials
```

그다음 root로 전용 Compose 설정만 생성한다.

```bash
sudo python3 deploy/multicloud/connect_naver.py prepare
```

기존 multicloud writer 키·CA·중앙 Docker 네트워크를 재사용한다. Elasticsearch 권한/기존 키/AWS 설정은 변경하지 않는다. 생성 경로는 /home/yoonji/cloud-soc-local/state/server/multicloud/naver.compose.json이다. name:cloud-soc-naver의 독립 Compose이므로 AWS Compose의 orphan 처리를 하지 않는다. 소스 scope가 기존 Naver 설정 사본과 다르면 자동 덮어쓰기·체크포인트 되감기를 하지 않고 중단한다.

prepared:true 출력 후에만 시작한다.

```bash
sudo docker compose \
  -f /home/yoonji/cloud-soc-local/state/server/multicloud/naver.compose.json \
  up -d naver
```

기존 포털 /multicloud의 Naver Cloud 필터로 조회한다. 컨테이너 시작은 실제 API 수집 성공/연속 수집 보장이 아니다. 별도 합성 이벤트/자동 인수 검사는 실행하지 않는다.

인증 키를 갱신했다면 비공개 env_file 변경 후 up -d --force-recreate naver로 컨테이너를 재생성해야 한다. 기존 writer 키는 발급일 기준90일 만료로, 별도 명시적 갱신이 필요하다. 컨테이너 중지는 같은 Compose 파일로 stop naver를 사용하며 데이터/상태/키는 유지한다.

근거:
- https://guide.ncloud-docs.com/docs/en/cat-subaccount
- https://guide.ncloud-docs.com/docs/en/subaccount-use
- https://guide.ncloud-docs.com/docs/en/cat-activities
- https://api.ncloud-docs.com/docs/en/management-cloudactivitytracer-getactivitylist
