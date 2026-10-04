# 증분 탐지 운영 배포 인수

2026-10-04: 사용자 운영 배포·기존 데이터 전환·실제 ES 검증 승인. 운영 접속은 미확보이며 아래 단계는 실행 결과가 아닌 준비 절차다.

## 현재 접속 상태

이전 기록의 중앙 Ubuntu 서버는 192.168.32.60, 계정 kopo, /home/kopo/cloud-soc다. 이번 환경에서 TCP 22는 4초 연결 시간 초과였다. SSH 설정/기존 등록 키가 발견되지 않았다. 현재 주소·인증 경로·신뢰한 SSH 지문을 확인한 뒤 재개한다. 개인키/비밀번호는 채팅·로그·패키지에 넣지 않는다.

## 실행 순서

1. 고정 SSH 지문, sudo 가능 여부, 실제 Compose 경로·실행 이미지·Git/배포 소스 차이, CA, ES 버전/상태, 디스크 여유, 현재 normalizer/detector/portal 상태를 확인한다. 기존 미커밋 운영 소스는 그대로 보호한다.
2. preflight-detection.py로 실제 ES 인덱스 수·필드 누락·기간·snapshot repository를 읽기 전용 검사한다. 이 도구는 저장소 존재만 확인하며 백업의 완료/복원 가능성을 인증하지 않는다.
3. 포털 DB 온라인 백업/verify, 중지 시점 백업, 기존 이미지/env/SQLite 처리 상태를 보호한다. ES snapshot을 생성하고 SUCCESS·실패 shard 0을 확인한다. 저장소 없으면 실제 서버 지원 경로에 맞춰 구성한다. VM 내부 백업과 외부 장애 복구 백업은 구분한다.
4. normalizer/detector를 중지하고 처리 체크포인트·정규화 문서·경보/근거 참조·사건 자료의 기준 건수/해시를 확보한다. 에이전트와 원본 수집 경로는 유지한다.
5. 기존 정규화 문서를 직접 update_by_query로 수정하지 않는다. normalized_at 추가가 기존 경보의 event_hash를 바꿀 수 있으므로 원본 및 정규화 증거는 보존한다. 실제 자료 확인 후 별도 이행 인덱스 또는 처리 기록 기반 수신 목록으로 전환한다. 새 참조/이전 참조를 모두 조회할 수 있어야 하며 과거 경보 중복, 재평가 시간 범위를 검증한다. 전체 역사 자료를 --accept-legacy-exclusion으로 제외하는 것은 사용자 요청의 데이터 전환 완료로 인정하지 않는다.
6. 이전 상태와 새 상태를 분리해 제한 키로 shadow 실행한다. 정상/임계값/배치 경계/재시작/지연/저장 실패·복구와 create-only·원본 쓰기 금지를 실제 ES에서 확인한다. 합성 이벤트는 운영 원본과 분리한 시험 조직/전용 인덱스에서 수행하며 기존 정상 운영 소스를 공격 시험 대상으로 사용하지 않는다.
7. 새 이미지와 필요한 매핑/역할만 준비하고 포털·normalizer·detector를 순차 교체한다. 같은 소스의 탐지기를 서로 다른 상태 파일로 동시에 가동하지 않는다.
8. 실제 신규 수집부터 정규화→탐지→경보 근거 조회까지 확인한다. detector 재시작 후 상태/동일 경보 ID/중복 없음을 확인하고 운영 화면 실패·stale·지연 표시도 대조한다.
9. 운영 체크포인트가 진행하고 기존 사건/패키지/키 이력 및 ES/Kibana/gateway/에이전트가 유지됨을 확인한다. 실패하면 새 처리기를 중지하고 보존한 이미지/env로 복구한다. ES/SQLite 상태는 임의 되감지 않고 재처리 영향 검토 후 복원한다.

## 사전 점검 명령 예시

서버의 실제 경로로 대체한다. 관리자 비밀번호는 파일로만 읽고 결과에는 이벤트 본문/자격 증명이 없다.

```sh
python3 deploy/server/preflight-detection.py \
  --es-url https://localhost:9200 --ca-file state/server/tls/ca.crt \
  --password-file state/server/secrets/elastic_password \
  --report state/verification/detection-preflight-20261004.json
```

Python Elasticsearch 의존성이 있는 보호 실행 환경에서 수행한다. code 2는 백업/클러스터 조건 미충족이며 자동 배포하지 않는다.
