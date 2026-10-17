# security-mall 3-C 실제 통합 인수

2026-10-16, 독립 Ubuntu VM `kopo@192.168.235.131`의 핵심3-C 통합 인수 완료. 이미 설치된 Elasticsearch9.5.2 `soc-mall-es-lab`과 독립 Filebeat9.5.2를 사용했다. 쇼핑몰 빌드·로그 생성·output.file 시험·ES 설치는 반복하지 않았다. Docker 명령이나 운영 Worker/Detector는 실행하지 않았다.

## 실제 저장 및 연결

| 구분 | 인덱스 | 결과 |
| --- | --- | --- |
| 실제 감사 원본 | `soc-host-raw-mall-isolated-20261016-8a070063` | 4건 |
| 기존3-A 정규화 결과 | `soc-normalized-mall-isolated-20261016-8a070063` | 4건 |
| 별도 합성 회전 시험 | `soc-host-raw-mall-isolated-20261016-8a070063-rotation` | 4건, 핵심4건과 분리 |

실제 입력은 로그인 실패1/성공2/타인 주문거부1이다. 네 event_id가 모두 다르므로 성공2건도 별도 정상 이벤트로 보존했다. 원본 전체 감사 객체와 실제 저장 객체가 같고 Filebeat fingerprint ID는 이전 output.file의 고정 ID와 같았다. 최종 root @timestamp는 앱 감사 시각과 같으며 event.ingested는 이번 중앙 수신 시각이다.

정규화는 최신 로컬 `processing.contract.normalize()`와 실제 import 의존18개 파일을 해시 대조해 VM의 독립 src로 전송하고 실행했다. 패키지 설치/운영 Worker·Detector/SQLite 상태 저장은 없다. 반환된 정규화 이벤트를 실습용 인덱스에 create Bulk로 저장했다. authentication3/iam1, event.id/action/outcome, source.ip, account_id/key_id/resource/reason, 조직·호스트와 `cloud_soc.provenance.raw={index,id}`를4건 모두 실제 원본과 대조했다. 발생·수신 시각은 원본과 같은 순간으로 보존하고 원래 나노초 문자열은 상세에 남겼다. 운영용 normalized 상수/워커 검색 범위·체크포인트는 변경하지 않았다.

## 수신·보안·create-only

- 고정 `https://127.0.0.1:19200`, 실습 CA/IP SAN 검증, 환경 프록시 및 리다이렉트 비활성화로 격리 대상만 사용했다. 버전/클러스터와 비인증401/인증200을 확인했다. TLS 검증을 끄지 않았다.
- 기존3-B YAML을 JSON으로 변환한 Painless pipeline `security-mall-isolated-final-v1-20261016-8a070063`을 실제 등록·컴파일했다. `_simulate` 정상 처리, 위조 event.ingested 덮어쓰기, 원문message/event.original 포함 입력 거부를 확인했다. 원본 strict 매핑과 source_ip=ip/event.ingested=date도 확인했다.
- 기존 템플릿을 이번 정확한 원본 인덱스 하나에만 적용하는 전용 템플릿으로 등록했다. final pipeline은 인덱스 설정에 고정했다. 기존3-B 검증 코드나 정상 수집기는 수정하지 않았다.
- 관리자 인증은 pipeline/template/인덱스/API Key 설정과 simulate에만 사용했다. 실제 Filebeat 전송에는 단일 원본 인덱스 `create_doc`와 cluster monitor만 있는2시간 만료 키를 사용했다. index/write/delete/manage/auto_configure/read 및 다른 인덱스 create_doc가 false임을 실제 권한 API로 확인했다. 정규화용 키는 해당 원본 read/view_index_metadata와 해당 정규화 인덱스 read/create_doc만 갖는다. 합성 회전은 별도 인덱스·키를 사용했다.
- 같은 writer로 보낸 명시적 ID의 `index` Bulk 작업이403으로 거부된 뒤 실제 Filebeat의 명시적 ID4건이 저장됐다. Filebeat로 동일4건과 내용이 바뀐 동일 ID1건을 실제 재전송했을 때5건 done/duplicates5, failed0/dropped0이었다. 원본4건의 `_source`, `_seq_no`, `_primary_term`이 최초 저장 그대로였다. 이 실제 서버 권한·응답과 Filebeat 메타데이터/고정 ID 결과로 create-only 동작을 판별했으며, 쓰기 권한 확대나 데이터 스트림 전환이 필요하지 않았다. 요청본문·인증 헤더의 복호화 trace는 수집하지 않았다.
- 원본과 정규화에는 message/event.original 및 비허용 원문 키가 없다. 설정·결과·Filebeat 진단23파일을 보호된 API Key 값/인코딩·관리자 비밀번호와 내부 비교해 비밀값 부재를 확인했다. 비밀은 VM secrets0600 및 Filebeat keystore에만 보존하며 보고서로 복사하지 않았다. 쇼핑몰 HMAC 키/기존 DB/원문 개인정보는 사용하지 않았다.

## 재시작·회전

- 같은 원본 registry와 설정으로6초 재시작 관찰: 새 입력0, 원본 내용/시퀀스 불변.
- 별도 합성 입력에서 최초 파일 → rename된 .1 → 새 활성 파일 수집을 확인했다.
- `compression:auto`, `file_identity.fingerprint`/growing을 유지한9.5.2에서 immutable .gz를 실제 읽어 저장했다. 합성 파일의 앞64바이트를 서로 다르게 만들어 시험의 지문 충돌을 피했다.
- 활성 파일에 JSON 절반만 추가한 동안 정상 이벤트는 저장되지 않았고, 나머지와 LF를 추가한 뒤 정확히1건 저장됐다. 별도 합성4건 모두 내용/ID가 일치했다.
- 각 임시 Filebeat 프로세스를 SIGINT로 종료해 exit0을 확인했다. 기존 Filebeat/Packetbeat의 inactive 상태와 쇼핑몰 원본 JSONL SHA256은 전후 동일했다. ES 컨테이너/서비스/볼륨을 변경·재시작하지 않았다.

이 결과는 정상 종료·시험한 rename/immutable GZIP 및 단일 인덱스 조건의 인수다. copytruncate/유실된 registry·디스크 장애/장기 지연/임의 회전 충돌에서 exactly-once를 보장하지 않는다. 실전 보존·장애/복구·운영 배포는 별도다. 이번 실제4건은 모두 계정 가명이 있는 이벤트이며 비로그인 null의 신규 실서버 사례는 추가하지 않았다(기존3-A 격리 계약 유지).

## 근거 위치

- VM: `/home/kopo/soc-mall-lab/integration-3c/`
- 보호된 실행 설정/keystore: `config/`, `data/`, `data-replay/`, `data-rotation/`. 기존 output.file 경로와 별도다.
- 단계 결과: `results/prepare.json`, `filebeat-first.json`, `replay.json`, `normalization.json`, `restart.json`, `rotation.json`, `summary.json`.
- 실제 원본/정규화 검색 근거: 보호된 `results/first-search.json`, `normalized-search.json`이며 저장소에 로그 전문을 복사하지 않았다.
- 로컬 재현 스크립트·의존 해시/안전한 요약: Git 제외 `D:/cloud-soc/state/mall-integration-20261016/`. API Key·관리자 인증 파일은 VM에만 존재한다. 키는 발급 후2시간 만료한다.

공식 계약: [create_doc 권한](https://www.elastic.co/docs/reference/elasticsearch/security-privileges), [Filebeat Elasticsearch 출력](https://www.elastic.co/docs/reference/beats/filebeat/elasticsearch-output), [filestream GZIP/fingerprint](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-filestream). 운영 적용·탐지/위험도/UI 개발은 이번 인수에 포함하지 않고 여기서 중단했다.
