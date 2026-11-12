# 실시간 탐지 확정 지연 900초 → 60초 변경 검토 (2026-11-12)

## 목적

운영 중인 `AUTH-001`, `AUTH-SEQ-001`, `AUTH-SPRAY-001`,
`ATTACK-01`, `WIN-AUTH-001`, `WEB-404-001`, `NET-PORT-001`의
일반 확정 평가를 이벤트 시각 기준 최대 15분 지연시키는 900초 frontier를
신규 상태에서는 **60초**로 단축한다.

이 값은 탐지 임계치의 5분 집계창과 별개다.
`--interval 10`과 `end = now - 30초`는 그대로 유지되므로
수집→정규화→화면 표시까지 60초 이내를 *보장*하는 설정은 아니다.
10초 polling, 30초 읽기 안정화 지연, Elasticsearch refresh, Filebeat
전송, 정규화 워커 지연, 경보 인덱싱·Portal 갱신을 별도 측정해야 한다.

## 변경 사항

- 신규 detector 4종 런타임 기본옵션 `--lateness-seconds 60`.
- `cloud_soc.detection` CLI 기본값 60초.
- `run_incremental`과 `run_retrospective` 직접 호출 기본값 60초.
- SSH 조기 경보는 기존대로 유지. 기존 rule 검증 해시/임계치는 변경하지 않음.
- 수신 중복검사 15분 범위는 유지. 60초 이전 이벤트는
  독립 retrospective worker의 역사적 문맥 조회로 별도 재분석한다.
- 탐지 및 감사 경보의 원본·정규화·증거 문서를 삭제하거나 재작성하지 않음.

## 기존 EC2에 즉시 적용되지 않는 이유

현재 운영자 checkout은 `JEONGRIM-SEO`의 이전 SHA `4c49c0d`이고,
`src/cloud_soc/processing/contract.py` 등 추적 중 변경과
미추적 `src/cloud_soc/parsers/suricata.py`가 있다.
새 이미지가 해당 파서를 덮어쓰면 IDS 정상 수집이 손상될 수 있다.

**설정 전환에는 런타임 상태 식별자 마이그레이션이 필요하다.**
`incremental.py`는 `lateness_seconds`를 규칙/소스/시작 시각과 함께
SQLite `runtime.identity`에 해시로 고정하며, 불일치 시
`rule_or_scope_changed_requires_new_state`로 중단한다.
`retrospective.py`의 SQLite 상태 식별자에도 동일 값이 포함된다.
`deployment.contract.build_contract(..., existing=...) `는 기존
준비된 런타임의 900초 옵션을 보존하도록 설계되어 있어서
**코드 기본값만 바꾸거나 PR을 병합하거나 서버 이미지만 바꾸면
작동 중인 900초 설정은 그대로 남는다.**

기존 DB를 삭제하거나 기존 `identity`만 바꾸는 즉석 편집,
`--lateness-seconds 0`, `docker compose down -v`, 기존 커밋에
`git reset --hard` 등을 수행하지 않는다.

## 전환을 위한 안전한 배포 기준

1. 기존 source/이미지, `runtime/contract.json`, 4개 탐지 워커의
   `runtime.sqlite`와 WAL/SHM, 조기 통지/outbox, 경보 인덱스의
   복구 가능한 백업을 확보하고 저장물 소유권을 확인한다.
2. 기존 수정된 Suricata 파서·portal/processing 코드를 별도 검증 브랜치에
   보존·통합한 뒤 신규 태그 이미지로 빌드한다.
3. 기존 감지 워커의 900초 확정 구간이 배출되는 동안 경보·체크포인트를
   보존하고, 별도의 60초 상태/워커를 위한 최초 시작점과 과거 이벤트
   이어받기 전략을 검증한다. 동일 7개 규칙을 병렬 실행한다면
   이중 경보를 예방하는 공통 ID/원본 참조·쿨다운 검증이 선행돼야 한다.
4. 60초 상태를 사용하도록 새 **명시적 런타임 계약 마이그레이션**
   및 기존 900초 상태의 보존/전환 시점을 승인·구현해야 한다.
   구 계약 자동 계승 로직은 미승인으로 변경하지 않는다.
5. 재시작 전후 정탐/오탐, 원문 증거, 늦게 도착하는 Filebeat 로그,
   checkpoint, dedup/outbox, retrospective 보정 결과를 테스트한다.
6. `manage.py plan → apply → verify`를 사용하고 실제 alert
   발생에서 Portal 가시화까지 지연 p50/p95/p99를 관측한다.

## 검증 결과의 경계

이 PR에는 60초 **신규 기본값과 regression 검사**를 구현했다.
**운영 EC2 런타임 계약/기존 SQLite state 전환은 아직 구현/적용하지 않았다.**
그러므로 이 PR만 병합한 시점에는 서버 탐지 지연이 바뀌었다고 말할 수 없다.
