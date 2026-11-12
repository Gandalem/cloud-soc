# 미지원 로그 분류와 선택적 감사 메타데이터 파서 (2026-11-12)

대상 인스턴스: 서울 `ap-northeast-2` / 공인 IP `52.78.127.135`.
이 브랜치는 운영 서버를 수정하지 않는 **배포 전 검토 후보**다.

## 실측 원본 분류

`soc-processing-v1`의 최근 24시간 `status=unsupported` 문서와
`raw.index + raw.id`로 연결한 원본 메타데이터를 전수 조사했다.
조회 기준 시간이 이동하므로 실행별 총량은 18,443~18,450건으로 소폭 변동한다.
원본 본문·키·비밀번호·스크립트 내용은 출력하거나 복사하지 않았다.

- Linux journald audit: 7,196
- Linux journald syslog: 5,518
- Linux file: 3,606
- Linux journald stdout: 1,616
- Linux journald journal/kernel: 243
- Windows 이벤트: 262
- 출처 불명확: 2

자주 관측된 유형:
CRON/CROND, systemd 서비스 시작/종료, SSM Agent stdout,
`/var/log/auth.log*`의 CRON PAM 세션, SELinux AVC/USER_AVC,
Windows Security 5379, PowerShell 4104, Defender 5007.

CRON `pam_unix` 세션은 SSH 실패나 인증 공격이 아니다.
회전된 `auth.log.1`의 과거 이벤트를 실시간 공격으로 오인하지 않는다.

## 이번 변경의 범위

`src/cloud_soc/parsers/unsupported_metadata.py`:
다음 **이미 인식 가능한 타입**의 보수적 관측 메타데이터만 추가한다.

- Linux journald transport=audit: SERVICE_START, SERVICE_STOP, AVC,
  USER_AVC, SECCOMP, BPF
- Windows Security: 5379
- Windows PowerShell/Operational: 4104
- Windows Defender/Operational: 5007
- Windows System / Service Control Manager: 7036

확정되지 않은 성공·침해 여부는 `outcome=unknown`으로 처리한다.
원문 메시지, PowerShell 스크립트 블록, Defender 값, 명령행, 자격증명,
원시 audit payload는 정규화된 이벤트에 담지 않는다.
원본 연결은 기존 `cloud_soc.provenance.raw`만 사용한다.
`agent.type=filebeat`, 정확한 로그 출처와 Windows 채널/제공자/이벤트 ID를 검증한다.

`processing/contract.py`는 SSH 파싱 다음, 범용 Linux 운영
fallback보다 먼저 선택적 감사 이벤트를 인식한다.
`processing/worker.py`는 필요한 작은 메타데이터 필드만 추가 조회한다.
기존 로그 원본과 기존 경보·체크포인트는 변경하지 않는다.

## 실제 데이터 읽기 전용 재평가

최근 24시간 미지원 레코드 18,450건을 `mget`으로 재구성한
**메모리 기반 시험**에서:

- Linux audit metadata: 7,128건
- Windows observation metadata: 160건
- 합계 신규 정규화 가능: **7,288건 (39.5%)**
- 남은 미지원: **11,162건 (60.5%)**
- 원본 참조 누락: 0건
- 새 코드 기반 정규화 중 예외: 0건
- `tests/test_unsupported_metadata.py` 7개 테스트 통과

이는 예상되는 **적용 후 새 이벤트의 파서 범위**를 확인한 것일 뿐,
과거 처리 레코드를 다시 작성했다는 뜻은 아니다.

## 운영 적용 전 필수 조건

1. 서버 checkout에 미커밋 `processing/contract.py` 변경과
   `parsers/suricata.py` 등 미추적 코드가 있다.
   이 브랜치를 그대로 배포하면 기존 Suricata 연동이 사라질 수 있다.
   **서버 변경을 먼저 보존·병합**해야 한다.
2. 차등 파서 테스트와 전체 기존 normalizer/portal/detection 테스트를 실행한다.
3. 승인된 후보 이미지를 별도 태그로 빌드하고 상태/키/인증서를 보존한 채
   `plan -> apply -> verify` 검증 절차를 수행한다.
4. 변경된 파서는 **새로 수집되는 이벤트에만 자동 적용**된다.
   과거 `soc-processing-v1` 및 `soc-normalized-v1` 기록을
   덮어쓰지 않는다. 과거 재처리는 별도 상태/인덱스/승인이 필요하다.
5. 별도 소스 범위별 샘플에 대해 정상 서비스 이벤트의 오탐과
   보안 이벤트의 정탐을 검증한 뒤 관련 탐지 규칙을 추가한다.
