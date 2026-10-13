# 초기 SSH 통지 시험 서버 보호 배포 — 2026-10-13

## 판정과 범위

192.168.32.60의 실제 중앙 SOC에 포털·정규화·기본 AUTH 탐지의 초기 통지를 적용했다. 실제 SSH 정상/실패 9회/실패 10회, 초기 화면 표시, 최종 frontier·근거 연결, 탐지·포털 재시작 보존을 검증했다. 관리자 화면의 지정 시험 범위이며 추가 조직/역할·지속 고유입 성능·신규 패턴·독립 재해 복구의 완료는 아니다.

사용자는 누락된 정규화 서비스 추가, 기존 해시 보호 후 포털 admin 비밀번호만 변경, ES snapshot 미지원 상태에서 기존 문서 수정·삭제 없이 새 수신부터 처리하는 시험 배포를 승인했다. 공개 ngrok 인증 전송은 자동 승인 검토에서 거부되었고, 사용자는 CA 검증 LAN 경로 검증을 선택했다. 실제 브라우저는 루프백 검증 프록시를 통해 중앙 IP의 CA·인증서/IP를 검증하고 기존 공개 Host로 요청했다. 인증 정보는 보호 파일/메모리에서만 사용했고 공개 터널로 보내지 않았다.

## 사전 상태와 보호

- 서버 저장소 HEAD는 92d13c0이며 실제 실행 이미지는 별도다. 기존 중앙 ES 9.5.2·Kibana·Caddy·포털과 수집기는 동작했지만 정규화/탐지 서비스·키·상태 DB는 없었다. 정규화/처리/상태 계약 인덱스는 0건이었다.
- 관리자 점검 당시 호스트 원본 2,911,564건·네트워크 2,738,757건, 최근 15분 수신 각각 6,617/7,155건을 확인했다. 서비스 Running만으로 수신을 판정하지 않았다.
- 보호 경로는 `/home/kopo/cloud-soc/state/early-deployment-20261013`이다. 기존 포털 이미지 tar(52,996,608 bytes), 실행 메타데이터·Compose·환경·키/CA를 제한된 권한으로 보존했다. 비밀 내용·원문은 Git에 넣지 않았다.
- 포털 packages/cases DB는 SQLite 온라인 backup·integrity_check와 별도 격리 복원을 통과했다. 기존 packages 16행·issued_keys 26행·사건 관련 0행은 최신 배포 후 공통 컬럼의 원래 행 전체와 대조해 유지됨을 확인했다.
- ES snapshot repository와 path.repo 설정이 없어 snapshot은 수행하지 못했다. ES를 재시작해 설정을 바꾸지 않았다. 기존 원본 문서/매핑을 수정·삭제하지 않았고 raw 매핑 전후 일치와 기존 ES/Kibana/gateway의 컨테이너 ID·StartedAt 불변을 확인했다. 따라서 전체 ES 재해 복구 인수는 남는다.
- 최종 경보 확정 후 탐지기를 잠시 정지해 main/early DB를 함께 보호하고, 포털·처리 DB도 일관 backup·격리 restore 검사했다. 쌍 DB의 미전달 outbox는 0건이었다.

## 적용 소스와 실행

| 구분 | 식별값 |
| --- | --- |
| 기능 소스 | 18dabf7, 000659f |
| 실제 정상 키 형식 보완 소스 | `3b9aff9d7f6948af25aa6b4bc0cae973f2c2005a` |
| 최초 기능 이미지 | `sha256:f1474a8a9d496740b22368f4f5eee222864714b486f8e8e1fef4967529969271` |
| 최종 포털·정규화·탐지 이미지 | `sha256:40ed90fb0c524c376cfb8bdda0a2908018f9475f414a8ebd783316f596646c90` |
| 활성 Compose override | `/home/kopo/cloud-soc/state/early-release-000659f/early.override.json` |
| 공통 UTC 시작점/SSH v2 receipt floor | `2026-10-13T02:35:47.839670+00:00` |
| 정규화 state | `state/server/processing/checkpoint.sqlite` |
| 탐지 main/early state | `state/server/detection/runtime.sqlite`, `runtime.sqlite.early.sqlite` |
| 활성 규칙/옵션 | AUTH-001, `--early-auth --interval 10`, lateness 900초 |

`--include-patterns`·cloud/sequence/attacks 프로필을 추가하지 않았다. 초기 통지 인덱스는 exact mapping으로 준비했고 새 worker 키 2개는 30일 만료의 전용 최소 권한으로 발급했다. 기존 키는 교체·폐기하지 않았다. 기존 monitor 역할에는 정확한 notice/탐지 진단 read 범위만 덧붙였고 기존 권한·비밀번호를 유지했다.

최초 후보의 기존 기반 이미지에는 cryptography가 없어 모듈 검사가 실패했다. 실행 서비스 교체 전에 발견해 프로젝트 requirements/constraints로 후보 의존성을 맞추고 pip check·offline AUTH·모듈 import 검사를 통과했다. 기존 이미지는 유지했다.

## 실제 시험

일반 사용자 계정에 실패를 발생시키지 않았다. 승인된 Ubuntu 자신의 서로 다른 loopback 출발지 127.0.0.2/127.0.0.3과 전용 존재하지 않는 시험 식별자를 사용했다. password auth·잠금 모듈 상태를 먼저 확인하고 9회/10회를 각각 5분 안에 수행했다. 실제 journal의 Failed password 관측도 9/10회였다.

| 시험 | 실제 결과 | 판정 |
| --- | --- | --- |
| 정상 SSH | 정상 공개키 로그인 성공. 보완 적용 이후 새 성공 정규화 6문서를 별도로 확인, 정상 출발지 경보 0건 | 통과 |
| 실패 9회 | journal 9회, 정규화 미러 18문서→고유 실패 9회, 초기/최종 0건 | 통과 |
| 실패 10회 | journal 10회, 정규화 미러 20문서→고유 실패 10회, 초기 1·최종 1건 | 통과 |
| 초기 지연 | ES tenth 검색 관측→Chrome 최초 표시 약25.894초 | 이번 1회 60초 목표 통과 |
| 근거 | 초기 10개 모두 실제 API의 exact_reference·normalized_hash_verified, 최종 근거 10개·threshold10/window300 | 통과 |
| 최종 frontier | 초기 창 종료 02:52:28.048 UTC < 재시작 전 실제 frontier 02:56:05.990650 UTC | 통과 |
| 연결/중복 | 같은 논리 통지가 confirmed로 전환, 최종 경보 연결 1개·화면 카드 1개 | 통과 |
| 재시작 | detector/portal 재시작 후 notice·최종 전체 문서 SHA·proof·개인/legacy 구성 유지, 9회0/10회1 유지 | 통과 |
| 실제 화면 | 홈1440/390 두 테마·근거 popup·개인 위젯 저장/재조회1440/390·확정 링크, 가로 넘침/JS 예외0 | 통과 |
| 장애 | 실제 ES 중단 없음. 조회 실패/권한/지연/저장 실패·복구는 로컬 격리 회귀, 실제 DB backup/restore는 위 보호 검증 | 범위 구분 |

정상 publickey 성공은 부가 `ssh2: ED25519 SHA256:...` 지문 때문에 기존 엄격한 suffix 검사에서 누락됐다. 실제 형식을 확인해 ED25519/RSA/ECDSA의 제한된 성공 형식만 허용하고 지문은 정규화에 남기지 않았다. 실패·password·잘못된 길이/알고리즘·추가 내용은 그대로 거부한다. 기존 시작점/체크포인트·SSH floor와 rule identity는 유지했고 원본/이전 해석은 삭제하지 않았다. 정규화기의 원래 15분 겹침 읽기 범위에서는 이전 unclassified와 별도로 새 성공 해석이 추가될 수 있으며, 전체 과거 재처리나 체크포인트 되감기는 하지 않았다.

## 실제 시각

모두 UTC이며 UI는 KST로 표시한다. server NTP synchronized=yes를 확인했다. 검색/화면 값은 직접 관측 시각이며 refresh 즉시성이나 지속 성능을 보장하지 않는다.

| 단계 | 시각 |
| --- | --- |
| 마지막 유효 실패 | 02:52:28.048000 |
| 해당 이벤트 중앙 receipt | 02:52:28.349849 |
| proof 최대 normalized_at | 02:53:23.632396 |
| ES에서 tenth 유효 조건 검색 관측 | 02:53:24.451157 |
| 초기 생성 | 02:53:33.722802 |
| Chrome 최초 표시 | 02:53:50.345 |
| 최종 확정/링크 | 03:08:00.756686 |

초기 측정은 000659f 이미지에서 실제 수집기·ES·Flask·Chrome으로 수행했다. 이후 3b9aff9는 정상 키 성공 suffix만 보완했고 같은 초기/최종 통지·근거·상태가 유지됨을 재검증했다. 마지막 실패→화면은 약82.297초로, 목표의 기준인 정규화 검색 가능 관측→화면과 다르다. 초기 엔진/화면 변경 없는 보완 뒤 지연을 새로 측정한 것으로 바꿔 보고하지 않았다.

## AWS·Windows 후속 시험

사용자 추가 요청으로 Ubuntu 인수를 마친 뒤 두 지정 서버를 점검했다. AWS 13.208.175.237은 ec2-user SSH·Amazon Linux2023·기존 DVWA 컨테이너·정상 GET→login.php 200을 확인했다. SOC/custom·일반 Filebeat/Packetbeat/Elastic Agent 서비스와 알려진 설정 경로는 없고 중앙 AWS 감사 receipt는 0건이다. 사용자는 기존 전송 경로가 없으며 현재 점검 결과를 기록하도록 선택했다. 자원 변경/센서 설치/CloudTrail 구성/공격은 수행하지 않았고 실제 AWS 탐지 검증은 미완료다.

Windows 192.168.1.138의 실제 컴퓨터명 DESKTOP-LESEHNO·사용자 HP를 중앙 인증 메타데이터 및 사용자 whoami로 대조했다. 지정 키에서 파생한 공개키는 사용자가 이전에 등록하도록 승인한 키와 일치하고, 승인된 출발지192.168.1.1·서버 host key도 검증됐다. 최초 서버는 제출 키를 받아들이지 않았다. 사용자 확인에서 HP Enabled=True, 관리자 키 파일 Owner=Administrators·ACL=SYSTEM/Administrators FullControl·기본 관리자 Match 설정은 정상이다. 추가 읽기 점검에서 NullBytes=0·UTF16BOM=False·HPIsAdmin=True지만 RegisteredKeyInUTF8=False여서 현재 파일에 지정 공개키가 없음을 확인했다. 사용자가 지정 VM 주소 확인·기존 파일/ACL 보호 백업 후 동일한 승인 키만 다시 추가했고 2026-10-13 13:08 KST 완료를 확인했다. 기존 출발지/forwarding 제한과 ACL을 유지했으며 다른 인증 수단이나 서버 인증 정책은 바꾸지 않았다.

재등록 후 실제 HP SSH 정상 접속을 성공했고 Windows의 cloud-soc-filebeat·cloud-soc-packetbeat가 Running, 직전15분 4624=7/4625=0임을 직접 조회했다. 새 로그인 시험 floor=04:08:35 UTC 이후 중앙 원본에는 승인 출발지의 OpenSSH Accepted publickey 1건·HP의4624 2건이 도착했다. 두4624는 결정적 정규화 ID를 직접 조회해 정확한 원본 provenance·windows_security_v1·outcome=success·LogonType=3을 대조했고 processing status도 모두 normalized였다. 두 원본/정규화 모두 유효 source IP는 0개였으며 임의 추정하지 않았다. 정상 출발지의 새 경보0·기존 Ubuntu final 전체문서 SHA 불변을 확인했다. LAN 포털의 Filebeat/Windows/IP·04:08:35~04:10 UTC 조회는200·36행 중 HP 정상4624 2건, 실제1440 화면·JS 예외0이며 `output/playwright/early-live/windows-normal-1440.png`에 보존했다. Windows 실패 공격/신규 규칙 인수는 미실행이다.

중앙에서는 해당 Windows IP의 최근15분 raw64건과 4624 등을 확인했다. 표본에서 LogonType4/TargetUserName6문서는 있었지만 유효한 IpAddress는 0개였다. OpenSSH/Operational6건에서도 현재 출발지192.168.1.1을 확인했으나 키 거부 원인 메시지는 확정하지 못했다. 실제 위험 규칙의 필수 필드/프로토콜을 추정하지 않는다. Windows/AWS/HTTP404/종료flow 신규 후보는 비활성, SSH 다수 계정 후보도 실행 프로필에 추가하지 않았다.

## 로컬·Git·잔여

최종 Python774 passed/19 skipped/257 subtests(89.34초), 관련92 passed/7 subtests, UI142 passed, Ruff·diff 통과, Bandit 중간/높음0. 000659f와 3b9aff9의 Windows/Ubuntu GitHub Actions가 모두 통과했다. [기능 CI](https://github.com/Gandalem/cloud-soc/actions/runs/38338941741), [정상 키 보완 CI](https://github.com/Gandalem/cloud-soc/actions/runs/38341068781).

18dabf7/000659f/3b9aff9와 검증 문서 d718ec9를 codex/dashboard-platform-20261013에 일반 push하고 원격 SHA를 대조했다. d718ec9의 [Windows/Ubuntu CI](https://github.com/Gandalem/cloud-soc/actions/runs/38344967868)도 통과했다. main·force push·PR 생성/병합은 하지 않았다. 개인 Word/JSON·비밀·서버 state/backup·브라우저 출력은 커밋에서 제외했고 사용자 파일 해시를 대조했다. 검증 스크린샷은 Git 제외 `output/playwright/early-live`에 보존했다. 실제 source/image report와 보호 복원 자료는 위 서버 보호 경로에 있다. 화면 검증 후 임시 루프백 인증 프록시와 시험 브라우저를 종료했다.

롤백은 보호된 원래 이미지/Compose/해시·SQLite 백업을 사용하되 관련 서비스만 중지하고 state/notice/증거를 보존하는 운영자 작업이다. rollback 자체를 실제 수행한 것으로 주장하지 않는다. 기존6개 비밀 파일 중 승인된 admin 해시 이외의 원래 비밀·CA/TLS는 모두 byte 일치했다. 수집기·ES·Kibana·gateway는 재시작하지 않았다. 독립 ES snapshot/복구, 실제 추가 계정/조직·세션 로그인/로그아웃, Windows 실패의 실제 source IP 필드 확인, AWS 수집 구성, 신규 프로필 인수와 실제 경보→사건/메모/판정 전체 시연은 후속이다.
