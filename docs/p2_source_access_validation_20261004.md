# P2-01 / P1-04 보호된 원문 실제 검증

2026-10-04 지정 VMware Ubuntu·Windows 시험 환경에서 포털 배포, 실제 ES/API/Edge 대조, 조직·역할·감사 검증, 기존 설치 보존형 마스킹 v3 적용과 실제 수신을 완료했다. 사용자가 승인한 **보호된 허용 필드 JSON** 범위다. 전체 비마스킹 원문·내보내기는 제공하지 않는다. 이전 [메타데이터 검증](log_query_validation_20261004.md)과 [작업 목록](work_tracker.md)의 성공·실패 이력은 보존한다.

## 기준과 단계

- 시작: clean `5c79b99`, 기능 브랜치 `codex/privacy-source-access`. fetch한 `origin/main`의 `cb329e4`가 선행 커밋임을 확인했다. main에서 편집하지 않았다.
- 구현: 기존 조직별 조회·허용 필드·감사·privacy v3 코드에 Linux 프로비저닝 자료 기본 제외와 모바일 사유 선택 색상을 추가했다. 관련 소스는 `deploy/agents/discover-linux.sh`, `deploy/agents/tests/installers.test.cjs`, `prototype/logs.css`다.
- 격리 검증: 이번 관련 Node 46/46, Python 정책·개인정보·원문 감사 21/21, Linux `bash -n`, 실제 파일 탐색, diff 검사 통과. 이전 전체 Python 350 중 344 통과/환경 6 제외·화면 78·수집 마스킹 6은 앞선 코드 검증 이력이며 이번 전체 재실행으로 기록하지 않는다.
- 배포: 보호 백업·이전 이미지 확보 → UID 1000/read-only/no-network import·공개 파일 읽기 → 포털만 교체 → 기존 DB 행/BLOB·비대상 컨테이너·런타임 소스 해시 대조.
- 실수신/화면: 네 기존 수집기의 ES 문서와 실제 HTTPS 포털의 역할별 응답·Edge JSON·SQLite 감사, 별도 합성 민감 표식 두 문서, 감사 장애·복구를 대조했다. 서비스 실행이나 단위 테스트로 실수신을 추정하지 않았다.

## 실제 배포와 보호 백업

최초 새 이미지 `479baebb59faa2c475fd77c61c3ff838b592dc4e3932179416490d062e66b223`에서 검증을 시작했다. 소스 검토 후 Linux 제외와 CSS를 반영한 최종 이미지:

`sha256:1cc44955201749cedb7257de06641ea8fe133170e3d1af8ea0191529913bcf9d`

태그는 `cloud-soc-p2-portal:5c79b99-source-review`다. **5c79b99 기반에 이번 미커밋 공개 파일 두 개를 더한 배포**이며 순수 5c79b99 이미지라고 표기하지 않는다. 서버의 기존 Git checkout·기존 ZIP은 유지했다. 이번 커밋·푸시는 요청되지 않아 수행하지 않았다.

2026-10-04 Git 후속: 검증 종료 뒤 사용자가 커밋·푸시와 진행도 안내를 요청했다. 같은 기능 브랜치에 위 공개 소스·회귀·문서를 반영한다. 앞 문단의 미커밋/미푸시는 배포·검증 시점의 이력이며, 이번 Git 반영으로 서버 checkout/이미지·정책·에이전트를 다시 변경하지 않는다. 배포 시 확인한 LF 소스 해시와 Git 반영 소스를 대조한다.

서버 보호 작업 경로는 `/home/kopo/cloud-soc/state/p2-20261004-5c79b99`다. 초기 이미지 `d5ff9ee6ae7b3b01b0a9b1250f3a6a504d1cee4f95cce50fd2e9b8d0d08ee1a6`를 `cloud-soc-p2-rollback:before-5c79b99`와 `portal-before.tar`로 보관했다. 초기 공개 소스, 보호 정책과 이전 파일도 별도 보관한다. 인증 정보·개인 키·원문은 Git에 추가하지 않았다.

초기 online/stopped format 1, 후속 source-review online/stopped 및 final format 2의 **backup → verify → 새 경로 restore → verify**가 모두 통과했다. 최종 감사 34개 행은 격리 복원 후 모든 컬럼·순번까지 일치했다. 처음 12개 감사 행도 최종 DB에 그대로 남았다. 운영 DB에 백업을 덮어쓰지 않았다.

기존 packages 10·issued_keys 18·enrollments 15와 사건 관련 4개 빈 테이블의 전체 행/BLOB 해시가 시작 기준과 일치했다. ES·Kibana·gateway·enrollment cleanup·CRL 컨테이너의 ID/이미지/시작 시각/재시작 횟수는 불변이었다. 기존 ES 문서 삭제·재처리·보존 기간 적용은 수행하지 않았다. SQLite 복원을 ES 스냅샷 복원으로 간주하지 않는다.

최종 실행 소스 8개 해시를 독립 확인했다. 주요 배포 바이트(LF)는 다음과 같다.

| 파일 | SHA-256 |
| --- | --- |
| `deploy/agents/privacy.js` | `a64cdfb6be0abb5a64455311430948091bec67298d3a07c411a5a744e4748404` |
| `deploy/agents/discover-linux.sh` | `67948ff9447bb5aa67596edaf25ab9d503d97fba511e6d33df6f45108864012d` |
| `prototype/logs.css` | `f3a2dc07ea91fce3fef8e5e338383f725c5ff44852174ca2aba5f31c28f50696` |

## ES → API → 실제 브라우저

Edge `154.0.4258.53`의 별도 인증 컨텍스트에서 admin/investigator 각각 Windows/Linux × Filebeat/Packetbeat 4조합을 확인했다. 최초 8건에 이어 최종 이미지에서 8건을 다시 검증했다. 설치·privacy probe는 일반 OS/네트워크 사례에서 제외했다. 수신 중 목록이 바뀌므로 최종 시험은 **실제 표시된 행**을 선택하고 그 참조를 ES와 대조했다.

최종 대표 참조는 아래와 같다. 인덱스는 각각 `soc-host-raw-{windows,linux}-9.5.2-2026.10.04`, `soc-network-{windows,linux}-9.5.2-2026.10.04`다.

| OS / 수집기 | admin 문서 ID / 감사 | investigator 문서 ID / 감사 |
| --- | --- | --- |
| Windows / Filebeat | `OQv6BqEBYPLrp-rqY1tb` / 18 | `Owv6BqEBYPLrp-rqY1u-` / 19 |
| Ubuntu / Filebeat | `IQv6BqEBYPLrp-rqU1st` / 20 | 같은 참조 / 21 |
| Windows / Packetbeat | `-wv6BqEBYPLrp-rqUFrt` / 22 | `eQv6BqEBYPLrp-rqeFtA` / 23 |
| Ubuntu / Packetbeat | `kAv6BqEBYPLrp-rqeFt8` / 24 | 같은 참조 / 25 |

독립 ES 허용 필드 GET, API JSON, DOM JSON이 일치했고 저장 타입·시각이 유지됐다. 사례별 동일 타입/값 필드는 18·21·12·12·24·24·24·24개였다. 사용자가 사유를 고르고 버튼을 누르기 전 원문 요청은 없었다. 성공 후 `complete_source=false`와 감사 순번을 확인했다. 닫기 후 JSON은 지워졌고 desktop/390px 모바일 각 8개 화면에 수평 넘침이 없었다. 사유 선택의 흰 배경/짙은 글씨를 실제 계산 스타일과 모바일 화면으로 확인했다.

viewer는 같은 조직의 메타데이터만 볼 수 있고 source 403·버튼 숨김을 확인했다. investigator/viewer/타 조직 시험 계정의 관리 API·페이지는 403이었다. 타 조직 목록은 빈 200, 타 조직 실제 참조/없는 참조의 source는 동일한 404, 잘못된 사유는 400이었다. 계정 간 커서 재사용은 400으로 거부됐다. 오류에는 합성 비밀 문자열이 없었다. TLS 우회/폐기 예외 없이 실제 브라우저 인증서 오류 0건이었다.

실제 감사 DB에서 actor·purpose·참조 SHA-256·outcome·정책 버전·응답 audit_id를 대조했다. 최종 일반 12개 요청, 별도 canary/복구 3개 요청, 임시 계정 제거 후 관리자 1개 요청이 일치했다. 최종 34개 기록(허용 26/권한 거부 2/잘못된 입력 2/문서 없음 4)은 초회·중간 시험의 정상 접근 기록도 포함한다. 34개가 모두 별도 최종 시험이라는 뜻은 아니다.

감사 DB를 쓰지 않는 `BEGIN EXCLUSIVE` 잠금으로 25초간 실제 저장 불가 상태를 만들었다. 요청은 `source_audit_unavailable` 503, source 필드 없음, 화면 JSON 비움으로 차단됐다. 잠금 전후 행 수 32가 같았고 해제 후 감사 33을 저장하며 조회가 복구됐다. DB/테이블 삭제·큐 복원은 하지 않았다. 최종 컨테이너 로그에는 시험 비밀 표식·로그 URL·시험 조회 계정명이 없었다.

## 기존 설치 보존형 v3와 소스 검토

두 VM 모두 Discovery 중지/잠금 → 두 Beat 중지 → 보호된 전체 파일 백업/해시 → `privacy.js`만 원자 교체 → 실제 Beat config/output 검사 → 시작 전 비정책·비로그 파일(큐/registry/keystore/설정/UUID 포함) 바이트 대조 → 서비스/Discovery 재개를 수행했다. 실패 때는 정책 파일만 복구했고 큐·registry를 과거 백업으로 되감지 않았다. 이전 v2 SHA는 `a8906acacecd6243481f7e8fe3d3ecbac39325d98b348b9f348246e4559f5fe2`였다.

Windows의 서비스 Auto/LocalSystem, Npcap Running, Discovery 정의·enabled를 유지했다. MachinePolicy/UserPolicy/Process/CurrentUser/LocalMachine 모두 Undefined인 저장 실행 정책이 그대로였다. 시험 자식 프로세스에만 RemoteSigned를 사용했다. Schannel의 IPv4 이름 판정 실패 후 기존 독립 .NET 검사에서 CA/주소/기간/**Online 폐기**까지 통과했으며 예외 옵션을 사용하지 않았다. 마지막 CA·키·설정·ID 파일 해시는 Windows 5/4개, Linux 4/4개가 시작 전 기준과 일치했다.

| OS / 수집기 | 유지한 agent.id | v3 실제 수신 시각(UTC) |
| --- | --- | --- |
| Windows / Filebeat | `927b681f-a1f2-4a2a-ad68-3e3627b7ba63` | `2026-10-04T13:01:01.483366743Z` |
| Ubuntu / Filebeat | `fa539fd5-b42b-4501-a4e7-86030927c2eb` | `2026-10-04T13:03:05.128974962Z` |
| Windows / Packetbeat | `23f17deb-0fa6-46d0-bbe5-ccf55bf2c563` | `2026-10-04T13:03:30.449350044Z` |
| Ubuntu / Packetbeat | `7212dfe2-dde4-4ae0-a452-bbb0bbb97083` | `2026-10-04T13:03:30.562136223Z` |

실제 설치의 기존 ndjson probe 입력에 OS별 **합성** 비밀 옵션/URI·secret 필드를 한 건씩 추가했다. ES 제한 GET에서 두 문서의 user.name/source.address/message가 `[REDACTED]`, secret/event.original 없음, 표식 원값 없음이 확인됐다. 이는 ndjson 합성 이벤트이며 Windows native winlog.message 제거 시험과 구분한다. 실제 보호 JSON·모바일 화면도 같은 마스킹을 확인했다. 원래 OS 사례에는 설치 probe를 섞지 않았다. 일부 새 표식/합성 필드는 기존 인덱스에서 검색 불가 또는 `_ignored`였으므로, 네 수집기의 최신 저장 표식과 canary의 event.action/agent.id·저장 marker를 대조했다. 저장 마스킹을 모든 필드의 색인 성공으로 확장하지 않는다.

Windows 실제 소스는 승인된 시스템 로그 루트 4개, selected 채널 355·파일 12, 알려진 비밀/문서/아카이브 제외 82·binary 7이었다. 선택된 사용자 홈 경로 0, include_xml 활성 0을 확인했다. 시스템 이벤트에도 이름/SID/경로/IP 같은 개인정보가 있을 수 있어 조직·목적 제한을 유지한다.

Ubuntu `/var/log`에 설치/초기화 자료가 포함된 것을 발견했다. 본문을 출력하지 않고 기존 정책 도구로 `/var/log/installer`, `/var/log/cloud-init.log`, `/var/log/cloud-init-output.log`를 DryRun 후 v0→v1 보호 적용했다. 실제 입력에서 해당 자료가 빠지고 파일 17개가 선택됐다. 새 기본 탐색도 installer 전체·user-data/autoinstall/cloud-init 회전본을 제외하도록 보완했고 실제 기본 탐색 17개 선택/알려진 프로비저닝 자료 28개 제외를 확인했다. 기존 설정·키·Beat 바이너리는 유지했다. 루트 소유의 탐색 스크립트만 별도 보호 백업/원자 교체하고 Discovery를 재개했다.

## 확정 정책과 종료 상태

사용자 승인: 과거 ES 문서는 삭제·재처리 없이 보존, 일반 조회 사용자는 보호 허용 필드만, ES/Kibana 직접 접근은 신뢰한 관리자에게 유지한다. 기존 직접 접근 권한을 확대하거나 조회 사용자에게 ES 자격 증명을 주지 않았다. 보존 기간·삭제/외부 백업 정책은 P2-02에서 별도 결정한다. 13:17 UTC 제한 조회에서 message 존재 832,067개와 민감 필드 존재 수 0을 **집계만** 했으며 자유 텍스트를 읽거나 보존할 가치가 없다고 판정하지 않았다.

임시 viewer/investigator/타 조직 계정 3개를 보호 정책에서 제거하고 실제 이전 자격 증명 401을 확인했다. 최종 정책은 `users=[]`, 보호 조회 활성, 관리자 허용 조직 `vmware-lab`이다. 최종 관리자 보호 조회/감사 34를 다시 확인했다. 보호된 이전 정책·시험 백업·큐를 보존한다. 소유 브라우저와 SSH 터널/세션을 종료하고 서비스는 유지한다.

## 시험 도구 실패 이력과 제한

초회 Docker 공개 파일 권한/import, read-only rootfs의 docker cp 실패는 권한 정상화와 stdin Python 실행으로 보완했다. ES 대조 도구의 임의 15필드 최소 가정(Linux 실제 12), 전송 중 목록 참조 경합, 비동기 dialog close 대기 누락도 보완 후 독립 재검증했다. 성공 증거로 실패 출력 파일을 덮어쓰지 않았다.

Linux 도구의 CRLF/LF 정책 해시 가정은 변경 전에 차단됐다. 이후 교체 성공 뒤 OS별 probe 파일명 가정/추가 시험의 import 누락을 발견해 기존 실제 입력에 별도 한 건을 추가했다. 교체를 다시 실행하거나 큐를 복원하지 않았다. Windows 시험 도구의 실행 정책/네이티브 stderr, 소유 discovery.lock 해시, PS5.1 File.Replace의 빈 backup 인자, 예약 HOME 변수 오류를 단계별로 보완했다. 실제 변경 후 실패 시 정책만 복구·서비스 재개가 확인됐고 최종 도구 v5 exit 0이었다. 긴 터미널 입력의 자동 검토 거절은 3KiB 입력 조각으로 해결했다. 잘못된 Python 테스트 경로로 0건/exit 5였던 시도는 정확한 모듈로 21건 재실행했다.

이번 보호 교체 도구는 지정 설치용 시험 도구이며 일반 Beat 업그레이드·자동 큐 복원 제품이 아니다. 정규식은 무명/인코딩/멀티라인 비밀을 모두 막는 DLP가 아니다. 전환 전 큐·ES 문서를 재마스킹하거나 전체 과거 로그 무손실을 증명하지 않았다. AWS 운영 배포, ES DLS/FLS, 외부 변조 방지 감사, 운영 ES 스냅샷·보존 정책·대규모 성능은 이번 완료 범위 밖이다.

## 보호 필드 증거

Git 제외 `state/privacy-source-20261004`에 시험 도구·초회/최종 결과·화면을 보관한다. 보호 정책·DB/큐 백업은 각 VM의 관리자 전용 경로에 둔다. 아래 파일은 자격 증명·전체 원문 없이 생성한 증거다.

| 파일 | SHA-256 |
| --- | --- |
| `final2/browser-source-evidence.json` | `34f59e8e5cec56ba142c374bb69747588a4c3d4bb7cd230c252659036a84788a` |
| `final2/source-es-audit-evidence.json` | `93c085cb07dc330075a4e5b2551d591d0f8318b94a3d92e2e94ac829a8b3d19c` |
| `privacy-receipt-v3-final.json` | `0c34004dd761f1907b9cd5a15c62c336ba116c45aa949e336925dc50a213625c` |
| `browser-extra-evidence.json` | `10bde7f217f43ec0031a8e92900a430c72f9928d9e279508242de6dbd9bd6cc1` |
| `browser-cleanup-evidence.json` | `0d46e2faf0f993f810ccb08db6265361ad5a5d681b7152fdb3a2aabc83d07918` |
| `server-final/p2-public-final-server.json` | `ee4e47de107e35a82e68eac04bd93f11b444038d1479f30c49b72adea2662a83` |

최종 보호 백업 manifest SHA-256은 `e0bffd353ab87d316dfd6e85cec747330dec323eba9a4232b9c45c71f0de303d`다. 다음 우선순위는 P2-02 실제 유입량 측정·사용자 승인 보존/용량/백업·격리 복원이며 이번 SQLite 복원만으로 P2-02를 완료 표시하지 않는다.
