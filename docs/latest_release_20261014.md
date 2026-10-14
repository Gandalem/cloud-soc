# 최신 main 지정 VM 배포 — 2026-10-14

사용자 요청으로 PC의 기존 기능 브랜치를 원격 main `7bb5fa0328c9611681d64d88e8faca3d1fc364d5`로 fast-forward하고, 사용자가 다시 지정한 중앙 Ubuntu `192.168.235.128`에 배포했다. 기존 중앙192.168.32.60은 SSH timeout이었다. 사용자가 후속으로 **Git 푸시는 필요 없다고 지시**했으므로 이번 작업은 commit/push 없이 로컬 기록으로 남긴다.

## 배포와 보존

- main의 [Actions38528572643](https://github.com/Gandalem/cloud-soc/actions/runs/38528572643)에서 Windows·Ubuntu 두 job success를 확인했다.
- 원격 VM의 `/home/kopo/cloud-soc`는 Git 체크아웃이 아니다. PC Git의 확정 커밋 바이트에서 Dockerfile의 공개 실행 파일259개만 추출해 개별 SHA256을 검증했다. 운영 상태·DB·개인 문서·비밀 파일은 전송 묶음에 포함하지 않았다.
- 기존 로컬 이미지를 재사용하고 외부 네트워크 없이 후보를 빌드했다. 파일 해시·import·pip check·14룰 오프라인 검증을 통과했다. 실제 portal/normalizer/detector 각각의 실행 이미지에서도259개 파일 해시를 대조했다.
- **19:03:46 KST**에 세 서비스를 `sha256:0099d8b70d56b57267e01cbed745396fa443d1ae8a2e2a052a68f06066cbad69`로 적용했다. 기존 명령·시작점·900초 유예·선택 룰·mount·체크포인트를 유지했다. 새 priority/additional/retrospective worker나 새로운 룰을 이 VM에 자동 활성화하지 않았다.
- SQLite8개 online backup·무결성·memory restore를 확인했다. 최초 적용과 재적용 각각 세 서비스를 멈춘 시점의8개 DB도 별도 보존했다. 설정/키/CA/수집기 식별자 등26개 파일과 기존 경보2개·패키지/사건/저장 대시보드 행을 대조했다. DB를 과거본으로 복원하거나 원본 문서를 삭제하지 않았다.
- 활성 명령은 서버 `state/latest-update-20261014/compose.active.json`이다. 기존 `state/unified-site-20261014/compose.active.json`도 같은 최신 명령을 가리킨다. 보호본은 `state/latest-update-20261014/backup`, `stopped-backup`, `stopped-backup-retry`다. 기존 이미지와 ES snapshot은 삭제하지 않았다. 독립DR/새 ES snapshot 인수가 아니다.

## 검사와 실제 관측

- 로컬 처리 재개·상태 보존·회고·룰셋 관련223 passed/2 subtests, UI21 passed, Ruff/diff 통과. 최초 로컬 pytest의 Windows 임시 폴더 생성 오류는 프로젝트 전용 D 드라이브 임시 경로로 분리해 재검증했다. 기존 venv의 Ruff 누락도 기존 별도 lint 의존성 경로를 지정해 확인했다.
- 실제 CA/IP 검증 HTTPS의 세션 로그인·로그아웃, auth/health/수집 상태·항목/operations/status·summary/대시보드/사건8개 API200을 확인했다. 처음 Basic 헤더로 세션 전용 경로를 읽던 검증 도구는 정상 세션 로그인 절차로 보정했다. 비밀번호/신뢰 저장소/인증서를 변경하지 않았다.
- 19:05 KST 표본에서 배포 이후 Linux 시스템128건·네트워크310건의 실제 중앙 수신을 확인했다. 같은 표본의 Windows 시스템/네트워크·웹 신규 수신은0건이었다. Windows 키 점검/교체나 AWS 테스트 요청을 실행하지 않았으며 이를 정상 수신으로 바꾸지 않는다.
- 기존 경보2개의 원문 해시가 동일하다. 정규화/탐지 상태는success/error없음이며 같은 체크포인트에서 전진했다. **약15시간의 과거 분석 적체가 남아 있다.** 정규화 checkpoint03:58 KST/탐지04:04 KST였고 검사 시각은19:05 KST다. 배포 후 생성 시각 조건의 신규 정규화 표본은0건이므로 최신 원본→정규화의 실제 인수를 주장하지 않는다.

## 중단·남은 문제

최초 보존 검사가 변경하지 않은 Kibana의 자동 재시작 시각 차이를 검출해 세 앱의 이전 이미지로 복귀했다. DB는 되감지 않았다. Kibana는 같은 container ID/image를 유지했고 Node heap out of memory/FATAL 로그와 restart count1→2를 확인했다(당시OOMKilled=false). 현재 메모리 여유는약4.1GiB였으며 Kibana 설정/자원 한도는 바꾸지 않았다. 재적용 중 추가 자동 재시작은0이었다. 이를 기존 서비스 시작 시각 전부 불변으로 기록하지 않는다.

실제 홈/개인 화면 검사에서 `/api/alerts/notices`503을 발견했다. 조회 계정 `cloud_soc_agent_monitor`에 최신 소스가 정의한 `soc-alert-notices-v1`의read/view_index_metadata가 빠져 있고, 관리자 읽기에서 해당 인덱스는존재하지 않았다. 기존 역할/사용자를 보존하며 정확한 인덱스 읽기 권한만 추가하고 미설정200으로 확인하는 변경안을 준비했다. **자동 승인 검토가 별도 보안 권한 변경이라는 사유로 실행을 차단해 아직 권한을 변경하지 않았다.** 사용자에게 해당 권한만의 명시적 허용 여부를 요청했다. 제품의 오류를0건/정상으로 숨기지 않는다.

Git 제외 근거는 PC `state/latest-update-20261014`와 `state/protected-deployment-20261012/latest-update-*.json`에 있다. 실제 새 통합 설치·새 룰 활성화·AWS/Windows 인수·적체 해소·Kibana 메모리 안정화·독립DR은 이번 소스 배포 완료와 구분한다.

## 사용자 승인 후 최종 결과

사용자가 정확한 읽기 권한 추가를 명시 허용했다. 초기 실행은 컨테이너 root가 private `/data`를 통과하지 못해 변경 전에 멈췄고, 기존 앱UID로 실행해 보호 권한을 유지했다. 기존 역할은 서버 `state/latest-update-20261014/backup/notice-reader-before.json`에 보존했다. 기존 권한/사용자를 유지하고 `soc-alert-notices-v1`의 read/view_index_metadata만 추가했으며, 인덱스·비밀번호·API키·쓰기 권한을 만들거나 변경하지 않았다. 초기 통지는 정상 `not_configured` 응답이며 실제 화면의503을 해소했다.

최종 실제 홈/개인×1440/390px×밝게/어둡게8조합에서JS오류0·HTTP오류0·가로넘침0·로그아웃401을 확인했다. 이전503의화면/보고서를 별도보존했다. 세 앱은모두최신이미지/Running/restart0이다. Kibana는같은기존컨테이너에서Node heap 문제로누적재시작8회여서안정화미완료다. 분석 적체·Windows/웹 신규 수신 인수와 새worker/룰활성화는 앞선 제한을 유지한다. 이번 소스 배포·포털 조회 작업만 완료하며 상위 미인수 작업을 완료로 바꾸지 않는다. Git commit/push는 수행하지 않았다.
