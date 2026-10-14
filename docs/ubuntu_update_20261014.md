# 기존 중앙 Ubuntu 최신화·설치 폼 수정 — 2026-10-14

사용자가 이번 대상을 **192.168.32.60**으로 확인했다. 최신 기록의 별도 VMware192.168.235.128/AWS56.155.117.55 인수와 구분한다. PC와 지정 중앙 저장소를 원격 main `eec0717f9a0588f35af733cb0842dd9162e6ac9e`로 fast-forward하고 포털·정규화기·탐지기를 같은 최신 공개 소스로 갱신했다. 이후 사용자가 지적한 설치 폼 빈 공간/가로 넘침을 CSS/HTML에서 수정해 포털에 추가 적용했다. 소스 수정·commit/push는 사용자의 후속 명시 요청이다.

## 적용 결과

| 항목 | 실제 결과 |
|---|---|
| PC 최신화 | main eec0717로 fast-forward. 개인 Word2개·JSON의 기존 SHA 동일. 작업은 codex/vm-form-layout-20261014에서 기록한다. |
| 중앙 저장소 | 기존92d13c0→main eec0717 fast-forward. 운영 HTTPS 수집 endpoint 한 줄과 기존 untracked3개를 보존했다. 폼 두 파일은 검증 후 작업 소스로 반영한다. |
| 애플리케이션 | portal/normalizer/detector에 공개288개 파일의 개별 SHA 검증·import·pip check를 통과한 이미지를 적용. 기존 명령/시작점/900초/키/상태 mount 유지. |
| 초기 최신 이미지 | `sha256:daf88016f9f737857da3690e870147da6361f9d99d46ee659d65225f06678824` |
| 최종 포털 이미지 | 폼 CSS/HTML2개만 추가한 `sha256:498ca9e7cc6b976ba734e7a1b6fac52055457c296dc38335d706601c052e8a1a` |
| 폼 patch SHA | `c4438a03a79755e8dd90b18afaacf1f493b433b038a862083b1c5d3bfec68a8c`(파일별 해시 사전의 canonical SHA) |
| 보호 | 최초8 SQLite 개별 온라인 backup/무결성/격리 restore, 당시3개 이미지·활성 구성·키/CA·실제 mounted 파일 보존. 처리기 중지 후3 DB의 WAL 포함 SQLite backup. 폼 후속은 당시 portal 이미지·override와 portal5 DB backup/격리 restore. |
| 기존 자료 | 저장된 dashboard2개/revision13·종결 사건 전체 응답·기존 경보1개 hash 동일. 신규 카탈로그는 사용자 저장 구성과 구분했다. |
| 기타 서비스 | ES/Kibana/gateway 컨테이너 ID/시작 시각 동일. 기존 Ubuntu/Windows 에이전트·키·CA·새 프로필/수집기 설치를 변경하지 않았다. 폼 후속은 portal만 재시작. |
| 실제 API | LAN CA/IP 검증·무인증401·인증된 auth/portal/status/components/operations/dashboards/logs200. 기존 private endpoint192.168.32.60:9200 유지. |
| 실제 수신 | Ubuntu Filebeat/Packetbeat의 현재 실제 recent receipt 확인. 기존 웹5건은 최근30일 검색과5개 정확 정규화 참조를 대조했으며 오늘 새 AWS 웹 수신 인수가 아니다. |
| 코드/화면 검사 | 관련 Python158 passed/21subtests, UI145 passed, Ruff/diff 통과. 실제 폼4폭×2테마×3OS=24조합·웹 toggle/선택 시작 시각·JS0/HTTP0·가로 넘침0. |
| CI/Git | 배포 기준 [main CI](https://github.com/Gandalem/cloud-soc/actions/runs/38439489458) Windows/Ubuntu success. 후속 폼 수정/기록은 명시 파일만 기능 브랜치에 commit/push하고 원격 SHA/CI 결과를 완료 메시지에서 확인한다. main 직접 push/PR 생성·병합은 하지 않는다. |

## 사용자 화면 결함과 수정

사이트 설정 fieldset이 기존 OS 라디오 행의 `fieldset.form-row {display:flex}`를 사용했다. 여러 label/설명 문장이 한 줄에 놓이며 길게 늘어났다. 실제929px 화면에서 dialog client width623px/scroll width858px, site height2358.03px/전체 scroll height3139px를 재현했다. 내용이 없어서 생긴 공간이 아니었다.

`prototype/agents.html`에 수집 선택 전용 class를 추가하고 `prototype/agents.css`에서 선택 항목과 사이트 입력을 block/grid 세로 배치로 구분했다. hidden 정책은 유지하고 웹 선택 해제 시 실제 하위 입력의 disabled도 확인했다. 사이트 ID/토큰/키/수집 범위·서버 파서는 변경하지 않았다.

실제 서버 화면 자산·API를 사용하는 임시 localhost 읽기 전용 viewer로1440/929/768/390px 두 테마와Windows/Ubuntu/Amazon Linux를 검증했다. desktop dialog client/scroll width623/623px, site height431.36px(사용자 정의 시작 시각 포함), 모바일324/324px·site height638.52px다. 설명과 입력이 세로로 배치되고 자식 넘침은0이다. 긴 폼의 정상 세로 스크롤은 유지한다. 생성/설치/토큰·키 발급·사용자 대시보드 저장을 실행하지 않았다.

CA 신뢰 저장소 추가나 TLS 우회는 하지 않았다. viewer는 관리자 인증을 CA/IP 검증한 LAN에만 전송하며 browser에는 비밀번호/게시 키가 없다. 일반 Chrome 직접 LAN의 인증서 경고 제거 인수가 아니다. 검증 스크린샷8개는 Git 제외 output/playwright/update-vm-20261014에 있다.

## 보호 검사 중 중단·보정

후보 빌드 도구에서 image ID의 sha256 접두사를 Dockerfile FROM에 잘못 지정해 외부 이미지 이름으로 해석됐다. 실행 서비스 교체 전 멈췄고 실제 로컬 tag의 image ID 일치를 확인한 후 외부 다운로드 없이 빌드했다. 공개 파일은 디렉터리 단위 layer로 구성하고 오래된 공개 코드 디렉터리는 후보 이미지 안에서만 교체했다.

운영 Compose의 실제 차이는 메모리가 아니라 `SOC_ELASTIC_ENDPOINT`의 private endpoint 지정이었다. 최신 Compose의 추가 환경 변수와 같은 구간에서 3-way 충돌해 기존 한 줄 변경임을 대조한 후 private endpoint를 유지했다. 기존 환경 값은 같으며 새 선택 변수는 기존 private 주소/비활성 기본값을 검증했다.

첫 적용에서는 `/api/dashboards` 전체 응답 동일 검사가 새 web/component 위젯 카탈로그도 차이로 잡아 원래 이미지3개로 복귀했다. 사용자 저장 설정의 변경이 아니었다. catalog/templates와 사용자 저장 구성을 구분한 보존 검사 후 재적용했고 실제 저장값·revision·사건/기존 경보는 동일하다. 각 중지 시점 보호본을 별도 경로로 남겼으며 DB/체크포인트를 과거값으로 복원하지 않았다.

브라우저 자동 검사에서 fieldset 자체에 isDisabled를 쓰던 도구 판정도 실제 하위 입력 기준으로 보정했다. 실제 웹 선택/해제는 정상이다. PowerShell의 CLI 코드 인자 전달 오류는 파일 기반 검증/안전한 인자로 수정했다. 이 도구 오류를 제품 성공/실수신으로 바꾸지 않는다.

## 처리 지연과 남은 범위

2026-10-14 **09:41 KST** 읽기에서 normalizer/detector의 state는success/error없음이고 두 checkpoint가 원래 상태에서 전진했다. 정규화 checkpoint는10/13 20:31:16 KST, 탐지는10/14 07:11:53 KST였다. 밀린 입력을 처리 중이므로 최신 시점 분석 완료·지연 해소를 선언하지 않는다. 포털의 실제 ‘새 로그 분석 지연’ 안내를 유지한다. 원본/큐 삭제·체크포인트 되감기·강제 재처리·새 프로필/임계값 변경을 하지 않았다.

이번 중앙에서 ES snapshot은 새로 만들지 않았다. SQLite/이미지/구성의 같은 VM 보호이며 독립DR·ES 전체 복구 인수가 아니다. AWS 새 주소/중계 이행·오늘 새 웹 수신·통합 에이전트 실제 신규 설치·Windows 키/실패·웹 공격/CloudTrail은 별도 범위다.

보호 경로는 중앙 `/home/kopo/cloud-soc/state/update-vm-20261014`, 폼 후속은 그 아래 `ui-fix`다. active base는deploy/server/compose.yaml, override는state/early-release-000659f/early.override.json, env는state/server/compose.env다. 복귀 시 현재 DB/큐를 과거본으로 덮어쓰지 않고 검토한 override/이미지로 변경 서비스만 되돌린다. 원래 사용자 untracked/운영 endpoint·개인 파일을 보존한다. 신규 기록/소스만 Git에 포함하고 state/이미지/DB/키/원문/개인Word·JSON은 제외한다.
