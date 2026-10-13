# 통합 사이트 에이전트 구현·시험 결과

2026-10-14 KST. 실제 대상은 사용자 확인한 AWS `56.155.117.55` → Ubuntu `192.168.235.128`이다. 처음 요청한 AWS/학교 중앙 주소는 timeout이며 이번 실수신 대상이 아니다. Windows 키 만료 검사는 제외했다.

## 구현과 Git

기능 브랜치 `codex/unified-site-agent-20261013`에서 기존 복구 변경·문서/완료 이력을 보존했다. `8ba91d8`에 통합 패키지·설정 화면·새 메타데이터/정규화·스위치·상태/웹 위젯을 구현하고, `a8e8c0a`에서 일반 파일/저널의 웹 선택 우회를 차단했다. 실환경 검색 지연을 `cf27fa6`/`009de94`에서 조사·보완했다. 마지막 코드 `009de944558361817908f12d832f55695537bce3`를 일반 push했으며 main push/병합은 하지 않았다.

웹 기본 비활성·시스템 기본 활성·Packetbeat 선택 설치, 최대 8개 사이트 API/화면 하나, 고정 시작 시각, 원문 제거, 동적 개별 중지/재개와 불변 설치 프로필을 제공한다. Ubuntu 22.04/24.04·Amazon Linux 2023·Windows의 코드 지원과 실제 인수 범위는 [설치 안내](unified_site_agent.md)를 따른다. 기존 DVWA/SSH/사건·개인 설정을 자동 교체하지 않는다.

## 검사

- 전체 로컬 Python 882 passed/15 skipped/257 subtests. 마지막 관련 124 passed/67 subtests, 사이트 16 passed, 검색 보완 34 passed/14 subtests, 웹/개인정보 59 passed/14 JS passed. 이후 source 변경별 필요한 회귀를 구분했다.
- UI 145, 실제 Windows .NET 발견/스위치 6, 웹 script 6(합계157) 통과. 별도 설치/선택 네트워크/기존 privacy는72 passed/1 skipped였다. 검사 프로세스의 RemoteSigned만 사용하고 시스템/GPO 정책을 변경하지 않았다.
- Ruff·diff·문서 링크575 통과. 실제 Filebeat9.5.2 격리 실행에서1건의 native 시각/응답 상태·민감 canary 부재를 확인했다. root 소유권이 아닌 전송 파일의 초기 차단·격리 도구 실패는 보정/재검증 근거에 남겼다. 운영 registry/키/큐를 초기화하지 않았다. 콘솔 실행이며 이를 중앙 게시로 표시하지 않는다.
- [최종 코드 CI](https://github.com/Gandalem/cloud-soc/actions/runs/38437154683)는 Windows/Ubuntu 모두 success. 이전 코드 CI38430324552/38432580837도 success다.

## 실제 포털 적용과 수신

공개 파일290개의 Git 바이트/SHA를 대조하고 외부 다운로드 없이 후보 이미지를 빌드했다. 01:51 KST a8e8c0a의 포털/정규화기를 보호 적용했고, 02:17 KST 검색 보완은 포털 하나만 적용했다. 현재 포털 이미지는 `sha256:4eb420ce5f98de406c3d3cf1053ccf1c2991cb6d15d3ea5bdd9fdd0f1bacd478`, 정규화기는 `sha256:a29ab1085716db21d76e6062ff54b3af2e1a0ccd6e0eaa102c44d1d139ff9f5b`다. 마지막 변경은 검색/검사/문서이며 정규화 구현은 동일하다. 탐지기 등 다른 서비스와 기존 명령·시작점·체크포인트·프로필·CA/키·수집기 설정/ID·대시보드 행을 유지했다.

기존 DVWA/producer/제한 SSH relay를 재시작하지 않았다. 두 차례 정상 GET200으로 새 Apache4건을 발생시키고 정확한 raw index/ID → 실제 정규화 ID/원본 참조를 대조했다. 실제 관리자 웹 검색에는 기존7+신규4=11건이 나타났고 신규4건 상세를 대조했다. 새 공격·원본 삭제/덮어쓰기·과거 재처리·새 규칙 활성화는 없다.

실제24시간 조회의 최초 runtime 전수 평가는 19 shard에서4초 제한으로 실패했다. 기존 labels의 text+keyword와 DVWA keyword를 확인하고 indexed 후보 선별 뒤 exact source 확인으로 바꿨다. 같은 실제19 shard/24시간/11건 조회는 단일 관측0.028초·부분 응답없음이었다. 제한을 늘리거나 실패를0건으로 바꾸지 않았고 지속 성능/SLO 인수는 아니다.

CA/IP 검증 TLS의 실제 포털과 loopback 검증 브라우저에서 로그인/로그아웃401, PC1440/모바일390×두테마, JS오류0/수평 넘침0, 개인 구성 보존을 확인했다. 실제 자료로 웹/항목 상태 위젯을 DOM 미리보기했고 사용자 구성을 저장하지 않았다. 이전 수집기의 개별 web 설정은 unknown이며 신규 보고 없이 추정하지 않는다.

실제 포털에서 Ubuntu 시스템+DVWA 웹·네트워크 미선택 공개 패키지 `d64d1fd32fab4f5791c304022d09cc47`를 생성했다. tar.gz SHA `08bf220d3230cb51f05ccc927001917ce83e87f00448c273f4c5449c312efd1d`, 멤버15개/SHA256SUMS·사이트/시작점·기본 웹 디렉터리 제외·network 파일 부재를 대조했다. 이 패키지의 토큰/키 발급과 설치는 하지 않았다. 실행 중인 기존 에이전트에 신규 설치기를 재실행하지 않았다.

## VM 정리·최신 보호본

사용자 추가 지시로 구버전 backup/restore24개·미사용 이미지17개·이전 ES snapshot2개와 캐시를 정리했다. 나중에 생성한 중간 snapshot/미사용 후보도 최신본을 확인한 후 정리했다. 원래 운영 데이터/마운트·키·큐·컨테이너는 보존했다. 최초 최신 snapshot은 당일 Windows index2개 primary 미할당으로 실패했으나 공간 확보 후 SUCCESS·미할당 primary0을 확인했다. 기존 replica yellow는 남는다.

최종 여유4,496,531,456 bytes(약4.19GiB), 최초2,271,354,880 bytes(약2.12GiB)다. 최신 SQLite8개(각 integrity ok)·현재 private 설정은 서버 `state/unified-site-20261014/latest-backup`, ES snapshot은 기존 repository `soc-deploy-20261012-4973e31`의 `unified-site-final-20261014` 하나다. 같은 VM 보호이며 독립 DR은 아니다. 과거 보고서의 삭제된 backup/rollback 경로는 당시 검증 이력이며 현재 복구 절차에 사용하지 않는다.

현재 활성 Compose 명령은 서버 `state/unified-site-20261014/compose.active.json`이다. 실제 명령을 읽고 필요한 서비스만 변경하며 이전 전체 Compose를 실행하지 않는다. 되돌리기도 현재 DB/큐를 과거본으로 덮어쓰지 않는다. 검증 proxy/브라우저/SSH 시험 세션은 종료하며 파일/화면/실패 근거는 Git 제외 state/unified-site-20261014 및 state/protected-deployment-20261012/unified-*.json에 보존한다.

## 남은 범위

새 통합 패키지의 Ubuntu/Windows/Amazon Linux 전체 신규 설치·개별 스위치의 실제 중앙 인수는 미완료다. AWS 시스템/Packetbeat 실수신은 아직 없으며, 기존 웹 전용 SSH pull 성공으로 이를 대신하지 않는다. 사설 중앙에 연결할 수 없는 EC2의 범용 설치에는 승인된 사설 VPN/라우팅 또는 별도로 검토한 제한 SSH 전송 경로가 필요하다. 기존 forced-command 키를 포괄 forwarding/원문 전송 권한으로 바꾸지 않았다. 공개 포트·IAM·새 과금 자원을 만들지 않았다.

IIS/사용자 정의 웹 형식·Docker 내부 파일 자동 탐색·현재 컨테이너의 마운트 변경·ARM64 실장·장기 회전/손실/성능·전체 웹 공격 탐지·독립 DR은 미인수다. 운영 설치 완료나 상위11/24 완료 수를 늘리지 않는다.
