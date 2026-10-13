# AWS DVWA 웹 접근 로그 수집 — 2026-10-13

WEB-LIVE-01~05 / ISSUE-04 진행 중. 최신 명시 요청에 따라 Windows 작업보다 웹 수집을 우선한다. 로그 발생·수집 실행·중앙 저장·정규화·포털 조회를 각각 검증하고, 개인정보는 큐/전송 전에 허용 필드로 투영한다. 실제 Apache 원문·자격·키·개인 파일·운영 DB는 공개 기록/Git에 포함하지 않는다. 기존 로그·DVWA·SSH 탐지·900초 유예·체크포인트·대시보드를 보존한다.

최초 기준: codex/dashboard-platform-20261013·1cb242b, main b67eefa. 실제 서버 읽기/안전한 경로 선택·구현·격리 회귀·보호 배포·새 실제 GET의 문서/근거/포털 결과는 확인 후 추가한다. 현재 수집 완료로 표시하지 않는다.

## 구현/격리 검증과 선택한 경로

AWS의 직접 중앙443/9200은 timeout이며 VPN 인터페이스가 없다. 중앙→AWS22 기존 경로는 연결됐다. 따라서 AWS에 ES 키를 두거나9200을 공개하지 않고 **중앙 전용·출발지 제한·forced-command SSH 읽기**로 보호된 큐만 가져온다. 개인 osaka 키는 중앙에 복사하지 않는다. 새 목적 키는 중앙에서 생성하며 shell/PTY/forwarding/user rc를 허용하지 않는다. 기존 AWS80/22·보안 그룹·DVWA를 유지한다.

원본은 지정 DVWA 컨테이너의 `/var/log/apache2/access.log` regular/combined 파일이다. Docker json-file에도 일부 접근 기록이 보이므로 중복 방지를 위해 한 경로만 선택한다. 수집기는 정확한 container cgroup/PID의 읽기 전용 파일을 사용하며 Docker 소켓을 연결하지 않는다. 원문을 메모리에서 allowlist로 투영한 뒤에만 SQLite 큐에 저장한다. 시작은 현재EOF이며 과거 원문을 임의 재수집하지 않는다.

새 `web_access_metadata_v1` 어댑터는 구조화 시각/메서드/상태/IP·정확한 메타데이터 원본 참조를 처리한다. 기존 Apache/SSH 파서는 바꾸지 않았다. 고정 web index는 기존 host intake prefix와 호환되고 정확한 index 전용 strict template/final receipt pipeline/create_doc-only key를 사용한다. 기존 bootstrap/역할/키를 재작성하지 않는다. 정상 GET의 실제 문서/정규화/포털 검증은 배포 후 별도로 인수한다.

격리31건은 Apache/Docker·5개 응답상태·시각/partial IP·canary·unknown fields·조직/근거·atomic cursor/실패 재개·rename/copytruncate·읽기 export·bounded queue를 통과했다. 전체 Python849 passed/19 skipped/257 subtests(98.84초), UI145 passed, Ruff/Bandit 중간·높음0을 확인했다. 단일 collector 큐 상한은10,000건/논리16MiB/SQLite64MiB다. 오래된 메타데이터가 상한에서 제거되면 eviction·sequence gap을 표시한다. copytruncate와 회전 파일 소실의 unread 데이터는 손실 가능성을 표시하며 모든 OS/순간의 완전 무손실을 보장하지 않는다.
