# AWS DVWA 웹 접근 로그 실제 수집 결과 — 2026-10-13

지정 AWS의 정상 GET 4회(리다이렉트 포함 Apache 기록 5건)를 실제 중앙 ES 저장 → 정규화 → 통합 로그 목록/상세까지 대조했다. 합성 이벤트를 운영 인덱스에 넣지 않았다. 사용자 추가 지적에 따라 수신 현황의 OS 이름 누락도 수정·포털 적용했고 실제 AWS 수집기 행은 **Linux**로 표시된다. 웹 수집 성공은 공격 탐지 성공을 뜻하지 않는다.

## 요청 항목별 실제 결과

| 항목 | 실제 결과 |
|---|---|
| AWS DVWA 로그 확인 | EC2 i-091d36449db353d09/ap-northeast-3. DVWA 실행·정상 GET 최종200·Apache 프로세스 실행 확인. 최초 빈 프로세스 배열은 Docker top 호출 형식 오류였으며 PID/comm 조회로 apache2 실행을 재확인했다. |
| 실제 로그 소스 | 지정 컨테이너 `/var/log/apache2/access.log`의 regular/combined 파일. Docker json-file에도 같은 접근이 일부 나타나므로 한 파일만 읽는다. |
| 수집 방식 | 원문을 메모리에서 허용 메타데이터로 투영한 후 SQLite 큐에 넣는다. 중앙이 목적 전용·출발지 제한·forced-command SSH로 큐를 읽고 create-only 키로 HTTPS ES에 게시한다. |
| AWS → 중앙 연결 | AWS→중앙443/9200 직접 연결은 timeout. 기존 중앙→AWS22 경로의 SSH pull로 실제 전송했다. 새 공개 수집 포트·VPN·보안 그룹·IAM을 만들지 않았다. |
| AWS 수집 서비스 설치 여부 | 새 cloud-soc-web-producer.service 설치/실행/재시작 확인. 원래 DVWA 컨테이너·이미지·시작 시각 유지. |
| 중앙 Elasticsearch 원본 수신 | 새 soc-host-raw-web-dvwa-v1에 실제 보호 메타데이터5건. Apache 원문을 ES에 저장했다는 의미가 아니다. |
| 정규화 성공 | 실제5건 모두 soc-normalized-v1의 고유 문서·web 어댑터·정확 원본 참조·해시 일치. 아래1건의 전체 근거 보존. |
| 포털에서 웹 로그 조회 | 실제 LAN API/상세200, web-collector/지정 호스트 조회5행, GET·HTTP200/302·관측 IP·시각 확인. 실제 서버 화면 자산/데이터를 읽기 전용 viewer로 표시해3개 폭×2테마·상세 검증. |
| 개인정보 보호 검증 | 격리 query/cookie/Authorization/token/POST body canary가 큐/export에 남지 않음. 미허용 필드·위조 identity/status·잘못된 형식 거부. 실제5건도 엄격한 스키마 검증 통과. 실서버에 민감 canary/공격 요청을 보내지 않았다. |
| 로그 중복·재시작 시험 | 실제 producer 재시작 후 stream/기존4건 동일. relay 정지 중 정상 GET1건 큐 보관→cursor4에서 재개→raw5/cursor5. 기존 ID 재전송은409/기존 문서 유지이며 count4 그대로. 격리 회전/중단/상한 시험 통과. |
| 기존 SSH 탐지 정상 여부 | detector ID/시작 시각·AUTH-001/early·900초 유예·상태 파일 유지. 실제 기존 경보1건 canonical hash 동일, detector success 확인. 새 SSH 실패/Windows 시험은 하지 않았다. |
| 운영체제 분류 추가 수정 | 실제 raw host.os.type=linux인데 수신 현황이 name만 읽던 결함 수정. 이름 우선, 없으면 명시된 유형/센서 태그로 Linux/Windows 표시. AWS/IP로 배포판을 추정하지 않는다. cloud 필터는 ‘해당 없음 (클라우드 API)’로 표시. |
| Python / UI 테스트 | 전체 Python **852 passed/19 skipped/257 subtests**, 95.89초. 관련 agent/web50 passed/14 subtests. UI **145 passed**. Ruff 통과, Bandit 중간/높음 발견0, git diff 검사 통과. |
| 실제 배포 상태 | AWS 새 producer·중앙 새 relay 실행. 중앙 normalizer/portal만 웹 코드 적용, OS 후속은 portal만 적용. ES/Kibana/detector/gateway 및 기존 Windows/Ubuntu 수집기는 재시작하지 않았다. |
| Git 커밋·푸시 | 기능 브랜치에8626b57 웹 수집, 8a8b5bd 전용 receipt, fe61a65 OS 표시를 일반 push. 소스 Windows/Ubuntu CI 성공. 결과 문서/관리표도 같은 브랜치에 별도 기록한다. main b67eefa 유지. |
| 남은 장애·제약 | 브라우저 CA 경고 유지, 직접 AWS→중앙 경로 없음. source IP 변경/새 키 만료 관리 필요. 큐 상한/회전 소실/copytruncate 손실 가능, 장기 ES 보존/독립 DR 미구성. 웹 공격/CloudTrail/Windows 작업은 후속. |

## 실제 최소 근거와 시간

첫 정상 GET 시작은 **2026-10-13 17:28:23.145 KST**(08:28:23.145 UTC), Apache 이벤트08:28:23 UTC, 중앙 수신08:28:32.071554694 UTC다. source timestamp→receipt 약9.07초는 한 건의 관측값이며 지속 SLO가 아니다. 실제 관측 peer IP는112.76.111.10이다. HostnameLookups Off/remoteip_module·RemoteIPHeader 미사용을 확인했으므로 전송 프록시 헤더로 추정한 주소가 아니다.

| 근거 필드 | 실제 값 |
|---|---|
| raw index | `soc-host-raw-web-dvwa-v1` |
| raw document ID | `b0a9045a97e2156b9bde4b1a1053068ea36464dcf05b72deb7fd8857fbdf6a7b` |
| organization.id | `aws-dvwa-lab` |
| host.id | `i-091d36449db353d09` |
| container.id | `717b447390eae79e8c8fabb23f2cd45586eef90712f3e3579f5a01818e978f14` |
| 실제 이벤트 시각 | `2026-10-13T08:28:23Z` |
| 실제 서버 수신 시각 | `2026-10-13T08:28:32.071554694Z` |
| HTTP | GET/200/success |
| normalized index | `soc-normalized-v1` |
| normalized document ID | `8bff9be63284134c48c649a986404db38432ce6b2ba44ec9bc587363e8e8f30b` |
| adapter/version | `web_access_metadata_v1`/`web-access-metadata-v1` |
| provenance.raw | 위 raw index/ID와 완전 일치(보호 메타데이터 참조) |
| normalized SHA-256 | `fec79811435524b558230b86dd6c0405f9fd6b668af53fa12d9082bb1557dd84` |

해시는 실제 정규화 `_source` 전체를 `json.dumps(sort_keys=True, ensure_ascii=True, separators=(',', ':'))`로 canonical 직렬화한 SHA-256이다. Apache 원문 해시가 아니다. 재시작/중복 시험 후 기존4건의 수신 시각·정규화 해시가 동일하다. 원래 SSH 경보 SHA-256은 `2ad12e5ededdacc807adecb9bc700c892aff08c9cee4eaa7c0e2dd527d1b23d8`로 보존됐다.

추가 정상 GET은08:28:24.481 UTC와08:28:25.844 UTC에 시작했다. 첫 요청이 정상302 후 로그인 화면으로 이동해 실제 Apache 기록은200/302/200/200의4건이었다. relay 정지 중 마지막 정상 GET은 **08:52:55.802 UTC**, 추가 이벤트08:52:55 UTC, 재개 후 수신08:53:53.521026021 UTC다. 중단을 포함한58.52초를 평상시 수집 지연으로 표시하지 않는다.

5번째 raw ID는 `2d2dd6fab377ce64a61122444fff727ceed57eee11431fd8c005c0c95c9687cf`, normalized ID는 `9d68a7f89983a0467253974690ecc576a6760651acf58933e75539288a6b22c7`, normalized hash는 `66b32ba72f541341fc058b460a7c6a19b50bc9d77b8faa667eed63b804c57caf`다. 과거 Apache 로그를 재수집하거나 시험 합성 이벤트를 운영 인덱스에 삽입하지 않았다.

## 전송·개인정보·회전 계약

producer는 정확한 컨테이너 cgroup/PID의 `/proc/PID/root/var/log/apache2/access.log`를 read-only로 열며 Docker 소켓을 사용하지 않는다. 기존 파일의 현재 EOF에서 시작한다. ID는 조직·호스트·컨테이너·파일 identity hash·generation·byte offset에서 결정하므로 같은 줄 재전송은 같은 ID이고, 다른 위치의 동일 요청 두 건은 별도 이벤트다.

저장 가능한 값은 명시된 조직/호스트/컨테이너/서비스 identity, 실제 Apache 시각, 메서드/상태/관측 IP, coarse path class, 수집 시각·버전·cursor뿐이다. URL/query/UA/referer/cookie/Authorization/usernames/본문을 저장·전송하지 않는다. 오류에도 원문을 로그로 출력하지 않는다. 잘못된 형식은 malformed counter로 제외하고 hostname·불명확 IP는 부분 메타데이터로 남겨 주소를 추정하지 않는다.

중앙 목적 키는 중앙에서 새로 생성했다. AWS authorized_keys에는 실제 중앙 egress source IP와 `restrict,command=...export-web.sh`를 붙이고 기존 키의 원래 prefix를 보존했다. export는 정해진 schema/after/limit JSON만 받아 SQLite read-only로 최대100건을 내보낸다. 다른 SSH 명령 id는 실제 거부했다. 개인 osaka 키를 중앙에 복사하지 않았으며 API 게시 키는 AWS/브라우저에 없다. forced-command/restrict는 [OpenSSH authorized_keys 계약](https://man.openbsd.org/sshd#AUTHORIZED_KEYS_FILE_FORMAT)을 사용한다.

ES 키는 정확한 새 index 하나의 create_doc만 갖고 cluster/read/update/delete 권한이 없다. HTTP proxy/redirect를 사용하지 않고 CA와IP를 검증한다. 새 strict template은 message/original/URL 등을 허용하지 않는다. 새 cloud-soc-web-received-at-v1 final pipeline이 수신 시각과 조직을 중앙에서 강제한다. 기존 global receipt pipeline·모든 기존 역할을 변경하지 않았다. 새 게시 키 만료는 **2026-11-12 17:24:11.930 KST**이며 자동 갱신은 미구현이다.

producer 큐는10,000건/논리16MiB/SQLite64MiB로 제한한다. 전달 cursor는 create201 또는 같은 ID409 확인 후에만 전진한다. bounded replay 보관이며 무한 보관소가 아니다. 오래된 큐 제거는 eviction/sequence gap, 회전 파일 소실·copytruncate는 source gap으로 나타난다. 실제5건 후 observed5/queued5/queued bytes5747/malformed0/evicted0/source_gaps0을 읽었다. 격리 rename 회전에서는 이전 inode의 unread 부분을 먼저 처리하고 재시작 후에도 이어갔다. 실제 Apache를 강제로 회전·삭제하지 않았다.

copytruncate의 unread 데이터와 이미 제거/압축된 회전 파일은 손실 가능성이 있다. 두 poll 사이 동일 prefix/size로 바뀐 모든 변화를 검출한다는 보장은 없다. 컨테이너 교체 시 자동으로 다른 컨테이너를 수집하지 않는다. 신규 서비스는 Memory128MiB/Tasks8 제한이며 기존 방화벽/포트를 바꾸지 않았다.

## 보호 적용·보존·화면 검증

최초 중앙 변경 전 `/home/kopo/cloud-soc/state/web-deployment-20261013`에 실행 이미지2개·실제 override·키/CA·8개 SQLite의 개별 온라인 백업/무결성/격리 복원을 확인했다. 원래 checkout은92d13c0이다. 전체 checkout 갱신 대신 공개 파일을 현재 이미지 위에 적용했고 기존 command/start/floor/900초/상태 mount를 유지했다. 기존 경보·사건·개인 dashboard2개/revision13 전체 응답이 동일하다.

웹 적용 당시 portal10/normalizer8 파일의 실제 이미지 내부 해시를 대조했다. OS 후속은 별도 state/web-os-fix-20261013에 당시 포털 이미지·override와8개 DB를 다시 보호한 뒤 공개3파일만 갱신했다.

| 구성 | 실제 source/image |
|---|---|
| AWS producer/중앙 relay | 웹 코드 `8626b57e68a67ea1ff6c76c86dca05d47c20bf8c` |
| 중앙 web template/receipt assets | 후속 `8a8b5bd191f90ca00b523a8ae16dd342daa9b310` |
| normalizer | `sha256:a41dafd71a21b17d1093507382012eca7d30f4c6471cda8e3d186ed03aeaebc9`/웹 코드8626b57 |
| 최종 portal | `sha256:97a31880e9110717bd51f869f32ab3d94a9f8dbb5fcc4558f04224db4895bf74`/웹 이미지 위에 OS 수정 `fe61a651ecf3ec3f921cf70f156ddf51bf84acef` |

DVWA image는 `sha256:e901498e651ae2806f3fda7406d97b7e9294eaada44d1d4970e9b28189b6d967`, StartedAt은2026-10-13T00:52:22.511533143Z이며 설치/producer 재시작 후에도 같다. Apache config checksum도 보호했다. 실제 producer/relay 재시작 때 별도 SQLite 온라인 백업/무결성 후 기존 state를 그대로 사용했다.

OS 이름이 없는 web 기록은 명시된 host.os.type=linux를 써서 Linux로 표시한다. Ubuntu/Windows 이름이 있는 행은 유지하고 이름/유형/센서 태그가 없으면 미확인으로 남긴다. AWS 배포판 이름·host IP를 로그에 관측된 것처럼 덧붙이지 않는다. 수신 상태는 실제 event.ingested 기준이므로 웹 요청이 없으면5분 후 지연·15분 후 장기 미수신이 되는 계약을 유지한다. 서비스 실행만으로 최근 수신으로 고정하지 않는다.

실제 LAN API는 중앙 IP로 직접 TLS/CA/IP와 관리자 인증을 검증했다. 최종 화면은 PC 신뢰 저장소 변경 없이 **임시 localhost 읽기 전용 viewer → CA/IP 검증된 실제 LAN 포털** 경로를 사용했다. 실제 서버 HTML/JS·ES 데이터이며 fixture/API mocking은 없다. viewer는 web/지정 호스트로 조회를 제한하고 수신 현황은 해당 AWS 행만 보여 준다. POST/관리 변경·원문 조회는 허용하지 않고 비밀번호·게시 키를 브라우저에 넣지 않았다. 일반 Chrome 직접 IP의 인증서 경고 제거·다른 실계정 인수를 뜻하지 않는다.

실제 목록5행/GET200·302/IP·상세의 정확 ID와 web 어댑터/개인정보 제한, 수신 현황 Linux/당시 최근 수신을1440/768/390px 두 테마에서 확인했다. document 가로 넘침·JS 예외·최종 HTTP 오류0이며 넓은 로그 표 내부 스크롤은 의도된 동작이다. 화면 증거13개는 Git 제외 output/playwright/web-live에 있다. 임시 browser/viewer를 종료했다. 초기 viewer의 source-view.js/access GET404와 CLI 코드 전달 오류는 도구를 수정하고 다시 인수했다.

기존 전체 위험 평가 누락 경고/미지원 로그는 그대로 표시한다. 새 정상 웹5건 성공을 전체 로그 위험 평가·모든 탐지 규칙의 건강 상태로 확장하지 않았다.

## 검사·Git·제한과 복구

웹 격리32건은 Apache/Docker envelope·상태·시각·malformed/partial IP·canary·중첩 허용 목록·ID/조직·정규화 참조·atomic cursor·실패 재개·rename/copytruncate·읽기 export·bounded queue·strict receipt를 검증했다. OS 후속은 raw-type만 있는 Linux/Windows, 기존 Ubuntu 이름, 센서 태그 및 미관측 AWS를 구분한다. 전체 Python852 passed/19 skipped/257 subtests, UI145 passed, Ruff/Bandit 중간·높음0/diff 통과. skipped는 Linux root5/Docker opt-in3/POSIX3/Caddy4/AWS SDK1/OCI SDK3이며 전체 플랫폼 인수로 대체하지 않는다.

시행 중 NTFS inode 크기·mock fixture 생성 오류를 수정·재검증했다. AWS archive basename 오류는 새 빈 디렉터리 단계에서 멈췄고 기존 데이터 변경 없이 재개했다. 중앙 secret UID 접근 오류는 root-owned 보호 사본으로 해결했다. 기존 receipt 계약 차이는 새 web-only pipeline으로 분리했다. 실제 참조 검증 도구의 변수 오류도 수정해5개 실제 문서를 다시 읽었다.

개인 Word2개/JSON의 최초 SHA와 동일하고 state/output/개인키/비밀번호/실제 요청 원문/운영 DB를 stage하지 않는다. 기준 main은b67eefa5f5b1af72bb76dc59e2181727ccc6c0ef, 기능 브랜치는codex/dashboard-platform-20261013이다. 소스 Windows/Ubuntu CI 성공은 [웹 코드8626b57](https://github.com/Gandalem/cloud-soc/actions/runs/38366406339), [OS 수정fe61a65](https://github.com/Gandalem/cloud-soc/actions/runs/38371878493)에서 확인했다. 결과 문서 commit/push와 최종 원격 SHA는 완료 메시지에서 제공한다. main push/force/PR 생성·병합을 하지 않았다.

복구가 필요하면 새 producer/relay만 중지해 추가 웹 전송을 멈춘다. OS 변경은 state/web-os-fix-20261013/override.before.json과 당시 포털 image로 portal만 복원할 수 있다. 최초 웹 변경은 state/web-deployment-20261013의 당시 override/images를 검토해 normalizer/portal만 복원한다. 새 raw/normalized 문서와 원래 상태·키를 삭제하지 않는다. 목적 키 제한을 되돌릴 때는 보호된 AWS authorized_keys 사본을 검토해야 하며 이번에 키 폐기/전체 복원을 실행하지 않았다. SQLite는 개별 격리 restore 인수이며 ES snapshot/전체 독립 DR은 미구성이다.

남은 작업은 장기 ES 보존·큐/목적 키 만료/source IP 변동 운영, 독립 백업/DR·지속 지연 측정·실제 역할별 화면 인수다. Windows 키 만료/교체·Windows 실패·CloudTrail·SQL Injection·웹 공격/새 규칙·ngrok 관리자 인증을 수행하지 않았다. WEB-404-001은 계속 비활성이다.
