# gyumin / JEONGRIM-SEO 통합 검토

2026-11-01 원격 fetch 기준. 원격 tip은 gyumin `5f57818e40b0593490d603632f735a367229bd15`, JEONGRIM-SEO `c14e426eca05c7f79247aff72eefe1340dab2fd0`이며 공통 조상은 `c87e9cae471547108917997130207366a767ee78`이다. 공통 조상 이후 독자 커밋은 gyumin3개/JEONGRIM-SEO1개다. 작업 중인 원본 체크아웃은 보존했다.

## 비교

| 영역 | gyumin | JEONGRIM-SEO |
|---|---|---|
| 주 변경 | Windows/Ubuntu 로그 종류·OS·이벤트 ID 표시, 원본 조회 수정 | AWS/Naver 등 멀티클라우드 감사 수집·저장·별도 포털·배포 도구 |
| 공통 조상 대비 변경량 | 11파일, +142/-8 | 45파일, +2081/-19 |
| 조회 | 긴 source allowlist의 GET 대신 단일 문서 mget POST 본문, 응답 wrapper 처리, 정확한 index/id 검증 | 기존 로그 조회 코드 재사용 |
| 수집/배포 | 기존 Filebeat·수집 정책·키·규칙 보존 | collector image/상태 DB/키 범위/reader grant/중앙 feature migration 추가 |

소스 변경 경로는 서로 거의 겹치지 않는다. 실제 Git 병합 충돌은 `docs/work_tracker.md`의 상단 작업 기록1개였다. 양측 기록을 모두 남겨 해결했다. 충돌 없는 병합이 운영 기능의 완전한 연결을 뜻하지는 않는다.

## 사용자 최신 요청 반영

별도 worktree `/home/lyn/문서/ChatGPT/융프/cloud-soc-merge-review`, 브랜치 `codex/merge-gyumin-jeongrim-react`에 JEONGRIM-SEO를 기준으로 gyumin을 no-commit 병합했다. 이어 현재 로컬의 검토된 React/정규화 변경을 반영했다.

- React 종합상황판·SVG 차트/지도 배경·기관/기간 필터·사고 상세, 기존 Flask 권한과 `/api/overview`, 빌드 번들.
- 문서 ID가 표시용 참조 검증을 통과하지 못하면 전체 정규화 구간이 멈추던 수정. 원본 ID를 노출하지 않는 invalid/raw_reference_rejected+ID해시 기록을 남기고 정상 입력은 계속 처리한다. 기존 정상 문서의 해시·중복 처리와 체크포인트 정책을 보존한다.
- 안전한 정규화 오류 코드, 읽기 전용 진단, 보존형 배포 wrapper, 탐지 지연 관찰 도구 및 직접 영향 검사.
- 런타임 state/키/자격증명/운영 DB/node_modules는 통합 소스에서 제외한다. 캡처 이미지 output/는 원본 작업 폴더의 참고 산출물로 남겨 소스 병합에서 제외한다.

현재 원격 tip에는 이 로컬 변경이 없으므로 위 별도 통합 후보를 게시해야 원격 두 브랜치 병합에 실제로 포함된다. 기존 원격 tip만 병합/배포하면 React 화면과 정규화 수정이 빠진다. 현재 커밋·push·운영 재배포는 하지 않았다.

## 남은 위험과 권장 대응

1. **높음 — 멀티클라우드 화면과 기존 탐지의 저장 경로 분리(기존 구조적 제한).** `multicloud/normalize.py`는 `soc-multicloud-*`에 쓰지만 `portal/log_contract.py`의 INDICES는 host/network/cloud-aws/cloud-oci만 포함한다. 일반 normalizer도 이 INDICES를 사용한다. 따라서 병합만으로 새 클라우드 로그가 통합 로그·정규화·탐지로 자동 연결되지 않는다. 단순 wildcard 추가는 document_reference·수집 계약·필드/시간 해석·reader/worker 권한을 함께 바꿔야 해 적절하지 않다. 전용 adapter와 근거 보존/규칙 연결을 별도 구현·인수해야 한다.
2. **높음 — 현재 정상화 수정 누락으로 재발 가능(이번 후보에 반영).** 원격 브랜치만 병합하면 invalid-reference 입력에서 일반 정규화가 다시 정체할 수 있다. 이번 후보에는 해당 수정과 재현 검사를 포함했다. 실제 적용 후보 image/source fingerprint에 contract.py와 continuation.py가 모두 들어 있는지 확인해야 한다.
3. **높음 — 규칙 실행 범위는 자동으로 확대되지 않음(기존 제한).** 사용자 제공 운영 상태에는 AWS/웹/통합 규칙의 not_observed가 남아 있다. 멀티클라우드 병합과 reader grant가 해당 규칙 활성화/실행/유효 탐지를 보증하지 않는다. 규칙별 소스 계약·실행 manifest·실제 근거를 별도 인수해야 한다. 요청 없이 새 규칙을 운영 활성화하지 않았다.
4. **중간 — 원본/근거 조회의 mget 변경은 실 ES 확인 필요.** gyumin은 LogReader/ProtectedSourceReader/Operations의 source-filter 조회를 바꾼다. 긴 URI 문제를 해결하면서 정확한 index/id·필드 allowlist·기존 기관 검증을 유지한다. mock 기반 직접 검사는 통과했지만 운영 HTTPS에서 통합 로그 상세/원본 열람/경보 근거의 실제 응답을 확인해야 한다.
5. **중간 — 배포가 현재 적체 처리에 미치는 영향.** 운영 탐지기는 성공하면서 과거 구간을 따라잡는 중이라는 사용자 결과가 있다. 병합 자체로 속도·제외 이력 문제는 해결되지 않는다. 기존 보존형 plan/apply를 사용하고 임의 체크포인트 초기화·현재 시각으로 건너뛰기·새 collector state 재생성은 하지 않아야 한다. 실제 중단 시간/지연은 운영 배포 후 재측정해야 한다.
6. **중간 — 운영 config/key/reader 권한은 소스 병합과 별개.** 멀티클라우드 source scope·provider credentials·reader grants·기존 collector SQLite는 운영 보존 대상이다. 예제 config로 덮어쓰거나 새 collector를 중복 시작하지 않는다. 해당 서버의 계획/설정 차이를 먼저 대조해야 한다.
7. **낮음 — 작업 이력 문서 충돌.** 양측 완료/미완료 기록을 함께 유지해 해결했다. 미완료 운영 인수 항목을 단순 병합으로 완료 처리하지 않았다.

## 검증 범위

- Git merge-tree와 별도 worktree의 실제 no-commit merge로 충돌 범위를 확인했다. 원본 작업 폴더의 코드/미커밋 변경은 그대로다.
- 원격 두 브랜치만 합친 임시 tree에서 로그 목록/상세·분류29검사, 관제 집계/상태17검사:46개 통과.
- 로컬 React/정규화 수정까지 포함한 통합 worktree에서 처리/재개/개인정보/참조계약/로그조회/관제집계/종합상황판API/진단4검사를 합쳐 Python107검사 통과.
- 통합 worktree의 React production build 통과.
- 최초 Node 로그 UI 실행은14통과/7환경오류(linkedom 미설치)였다. 의존성 준비 후 로그 UI21개와 공통 shell8개 모두 통과했다.
- 추가 원본 접근/멀티클라우드/세션/기관별 사건 조사55개 검사에서 최초45통과/10실패였다. 사건 조사 fixture의 mget 응답이 실제 ES의 _index/_id/found 계약을 제공하지 않아 발생한 실패로 확인했다. 별도의 실제 응답 형태 mget fixture를 추가한 뒤 직접 영향 사건/기관권한13개 모두 통과했다. 제품의 기관 검증은 완화하지 않았다.
- 전체 테스트/Windows/CI/실서버 병합 배포는 이번 검사 범위가 아니다. 검증은 새 원격 커밋이나 운영 적용을 의미하지 않는다.


## 후속 요청 반영

멀티클라우드 어댑터와 AWS 선택지 복원을 이 통합 후보에 추가했다. 위 위험1의 어댑터 부재는 코드 수준에서 보완됐지만, 운영 전용 키/독립 워커 시작·소스별 규칙 활성화/과거 로그 인수는 여전히 별도다. 상세는 multicloud_pipeline_adapter.md를 따른다. 운영 반영 없이 원격/기존 워커를 보존했다.
