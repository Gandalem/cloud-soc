# Screenshot provenance and reproduction

2026-10-05 실제 `prototype/` HTML/CSS/JS를 headless Chromium에서 실행해 캡처했다. 상단 `SYNTHETIC DEMO` 표시는 합성 자료라는 뜻이며 운영 캡처가 아니다. UI를 그림으로 재현하지 않았다.

| 파일 | 확인한 동작 |
| --- | --- |
| `images/dashboard.png` | production 탐지 코드가 생성한 AWS 규칙 3개 경보 표시 |
| `images/alert-detail.png` | CloudTrail 경보 상세, 정확한 raw 참조와 정규화 내용 해시 일치 |
| `images/investigation.png` | 실제 Flask 사건 API + 임시 SQLite에 사건 생성/담당자/상태/판정/메모 저장, MITRE와 변경 이력 표시 |

경보 상세와 근거 projection은 production `Operations.detail/evidence`를 실행하며 ES 읽기만 메모리 자료로 대체한다. summary의 counts/chart는 캡처용 fixture이다. 따라서 실시간 수집/범위 필터, ES 쓰기/최소 권한, 운영 인증은 이 캡처의 인수 대상이 아니다. 이미지에 나오는 2026-09-22 경보는 고정 fixture이고 현재 조회 기간과의 차이는 합성 preview 특성이다.

## 재현

Python 의존성은 저장소 루트에서 설치한다. 별도 터미널 두 개를 사용한다.

```bash
# 터미널 1
python tools/portfolio_preview.py --port 8770
```

```bash
# 터미널 2: Node + Playwright + Chromium 필요
npm install --prefix /tmp/soc-capture playwright
NODE_PATH=/tmp/soc-capture/node_modules node /tmp/soc-capture/node_modules/playwright/cli.js install chromium
NODE_PATH=/tmp/soc-capture/node_modules node tools/capture_portfolio.cjs
```

한국어 글꼴(Noto Sans KR 등)을 설치하고 실행한다. 기존 Chromium을 사용할 경우 `PORTFOLIO_CHROMIUM`에 실행 경로를 지정할 수 있다. Windows에서는 설치 위치와 환경변수 설정을 해당 OS에 맞춘다.

캡처 스크립트는 경보 → 상세 → 근거 → 사건 생성 → 업무 저장 → 근거 재조회 → 저장된 사건 재로딩을 자동 확인하며 JS page error를 실패로 처리한다. 완료 뒤 터미널 1에서 Ctrl+C를 누르면 임시 DB가 제거된다. 실제 운영 주소로 이 도구를 바꾸거나 공개 호스트에서 preview를 실행하지 않는다.
