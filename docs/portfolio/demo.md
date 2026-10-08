# Three reproducible SOC scenarios

실제 클라우드 자원을 공격하거나 방화벽을 변경하지 않는 합성 재현이다. `tools/portfolio_eval.py`가 기존 AWS 투영/정규화/탐지/경보 생성 함수를 호출하고 `evaluation.json`에 세 시나리오의 결과와 정확한 근거 참조를 기록한다.

| 시나리오 | 입력 | 예상 결과 | 조사 질문 |
| --- | --- | --- | --- |
| 1. 권한 확대 | 성공한 AttachUserPolicy, AdministratorAccess ARN | AWS-IAM-001, high, 근거 1개 | 누가 어느 사용자에 연결했는가? 승인·대상·유효 권한은? |
| 2. 감사 가시성 저하 | 성공한 StopLogging | AWS-AUDIT-001, high, 근거 1개 | 어떤 Trail인가? 다른 Trail/region 수집이 보완하는가? |
| 3. 관리 포트 노출 | 성공한 AuthorizeSecurityGroupIngress, tcp/22, 0.0.0.0/0 | AWS-NETWORK-001, high, 근거 1개 | 실제 라우팅/공인 IP/SG 적용·접근 가능성은? |

## 재현

저장소 루트에서 Python 3.12 환경을 사용한다.

```bash
python -m pip install -c constraints.txt -r requirements-dev.txt
python tools/portfolio_eval.py --events 10000 --repeats 3
python -m pytest -q tests/test_portfolio.py
python tools/portfolio_preview.py --port 8770
```

1. `http://127.0.0.1:8770/index.html`에서 실제 탐지 코드가 만든 세 경보를 확인한다.
2. ‘상세 / 근거’에서 rule/version, 위험 점수, MITRE, 근거 문서 개수를 확인한다.
3. ‘근거 1 확인’로 정확한 raw index/ID와 정규화 내용 해시 일치를 확인한다. 원본 내용 자체의 해시는 별도 미검증이다.
4. ‘사건 조사 / 등록’에서 사건을 만들고 담당자·조사 중·판단 보류·메모를 저장한다.
5. 타임라인에서 경보를 다시 열어 정확한 근거를 확인한다. 주변 활동은 통합 로그에서 별도로 조사한다.
6. Ctrl+C로 종료한다. 임시 SQLite는 삭제되고 운영 서버/사건/키/클라우드에는 영향이 없다.

합성 API summary는 캡처용 세 경보를 현재 조회 범위에 보여준다. 이 합성 차트가 실시간 수집량/시각 필터의 검증은 아니다. 경보 이벤트 시각은 고정 fixture 시각이다. 오프라인 증적 검증은 실제 ES 조회·삭제/만료·샤드 실패·수집 지연 검증과 구분한다.

면접 설명 예: “StopLogging 로그를 허용 필드로 투영하고 공통 스키마로 정규화했습니다. YAML 단일 이벤트 규칙이 경보를 생성하고 규칙 버전·정확한 근거 참조를 보존합니다. 분석가는 다른 Trail과 변경 승인까지 조사한 뒤 판정합니다.”
