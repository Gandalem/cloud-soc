# 선택 실습과 참고 자료

Cloud SOC는 Security Mall 없이 시스템·일반 웹·선택 네트워크 로그를 수집한다. 기본 설치와 첫 경보는 [장치 설치](device_installation.md), [독립 SOC 인수](operational_acceptance.md)를 따른다. 과거 Mall 실습·설계·배포 사전점검은 현재 필수 설치 절차에서 분리해 [보관 색인](archive/README.md)에 압축했다.

## Security Mall

| 범위 | 현재 구분 |
| --- | --- |
| 일반 웹 로그 | Apache/Nginx 또는 표준 접근 형식이 들어 있는 Docker JSON 선택 수집 |
| 앱 내부 감사 | service.name 등 앱 계약을 맞춘 선택 확장. 웹 로그만으로 로그인 성공/주문 소유권을 확정하지 않음 |
| ModSecurity | 별도 WAF 설치/설정과 지원 JSON 감사 입력이 필요. SOC/에이전트 설치가 WAF를 자동 설치하지 않음 |
| 요청 연관/조사 | 신뢰하는 site/host/request_id·조직 범위의 앱/웹/WAF 증거. 기존 Mall 조사는 읽기 전용 snapshot 계약 |
| 규칙 실행 | YAML의 enabled만으로 런타임 활성화가 증명되지 않음. 실제 프로필·revision·상주 처리/경보 저장 확인 필요 |

앱 감사·웹/WAF 원본과 정규화, 탐지·근거·조사를 각각 확인한다. DetectionOnly의 SQLi 관측/경보는 WAF 차단 성공을 뜻하지 않는다. 실제 Spring 요청3건에서 앱/웹/WAF 원본9·정규화9를 확인한 시험과 이후 상주 탐지·Portal 시험은 날짜/범위가 다르다. 서버 실행만으로 Slack 수신까지 완료로 계산하지 않는다.

코드의 선택 경로는 src/cloud_soc/web, src/cloud_soc/correlation, rules/security_mall.yml과 기존 Portal 연동이다. 새 범용 사이트 수집은 [통합 사이트](unified_site_agent.md), 사용자 규칙은 [규칙 작성](rule_authoring.md), 최근 실습 상주는 [상시 처리](live_ajax_runtime.md)를 따른다. 기존 사이트/설치에 과거 콘솔 명령이나 키를 재사용하지 않는다.

몰 전용17문서의 단계별 계약·점수식·최소 권한 읽기 키·실제 인수/실패·사전 승인 기록은 **[mall-docs.zip](archive/mall-docs.zip)**의 원래 docs/security_mall_*.md 경로에 보존했다.9-C 배포 계획·7-A/B 읽기 키 준비 문서는 해당 시점 기록이며 현재 배포 승인으로 해석하지 않는다.

## 합성 시연과 포트폴리오

tools/portfolio_eval.py는 기존 AWS 규칙의 합성 평가/근거 참조를 만들고 tools/portfolio_preview.py는 루프백 시연을 제공한다. 실제 클라우드 공격·현장 FP율·실시간 지연 검증이 아니다. 기존 시연 안내/스크린샷/평가 snapshot은 [portfolio-docs.zip](archive/portfolio-docs.zip)에 있다.

CI가 생성하는 docs/portfolio/coverage.svg와 평가 도구의 기본 출력 evaluation.json은 원래 위치를 유지한다. 캡처 도구는 필요할 때 docs/portfolio/images를 다시 만들며 이번 정리가 도구 실행을 뜻하지 않는다.

## 연구 자료와 보고서

과거 데이터 소스 전략·공격 시나리오·Security Datasets/Stratus 참고와 루트의 중복 탐지/조사 가이드는 [reference-docs.zip](archive/reference-docs.zip)에 있다. 검토 후보와 실제 실행/인수는 다르며 외부 자료가 기존 권한·수집 필드·실제 공격 실행 승인을 대신하지 않는다.

기존 Word 보고서2개는 [reports-docs.zip](archive/reports-docs.zip)에 바이트 그대로 보존했다. 문서 내용이나 개인 이미지를 새로 편집하지 않았다. ZIP별 원래 경로·크기·SHA256은 내부 MANIFEST.json과 [보관 색인](archive/README.md)에서 찾을 수 있다.
