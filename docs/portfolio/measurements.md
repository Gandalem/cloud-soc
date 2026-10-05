# Reproducible measurements

2026-10-05 checkout base `8a0abd8` + PORT changes. 합성 오프라인 측정, 운영 환경 성능/공격 탐지 정확도와 구분한다.

## Coverage

Linux Python 3.12.14: **417 passed, 5 skipped, 154 subtests passed**. 전체 `cloud_soc` statement coverage **88.5%** (4990 statements, 575 missed). branch coverage는 측정하지 않았다. OS/opt-in 시험 생략과 CLI/setup의 미커버 경로가 남아 있다. CI는 XML/JSON/HTML을 artifact로 올리며 배지는 로컬 스냅샷이다.

## Labeled detection quality

정답 라벨은 “선언한 규칙 조건에 맞아야 하는가”이다. 승인된 변경이라도 규칙에 해당하면 positive이며, 실제 악성 여부/현장 FP율은 평가하지 않는다. 테스트에서 설계한 사례라 독립 평가 집합도 아니다. SSH/OCI/sequence는 기존 회귀가 있지만 이 수치 집계 대상은 AWS 3개 규칙이다.

| Rule | TP | FP | FN | TN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AWS-IAM-001 | 2 | 0 | 0 | 3 | 100% | 100% |
| AWS-AUDIT-001 | 2 | 0 | 0 | 3 | 100% | 100% |
| AWS-NETWORK-001 | 3 | 0 | 0 | 4 | 100% | 100% |

Precision = TP/(TP+FP), Recall = TP/(TP+FN); 분모 0은 null. 예상 밖 다른 규칙 탐지도 실패로 처리한다. 17개 사례는 실패 API·잘못된 provider·필드 누락·ReadOnly 정책·사설 SSH·공개 웹 등을 포함한다. 샘플이 작아 모집단 성능을 추정할 수 없다.

## Performance

10,000개 고유 StopLogging positive 이벤트; warmup 1회, 반복 3회, `time.perf_counter`. 고유 ID마다 실제 경보 1개가 생성되는지 검사한다. 생성 fixture/디스크 보고서 쓰기는 시간에서 제외. 환경 Linux 6.18.44 x86_64 / Python 3.12.14 / glibc 2.39; 공유 실행 컨테이너라 CPU·메모리 자원을 고정하거나 보장하지 않는다.

| Stage | Median seconds |
| --- | ---: |
| projection | 0.816 |
| normalization | 1.686 |
| detection | 2.712 |
| alert_build | 0.099 |

합계의 반복별 중앙값 **5.451초**, **1,835 events/sec**. 단계 중앙값의 합과 합계 중앙값은 같지 않을 수 있다.

실제 운영 end-to-end throughput/SLA가 아니다. ES indexing, network, SDK API, SQLite runtime, 혼합 로그, 장시간 메모리/백프레셔·부하·수집 지연을 포함하지 않았다. 머신/부하에 따라 결과가 달라진다.

```bash
python tools/portfolio_eval.py --events 10000 --repeats 3
```

[원시 반복 값·dataset SHA256·데모 결과](evaluation.json). 기존 `evaluation.json`을 갱신하면 README와 이 문서도 새 측정에 맞춰 갱신한다.
