# P0C-03 실제 통합 검증 결과 — 2026-10-04

사용자가 지정한 VMware Ubuntu·Windows 시험 VM에서 잔여 구현, 격리 회귀, 실제 배포와 실제 에이전트 수신을 각각 검증했다. 사용자에게 두 VM 스냅샷 생성 완료 답변을 받은 뒤 중단·복구 시험을 수행했다. 기능 브랜치는 `codex/p0c03-integration-readiness`, 작업 시작 기준은 최신 `origin/main`의 `cb329e4`다. 커밋·푸시는 수행하지 않았다.

## 구현

- Windows·Ubuntu, 로그 전용·로그+네트워크의 네 조합 모두 단일 토큰과 자동 중앙 receipt를 지원한다. 로그 전용은 host 키 하나만 발급한다.
- Windows `-Enroll -ReEnroll`, Ubuntu `--enroll --reenroll`은 확인된 실패 설치만 대상으로 한다. 중앙에서 이전 키의 실제 폐기를 재확인하고, 보호 백업과 동일 수집기 ID·큐·registry를 유지한 새 키 등록 후 실제 수신을 확인한다.
- 기존 수동 키·Repair·Discovery 갱신 경로와 과거 패키지·키 이력은 유지한다. 정상·수동·출처 불명 설치를 자동 채택하지 않는다.
- Windows 런처의 함수 범위와 번들의 repair 의존성, 로그 전용 분기, 반복 검증 이벤트의 fingerprint 충돌을 보완했다. 새 표식은 NDJSON의 첫 1,024바이트 안에 놓인다.
- Docker 이미지는 명시된 공개 코드 디렉터리의 판독 권한만 정규화한다. 마운트되는 DB·키·인증서의 권한은 변경하지 않는다.

주요 파일: `src/cloud_soc/portal/enrollment.py`, `packages.py`, `deploy/agents/enrollment-linux.py`, `enrollment-windows.ps1`, `reenroll-windows.ps1`, `bundle*.ps1`, Ubuntu 설치기, `deploy/server/Dockerfile`, `prototype/agents.*`와 관련 회귀 시험.

## 격리 회귀

| 시험 | 결과 |
| --- | --- |
| 최종 Python 전체 | 337건 중 331건 통과, 6건 조건부 건너뜀 |
| 포털 화면 Node 회귀 | 73건 통과 |
| 에이전트 설치·네트워크 Node 회귀 | 53건 통과 |
| Windows 번들·Enrollment, PowerShell 5.1/7 | 최종 13건 통과 |
| Linux Enrollment 제어기 | Windows 및 실제 Ubuntu에서 4건 통과 |
| OCI / AWS 선택 SDK 합성 시험 | 17 / 16건 통과, 실제 클라우드 접속 없음 |
| Bash 구문·패키지 내부 SHA256SUMS·Git diff 검사 | 통과 |

Python의 건너뜀은 Windows에서 실행할 수 없는 Linux root 파일시스템 시험 5건과 opt-in 격리 Docker ES 시험 1건이다. 실제 시험 서버의 ES 9.5.2 수신·파이프라인·권한 검증은 아래에 별도로 기록한다. PowerShell 회귀의 실행 정책은 자식 프로세스에만 RemoteSigned를 적용했다. 영구 정책은 변경하지 않았다.

마지막 문구 수정 후 기존 오류 문구 기대값을 갱신했다. 시험 파일 동시 실행에서 실제 전역 설치 잠금의 경합이 발생해 `node --test --test-concurrency=1`로 순차 재실행했고 13건 모두 통과했다. 이 실패를 제품 설치 성공으로 계산하지 않는다.

## 실제 배포와 보존

Ubuntu 24.04.5 시험 서버에 ES/Kibana 9.5.2, HTTPS gateway, 명시적으로 활성화한 Enrollment와 정리 서비스를 사용했다. ES 수신 final pipeline과 Packetbeat 공식 파이프라인은 중앙에서 준비했고 publisher의 관리 권한을 확대하지 않았다.

최종 실행 이미지:

- portal: `sha256:d5ff9ee6ae7b3b01b0a9b1250f3a6a504d1cee4f95cce50fd2e9b8d0d08ee1a6`
- enrollment-cleanup: `sha256:ab7936633b01e624795485a5f06ee7db36894b377c11accf7305be7ce90366b2`
- 최종 `bundle-repair-windows.ps1`: SHA-256 `354d6b24ef065d31a334833f2dcb337367c3f44cad0f170ec3e47a124f20efb4`

두 이미지의 공개 코드 전체 판독·UID 1000 import를 네트워크 차단·읽기 전용 컨테이너에서 검사했다. 마지막 배포 후 portal/cleanup running·restart 0, ES healthy·restart 0, Kibana/gateway running·restart 0을 확인했다.

온라인/중지 백업, verify, 격리 restore/verify를 수행했다. 마지막 이미지 교체 직후 `packages.sqlite3`의 모든 3개 테이블 및 `cases.sqlite`의 모든 4개 테이블 전체 행·BLOB이 중지 백업과 동일했다. 이후 폐기한 자기 시험 키 2개의 이력만 갱신하고 새 Windows 최종 패키지 2개를 추가했다. 종료 백업은 packages 10개·issued_keys 18개·enrollments 15개, 사건 테이블 모두 0개, missing 없음으로 verify를 통과했다.

서버 보호 기록: `state/portal-backups/p0c03-final-stopped-20261004`, `p0c03-final-result-20261004`, `state/portal-restore-drills/p0c03-final-20261004`. 이전 이미지·소스와 기존 백업도 보존했다. 실제 설치 검증 뒤 마지막 배포 변경은 Windows 복구 상태 문구이며 설치·수신 로직은 같고 최종 새 ZIP의 해당 파일·내부 해시를 다시 검증했다.

## 실제 설치와 중앙 문서

| 구성 | 완료 세션 | 실제 수집기 ID |
| --- | --- | --- |
| Windows 로그+네트워크 | `a62535f0484f40c48964cec4c1c3ebb8` | host `927b681f-a1f2-4a2a-ad68-3e3627b7ba63`, network `23f17deb-0fa6-46d0-bbe5-ccf55bf2c563` |
| Ubuntu 로그+네트워크 | `dc797900183142a29501fcf9c543edd7` | host `fa539fd5-b42b-4501-a4e7-86030927c2eb`, network `7212dfe2-dde4-4ae0-a452-bbb0bbb97083` |
| Windows 로그 전용, 시작 후 재등록 | `e2ee452faf344381ace6a703ac647a19` | host `ad1a3079-e1db-45bd-b40f-2d7ccded1ef1` 유지 |
| Ubuntu 로그 전용, 시작 후 재등록 | `c94a8f864aec44ffa4e9ae96cfd330e6` | host `734372cc-e6a2-4adf-a45f-37190fa57ee7` 유지 |

설치기가 실제 Filebeat 합성 이벤트와 필요한 Packetbeat TCP 흐름 문서를 조회해야 완료했다. 별도 monitor 조회에서 agent ID·조직·고유 표식·실제 인증 key ID/scope/package·서버 수신 시각·해당 인덱스 final pipeline을 대조했다. 로그 전용 문서 참조는 Windows `soc-host-raw-windows-9.5.2-2026.10.04/aAlIBqEBYPLrp-rqg9v1`(09:39:38.100455187 UTC), Ubuntu `soc-host-raw-linux-9.5.2-2026.10.04/6ghGBqEBYPLrp-rq3f-s`(09:37:49.990450251 UTC)다.

기존 수동 Linux 설치와 통합 설치, 로그 전용 시험 설치를 보호 보관했다. 중지 상태의 전체 파일·큐·registry 해시를 검사한 뒤 원래 통합 설치를 동일 바이트로 되돌려 시작했다. Windows 보관 도구의 중복 경로 구분자 때문에 생긴 해시 키 비교 오류는 경로 정규화 후 전체 파일 대조로 해결했다. 실제 파일 변조나 큐 초기화로 처리하지 않았다. 종료 시 양 VM의 Filebeat/Packetbeat 실행·자동 시작과 Discovery 결과를 확인했다. Windows SYSTEM Discovery LastTaskResult=0, Npcap running, Ubuntu Discovery/CRL 갱신 timer active다.

## 실제 실패·권한·만료 시험

- ES 컨테이너를 실제로 중지한 뒤 두 로그 전용 설치의 수신 확인을 진행했다. 둘 다 성공 처리를 거부하고 소유 서비스 중지·비활성화, 큐·keystore·보호 실패 상태 보존, 중앙 접속 불가 시 폐기 미확인을 표시했다. ES를 정상 재시작한 뒤 실제 cleanup 서비스가 두 실패 키를 폐기했고, 원격 invalidated=true를 독립 확인했다. 새 토큰 재등록은 동일 수집기 ID로 실제 수신을 마쳤다.
- 앞선 Windows/Linux 방화벽 보조 시험은 수신을 실제 차단하지 못했다. 정상 receipt는 인정하지만 장애 검증으로 인정하지 않았고 자기 시험 규칙은 제거했다.
- 같은 attempt의 실제 HTTP 재전달은 같은 응답·같은 키를 반환했다. 다른 attempt는 HTTP 409, 동시 두 attempt는 200/409 한 번만 성공했고 원격 키는 하나였다. 잘못된 패키지 ID/해시·조직 덮어쓰기 요청도 거부됐다.
- 실제 host/network publisher 키로 자기 범위 create를 확인한 뒤 읽기·삭제·다른 수집 범위/OS 쓰기·키 관리·클러스터 설정 변경 요청 각각 HTTP 403을 확인했다. 독립 읽기에서 위조한 조직·검증 신원이 실제 인증 키의 메타데이터로 교체됐음을 확인했다. 직접 작성한 합성 권한 시험 문서는 실제 에이전트 수신 증거로 계산하지 않는다. 해당 시험 키는 폐기했다.
- 미사용 세션 `5589e851d72a4649b4105014e952bff8`은 910초 실제 경과 후 HTTP 410 `enrollment_expired`였다. 중앙 DB와 원격 ES 모두 발급 키 없음·attempt/sealed 없음 확인. 서버 시계를 바꾸지 않았다.
- 방치 세션 `84f74e3a5e5f45208a4a5c7a946bd813`의 deadline만 시험용으로 과거로 설정했다. 수동 sweep 없이 실제 cleanup 서비스가 cancelled·sealed 제거·원격 키 폐기를 완료했다. 이는 30분 자연 경과 시험과 구분한다.
- 종료 시 세션 complete 4개·cancelled 8개·expired 3개, unused/issuing/issued/cleanup_pending 0개, sealed 잔존 0개를 확인했다. 통합 설치의 유효 키는 유지했고 보호 보관한 로그 전용 시험 키만 개별 폐기했다.

## TLS와 실제 화면

사용자의 기본 엄격 검사 선택을 유지했다. 출처·해시를 대조한 공개 CA는 승인받은 Windows 시험 계정 CurrentUser Root에만 등록했다. 개발 PC·LocalMachine·다른 VM의 신뢰 저장소는 변경하지 않았다. 기존 시험 CA/개인키를 유지하고 같은 시험 서버의 서명된 CRL 배포·갱신을 구성했다. Windows 최종 독립 온라인 chain 검사 NativeErrors=None, Ubuntu 토큰 제어기의 CA·이름·유효기간·서명 CRL/폐기 검사가 통과했다. 폐기 불명 예외나 인증서 우회는 사용하지 않았다.

시험 Windows Edge 154의 독립 headless 세션에서 실제 HTTPS 관리자 화면을 검사했다. 네 조합의 명령·해시와 로그 전용의 NIC 생략, 토큰 password 표시·저장소 비저장·닫기 시 삭제·실제 발급/취소, 데스크톱·390px 모바일 표시를 확인했다. 실제 접속 현황의 통합 수집기 4개가 recent이고 API ID/수신 시각/문서 수와 DOM을 대조했다. 소유 브라우저와 SSH 디버깅 터널은 종료했다.

Git 제외 공개 메타데이터 증거: `state/lab-20261004/lab-proof-*.json`, `lab-protocol-evidence.json`, `lab-natural-expiry.json`, `browser-evidence.json`, `browser-*.png`, `python-final-regression.txt`. 실제 수신 증거 묶음 SHA-256: `cb3088866ad66e81bac72520e3922d8cdc0c40975148d076068e0dade8dde14d`. 비밀번호·토큰·시도 비밀·역할 키 비밀·개인키·실제 민감 원문은 이 문서와 작업 목록에 기록하지 않는다.

## 남는 지원 제한

P0C-03의 명시된 기준을 이번 두 시험 VM과 대표 실패 시점에서 충족했다. 모든 OS/정전 시점의 인증, 모든 과거 이벤트 무손실, 정상 설치의 키 자동 교체·Beat 업그레이드·서버/CA 이행·자동 중단 채택을 뜻하지 않는다. 재등록 중 보호 기록/해시 불일치는 보존 후 검토하며 Windows 로그 전용의 중단 Repair `-ResumeRepair`는 지원하지 않는다. 기존 운영/AWS 서버 배포, P0-03/P1-04 등 다른 작업의 완료 표시는 하지 않았다.
