# 통합 로그의 OWASP Top 10:2025 해석 기준

[OWASP Top 10:2025](https://top10.owasp.org/2025/) 분류를 통합 로그의 관측 근거에 연결한다. `normalization.owasp`는 분류 ID와 근거 코드를 반환한다. 일반적인 서비스 시작·중지나 HTTP 오류, 권한·암호화 관련 단어만으로 분류하지 않는다.

| 분류 | 필요한 근거 |
| --- | --- |
| A01 접근 제어 | 쇼핑몰에서 리소스 소유자 또는 관리자 요건으로 권한을 거부한 감사 이벤트 |
| A02 보안 설정 | 애플리케이션 보안 설정 점검 실패 |
| A03 소프트웨어 공급망 | 의존성 출처 검증 실패 |
| A04 암호화 | 암호화 정책 점검 실패 |
| A05 인젝션 | 검증된 ModSecurity SQLi 또는 AWS WAF 인젝션 신호 |
| A06 안전하지 않은 설계 | 애플리케이션의 업무 흐름 보안 조건 점검 실패 |
| A07 인증 | 검증된 Windows, Linux, 쇼핑몰 인증 실패 |
| A08 무결성 | 아티팩트 무결성 점검 실패 또는 Linux 감사 무결성 검증 실패 |
| A09 로깅·경보 | Windows 감사 로그 삭제·이벤트 로깅 종료 또는 Linux 감사 데몬 오류 |
| A10 예외 처리 | 예외 상황에서 접근이 허용되는지 확인하는 애플리케이션 점검 실패 |

설정·공급망·암호화·설계·아티팩트 무결성·예외 처리 규칙에 필요한 생산자 형식은 수집 태그 `application_security_audit`, 사이트 식별자 `service.id`, `application_security.schema=1`, 허용된 `check`, `result=pass|fail`이다. 생산자는 실제 점검 결과를 제공해야 한다. 이 변경에서 운영 수집 생산자를 등록하지 않았다.

Linux 저널은 `systemd.transport=audit`와 `journald.custom.audit_type`을 대조한다. 결과는 감사 유형 이름이 맞고 마지막 `res` 필드가 허용값인 경우에만 채운다. `1130`·`1131`은 각각 서비스 시작·중지로 표시한다. Windows 이벤트는 채널·공급자·이벤트 ID를 대조한다. [Linux Audit 이벤트 정의](https://github.com/linux-audit/audit-userspace/blob/master/lib/audit-records.h), [Microsoft Windows 감사 이벤트](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/other-events).
