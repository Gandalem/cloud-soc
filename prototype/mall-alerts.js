/* Safe DOM projection shared by the existing alert and investigation screens. */
(() => {
  'use strict';
  const rules = new Set(['WEB-ACCESS-01', 'WEB-AUTH-01', 'WEB-WAF-01']);
  function line(box, label, value) {
    const p = document.createElement('p');
    p.textContent = label + ': ' + (value ?? '미관측');
    box.append(p);
  }
  function summary(box, data) {
    if (!rules.has(data.alert?.rule)) return;
    line(box, '서비스', data.alert.service);
    line(box, '해석', data.alert.rule === 'WEB-ACCESS-01'
      ? '타인 주문 접근 시도 차단 · 정보 유출 성공을 의미하지 않음'
      : data.alert.rule === 'WEB-WAF-01'
        ? 'SQLi 의심 메타데이터 관측 · SQL 실행 또는 침해 성공 확정 아님'
        : '의심 인증 시퀀스 · 계정 탈취 확정 아님');
    line(box, '탐지 사유', data.alert.reason);
    line(box, '규칙 severity', data.alert.severity);
    line(box, '계산 위험 점수 / 등급', (data.risk?.score ?? '미기록') + ' / ' + (data.risk?.level ?? '미기록'));
    const rule = data.rule_snapshot;
    line(box, '탐지 조건', JSON.stringify(rule ? {conditions: rule.conditions, threshold: rule.threshold,
      time_window: rule.time_window, success_window: rule.success_window, cooldown: rule.cooldown,
      waf_sqli: rule.waf_sqli} : data.condition));
    if (data.alert.rule === 'WEB-WAF-01' && data.assessment?.reason === 'scoped_crs_sqli_metadata') {
      const a = data.assessment;
      line(box, '관측 독립 요청 / 반복 기준', a.request_count + ' / ' + a.repeat_threshold);
      const patterns = {single_suspected_request: '단일 의심 요청', multiple_suspected_requests: '복수 요청 · 반복 기준 미만',
        repeated_suspected_requests: '짧은 시간 내 반복 의심 요청'};
      line(box, '자체 판단', patterns[a.pattern] || '미확인');
      line(box, 'SQLi 근거 규칙 ID', (a.matched_rule_ids || []).join(', '));
      line(box, '선언 동작', (a.declared_actions || []).join(', '));
      line(box, 'WAF 처리', a.engine_mode === 'DetectionOnly' && a.blocked === false
        ? 'DetectionOnly · 실제 차단 아님' : '미확인');
      line(box, '연결 한계', '요청 ID는 출처 인증 아님 · 관측 IP는 실제 클라이언트로 확정하지 않음');
    }
    const triage = data.investigation;
    if (triage?.state !== 'available') {
      line(box, '조사 분석', '미확인 · 분석 결과 또는 검증 가능한 증거 부족');
      return;
    }
    line(box, '조사 우선순위 점수 / 등급', triage.triage_score + ' / ' + triage.triage_priority);
    line(box, '증거 신뢰도', triage.evidence_confidence + ' · 공격 성공 확률 아님');
    line(box, '증거 완전성', triage.completeness);
    line(box, '연결 이벤트 / 증거 / 요청 묶음', triage.event_count + ' / ' + triage.evidence_count + ' / ' + triage.bundle_count);
    line(box, '웹 증거로 확인된 독립 요청 하한', triage.independent_request_count + ' · 실제 전체 요청 수 아님');
    for (const [key, label] of [['web', '웹'], ['waf', 'WAF'], ['app', '앱']]) {
      line(box, label + ' 연결 증거', triage.streams?.[key] === 'observed' ? '관측됨' : '미확인 · 증거 부족');
    }
    const reasons = {
      existing_detection_risk: '기존 탐지 위험도',
      repeated_independent_application_denials: '독립 요청의 반복 권한 거부',
      authentication_sequence_already_in_base_risk: '인증 시퀀스는 기존 위험도에 반영됨',
      additional_streams_change_confidence_not_risk: '추가 로그는 신뢰도 보강이며 위험도 자동 가산 아님'
    };
    for (const factor of triage.factors || []) {
      line(box, '우선순위 근거', (reasons[factor.code] || '미확인') + ' (' + factor.points + '점)');
    }
    line(box, '미검증 경보 증거', triage.unresolved_alert_references);
    const uncertainties = {
      missing_streams: '일부 로그 미확인', ambiguous_request_id: '요청 ID 연결 모호',
      request_id_reused_multiple_web_events_no_join: '같은 요청 ID의 복수 웹 요청 · 확정 연결하지 않음',
      delayed_evidence: '지연 수신 증거 포함', receipt_precedes_event_clock_uncertainty: '발생·수신 시계 불확실',
      evidence_missing_or_integrity_unverified: '경보 증거 누락 또는 무결성 미확인',
      raw_contents_not_reverified_by_triage: '분석 스냅샷은 원본 내용의 재검증 결과가 아님'
    };
    for (const key of triage.uncertainties || []) {
      if (uncertainties[key]) line(box, '불확실성', uncertainties[key]);
    }
    line(box, '해석 한계', '요청 ID는 출처 인증이 아님 · DetectionOnly는 차단 성공이 아님 · 403만으로 WAF 차단 판정 불가');
    line(box, '분석 기준 범위', triage.range.start + ' ~ ' + triage.range.end);
    line(box, '분석 갱신', '검증된 스냅샷 · 실시간 분석 아님 · 지연 증거는 다음 revision에 반영');
  }
  function evidence(box, item, position) {
    if (item.state === 'exact_reference' && item.integrity === 'normalized_hash_verified'
        && item.security?.status === 'recognized' && item.security?.adapter === 'security_mall_edge_v1') {
      const f = item.security.fields;
      line(box, '이벤트 순서', position + 1);
      line(box, '이벤트 시각', f.timestamp);
      line(box, '요청 ID', f.request_id);
      line(box, '원본 이벤트 ID', item.normalized_event?.id);
      line(box, 'WAF 규칙 ID', (f.rules || []).map(r => r.id).join(', '));
      line(box, 'WAF 처리', f.engine_mode === 'DetectionOnly' && f.blocked === false
        ? 'DetectionOnly · 실제 차단 아님' : '미확인');
      line(box, '정규화 참조', item.normalized.index + ' / ' + item.normalized.id);
      line(box, '원본 참조', item.raw.index + ' / ' + item.raw.id);
      const link = document.createElement('a');
      link.textContent = '정제 메타데이터 상세';
      link.href = '/api/logs/detail?index=' + encodeURIComponent(item.raw.index) + '&id=' + encodeURIComponent(item.raw.id);
      box.append(link);
      return;
    }
    if (item.state !== 'exact_reference' || item.integrity !== 'normalized_hash_verified'
        || item.security?.adapter !== 'security_mall_audit_v1') return;
    const f = item.security.fields;
    line(box, '이벤트 순서', position + 1);
    line(box, '이벤트 시각', f.timestamp);
    line(box, '행동 / 결과', f.action + ' / ' + f.outcome);
    line(box, '접근 차단', f.authorization_reason === 'not_owner' ? '타인 주문 접근 차단' : '이 이벤트로 판단하지 않음');
    line(box, 'HTTP 상태', item.http_status); // Audit schema v1 does not record HTTP status.
    line(box, '권한 사유', f.authorization_reason);
    line(box, '계정 가명', f.account_id);
    line(box, '계정 키 버전', f.account_key_id);
    line(box, '원본 이벤트 ID', f.event_id);
    line(box, '정규화 참조', item.normalized.index + ' / ' + item.normalized.id);
    line(box, '원본 참조', item.raw.index + ' / ' + item.raw.id);
    const link = document.createElement('a');
    link.textContent = '원본 메타데이터 상세';
    link.href = '/api/logs/detail?index=' + encodeURIComponent(item.raw.index) + '&id=' + encodeURIComponent(item.raw.id);
    box.append(link);
  }
  window.CloudSOCMall = {summary, evidence};
})();
