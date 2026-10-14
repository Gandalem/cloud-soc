(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let generation = 0, cursor = null, scope = {}, records = new Map(), anonymous = 0, pipelineGeneration = 0, pipelineController;
  const states = {evaluated: '최종 저장 미확인', committed: '실행 완료', failed: '실행 실패', waiting: '입력 대기'};
  const rank = {committed: 4, failed: 3, evaluated: 2, waiting: 1};
  const names = {'AUTH-001': 'SSH 반복 로그인 실패', 'ATTACK-01': 'SSH 인증 후 특권 활동',
    'ATTACK-02': 'AWS API 열거 의심', 'ATTACK-03': '권한 변경 후 감사 중단 의심',
    'AUTH-SEQ-001': 'SSH 실패 후 로그인 성공', 'AUTH-SPRAY-001': '여러 계정 대상 SSH 실패',
    'AWS-IAM-001': 'AWS 고권한 정책 연결', 'AWS-AUDIT-001': 'AWS 감사 중지·삭제',
    'AWS-NETWORK-001': 'AWS 관리 포트 인터넷 허용', 'OCI-IAM-001': 'OCI 정책 생성·변경',
    'WIN-AUTH-001': 'Windows 반복 로그인 실패', 'WEB-404-001': '웹 404 반복 응답',
    'NET-PORT-001': '다수 목적지 포트 관측', 'AWS-CONSOLE-001': 'AWS 콘솔 반복 로그인 실패'};
  const reasons = {late_event: '평가 가능한 지연 시간을 초과했습니다.', missing_condition_fields: '규칙에 필요한 정보가 없습니다.',
    missing_group_fields: '조직·사용자 등 연결에 필요한 정보가 없습니다.', invalid_event_time: '발생 시각을 확인할 수 없습니다.',
    future_event_clock: '발생 시각이 미래로 기록돼 있습니다.', approved_policy_exception: '승인된 예외 조건에 해당합니다.'};
  const counters = ['input_events', 'matched', 'not_matched', 'unknown', 'excluded', 'late', 'policy_excluded', 'evaluated_events', 'detection_matches', 'alerts_created', 'alerts_existing'];
  const number = value => Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString('ko-KR') : '미기록';
  const fmt = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString('ko-KR', {timeZone: 'Asia/Seoul'}) : '미기록';
  function node(tag, text) { const element = document.createElement(tag); if (text !== undefined) element.textContent = text; return element; }
  function idle(row) { return row.state === 'committed' && counters.every(key => row.counts?.[key] === 0); }
  function card(row) {
    const box = node('section'); box.className = 'ops-evidence';
    const rule = row.rule?.id || '규칙 미기록';
    box.append(node('h2', (names[rule] || rule) + ' · ' + (row.reason ? '평가 제외' : states[row.state] || '상태 미확인')));
    box.append(node('p', fmt(row['@timestamp']) + ' (KST)'));
    if (row.reason) box.append(node('p', reasons[row.reason] || '제외 사유 확인이 필요합니다.'));
    if (row.assessment) {
      const labels = {unverified: '미검증', not_evaluable: '평가 불가', evaluated: '관측 입력 평가 완료'};
      const notes = {no_source_observations: '이 실행 구간에 해당 로그 소스가 관측되지 않았습니다.',
        incomplete_or_excluded_input: '필수 정보 누락 또는 평가 제외 입력이 있습니다.',
        run_not_committed: '최종 처리 위치 저장이 확인되지 않았습니다.',
        bounded_observed_input: '해당 실행 구간의 관측 입력에 한정된 결과입니다.'};
      box.append(node('p', (labels[row.assessment.state] || '미검증') + ' · ' + (notes[row.assessment.reason] || '검증 범위를 확인하세요.')),
        node('p', '경보 0건은 공격 부재나 전체 실환경 검증 완료를 의미하지 않습니다.'));
    }
    if (row.counts) {
      const c = row.counts;
      box.append(node('p', '새 입력 ' + number(c.input_events) + '건 · 새 경보 ' + number(c.alerts_created) + '건 · 평가 제외 ' + number(c.excluded) + '건'));
      const detail = node('details'); detail.append(node('summary', '실행 상세'));
      detail.append(node('p', '규칙: ' + rule), node('p', '분석 구간: ' + fmt(row.range_start) + ' ~ ' + fmt(row.range_end)));
      detail.append(node('p', '조건 일치 ' + number(c.matched) + ' · 불일치 ' + number(c.not_matched) + ' · 평가 불가 ' + number(c.unknown)));
      detail.append(node('p', '시간 창 평가 ' + number(c.evaluated_events) + ' · 탐지 일치 ' + number(c.detection_matches) + ' · 기존 경보 ' + number(c.alerts_existing)));
      detail.append(node('p', '승인된 예외 ' + number(c.policy_excluded) + '건'));
      if (Array.isArray(row.phases)) detail.append(node('p', '보존된 단계 기록: ' + row.phases.map(value => ({evaluated: '평가 종료', committed: '완료 위치 저장', failed: '실패 기록', waiting: '입력 대기'}[value] || '미확인')).join(' / ')));
      box.append(detail);
    }
    if (row.normalized || row.raw) {
      const refs = node('details'); refs.append(node('summary', '해당 로그 확인 정보'));
      if (row.normalized) refs.append(node('p', '분석 문서: ' + row.normalized.index + ' / ' + row.normalized.id));
      if (row.raw) refs.append(node('p', '원본 문서: ' + row.raw.index + ' / ' + row.raw.id));
      box.append(refs);
    }
    if (row.missing_fields?.length) {const missing = node('details'); missing.append(node('summary', '누락 정보 상세'), node('p', row.missing_fields.join(', '))); box.append(missing);}
    if (row.state === 'evaluated') box.append(node('p', '평가는 종료됐지만 최종 처리 위치의 저장은 확인되지 않았습니다.'));
    if (row.error) box.append(node('p', '실행이 실패했습니다. 상단의 분석 상태와 마지막 완료 시각을 확인하세요.'));
    return box;
  }
  function render() {
    $('history-rows').replaceChildren();
    const quiet = [], active = [];
    for (const row of records.values()) (idle(row) ? quiet : active).push(row);
    if (!active.length && quiet.length) $('history-rows').append(node('p', '조회한 완료 실행에는 새 분석 입력이 없습니다. 현재 분석 상태는 상단에서 확인하세요.'));
    for (const row of active) $('history-rows').append(card(row));
    if (quiet.length) {
      const details = node('details'); details.className = 'history-idle panel';
      details.append(node('summary', '새 입력 없는 완료 실행 ' + quiet.length.toLocaleString('ko-KR') + '회' +
        (quiet.some(row => row.assessment) ? ' · 미검증' : '') + ' · 개별 시각 보기'));
      const table = node('table'); table.className = 'history-idle-table';
      for (const row of quiet) {const tr = node('tr'); tr.append(node('td', fmt(row['@timestamp'])), node('td', names[row.rule?.id] || row.rule?.id || '규칙 미기록'), node('td', row.assessment ? '새 입력 없음 · 미검증' : '새 입력 없음')); table.append(tr);}
      details.append(table); $('history-rows').append(details);
    }
  }
  async function load(reset) {
    const version = ++generation;
    if (reset) {
      const end = new Date();
      const minutes = Number($('history-period').value || 1440);
      scope = {kind: $('history-kind').value, start: new Date(end.getTime() - minutes * 60000).toISOString(), end: end.toISOString()};
      if (scope.kind === 'runs') scope.view = 'summary';
      if ($('history-rule').value.trim()) scope.rule = $('history-rule').value.trim();
      cursor = null; records = new Map(); $('history-rows').replaceChildren();
    }
    $('history-state').textContent = '조회 중'; $('history-next').disabled = true;
    try {
      const params = {...scope}; if (cursor) params.after = cursor;
      const response = await fetch('/api/detection/history?' + new URLSearchParams(params), {cache: 'no-store', credentials: 'same-origin'});
      if (!response.ok) throw new Error('이력을 조회하지 못했습니다. 연결과 조회 권한을 확인하세요.');
      const data = await response.json();
      if (version !== generation) return;
      if (!['ok', 'no_index'].includes(data.state) || !Array.isArray(data.rows) || (cursor && data.next === cursor)) throw new Error('이력 응답을 확인할 수 없습니다. 다시 조회하세요.');
      for (const row of data.rows) {
        const key = scope.kind === 'runs' && row.run_id ? row.run_id + ':' + row.rule?.id : row.record_id || 'legacy-' + (++anonymous);
        const previous = records.get(key);
        if (!previous || (rank[row.state] || 0) >= (rank[previous.state] || 0)) records.set(key, row);
      }
      render(); cursor = data.next; $('history-next').hidden = !cursor;
      $('history-state').textContent = data.state === 'no_index' ? '아직 저장된 실행 이력이 없습니다.' : records.size ?
        '조회한 ' + (scope.kind === 'runs' ? '실행 ' : '평가 제외 ') + records.size + '건' + (cursor ? ' · 추가 기록은 다음 페이지에서 확인하세요.' : '') : '조회 기간에 기록이 없습니다.';
    } catch (error) {
      if (version === generation) { $('history-state').textContent = error.message; $('history-next').hidden = !cursor; }
    } finally { if (version === generation) $('history-next').disabled = false; }
  }
  async function pipeline() {
    const box = $('history-pipeline');
    const version = ++pipelineGeneration;
    pipelineController?.abort(); const controller = pipelineController = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch('/api/operations/status', {cache: 'no-store', credentials: 'same-origin', signal: controller.signal});
      if (!response.ok) throw new Error('unavailable');
      const p = await response.json(), detector = p.detector || {};
      if (version !== pipelineGeneration) return;
      const labels = {failed: '실패', success: '최근 실행 확인', running: '처리 중', waiting: '입력 대기', stale: '상태 보고 지연', not_started: '미시작', unavailable: '확인 불가'};
      box.replaceChildren(node('p', '로그 해석: ' + (labels[p.state] || '확인 불가') + ' · 위험 평가: ' + (labels[detector.state] || '확인 불가')),
        node('p', '로그 해석 완료 위치: ' + fmt(p.checkpoint) + ' · 위험 평가 마지막 실행: ' + fmt(detector.last_success)));
      if (p.progress?.state === 'catching_up') box.append(node('p', '현재 구간 ' + number(p.progress.processed) + '건 처리 · 구간 완료 전'));
      if (p.state === 'failed' || detector.state === 'failed') box.append(node('p', '분석 실패가 있습니다. 입력·경보 0건을 정상이나 안전으로 해석하지 마세요.'));
    } catch { if (version === pipelineGeneration) box.textContent = '현재 분석 상태를 확인할 수 없습니다. 이력의 실행 완료만으로 전체 정상 여부를 판단할 수 없습니다.'; }
    finally {clearTimeout(timer);}
  }
  $('history-filter').addEventListener('submit', event => {event.preventDefault(); load(true); pipeline();});
  $('history-next').addEventListener('click', () => load(false));
  load(true); pipeline();
  const pipelineTimer = setInterval(pipeline, 30000);
  window.addEventListener('pagehide', () => {clearInterval(pipelineTimer); pipelineGeneration++; pipelineController?.abort(); generation++;});
})();
