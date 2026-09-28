/* Read-only, no sample fallback and no untrusted HTML interpolation. */
(() => {
  'use strict';
  const rows = document.querySelector('#health-rows');
  const state = document.querySelector('#query-state');
  const next = document.querySelector('#next');
  let cursor = null;
  let controller = null;
  let generation = 0;
  const statuses = {selected: '선택', unreadable: '읽기 실패', enumeration_error: '탐색 오류', disabled: '비활성',
    unsupported_direct_channel: '미지원 채널', unsafe_name: '이름 제외', unsafe_path: '경로 제외', missing: '경로 없음',
    reparse_point: '링크 제외', symlink: '링크 제외', binary_archive_or_secret: '비밀·문서·바이너리 제외',
    unsupported_encoding: '미지원 인코딩', unsupported_encoding_or_binary: '인코딩·바이너리 제외',
    binary: '바이너리 제외', empty_pending: '빈 파일 대기', policy_excluded: '정책 제외'};
  const time = value => new Date(value).toLocaleString('ko-KR', {timeZone: 'Asia/Seoul'}) + ' (KST)';
  function cell(row, value) { const td = document.createElement('td'); td.textContent = String(value); row.append(td); return td; }
  const number = value => typeof value === 'number' && Number.isFinite(value) ? value.toLocaleString('ko-KR') : '미보고';
  function metricsCells(row, metrics) {
    const m = metrics || {};
    const stateName = {unavailable: '미측정', invalid: '보고 형식 확인', stale: '오래된 표본', clock_warning: '시계 확인', recent: '최근 표본'}[m.state] || '미측정';
    const queue = cell(row, stateName);
    const transport = cell(row, stateName);
    if (!['recent', 'stale', 'clock_warning'].includes(m.state)) return;
    const paragraph = (parent, text) => { const p = document.createElement('p'); p.textContent = text; parent.append(p); };
    paragraph(queue, `대기 ${number(m.queue_events)}건 / ${number(m.queue_bytes)} bytes`);
    paragraph(queue, `사용률 ${typeof m.queue_pct === 'number' ? (m.queue_pct * 100).toFixed(1) + '%' : '미보고'}${m.queue_state === 'high' ? ' · 적체 주의' : ''}`);
    paragraph(queue, time(m.sampled_at));
    paragraph(transport, `표본 구간 ${number(m.interval_seconds)}초 · 시도 ${number(m.output_total)} / ACK ${number(m.output_acked)}`);
    paragraph(transport, `재시도 실패 ${number(m.output_failed)} / 포기 ${number(m.output_dropped)}`);
    paragraph(transport, `통신 읽기 오류 ${number(m.read_errors)} / 쓰기 오류 ${number(m.write_errors)}`);
    if ((m.output_dead_letter || 0) > 0 || (m.output_failure_store || 0) > 0) paragraph(transport, `실패 보관소 이동 ${number(m.output_dead_letter)} / ${number(m.output_failure_store)}`);
    if (m.last_problem_at) paragraph(transport, '최근 오류 관측: ' + time(m.last_problem_at));
    if (m.transport_state === 'error_observed') paragraph(transport, '전송 오류 기록 있음 · 수집기 확인 필요');
    paragraph(transport, '관측 구간만 표시 · 누적 유실량/전체 정상 판정 아님');
    if (m.scan_partial) paragraph(transport, '읽기 범위 제한 있음');
  }
  async function load(after = null) {
    controller?.abort(); controller = new AbortController();
    const active = controller;
    const request = ++generation;
    const timer = setTimeout(() => active.abort(), 15000);
    rows.replaceChildren(); next.disabled = true; cursor = null; state.textContent = '조회 중';
    try {
      const response = await fetch('/api/agents/health' + (after ? '?cursor=' + encodeURIComponent(after) : ''),
        {signal: active.signal, credentials: 'same-origin', cache: 'no-store'});
      if (!response.ok) { const error = new Error('request failed'); error.login = response.status === 401; throw error; }
      const data = await response.json();
      if (request !== generation) return;
      if (!Array.isArray(data.rows) || data.rows.length > 50) throw new Error('잘못된 보고 응답입니다.');
      for (const item of data.rows) {
        const tr = document.createElement('tr');
        cell(tr, (item.host || '알 수 없음') + ' / ' + (item.organization || '-'));
        cell(tr, ({recent: '최근 수신', stale: '보고 지연', unknown: '판단 불가'})[item.report_state] || '판단 불가');
        cell(tr, `${item.selected} / ${item.excluded} / ${item.errors}`);
        cell(tr, time(item.generated_at) + ' / ' + time(item.received_at));
        cell(tr, `${item.delay_seconds ?? '?'}초 / v${item.policy_version}${item.clock_warning ? ' (시계 확인)' : ''}`);
        metricsCells(tr, item.collector_metrics);
        const td = cell(tr, '');
        const details = document.createElement('details'); const summary = document.createElement('summary');
        summary.textContent = `${item.sources.length}개 보기 (생략 ${item.omitted_sources}개)`;
        details.append(summary);
        for (const source of item.sources) {
          const line = document.createElement('p');
          const id = document.createElement('code'); id.textContent = source.id.slice(0, 12); id.title = source.id;
          line.append(id, ' : ' + (statuses[source.status] || '알 수 없음')); details.append(line);
        }
        td.append(details); rows.append(tr);
      }
      cursor = data.next_cursor; next.disabled = !cursor;
      state.textContent = data.rows.length ? `${data.rows.length}개 보고 · 큐/전송은 표본 기준, 미지원 에이전트는 미측정` : '수신된 보고가 없습니다. 에이전트 미설치·구버전·전송 지연을 확인하세요.';
    } catch (error) {
      if (request !== generation) return;
      rows.replaceChildren(); cursor = null; next.disabled = true;
      state.textContent = error.name === 'AbortError' ? '조회 시간 초과. 다시 시도하세요.' : error.login ? '관리자 로그인이 필요합니다.' : '조회 실패: 서버·권한·보고 형식을 확인하세요.';
    } finally { clearTimeout(timer); }
  }
  document.querySelector('#refresh').addEventListener('click', () => load());
  next.addEventListener('click', () => { if (cursor) load(cursor); });
  load();
})();
