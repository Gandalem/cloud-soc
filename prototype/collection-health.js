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
  const time = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString('ko-KR', {timeZone: 'Asia/Seoul'}) + ' (KST)' : '시각 미보고';
  function cell(row, value) { const td = document.createElement('td'); td.textContent = String(value); row.append(td); return td; }
  const number = value => Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString('ko-KR') : '미보고';
  function metricsCells(row, metrics, collector = '호스트 로그 (Filebeat)') {
    const m = metrics || {};
    const stateName = {unavailable: '미측정', invalid: '보고 형식 확인', stale: '오래된 표본', clock_warning: '시계 확인', recent: '최근 표본'}[m.state] || '미측정';
    const queue = cell(row, stateName);
    const transport = cell(row, stateName);
    const paragraph = (parent, text) => { const p = document.createElement('p'); p.textContent = text; parent.append(p); };
    paragraph(queue, collector); paragraph(transport, collector);
    if (!['recent', 'stale', 'clock_warning'].includes(m.state)) {
      paragraph(queue, m.state === 'invalid' ? '통계 형식을 확인해야 합니다.' : '이 보고에는 유효한 큐 통계가 없습니다.');
      paragraph(transport, '통계 없음은 전송 실패나 오류 0을 뜻하지 않습니다.');
      return;
    }
    paragraph(queue, `전송 대기 ${number(m.queue_events)}건`);
    paragraph(queue, Number.isSafeInteger(m.queue_bytes) && m.queue_bytes >= 0 ? `${(m.queue_bytes / 1048576).toFixed(1)} MiB (${number(m.queue_bytes)} bytes)` : '대기 크기 미보고');
    paragraph(queue, `사용률 ${typeof m.queue_pct === 'number' && Number.isFinite(m.queue_pct) && m.queue_pct >= 0 && m.queue_pct <= 1 ? (m.queue_pct * 100).toFixed(1) + '%' : '미보고'}${m.queue_state === 'high' ? ' · 적체 주의' : ''}`);
    paragraph(queue, '아직 출력 확인 전인 큐 표본 · 유실량 아님');
    paragraph(queue, time(m.sampled_at));
    paragraph(transport, `표본 구간 ${number(m.interval_seconds)}초 · 전송 시도 ${number(m.output_total)} / 수신 확인(ACK) ${number(m.output_acked)}`);
    paragraph(transport, `전송 실패 ${number(m.output_failed)} / 전송 포기 ${number(m.output_dropped)}`);
    paragraph(transport, `통신 읽기 오류 ${number(m.read_errors)} / 쓰기 오류 ${number(m.write_errors)}`);
    if ((m.output_dead_letter || 0) > 0 || (m.output_failure_store || 0) > 0) paragraph(transport, `실패 보관소 이동 ${number(m.output_dead_letter)} / ${number(m.output_failure_store)}`);
    if (m.last_problem_at) paragraph(transport, '최근 오류 관측: ' + time(m.last_problem_at));
    if (m.transport_state === 'error_observed') paragraph(transport, '전송 오류 기록 있음 · 수집기 확인 필요');
    paragraph(transport, '관측 구간만 표시 · 누적 유실량/전체 정상 판정 아님');
    if (['output_failed', 'output_dropped', 'read_errors', 'write_errors'].some(key => m[key] == null)) paragraph(transport, '미보고 항목은 오류 0으로 판단할 수 없습니다.');
    if (m.scan_partial) paragraph(transport, '통계 로그 읽기 범위 제한 · 원본 로그 수집 실패를 뜻하지 않음');
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
        metricsCells(tr, item.network_collector_metrics, '네트워크 (Packetbeat)');
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
