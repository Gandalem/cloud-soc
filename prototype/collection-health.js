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
      state.textContent = data.rows.length ? `${data.rows.length}개 보고 · 큐 상태 / 전송 오류: 미측정` : '수신된 보고가 없습니다. 에이전트 미설치·구버전·전송 지연을 확인하세요.';
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
