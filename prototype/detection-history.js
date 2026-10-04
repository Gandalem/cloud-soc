(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let generation = 0, cursor = null, scope = {};
  const states = {evaluated: '평가 종료 · 처리 위치 확정 전', committed: '처리 완료 · 처리 위치 저장됨', failed: '실행 실패', waiting: '새 처리 구간 대기'};
  const reasons = {late_event: '허용 지연 초과', missing_condition_fields: '조건 필드 누락', missing_group_fields: '그룹 필드 누락', invalid_event_time: '발생 시각 오류', future_event_clock: '미래 시각 이상'};
  const fmt = value => value ? new Date(value).toLocaleString('ko-KR', {timeZone: 'Asia/Seoul'}) : '미기록';
  function node(tag, text) { const element = document.createElement(tag); if (text !== undefined) element.textContent = text; return element; }
  async function load(reset) {
    const version = ++generation;
    if (reset) {
      const end = new Date();
      scope = {kind: $('history-kind').value, start: new Date(end.getTime() - 86400000).toISOString(), end: end.toISOString()};
      if ($('history-rule').value.trim()) scope.rule = $('history-rule').value.trim();
      cursor = null; $('history-rows').replaceChildren();
    }
    $('history-state').textContent = '조회 중'; $('history-next').disabled = true;
    try {
      const params = {...scope}; if (cursor) params.after = cursor;
      const response = await fetch('/api/detection/history?' + new URLSearchParams(params), {cache: 'no-store', credentials: 'same-origin'});
      if (!response.ok) throw new Error('이력 조회 실패: 연결·권한·조회 조건을 확인하세요.');
      const data = await response.json();
      if (version !== generation) return;
      if (!['ok', 'no_index'].includes(data.state) || !Array.isArray(data.rows)) throw new Error('이력 응답을 확인하세요.');
      for (const row of data.rows) {
        const box = node('section'); box.className = 'ops-evidence';
        box.append(node('h2', (row.rule?.id || '미기록') + ' · ' + (states[row.state] || reasons[row.reason] || '미확인')));
        box.append(node('p', '기록 시각 (KST): ' + fmt(row['@timestamp'])));
        if (row.counts) {
          const c = row.counts;
          box.append(node('p', '새 입력 ' + c.input_events + ' · 조건 일치 ' + c.matched + ' · 불일치 ' + c.not_matched + ' · 평가 불가 ' + c.unknown + ' · 제외 ' + c.excluded));
          box.append(node('p', '시간 창 평가 이벤트 ' + (c.evaluated_events ?? '미기록') + ' · 탐지 일치 ' + (c.detection_matches ?? '미기록') + ' · 새 경보 ' + c.alerts_created + ' · 기존 경보 ' + c.alerts_existing));
        }
        if (row.normalized) box.append(node('p', '정규화 참조: ' + row.normalized.index + ' / ' + row.normalized.id));
        if (row.raw) box.append(node('p', '원본 참조: ' + row.raw.index + ' / ' + row.raw.id));
        if (row.missing_fields?.length) box.append(node('p', '누락 필드: ' + row.missing_fields.join(', ')));
        if (row.error) box.append(node('p', '실행 실패 · 처리 위치는 운영 현황에서 확인하세요.'));
        $('history-rows').append(box);
      }
      cursor = data.next; $('history-next').hidden = !cursor;
      $('history-state').textContent = data.state === 'no_index' ? '이력 저장소가 준비되지 않았습니다.' : data.rows.length ? '조회 성공' : '조회 범위의 기록이 없습니다.';
    } catch (error) {
      if (version === generation) { $('history-state').textContent = error.message; $('history-next').hidden = true; }
    } finally { if (version === generation) $('history-next').disabled = false; }
  }
  $('history-filter').addEventListener('submit', event => {event.preventDefault(); load(true);});
  $('history-next').addEventListener('click', () => load(false));
  load(true);
})();
