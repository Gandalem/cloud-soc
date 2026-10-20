(() => {
  'use strict';
  const labels = { recent: '최근 수신', delayed: '수신 지연', silent: '장기 미수신', unknown: '판단 불가' };
  const escape = value => String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  const date = value => value && Number.isFinite(Date.parse(value)) ? new Intl.DateTimeFormat('ko-KR', { timeZone: 'Asia/Seoul', dateStyle: 'short', timeStyle: 'medium' }).format(new Date(value)) : '없음';
  const status = value => Object.hasOwn(labels, value) ? value : 'unknown';
  function rowsFor(rows, query, selected) {
    const q = query.trim().toLowerCase();
    return rows.filter(row => (selected === 'all' || status(row.status) === selected) &&
      [row.host_name, ...(row.host_ips || []), row.os, row.organization, row.agent_id, row.agent_type, row.version].join(' ').toLowerCase().includes(q));
  }
  function rowMarkup(row) {
    const state = status(row.status);
    const reason = row.reason === 'future_ingestion_time' ? '서버 시각 확인 필요' : state === 'unknown' ? '수신 시각 기록 없음' : '';
    const show = value => escape(value || '정보 없음');
    return `<tr><td><span class="activity-badge ${state}">${labels[state]}</span><small class="agent-meta">${reason}</small></td><td><strong>${show(row.host_name)}</strong><small class="agent-meta">${(row.host_ips || []).map(escape).join('<br>') || 'IP 정보 없음'}</small></td><td>${show(row.os)}</td><td>${show(row.organization)}</td><td>${show(row.agent_type)} <span class="agent-meta">${show(row.version)}</span><code class="agent-meta agent-id">${show(row.agent_id)}</code></td><td><time>${date(row.last_received)}</time></td><td><time>${date(row.last_event)}</time></td><td>${Number.isSafeInteger(row.documents) && row.documents >= 0 ? row.documents.toLocaleString('ko-KR') : '-'}</td></tr>`;
  }
  // Export pure helpers for offline tests without loading demo data into production.
  if (typeof module !== 'undefined' && module.exports) { module.exports = { rowsFor, rowMarkup, status }; return; }
  const $=selector=>document.querySelector(selector);
  const state={snapshot:null,cursors:[null],page:0,displayedPage:0,healthy:false};
  function render(){
    const rows=state.healthy?state.snapshot.agents:[],shown=rowsFor(rows,$('#agent-search').value,$('#agent-filter').value);
    const body=document.createElement('tbody');body.innerHTML=shown.map(rowMarkup).join('');
    [...body.children].forEach((r,i)=>r.dataset.liveKey=shown[i].agent_id||String(i));window.CloudSOCLive.children($('#agent-rows'),body.childNodes);
    for(const[id,items]of [['count-all',rows],['count-recent',rows.filter(r=>r.status==='recent')],['count-delayed',rows.filter(r=>r.status==='delayed')],['count-other',rows.filter(r=>!['recent','delayed'].includes(r.status))]])$('#'+id).textContent=state.healthy?String(items.length):'-';
    $('#row-count').textContent=state.healthy?'현재 페이지 '+rows.length+'개 · 필터 결과 '+shown.length+'개':'조회 결과 없음';
    $('#status-empty').hidden=state.healthy&&shown.length>0;$('#empty-title').textContent=state.healthy?'일치하는 수집기가 없습니다.':'수신 상태를 판단할 수 없습니다.';$('#empty-description').textContent='검색 조건과 마지막 조회 시각을 확인하세요.';
    $('#status-page').textContent=(state.displayedPage+1)+' 페이지';$('#status-previous').disabled=state.page===0;$('#status-next').disabled=!state.healthy||!state.snapshot.next_cursor;
    const missing=state.snapshot?.unidentified_documents||0;$('#unidentified-note').hidden=!missing;$('#unidentified-note').textContent='agent.id가 없는 문서 '+missing+'건은 수집기 목록에서 제외했습니다.';
  }
  const live=window.CloudSOCLive.create({host:document.querySelector('.status-controls'),interval:10000,
    load:async signal=>{const cursor=state.cursors[state.page];const response=await fetch('/api/agents/status'+(cursor?'?cursor='+encodeURIComponent(cursor):''),{credentials:'same-origin',cache:'no-store',signal});
      const data=await response.json();if(!response.ok)throw new Error(data.error||'수신 현황 조회 실패');if(!Array.isArray(data.agents)||!data.checked_at||data.basis!=='server_ingestion')throw new Error('잘못된 수신 현황 응답입니다.');return data;},
    apply:data=>{state.snapshot=data;state.healthy=true;state.displayedPage=state.page;state.cursors.length=state.page+1;if(data.next_cursor)state.cursors.push(data.next_cursor);$('#checked-at').textContent=date(data.checked_at);$('#query-state').textContent='조회 성공 · 수신 기록 기준';$('#status-error').hidden=true;render();},
    onError:error=>{state.page=state.displayedPage;$('#query-state').textContent='갱신 실패 · 마지막 조회 내용';$('#status-error').hidden=false;$('#status-error').textContent=error.name==='TypeError'?'중앙 서버에 연결하지 못했습니다.':error.message;}});
  $('#status-refresh').addEventListener('click',()=>live.refresh(true));$('#agent-search').addEventListener('input',render);$('#agent-filter').addEventListener('change',render);
  $('#status-previous').addEventListener('click',()=>{if(state.page>0){state.page--;live.refresh(true);}});
  $('#status-next').addEventListener('click',()=>{if(state.snapshot?.next_cursor){state.page++;live.refresh(true);}});
  render();live.start();
})();
