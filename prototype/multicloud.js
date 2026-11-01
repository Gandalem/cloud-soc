'use strict';
const el = id => document.getElementById(id);
const names = {aws: 'AWS', azure: 'Microsoft Azure', naver: 'Naver Cloud'};
const labels = {success: '성공', failure: '실패', unknown: '확인 불가'};
const date = value => value ? new Date(value).toLocaleString() : '수신 기록 없음';
function node(tag, content, css) { const n = document.createElement(tag); if (content !== undefined) n.textContent = content; if (css) n.className = css; return n; }
let timelineData=[];
function drawTimeline(input){
 timelineData=input;const target=el('timeline');target.replaceChildren();
 if(!input.length||!input.some(b=>b.doc_count>0)){target.append(node('p','조회 기간의 활동 기록이 없습니다.','empty'));return;}
 const step=Math.max(1,Math.ceil(input.length/24)),buckets=[];
 for(let i=0;i<input.length;i+=step)buckets.push({key:input[i].key,count:input.slice(i,i+step).reduce((n,b)=>n+b.doc_count,0)});
 const width=Math.max(320,target.clientWidth||600),plot=width-70,max=Math.max(1,...buckets.map(b=>b.count)),ns='http://www.w3.org/2000/svg';
 const svg=document.createElementNS(ns,'svg');svg.setAttribute('viewBox',`0 0 ${width} 210`);svg.setAttribute('role','img');svg.setAttribute('aria-label','시간별 감사 이벤트 건수 · 브라우저 현지 시각');
 for(let i=0;i<4;i++){const y=20+i*46,line=document.createElementNS(ns,'line'),text=document.createElementNS(ns,'text');for(const[k,v]of Object.entries({x1:46,x2:width-24,y1:y,y2:y}))line.setAttribute(k,v);text.setAttribute('x','36');text.setAttribute('y',y+4);text.setAttribute('text-anchor','end');text.textContent=Math.round(max*(1-i/3));svg.append(line,text);}
 buckets.forEach((b,i)=>{const r=document.createElementNS(ns,'rect'),h=b.count/max*138;for(const[k,v]of Object.entries({x:46+i*plot/buckets.length,y:158-h,width:Math.max(.5,plot/buckets.length-4),height:h,rx:1}))r.setAttribute(k,v);const title=document.createElementNS(ns,'title');title.textContent=date(b.key)+' · '+b.count+'건';r.append(title);svg.append(r);});
 for(const i of [...new Set([0,Math.floor((buckets.length-1)/2),buckets.length-1])]){const t=document.createElementNS(ns,'text');t.setAttribute('x',46+i*plot/Math.max(1,buckets.length-1));t.setAttribute('y','191');t.setAttribute('text-anchor',i===0?'start':i===buckets.length-1?'end':'middle');t.textContent=new Date(buckets[i].key).toLocaleString([],{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'});svg.append(t);}target.append(svg);
}
window.addEventListener('resize',()=>drawTimeline(timelineData));
let busy = false;
async function load() {
  if (busy) return;
  busy = true; el('refresh').disabled = true; el('status').textContent = '로그를 불러오는 중입니다.';
  try {
    const params = new URLSearchParams({hours: el('hours').value});
    for (const key of ['provider', 'outcome']) if (el(key).value) params.set(key, el(key).value);
    const response = await fetch('/api/multicloud?' + params, {credentials: 'same-origin', headers: {'Accept': 'application/json'}});
    if (response.status === 401) { window.location.assign('/login'); return; }
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || '로그를 조회하지 못했습니다.');
    el('cards').replaceChildren();
    for (const provider of Object.keys(names)) {
      const bucket = data.metrics.providers?.buckets?.find(v => v.key === provider);
      const card = node('article', undefined, 'card');
      card.append(node('h2', names[provider]), node('strong', (bucket?.doc_count || 0).toLocaleString()), node('p', `실패 ${(bucket?.failures?.doc_count || 0).toLocaleString()}건`), node('small', `마지막 이벤트: ${date(bucket?.last_event?.value_as_string)}`));
      el('cards').append(card);
    }
    drawTimeline(data.metrics.timeline?.buckets || []);
    el('actions').replaceChildren(...(data.metrics.actions?.buckets || []).map(b => node('span', `${b.key} · ${b.doc_count}건`, 'chip')));if(!el('actions').children.length)el('actions').append(node('p','조회 기간의 작업 기록이 없습니다.','empty'));
    el('events').replaceChildren();
    for (const e of data.events) {
      const row = node('tr');
      const values = [date(e['@timestamp']), `${names[e.cloud.provider]} / ${e.cloud.account.id}`, e.organization.id, `${e.event.action} / ${e.event.dataset}`, labels[e.event.outcome] || '확인 불가', e.user?.id || '—', e.source?.ip || '—', e.resource?.id || '—'];
      values.forEach((v, i) => row.append(node('td', v, i === 4 ? e.event.outcome : undefined)));
      el('events').append(row);
    }
    el('count').textContent = `총 ${data.total.toLocaleString()}건`;
    el('status').textContent = data.total ? '현재 필터에 해당하는 감사 로그입니다.' : '현재 권한과 조회 조건에 해당하는 로그가 없습니다.';
    el('updated').textContent = `갱신 ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    el('status').textContent = err.message;
    el('updated').textContent = '갱신 실패 · 이전 표시 데이터는 최신 상태가 아닙니다.';
  } finally { busy = false; el('refresh').disabled = false; }
}
for (const key of ['hours','provider','outcome']) el(key).addEventListener('change', load);
el('refresh').addEventListener('click', load);
setInterval(() => { if (!document.hidden) load(); }, 30000);
load();
