(() => {
  "use strict";
  const $ = id => document.getElementById(id), form = $("case-filters");
  const listPage = ['cases.html','operations.html'].includes(document.body?.dataset?.caseListPage) ? document.body.dataset.caseListPage : 'index.html';
  const states = {new:"신규",triage:"초기 분류",investigating:"조사 중",escalated:"상위 이관",closed:"종결"};
  const priorities = {critical:"긴급",high:"높음",medium:"중간",low:"낮음"};
  let page = 1, generation = 0;
  const saved = new URLSearchParams(window.location.search);
  for (const field of form.querySelectorAll("select")) if (saved.has("case_" + field.name) && Array.from(field.options).some(o => o.value === saved.get("case_" + field.name))) field.value = saved.get("case_" + field.name);
  if (/^[1-9][0-9]{0,4}$/.test(saved.get("case_page") || "")) page = Number(saved.get("case_page"));
  function node(tag, text) {const n=document.createElement(tag);n.textContent=text;return n;}
  let applied=null,shown=null,appliedBack=null;
  const pending=window.CloudSOCLive.notice($('case-queue'),'새 사건');
  function params(){const p=new URLSearchParams();for(const [key,value]of new FormData(form))if(value)p.set(key,value);p.set('page',String(page));return p;}
  function render(data){
    const c=data.counts;$('case-counts').textContent='현재 필터: 전체 '+c.total+' · 미종결 '+c.open+' · 조사 중 '+c.investigating+' · 미배정 '+c.unassigned;
    const body=document.createDocumentFragment(),back=new URLSearchParams(appliedBack);
    for(const row of data.rows){const tr=node('tr',''),td=node('td',''),link=node('a',row.title);tr.dataset.liveKey=row.id;link.href='workbench.html?'+new URLSearchParams({case:row.id,return:back.toString(),return_page:listPage});td.append(link);tr.append(td);
      for(const value of [row.organization,priorities[row.priority],states[row.status],row.owner||'미배정',new Date(row.created_at).toLocaleString('ko-KR',{timeZone:'Asia/Seoul'})])tr.append(node('td',value));body.append(tr);}
    if(!data.rows.length)$('case-counts').textContent+=' · 해당 사건 없음';
    window.CloudSOCLive.children($('case-rows'),body.childNodes);$('case-page').textContent=page+' 페이지';$('case-prev').disabled=page<=1;$('case-next').disabled=!data.has_next;
  }
  const live=window.CloudSOCLive.create({host:$('case-queue'),interval:10000,enabled:()=>applied===params().toString(),
    load:async signal=>{const response=await fetch('/api/cases?'+applied,{credentials:'same-origin',cache:'no-store',signal});if(!response.ok)throw new Error('사건 조회 실패 ('+response.status+')');const data=await response.json();if(!Array.isArray(data.rows)||data.rows.length>25||!Number.isSafeInteger(data.counts?.total))throw new Error('잘못된 사건 응답입니다.');return data;},
    apply:(data,{manual})=>{if(manual||!shown){shown=data;pending.clear();render(shown);}else if(JSON.stringify(data.rows)!==JSON.stringify(shown.rows)){const added=data.rows.filter(r=>!shown.rows.some(old=>old.id===r.id)).length;pending.offer(added,()=>{shown=data;render(shown);});}else render(data);$('case-error').hidden=true;},
    onError:error=>{$('case-error').hidden=false;$('case-error').textContent=error.message+' · 마지막 조회 내용 유지';}});
  function load(anchor='#case-queue'){applied=params().toString();pending.clear();const back=new URLSearchParams();for(const[k,v]of new FormData(form))back.set('case_'+k,v);back.set('case_page',String(page));appliedBack=back.toString();window.history.replaceState(null,'',listPage+'?'+back+anchor);return live.refresh(true);}
  form.addEventListener("submit",event=>{event.preventDefault();page=1;load();});
  $("case-prev").addEventListener("click",()=>{if(page>1){page--;load();}});
  $("case-next").addEventListener("click",()=>{page++;load();});
  window.addEventListener("pagehide",()=>{generation++;$("case-rows").replaceChildren();});
  load(listPage === "cases.html" ? "#case-queue" : (window.location.hash || ""));
})();
