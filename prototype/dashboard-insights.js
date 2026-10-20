/* Private dashboard insight widgets. Server scopes every read and mutation. */
(() => {
 'use strict';
 const N=(tag,text,cls)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=String(text);if(cls)e.className=cls;return e;};
 const state=new Map(),pending=new Map();let epoch=0;
 const when=v=>v==null?'기록 없음':new Date(typeof v==='number'?v*1000:v).toLocaleString('ko-KR',{timeZone:'Asia/Seoul',hour12:false});
 const button=(label,fn)=>{const b=N('button',label);b.type='button';b.addEventListener('click',fn);return b;};
 async function request(path,options={}){
  const response=await fetch(path,{credentials:'same-origin',cache:'no-store',...options});let data;
  try{data=await response.json();}catch{throw new Error('자료를 읽지 못했습니다.');}
  if(!response.ok)throw new Error(data.error||'요청을 처리하지 못했습니다.');return data;
 }
 async function shared(path){
  const old=pending.get(path);if(old&&Date.now()-old.at<30000)return old.promise;
  if(pending.size>50)pending.clear();
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),20000);
  const promise=request(path,{signal:controller.signal}).finally(()=>clearTimeout(timer));
  pending.set(path,{promise,at:Date.now(),controller});try{return await promise;}catch(e){pending.delete(path);throw e;}
 }
 function text(box,value){box.append(N('p',value,'insight-note'));}
 function list(box,headers,rows){
  if(!rows.length){text(box,'해당 범위의 기록이 없습니다.');return;}
  const scroll=N('div',undefined,'insight-table'),t=N('table'),head=N('tr');headers.forEach(h=>head.append(N('th',h)));const thead=N('thead');thead.append(head);t.append(thead);
  const body=N('tbody');rows.forEach(row=>{const tr=N('tr');row.forEach(value=>{const td=N('td');td.append(value instanceof Node?value:document.createTextNode(String(value??'기록 없음')));tr.append(td);});body.append(tr);});t.append(body);scroll.append(t);box.append(scroll);
 }
 function link(title,url){const a=N('a',title);a.href=url;return a;}
 function formField(form,name,label,value='',type='text'){
  const l=N('label',label),input=N('input');input.name=name;input.type=type;input.value=value;input.required=true;l.append(input);form.append(l);return input;
 }
 function fleet(box,data){
  text(box,'현재 상태 · 대시보드 조회 기간과 별도');
  const labels={reporting:'보고 중',delayed:'보고 지연',report_missing:'보고 두절',awaiting_first_report:'최초 보고 대기',paused:'일시중지',revoked:'폐기',credential_expired:'자격 증명 만료',credential_reset_required:'자격 증명 재설정 필요',unknown:'확인 불가'};
  text(box,'등록 '+data.total+'대 · '+Object.entries(data.counts||{}).map(([k,n])=>(labels[k]||k)+' '+n+'대').join(' · '));
  const management=N('details');management.append(N('summary','상태 보고 장치 등록'));
  const form=N('form',undefined,'insight-form');const org=formField(form,'organization','조직 ID'),label=formField(form,'label','장치 이름'),interval=formField(form,'interval','보고 주기 (초)','30','number'),days=formField(form,'days','자격 증명 유효일','30','number');
  interval.min='15';interval.max='300';days.min='1';days.max='90';org.maxLength=128;label.maxLength=80;
  const submit=N('button','등록');submit.type='submit';const result=N('div');form.append(submit,result);
  const requestId=crypto.randomUUID();
  form.addEventListener('submit',async e=>{e.preventDefault();submit.disabled=true;result.replaceChildren();try{
   const reply=await request('/api/dashboard-devices',{method:'POST',headers:{'Content-Type':'application/json','X-Cloud-SOC':'portal'},body:JSON.stringify({request_id:requestId,organization:org.value.trim(),label:label.value.trim(),interval:Number(interval.value),days:Number(days.value)})});
   text(result,'발급됐습니다. 자격 증명은 이 응답에서 한 번만 표시됩니다. 상태 보고에는 HTTPS 연결을 사용하세요.');
   const secret=N('output',reply.credential,'insight-credential');result.append(secret);text(result,'장치 ID '+reply.id+' · 실행 세대 '+reply.generation);
   result.append(button('표시 닫기',()=>{secret.textContent='';result.replaceChildren();management.open=false;}));
  }catch(error){text(result,error.message);}finally{submit.disabled=false;}});
  management.append(form);box.append(management);
  list(box,['장치 / 조직','보고 상태','수집기','마지막 보고','관리'],(data.rows||[]).map(r=>{
   const controls=N('div',undefined,'insight-actions');
   for(const [action,title] of [['pause','중지'],['resume','재개'],['rotate','키 회전'],['revoke','폐기']])controls.append(button(title,async()=>{
    if(!confirm(r.label+' — '+title+'할까요?'))return;
    try{const reply=await request('/api/dashboard-devices/'+encodeURIComponent(r.id),{method:'POST',headers:{'Content-Type':'application/json','X-Cloud-SOC':'portal'},body:JSON.stringify({action,version:r.version,...(action==='rotate'?{days:30}:{})})});
     controls.replaceChildren(N('span','변경됐습니다. 목록을 갱신하면 적용됩니다.'));
     if(reply.credential){const output=N('output',reply.credential,'insight-credential');controls.append(output,N('span','실행 세대 '+reply.generation),button('표시 닫기',()=>output.remove()));}
    }catch(error){text(controls,error.message);}
   }));
   return [r.label+' / '+r.organization+' / '+r.id,labels[r.state]||r.state,{running:'실행 보고',error:'오류 보고',stopped:'중단 보고',unknown:'미확인'}[r.collector?.state]||'보고 없음',when(r.reported_at),controls];
  }));
  text(box,'최근 '+Math.min(data.rows?.length||0,50)+'대 표시 · 상태 건수는 전체 등록 장치 기준입니다. 보고 두절만으로 장치 전원 종료를 단정하지 않습니다.');
  const paging=N('div',undefined,'insight-actions');
  const page=offset=>request('/api/dashboard-data/fleet?offset='+offset).then(reply=>{if(box.querySelector('output.insight-credential')&&!confirm('발급된 자격 증명 표시를 닫고 이동할까요?'))return;box.replaceChildren();fleet(box,reply);}).catch(error=>text(box,error.message));
  if(data.offset>0)paging.append(button('이전 장치',()=>page(Math.max(0,data.offset-50))));
  if(data.next_offset!=null)paging.append(button('다음 장치',()=>page(data.next_offset)));box.append(paging);

 }
 function evidence(box,w,data,view){
  const alerts=data.sections?.alerts;
  if(alerts?.state!=='ok'){text(box,'경보 자료를 조회할 수 없습니다.');return;}
  const rows=(alerts.rows||[]).slice(0,5);
  if(!rows.length){text(box,'선택 기간에 표시할 경보가 없습니다.');return;}
  text(box,'최근 경보 5개 · 선택한 경보의 규칙 일치 근거');
  const select=N('select');select.setAttribute('aria-label','근거를 볼 경보');
  rows.forEach(r=>{const o=N('option',r.title||r.rule);o.value=r.id;select.append(o);});
  if(rows.some(r=>r.id===view.selected))select.value=view.selected;else view.selected=select.value;
  const detail=N('div',undefined,'insight-evidence');box.append(select,detail);
  async function show(offset=0){
   view.selected=select.value;const id=select.value,ticket=++view.ticket,current=epoch;
   if(offset===0)detail.replaceChildren(N('p','근거 조회 중'));
   try{const reply=await shared('/api/dashboard-data/evidence?'+new URLSearchParams({id,offset:String(offset)}));
    if(view.ticket!==ticket||epoch!==current)return;
    if(offset===0){detail.replaceChildren();text(detail,reply.kind==='sequence'?'저장된 규칙 일치 순서':'일치 근거 목록 · 사건 간 인과관계를 뜻하지 않습니다.');text(detail,'근거 '+reply.total+'건 · 규칙 버전 '+(reply.rule_version||'기록 없음')+' · 조회 '+when(reply.checked_at));}
    const ordered=N('ol',undefined,'insight-timeline');
    for(const r of reply.rows){const item=N('li'),event=r.event||{};item.append(N('strong',(r.position+1)+'. '+(event.action||'행위 기록 없음')),N('time',when(event.timestamp)),N('span',({success:'성공',failure:'실패',unknown:'결과 미확인'}[event.outcome]||'결과 기록 없음')));
     text(item,r.state==='exact_reference'?(r.integrity==='normalized_hash_verified'?'정규화 해시·정확한 원본 참조 확인':'원본 참조 확인 · 정규화 해시 미확인'):'근거 상태: '+r.state);
     if(r.raw)text(item,r.raw.index+' / '+r.raw.id);
     item.append(link('원본 근거 상세','workbench.html?'+new URLSearchParams({alert:id})));ordered.append(item);
    }
    detail.append(ordered);detail.querySelector('.insight-more')?.remove();
    if(reply.next_offset!==null){const more=button('근거 더 보기',()=>show(reply.next_offset));more.className='insight-more';detail.append(more);}
   }catch(error){if(view.ticket===ticket)text(detail,error.message);}
  }
  select.addEventListener('change',()=>show());show();
 }
 function cloud(box,w,data){
  if(data.state==='no_cloud_data'){text(box,'선택 범위에 클라우드 기록이 없습니다. 수집 연결 상태는 별도로 확인해 주세요.');return;}
  if(data.state==='no_index'){text(box,'클라우드 수집 자료가 없습니다.');return;}
  text(box,'전체 '+data.recognized+'건 · 해석 제외 '+data.invalid_or_unsupported+'건 · 서버 수신 시각 기준');
  if(data.unidentified_account_events)text(box,'계정 식별이 없거나 보호된 이벤트 '+data.unidentified_account_events+'건은 개별 계정 수에 포함하지 않습니다.');
  if(['cloud-services','cloud-accounts'].includes(w.type)){
   let groups=w.type==='cloud-services'?(data.services||[]):(data.accounts||[]).map(r=>({title:r.organization+' / '+r.provider+' / '+r.account,count:r.count}));
   if(w.config.sort==='count')groups=[...groups].sort((a,b)=>b.count-a.count);
   text(box,'전체 그룹 '+(w.type==='cloud-services'?data.service_total:data.account_total)+'개 중 '+Math.min(groups.length,w.config.limit)+'개 표시');
   window.CloudSOCWidgets.parts(box,groups.slice(0,w.config.limit),w.config.chart);
  }
  else{const group=w.type==='cloud-iam'?data.iam:w.type==='cloud-audit'?data.audit:data;const rows=group.rows||[];
   text(box,'해당 분류 '+(group.count??data.recognized)+'건 · 최근 목록 '+Math.min(rows.length,w.config.limit)+'건');
   list(box,['수신 시각','공급자 / 계정','관측 행위','상세'],rows.slice(0,w.config.limit).map(r=>[when(r.received_at),r.cloud_provider+' / '+(r.cloud_account||'계정 기록 없음'),r.action||r.interpretation?.fields?.action||'행위 기록 없음',link('통합 로그','logs.html')]));
  }
 }
 const handles=meta=>meta?.renderer==='evidence'||['cloud','fleet','geo','accounts','evaluation'].includes(meta?.source);
 function render(box,w,meta,result,extras={}){
  if(!result?.body){text(box,result?.loading?'자료 조회 중':'자료를 조회하지 못했습니다.');return;}
  if(box.querySelector('details[open],output.insight-credential')||box.matches(':focus-within'))return;
  const view=state.get(w.id)||{ticket:0};state.set(w.id,view);box.replaceChildren();box.classList.add('insight-widget');
  if(result.stale)text(box,'갱신 실패 · 마지막 조회 내용입니다.');
  if(meta.renderer==='evidence'){evidence(box,w,result.body,view);return;}
  if(meta.source==='fleet'){fleet(box,result.body);return;}
  if(meta.source==='cloud'){cloud(box,w,result.body);return;}
  window.CloudSOCInsightMetrics?.render(box,w,meta,result.body,{N,text,list,link,button,request,when,formField});
 }
 window.CloudSOCInsights={handles,render,request};
 window.addEventListener('pagehide',()=>{epoch++;pending.forEach(r=>r.controller?.abort());pending.clear();state.clear();});
})();
