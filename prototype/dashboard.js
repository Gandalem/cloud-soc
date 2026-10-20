/* Fixed widget catalogue; persisted layout contains no telemetry or query scope. */
(() => {
  'use strict';
  const titles = {overview:'관제 요약',intake:'로그 수신 추이',trend:'경보 추이',severity:'최근 경보 심각도',alerts:'최근 경보',cases:'진행 중인 사건'};
  const ids=Object.keys(titles), knownIds=[...ids,'pipeline','processing'], $=id=>document.getElementById(id);
  const copy=value=>JSON.parse(JSON.stringify(value));
  const defaults=()=>({name:'내 대시보드',period:1440,theme:'light',widgets:ids.map(id=>({id,size:['overview','alerts'].includes(id)?'wide':'normal'}))});
  const numeric=value=>Number.isSafeInteger(value)&&value>=0;
  const time=value=>typeof value==='string'&&Number.isFinite(Date.parse(value))?new Date(value).toLocaleString('ko-KR',{timeZone:'Asia/Seoul',hour12:false}):'미확인';
  const count=section=>section?.state==='ok'&&numeric(section.count)?section.count.toLocaleString('ko-KR'):'미확인';
  function validLayout(layout) {return layout&&typeof layout.name==='string'&&layout.name.length>0&&layout.name.length<=48&&[60,1440,10080].includes(layout.period)&&['light','dark'].includes(layout.theme)&&Array.isArray(layout.widgets)&&layout.widgets.length>0&&layout.widgets.length<=knownIds.length&&new Set(layout.widgets.map(w=>w?.id)).size===layout.widgets.length&&layout.widgets.every(w=>knownIds.includes(w?.id)&&['normal','wide'].includes(w.size));}
  window.CloudSOCDashboard={validLayout,count,defaults};
  if(!$('dashboard-grid'))return;
  const personal=document.body.dataset.dashboard==='personal';
  let saved={revision:0,layout:defaults()},layout=defaults(),draft=[],data=null,cases=null,version=0,controller,timer,editing=false,ready=!personal,expandedAlerts=false;
  function node(tag,text,cls) {const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;}
  function link(label,href) {const e=node('a',label);e.href=href;return e;}
  function svg(tag,attrs={}) {const e=document.createElementNS('http://www.w3.org/2000/svg',tag);for(const[k,v]of Object.entries(attrs))e.setAttribute(k,String(v));return e;}
  async function request(path,options={}) {const r=await fetch(path,{credentials:'same-origin',cache:'no-store',...options});const body=await r.json();if(!r.ok){const e=new Error(body.error||'조회하지 못했습니다. 연결과 권한을 확인하세요.');e.status=r.status;throw e;}return body;}
  function unavailable(box,section) {box.append(node('p',section?.state==='no_index'?'저장된 기록이 없습니다.':'조회 권한·연결·측정 상태를 확인하세요.','dash-empty'));}
  function series(box,section) {
    if(section?.state!=='ok'||!numeric(section.count)||!Array.isArray(section.buckets)||section.buckets.length>1000||section.buckets.some(b=>!numeric(b.count)||!Number.isFinite(Date.parse(b.time)))){unavailable(box,section);return;}
    if(!section.buckets.length){box.append(node('p','조회 기간의 기록이 없습니다.','dash-empty'));return;}
    const values=section.buckets,max=Math.max(...values.map(b=>b.count)),scale=Math.max(1,max);
    box.append(node('div','기간 합계 '+count(section)+'건 · 최대 구간 '+max.toLocaleString('ko-KR')+'건','dash-chart-total'));
    const chart=svg('svg',{viewBox:'0 0 600 160',role:'img','aria-label':'시간별 문서 수. 합계 '+section.count+'건',class:'dash-chart'});
    for(const y of [20,70,120])chart.append(svg('line',{x1:0,x2:600,y1:y,y2:y,class:'grid-line'}));
    const points=values.map((b,i)=>[values.length===1?300:i*600/(values.length-1),145-b.count/scale*130]);
    chart.append(svg('polygon',{points:[[points[0][0],150],...points,[points.at(-1)[0],150]].map(p=>p.join(',')).join(' '),class:'area'}),svg('polyline',{points:points.map(p=>p.join(',')).join(' '),class:'trace'}));
    values.forEach((b,i)=>{const p=svg('circle',{cx:points[i][0],cy:points[i][1],r:values.length===1?4:1.5});p.append(svg('title'));p.firstChild.textContent=time(b.time)+' · '+b.count+'건';chart.append(p);});
    const axis=node('div',undefined,'dash-axis');axis.append(node('span',time(values[0].time)),node('span',time(values.at(-1).time)));box.append(chart,axis);
  }
  const colors=['#d75b6a','#eea345','#4d86df','#49a49b','#8798b4'];
  function ring(box,parts,caption,palette=colors) {
    const total=parts.reduce((n,p)=>n+p.count,0);if(!total){box.append(node('p','조회 기간의 경보가 0건입니다.','dash-empty'));return;}
    const wrap=node('div',undefined,'dash-meter'),chart=svg('svg',{viewBox:'0 0 160 160',role:'img','aria-label':parts.map(p=>p.title+' '+p.count+'건').join(', '),class:'dash-ring'});
    chart.append(svg('circle',{cx:80,cy:80,r:56,class:'ring-track'}));let offset=0;const length=2*Math.PI*56;
    parts.forEach((p,i)=>{const arc=length*p.count/total;chart.append(svg('circle',{cx:80,cy:80,r:56,stroke:palette[i%palette.length],'stroke-dasharray':arc+' '+(length-arc),'stroke-dashoffset':-offset,transform:'rotate(-90 80 80)'}));offset+=arc;});
    const label=svg('text',{x:80,y:88});label.textContent=total.toLocaleString('ko-KR');chart.append(label);
    const legend=node('ul',undefined,'dash-legend');parts.forEach((p,i)=>{const row=node('li'),name=node('span'),swatch=svg('svg',{width:9,height:9,'aria-hidden':true});swatch.append(svg('rect',{width:9,height:9,fill:palette[i%palette.length],rx:2}));name.append(swatch,document.createTextNode(' '+p.title));row.append(name,node('strong',p.count.toLocaleString('ko-KR')+'건'));legend.append(row);});wrap.append(chart,legend);box.append(wrap,node('p',caption,'dash-subtitle'));
  }
  function table(box,headers,rows) {const scroll=node('div',undefined,'dash-table-scroll');scroll.tabIndex=0;scroll.setAttribute('aria-label',headers.join(' · '));const t=node('table'),head=node('tr');headers.forEach(h=>head.append(node('th',h)));const thead=node('thead');thead.append(head);t.append(thead);const body=node('tbody');rows.forEach(cells=>{const row=node('tr');cells.forEach((v,i)=>{const td=node('td',undefined,i===1?'dash-title':'');td.append(typeof v==='string'?document.createTextNode(v):v);row.append(td);});body.append(row);});t.append(body);scroll.append(t);box.append(scroll);}
  function render() {
    const fragment=document.createDocumentFragment();
    if(personal)$('dashboard-title').textContent=layout.name;
    const sections=data?.sections||{},pipeline=sections.pipeline||{},coverage=pipeline.coverage?.state||'unknown';
    const initialWarnings={initial_notice_failed:'초기 탐지 통지 처리에 실패했습니다.',initial_notice_reconciliation_required:'초기 통지와 최종 근거의 연결을 다시 확인해야 합니다.',initial_notice_pending:'초기 통지의 조회·전달 또는 최종 연결이 아직 완료되지 않았습니다.',initial_notice_unconfirmed:'초기 통지 상태를 확인하지 못했습니다.'};
    const reason=pipeline.coverage?.reason;
    let message=coverage==='warning'&&Object.hasOwn(initialWarnings,reason)?initialWarnings[reason]:({blocked:'새 로그 분석이 중단됐습니다.',delayed:'새 로그 분석이 지연되고 있습니다.',catching_up:'대기 로그를 분석하고 있습니다.',warning:'일부 로그의 위험 평가가 완료되지 않았습니다.',not_started:'위험 분석이 아직 시작되지 않았습니다.'}[coverage]||'분석 범위를 확인하지 못했습니다.');
    const processing=window.CloudSOCProcessing?.view(pipeline);
    for(const [id,key] of [['dashboard-realtime','realtime'],['dashboard-backlog','historical']]){const box=$(id);if(box){box.hidden=!processing;box.textContent=processing?.[key]||'';}}
    if(processing&&['observed','warning'].includes(processing.state)&&coverage==='delayed')message='과거 로그 분석이 지연되고 있습니다.';
    if(reason==='retrospective_failed')message='늦게 도착한 과거 로그의 재평가가 중단됐습니다.';
    const warning=$('dashboard-coverage');warning.hidden=!data||coverage==='observed';warning.dataset.state=coverage;warning.textContent=message+' 경보 0건이 안전을 뜻하지 않습니다.';
    for(const widget of layout.widgets.filter(w=>ids.includes(w.id))){const box=node('section',undefined,'dash-widget'+(widget.size==='wide'?' wide':''));box.dataset.widget=widget.id;box.append(node('h2',titles[widget.id]));
      if(widget.id==='overview') {const group=node('div',undefined,'dash-overview');const metrics=[['저장된 경보',count(sections.alerts),'선택한 조회 기간'],['수신 로그',count(sections.intake),'서버 수신 시각 기준'],['진행 중 사건',numeric(cases?.counts?.total)?cases.counts.total.toLocaleString('ko-KR'):'미확인','미종결 사건 · 조회 기간과 별도']];metrics.forEach(([title,value,description],i)=>{const card=node('div',undefined,'dash-kpi'+(i===0?' alert':''));card.append(node('p',title),node('strong',value),node('span',description));group.append(card);});box.append(group);}
      if(widget.id==='intake'||widget.id==='trend')series(box,sections[widget.id==='intake'?'intake':'alerts']);
      if(widget.id==='severity'){const a=sections.alerts;if(a?.state!=='ok'||!Array.isArray(a.rows)){unavailable(box,a);}else{const severity={critical:'긴급',high:'높음',medium:'중간',low:'낮음',unknown:'미기록'},parts=Object.keys(severity).map(k=>({title:severity[k],count:a.rows.filter(r=>(Object.hasOwn(severity,r.severity)?r.severity:'unknown')===k).length}));ring(box,parts,'최근 표시된 '+a.rows.length+'건 기준 · 전체 경보의 분포가 아닙니다.');}}
      if(widget.id==='alerts'){const a=sections.alerts;if(a?.state!=='ok'||!Array.isArray(a.rows)){unavailable(box,a);}else if(!a.rows.length){box.append(node('p','조회 기간에 저장된 경보가 0건입니다. 탐지 조건을 만족한 로그에서 경보가 생성됩니다.','dash-empty'));}else{const visible=a.rows.slice(0,expandedAlerts?50:8);table(box,['계산 위험 등급','규칙 ID','경보','서비스','조직','발생 구간 시각 (KST)','상태','관측 건수','조사'],visible.map(r=>{const badge=node('span',({critical:'긴급',high:'높음',medium:'중간',low:'낮음',unassessed:'미평가'}[r.risk_level]||'미기록'),'dash-severity '+(['critical','high','medium','low'].includes(r.risk_level)?r.risk_level:''));return[badge,r.rule||'미기록',(r.historical_review===true?'과거 로그 재평가 · ':'')+(r.title||r.rule||'미기록'),r.service||'미관측',r.organization||'미관측',time(r.timestamp),r.status==='stored'?'저장됨':'미기록',numeric(r.event_count)?r.event_count:'미기록',link('근거 보기','workbench.html?'+new URLSearchParams({alert:r.id,return_page:personal?'dashboard.html':'index.html'}))];}));box.append(node('p','최신 '+visible.length+'건 표시 · 최대 50건까지 조회합니다.','dash-subtitle'));if(a.rows.length>8){const more=node('button',expandedAlerts?'목록 접기':'경보 목록 펼치기');more.type='button';more.setAttribute('aria-expanded',String(expandedAlerts));more.addEventListener('click',()=>{expandedAlerts=!expandedAlerts;render();$('dashboard-grid').querySelector('[data-widget="alerts"] button').focus();});box.append(more);}}}
      if(widget.id==='cases'){if(!cases||!Array.isArray(cases.rows)){unavailable(box);}else if(!cases.rows.length)box.append(node('p','진행 중 사건이 0건입니다. 경보에서 조사를 시작하면 사건을 등록할 수 있습니다.','dash-empty'));else table(box,['우선순위','사건','상태','조사'],cases.rows.slice(0,5).map(c=>[({critical:'긴급',high:'높음',medium:'중간',low:'낮음'}[c.priority]||'미기록'),c.title||'이름 없음',({new:'신규',triage:'초기 분류',investigating:'조사 중',escalated:'이관'}[c.status]||c.status),link('사건 보기','workbench.html?'+new URLSearchParams({case:c.id}))]));box.append(link('사건 목록','cases.html'));}
      fragment.append(box);
    }
    if(!layout.widgets.some(w=>ids.includes(w.id)))fragment.append(node('p','위젯을 1개 이상 선택하세요.','dash-empty'));
    window.CloudSOCLive.children($('dashboard-grid'),fragment.childNodes);
  }
  const pending=window.CloudSOCLive.notice($('dashboard-updated').parentElement,'새 경보');
  let displayedAlerts=null,displayedCases=null;
  function reflect(next,nextCases,manual){
    const fresh=next.sections.alerts;
    const incoming=fresh?.state==='ok'?(fresh.rows||[]).filter(r=>!(displayedAlerts?.rows||[]).some(old=>old.id===r.id)):[];
    if(manual||!displayedAlerts){displayedAlerts=copy(fresh);displayedCases=nextCases;pending.clear();}
    else if(incoming.length||JSON.stringify(nextCases)!==JSON.stringify(displayedCases)){
      pending.offer(incoming.length,()=>{displayedAlerts=copy(fresh);displayedCases=nextCases;data.sections.alerts.rows=displayedAlerts?.rows||[];cases=displayedCases;render();});
    }
    data=next;cases=displayedCases;
    // Counts/charts are current; the reading list remains fixed until explicitly accepted.
    if(displayedAlerts&&fresh?.state==='ok')data.sections.alerts={...fresh,rows:displayedAlerts.rows};
    render();
  }
  const live=window.CloudSOCLive.create({host:$('dashboard-updated').parentElement,interval:10000,enabled:()=>!editing,
    load:async signal=>{const end=new Date(),start=new Date(end-layout.period*60000);
      const result=await Promise.allSettled([request('/api/operations?'+new URLSearchParams({start:start.toISOString(),end:end.toISOString()}),{signal}),request('/api/cases?status=open&sort=priority&page=1',{signal})]);
      if(result[0].status!=='fulfilled'||!result[0].value?.sections)throw new Error('관제 데이터를 조회하지 못했습니다. 마지막 조회 내용을 표시합니다.');
      const next=result[0].value;
      for(const key of Object.keys(next.sections))if(next.sections[key]?.state==='unavailable'&&data?.sections[key]?.state==='ok')throw new Error('일부 데이터를 조회하지 못했습니다. 마지막 조회 내용을 표시합니다.');
      return {next,nextCases:result[1].status==='fulfilled'?result[1].value:cases};},
    apply:({next,nextCases},{manual})=>{reflect(next,nextCases,manual);$('dashboard-error').hidden=true;$('dashboard-updated').textContent='조회 시각: '+time(new Date().toISOString());},
    onError:error=>{$('dashboard-error').hidden=false;$('dashboard-error').textContent=error.message;}});
  function refresh(){pending.clear();return live.refresh(true);}
  function draftLayout() {return{name:$('dashboard-name').value,theme:window.CloudSOCTheme?.get()||layout.theme,period:Number($('dashboard-period').value),widgets:draft.filter(w=>w.enabled).map(({id,size})=>({id,size}))};}
  function editor() {$('dashboard-widget-options').replaceChildren();draft.forEach((w,i)=>{const row=node('li'),label=node('label'),check=node('input');check.type='checkbox';check.checked=w.enabled;check.setAttribute('aria-label',titles[w.id]+' 표시');check.addEventListener('change',()=>{w.enabled=check.checked;layout=draftLayout();render();});label.append(check,document.createTextNode(titles[w.id]));const size=node('select');size.setAttribute('aria-label',titles[w.id]+' 크기');for(const[value,title]of[['normal','기본 너비'],['wide','전체 너비']]){const option=node('option',title);option.value=value;size.append(option);}size.value=w.size;size.addEventListener('change',()=>{w.size=size.value;layout=draftLayout();render();});row.append(label,size);for(const[delta,title]of[[-1,'위로'],[1,'아래로']]){const b=node('button',title);b.type='button';b.disabled=i+delta<0||i+delta>=draft.length;b.setAttribute('aria-label',titles[w.id]+' '+title);b.addEventListener('click',()=>{[draft[i],draft[i+delta]]=[draft[i+delta],draft[i]];layout=draftLayout();editor();render();});row.append(b);}$('dashboard-widget-options').append(row);});}
  function begin() {editing=true;$('dashboard-editor').hidden=false;$('dashboard-name').value=layout.name;draft=[...layout.widgets.filter(w=>ids.includes(w.id)).map(w=>({...w,enabled:true})),...ids.filter(id=>!layout.widgets.some(w=>w.id===id)).map(id=>({id,size:'normal',enabled:false}))];editor();$('dashboard-name').focus();}
  function cancel() {editing=false;$('dashboard-editor').hidden=true;layout=copy(saved.layout);controls();render();refresh();}
  function controls() {$('dashboard-period').value=String(layout.period);layout.theme=window.CloudSOCTheme?.get()||layout.theme;}
  $('dashboard-refresh').addEventListener('click',refresh);
  $('dashboard-period').addEventListener('change',()=>{live.cancel();data=null;cases=null;displayedAlerts=null;displayedCases=null;pending.clear();layout.period=Number($('dashboard-period').value);if(personal&&!editing)begin();refresh();});
  window.addEventListener('cloud-soc-themechange',event=>{layout.theme=event.detail.theme;});
  $('dashboard-edit').addEventListener('click',begin);$('dashboard-cancel').addEventListener('click',cancel);
  $('dashboard-reset').addEventListener('click',()=>{layout=defaults();controls();begin();render();});
  $('dashboard-save').addEventListener('click',async()=>{const button=$('dashboard-save');layout=draftLayout();if(!validLayout(layout)){$('dashboard-save-state').textContent='이름과 선택한 위젯을 확인하세요.';return;}const controlsToLock=[...$('dashboard-editor').querySelectorAll('button,input,select'),$('dashboard-period'),$('dashboard-edit')];controlsToLock.forEach(c=>c.disabled=true);try{const result=await request('/api/dashboard',{method:'POST',headers:{'Content-Type':'application/json','X-Cloud-SOC':'portal'},body:JSON.stringify({revision:saved.revision,layout})});if(!validLayout(result.layout)||!numeric(result.revision))throw new Error('저장 응답을 확인하세요.');saved=copy(result);layout=copy(result.layout);editing=false;$('dashboard-editor').hidden=true;$('dashboard-updated').textContent='구성을 저장했습니다.';render();}catch(e){$('dashboard-save-state').textContent=e.message;if(e.status===409){const reload=node('button','서버 구성 불러오기 · 편집 취소');reload.type='button';reload.addEventListener('click',async()=>{try{const r=await request('/api/dashboard');if(!validLayout(r.layout)||!numeric(r.revision))throw new Error('설정 형식을 확인하세요.');saved=r;cancel();}catch(error){$('dashboard-save-state').textContent=error.message;}});$('dashboard-save-state').append(reload);}}finally{controlsToLock.forEach(c=>c.disabled=false);if(editing)editor();}});
  (async()=>{if(personal){$('personal-link').hidden=true;try{const r=await request('/api/dashboard');if(!validLayout(r.layout)||!numeric(r.revision))throw new Error('저장된 구성 형식을 확인하세요.');saved=r;layout=copy(r.layout);window.CloudSOCTheme?.adopt(layout.theme);ready=true;$('dashboard-edit').hidden=false;}catch(e){$('dashboard-error').textContent='내 구성을 불러오지 못했습니다. '+e.message;$('dashboard-error').hidden=false;return;}}controls();if(ready)refresh();})();
})();
