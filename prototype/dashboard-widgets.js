/* Safe renderers and shared, bounded data providers for the personal dashboard. */
(() => {
  'use strict';
  const number = value => Number.isSafeInteger(value) && value >= 0;
  const copy = value => JSON.parse(JSON.stringify(value));
  const node = (tag, text, cls) => {const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;};
  const time = value => typeof value==='string'&&Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString('ko-KR',{timeZone:'Asia/Seoul',hour12:false}) : '미관측';
  const link = (label,path) => {const e=node('a',label);e.href=path;return e;};
  const svg = (tag,attributes={}) => {const e=document.createElementNS('http://www.w3.org/2000/svg',tag);Object.entries(attributes).forEach(([k,v])=>e.setAttribute(k,String(v)));return e;};
  const severity = {critical:'긴급',high:'높음',medium:'중간',low:'낮음',unknown:'미기록'};
  const alertTitle = row => (row.historical_review===true ? '과거 로그 재평가 · ' : '')+(row.title||row.rule||'경보');
  const chartNames = {line:'꺾은선',bar:'막대',heatmap:'히트맵',trend:'추이 카드',donut:'도넛',stacked:'누적 막대',table:'목록',timeline:'시간순 목록',graph:'관계 그래프',status:'상태 카드',kpi:'수치 카드'};
  function compact(widgets) {
    let x=0,y=0,height=0;
    for(const w of widgets){if(x+w.w>12){x=0;y+=height;height=0;}w.x=x;w.y=y;x+=w.w;height=Math.max(height,w.h);}
    return widgets;
  }
  const overlaps = (a,b) => a.x<b.x+b.w&&a.x+a.w>b.x&&a.y<b.y+b.h&&a.y+a.h>b.y;
  function place(widgets,id,position) {
    const candidate=copy(widgets),w=candidate.find(w=>w.id===id);if(!w)return null;
    Object.assign(w,position);
    if(w.x<0||w.y<0||w.x+w.w>12||w.y>240||![3,6,12].includes(w.w)||w.h<2||w.h>8||candidate.some(other=>other.id!==id&&overlaps(w,other)))return null;
    return candidate.sort((a,b)=>a.y-b.y||a.x-b.x);
  }
  function plan(layout,catalog) {
    const sources=new Set(['status']);
    for(const w of layout.widgets){const meta=catalog.find(m=>m.type===w.type);if(!meta?.enabled)continue;
      const period=w.config.period||layout.period;
      if(['operations','logs','notices','web'].includes(meta.source))sources.add(meta.source+':'+period);
      else sources.add(meta.source);
      if(w.type==='overview')sources.add('cases');
    }
    return [...sources];
  }
  async function query(path,options={}) {
    const response=await fetch(path,{credentials:'same-origin',cache:'no-store',...options});
    let body;try{body=await response.json();}catch{throw Object.assign(new Error('서버 응답을 읽지 못했습니다.'),{status:response.status});}
    if(!response.ok)throw Object.assign(new Error(body.error||'데이터를 조회하지 못했습니다.'),{status:response.status});return body;
  }
  function pathFor(key,end) {
    const [source,raw]=key.split(':');
    if(!['operations','logs','notices','web'].includes(source))return {cases:'/api/cases?status=open&sort=priority&page=1',agents:'/api/agents/status',collection:'/api/agents/components',status:'/api/operations/status'}[source];
    const period=Number(raw),params=new URLSearchParams({start:new Date(end-period*60000).toISOString(),end:new Date(end).toISOString()});
    if(source==='operations')return '/api/operations?'+params;
    if(source==='notices')return '/api/alerts/notices?'+params;
    if(source==='web')params.set('source_kind','web');
    if(source==='logs'||source==='web'){params.set('page_size','50');params.set('time_basis','ingested');return '/api/logs?'+params;}
  }
  async function load(keys,signal,end=Date.now()) {
    const results={},queue=[...keys];
    async function worker(){while(queue.length&&!signal.aborted){const key=queue.shift();try{results[key]={body:await query(pathFor(key,end),{signal})};}catch(error){results[key]={error:error.message,status:error.status||0};}}}
    await Promise.all(Array.from({length:Math.min(3,keys.length)},worker));return results;
  }
  function empty(box,text){box.append(node('p',text,'dash-empty'));}
  function failure(box,result){empty(box,result?.loading?'데이터 조회 중…':result?.status===403?'조회 권한이 없습니다.':result?.status===401?'로그인이 필요합니다.':'조회 실패 · 연결과 측정 상태를 확인하세요.');}
  function table(box,headers,rows){if(!rows.length){empty(box,'조회 범위에 표시할 기록이 0건입니다.');return;}const scroll=node('div',undefined,'dash-table-scroll');scroll.tabIndex=0;scroll.setAttribute('aria-label',headers.join(' · '));const t=node('table'),head=node('tr');headers.forEach(h=>head.append(node('th',h)));const thead=node('thead');thead.append(head);t.append(thead);const body=node('tbody');rows.forEach(cells=>{const tr=node('tr');cells.forEach(v=>{const td=node('td');td.append(typeof v==='object'&&v?.nodeType?v:document.createTextNode(String(v??'미관측')));tr.append(td);});body.append(tr);});t.append(body);scroll.append(t);box.append(scroll);}
  function kpi(box,title,value,caption){const card=node('div',undefined,'dash-kpi');card.append(node('p',title),node('strong',number(value)?value.toLocaleString('ko-KR'):'미확인'),node('span',caption));box.append(card);}
  function section(box,part){if(part?.state==='ok')return true;empty(box,part?.state==='no_index'?'데이터 미수집 · 저장된 인덱스가 없습니다.':'조회 실패·권한·측정 상태 확인 불가');return false;}
  function series(box,part,chartType){
    if(!section(box,part))return;
    if(!number(part.count)||!Array.isArray(part.buckets)||part.buckets.length>1000||part.buckets.some(b=>!number(b.count)||!Number.isFinite(Date.parse(b.time)))){failure(box);return;}
    const rows=part.buckets;if(!rows.length){empty(box,'조회 기간에 집계 구간이 없습니다.');return;}
    const max=Math.max(1,...rows.map(r=>r.count));box.append(node('p','기간 합계 '+part.count.toLocaleString('ko-KR')+'건 · '+rows.length+'개 구간','dash-chart-total'));
    const chart=svg('svg',{viewBox:'0 0 600 160',role:'img','aria-label':'시간별 문서 수 '+part.count+'건',class:'dash-chart'});
    if(chartType==='heatmap'){
      rows.forEach((r,i)=>{const c=svg('rect',{x:(i%24)*25,y:Math.floor(i/24)*12,width:22,height:9,rx:2,opacity:0.12+r.count/max*0.88,class:'heat-cell'});c.append(svg('title'));c.firstChild.textContent=time(r.time)+' · '+r.count+'건';chart.append(c);});
      chart.setAttribute('viewBox','0 0 600 '+Math.max(24,Math.ceil(rows.length/24)*12));
    }else if(chartType==='bar'){
      rows.forEach((r,i)=>{const width=600/rows.length,h=r.count/max*140,c=svg('rect',{x:i*width,y:150-h,width:Math.max(.5,width*.8),height:h,class:'heat-cell'});c.append(svg('title'));c.firstChild.textContent=time(r.time)+' · '+r.count+'건';chart.append(c);});
    }else{
      for(const y of [10,80,150])chart.append(svg('line',{x1:0,x2:600,y1:y,y2:y,class:'grid-line'}));
      const points=rows.map((r,i)=>[rows.length===1?300:i*600/(rows.length-1),150-r.count/max*140]);
      chart.append(svg('polyline',{points:points.map(p=>p.join(',')).join(' '),class:'trace'}));
      rows.forEach((r,i)=>{const c=svg('circle',{cx:points[i][0],cy:points[i][1],r:2});c.append(svg('title'));c.firstChild.textContent=time(r.time)+' · '+r.count+'건';chart.append(c);});
    }
    box.append(chart);const axis=node('div',undefined,'dash-axis');axis.append(node('span',time(rows[0].time)),node('span',time(rows.at(-1).time)));box.append(axis);
  }
  function groups(rows,key){const totals=new Map();for(const r of rows){const value=r[key]||'미관측';totals.set(value,(totals.get(value)||0)+1);}return [...totals].map(([title,count])=>({title,count}));}
  function parts(box,rows,chartType){
    if(rows.some(r=>!number(r.count))){failure(box);return;}
    const total=rows.reduce((n,r)=>n+r.count,0);if(!total){empty(box,'조회 범위의 기록이 0건입니다.');return;}
    const palette=['#4386e7','#25b5aa','#e3ab39','#9d75e8','#e76d85','#8096b1'],hidden=new Set();
    const graph=node('div',undefined,'builder-parts'),legend=node('div',undefined,'builder-legend');
    function draw(){graph.replaceChildren();const visible=rows.filter((_,i)=>!hidden.has(i)),sum=visible.reduce((n,r)=>n+r.count,0);if(!sum){empty(graph,'표시할 계열을 선택하세요.');return;}
      const s=svg('svg',{viewBox:chartType==='donut'?'0 0 160 160':'0 0 600 '+(chartType==='stacked'?40:Math.max(40,visible.length*32)),role:'img','aria-label':visible.map(r=>r.title+' '+r.count+'건').join(', '),class:chartType==='donut'?'dash-ring':'builder-bar-chart'});let offset=0;
      visible.forEach(r=>{const i=rows.indexOf(r),fraction=r.count/sum,c=chartType==='donut'?svg('circle',{cx:80,cy:80,r:56,stroke:palette[i%6],'stroke-dasharray':fraction*352+' '+(352-fraction*352),'stroke-dashoffset':-offset,transform:'rotate(-90 80 80)'}):svg('rect',{x:chartType==='stacked'?offset:0,y:chartType==='stacked'?5:visible.indexOf(r)*32,width:chartType==='stacked'?fraction*600:r.count/Math.max(1,...visible.map(p=>p.count))*600,height:24,fill:palette[i%6],rx:3});c.append(svg('title'));c.firstChild.textContent=r.title+' · '+r.count+'건';s.append(c);offset+=fraction*(chartType==='donut'?352:600);});if(chartType==='donut'){const label=svg('text',{x:80,y:88});label.textContent=sum.toLocaleString('ko-KR');s.append(label);}graph.append(s);}
    rows.forEach((r,i)=>{const button=node('button',r.title+' · '+r.count.toLocaleString('ko-KR')+'건');button.type='button';button.setAttribute('aria-pressed','true');button.addEventListener('click',()=>{hidden.has(i)?hidden.delete(i):hidden.add(i);button.setAttribute('aria-pressed',String(!hidden.has(i)));draw();});legend.append(button);});box.append(graph,legend);draw();
  }
  function filteredAlerts(rows,w){let result=rows.filter(r=>w.config.severity==='all'||r.severity===w.config.severity);if(w.type==='high-alerts')result=result.filter(r=>['critical','high'].includes(r.severity));if(w.type==='cloud-alerts')result=result.filter(r=>/^(AWS|OCI)[-_]/.test(r.rule||''));result=[...result].sort((a,b)=>(Date.parse(a.timestamp)||0)-(Date.parse(b.timestamp)||0));if(w.config.sort!=='oldest')result.reverse();return result;}
  const iam=new Set(['AttachUserPolicy','AttachRolePolicy','PutUserPolicy','PutRolePolicy','CreatePolicy','CreatePolicyVersion','SetDefaultPolicyVersion','DetachUserPolicy','DetachRolePolicy','DeleteUserPolicy','DeleteRolePolicy']);
  const audit=new Set(['StopLogging','StartLogging','DeleteTrail','UpdateTrail','CreateTrail','PutEventSelectors']);
  function filteredLogs(rows,type){if(type==='web-events')return rows.filter(r=>['web_access_metadata','generic_web_access'].includes(r.source_kind));if(type.startsWith('cloud-')){rows=rows.filter(r=>['aws_cloudtrail','oci_audit'].includes(r.source_kind)&&['aws','oci'].includes(r.cloud_provider));if(type==='cloud-iam')rows=rows.filter(r=>iam.has(r.action));if(type==='cloud-audit')rows=rows.filter(r=>audit.has(r.action));}return rows;}
  function render(box,w,meta,result,extras={}) {
    if(!meta?.enabled){empty(box,meta?.reason||'미지원 위젯입니다.');return;}
    if(meta.renderer==='notices'){
      const rows=result?.body?.rows;
      const prepared=Array.isArray(rows)&&rows.length<=50?{...result,body:{...result.body,rows:[...rows].sort((a,b)=>(Date.parse(a.initial_at)-Date.parse(b.initial_at))*(w.config.sort==='oldest'?1:-1)).slice(0,w.config.limit)}}:result;
      window.CloudSOCNotices.render(box,prepared);return;
    }
    if(!result?.body){failure(box,result);return;}
    const data=result.body,s=data.sections||{},config=w.config,limit=config.limit;
    const periodLabel=(config.period||extras.period)===60?'최근 1시간':(config.period||extras.period)===10080?'최근 7일':'최근 24시간';
    box.append(node('p',['cases','agents'].includes(meta.source)?'현재 상태 · 조회 기간과 별도':w.type==='pipeline'?'현재 상태':periodLabel+' · KST','dash-subtitle'));
    if(meta.renderer==='overview'){const g=node('div',undefined,'dash-overview');kpi(g,'저장된 경보',s.alerts?.state==='ok'?s.alerts.count:null,'선택 기간 전체');kpi(g,'수신 로그',s.intake?.state==='ok'?s.intake.count:null,'선택 기간 전체');kpi(g,'미종결 사건',extras.cases?.body?.counts?.total,'현재 전체 집계');box.append(g);return;}
    if(meta.renderer==='kpi'){if(w.type==='case-count')kpi(box,config.title,data.counts?.total,'현재 미종결 사건 전체');else{const part=s[w.type==='alert-count'?'alerts':'intake'];if(section(box,part))kpi(box,config.title,part.count,'선택 기간 전체 집계');}return;}
    if(meta.renderer==='series'){series(box,s[w.type==='intake'?'intake':w.type==='processing'?'processing':'alerts'],config.chart);return;}
    if(meta.renderer==='status'){const state=s.pipeline?.coverage?.state||'unknown';box.append(node('p',({observed:'최근 분석 보고 확인',blocked:'분석 중단',delayed:'분석 지연',catching_up:'대기 로그 처리 중',warning:'일부 위험 평가 미완료',not_started:'분석 미실행'}[state]||'상태 미확인'),'dash-status'));table(box,['서비스','상태','마지막 성공'],['normalizer','detector'].map(k=>{const row=k==='normalizer'?s.pipeline:s.pipeline?.detector;return [k==='normalizer'?'정규화':'탐지',row?.state||'미확인',time(row?.last_success)];}));return;}
    if(meta.source==='agents'){if(!Array.isArray(data.agents)){failure(box);return;}table(box,['호스트','수집기','마지막 수신 (KST)','수신 활동'],data.agents.slice(0,limit).map(r=>[r.host_name,r.agent_type,time(r.last_received),({recent:'최근 수신',delayed:'수신 지연',silent:'최근 미수신',unknown:'미확인'}[r.status]||'미확인')]));box.append(link('수신 현황','agent-status.html'));return;}
    if(meta.source==='collection'){if(!Array.isArray(data.rows)){failure(box);return;}const labels={normal:'정상 수신',unconfigured:'미설정',error:'오류',delayed:'지연',no_data:'데이터 없음',unknown:'상태 미확인'};table(box,['호스트','수집 항목','상태','마지막 수신 (KST)'],data.rows.slice(0,10).flatMap(r=>['system','web','network'].map(k=>[r.host_name,{system:'시스템·보안',web:'웹',network:'네트워크'}[k],labels[r[k]?.state]||'상태 미확인',time(r[k]?.last_received)])));box.append(node('p','최근 보고한 설치 표본입니다. 데이터 없음은 오프라인이나 안전 판정이 아닙니다.','builder-scope'));return;}
    if(meta.source==='cases'){if(!Array.isArray(data.rows)||!number(data.counts?.total)){failure(box);return;}if(w.type==='case-status'){const n=data.counts.investigating;if(!number(n)||n>data.counts.total){failure(box);return;}parts(box,[{title:'조사 중',count:n},{title:'기타 미종결',count:data.counts.total-n}],config.chart);}else table(box,['우선순위','사건','상태','상세'],data.rows.slice(0,limit).map(r=>[severity[r.priority]||'미기록',r.title,({new:'신규',triage:'초기 분류',investigating:'조사 중',escalated:'이관'}[r.status]||r.status),link('사건 보기','workbench.html?'+new URLSearchParams({case:r.id}))]));box.append(link('사건 목록','cases.html'));return;}
    if(meta.source==='logs'||meta.source==='web'){
      if(!Array.isArray(data.rows)||data.rows.length>50){failure(box);return;}
      if(data.data_state==='no_index'){empty(box,'데이터 미수집 · 조회할 로그 인덱스가 없습니다.');return;}
      if(!data.rows.length&&!data.data_state){empty(box,'조회 기간에 반환된 로그가 없습니다. 미수집 여부는 수신 추이에서 확인하세요.');return;}
      let rows=filteredLogs(data.rows,w.type);box.append(node('p','최근 수신 로그 '+data.rows.length+'건 중 '+rows.length+'건 표본 · 전체 집계가 아닙니다.','builder-scope'));
      if(meta.renderer==='parts'){const key={'cloud-services':'cloud_service','cloud-accounts':'cloud_account','source-counts':'source_kind'}[w.type];let p=groups(rows,key);if(config.sort==='count')p.sort((a,b)=>b.count-a.count);parts(box,p.slice(0,limit),config.chart);}else{rows=[...rows].sort((a,b)=>(Date.parse(a.received_at)||0)-(Date.parse(b.received_at)||0));if(config.sort!=='oldest')rows.reverse();table(box,['수신 (KST)',w.type.startsWith('cloud-')?'클라우드 / 계정':'호스트','관측 행위','조회'],rows.slice(0,limit).map(r=>[time(r.received_at),w.type.startsWith('cloud-')?(r.cloud_provider||'미관측')+' / '+(r.cloud_account||'미관측'):r.host_name,r.action||'행위 미관측',link('통합 로그','logs.html')]));}return;
    }
    if(!section(box,s.alerts)||!Array.isArray(s.alerts.rows))return;
    const rows=filteredAlerts(s.alerts.rows,w);box.append(node('p','최근 경보 '+s.alerts.rows.length+'건 표본 · 전체 '+(number(s.alerts.count)?s.alerts.count.toLocaleString('ko-KR'):'미확인')+'건과 구분합니다.','builder-scope'));
    if(meta.renderer==='parts'){let p=w.type==='severity'?Object.entries(severity).map(([key,title])=>({title,count:rows.filter(r=>(Object.hasOwn(severity,r.severity)?r.severity:'unknown')===key).length})):groups(rows,w.type==='source-alerts'?'source_ip':'rule');if(config.sort==='count')p.sort((a,b)=>b.count-a.count);parts(box,p.slice(0,limit),config.chart);return;}
    if(meta.renderer==='entities'){
      if(!rows.length){empty(box,'경보가 없어 연결할 관측 관계가 없습니다.');return;}
      rows.slice(0,Math.min(limit,5)).forEach(r=>{const panel=node('div',undefined,'builder-relation');panel.append(link(alertTitle(r),'workbench.html?'+new URLSearchParams({alert:r.id,return_page:'dashboard.html'})));if(r.source_ip){const graph=svg('svg',{viewBox:'0 0 360 110',class:'builder-entity-graph',role:'img','aria-label':'출발지 '+r.source_ip+'가 이 경보 문서에 기록됨'});graph.append(svg('line',{x1:75,x2:285,y1:35,y2:35}),svg('circle',{cx:75,cy:35,r:20}),svg('circle',{cx:285,cy:35,r:20}));for(const [x,label] of [[75,'출발지'],[285,'경보'],[75,r.source_ip],[285,r.rule||'저장 경보']]){const t=svg('text',{x,y:['출발지','경보'].includes(label)?40:83,'text-anchor':'middle'});t.textContent=label;graph.append(t);}panel.append(graph,node('span','동일 경보 문서에 기록된 출발지'));}else panel.append(node('span','출발지 미관측 · 연결하지 않음'));box.append(panel);});box.append(node('p','같은 문서의 명시적 관계만 표시합니다. 공격 귀속·같은 세션을 뜻하지 않습니다.','dash-subtitle'));return;
    }
    if(config.chart==='timeline'||w.type==='alert-timeline'){const list=node('ol',undefined,'builder-timeline');rows.slice(0,limit).forEach(r=>{const li=node('li');li.append(node('time',time(r.timestamp)),link(alertTitle(r),'workbench.html?'+new URLSearchParams({alert:r.id,return_page:'dashboard.html'})),node('span',severity[r.severity]||'미기록'));list.append(li);});if(!rows.length)empty(box,'표시할 경보가 0건입니다.');box.append(list,node('p','서로 다른 경보의 발생 구간 시각 순서이며 공격 인과관계를 추정하지 않습니다.','dash-subtitle'));}
    else table(box,['심각도','경보','출발지','발생 구간 시각 (KST)','조사'],rows.slice(0,limit).map(r=>[node('span',severity[r.severity]||'미기록','dash-severity '+(Object.hasOwn(severity,r.severity)?r.severity:'')),alertTitle(r),r.source_ip,time(r.timestamp),link('근거 보기','workbench.html?'+new URLSearchParams({alert:r.id,return_page:'dashboard.html'}))]));
  }
  window.CloudSOCWidgets={copy,node,time,link,number,compact,place,plan,load,query,render,chartNames,filteredAlerts,filteredLogs,alertTitle};
})();
