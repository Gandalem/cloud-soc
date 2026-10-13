/* Multiple private dashboards. Only explicit actions persist server-side metadata. */
(() => {
  'use strict';
  const W=window.CloudSOCWidgets,$=id=>document.getElementById(id);
  if(!W||!$('platform-grid'))return;
  const {copy,node,query}=W;
  let collection=null,catalog=[],templates=[],selected='legacy',layout=null,baseline=null,editing=false,busy=false,history=[],results={},generation=0,controller,timer,noticeController,noticeTimer,modalAction,configId;
  const item=()=>selected==='legacy'?collection?.legacy:collection?.dashboards.find(row=>row.id===selected);
  const dirty=()=>editing&&JSON.stringify(layout)!==JSON.stringify(baseline);
  function error(message){$('dashboard-error').textContent=message;$('dashboard-error').hidden=!message;}
  function setPanel(panel){document.querySelector('.builder-workspace').dataset.panel=panel;document.querySelectorAll('.builder-tabs button').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.panel===panel)));}
  function message(text){$('dashboard-save-state').textContent=text;}
  function remember(){history.push(copy(layout));if(history.length>30)history.shift();}
  function update(fn,{reflow=false,fetch=false}={}){if(busy)return;remember();fn();if(reflow)W.compact(layout.widgets);render();if(fetch)refresh();message('미리보기 · 변경사항을 저장하세요.');}
  function locked(value){busy=value;document.querySelectorAll('main button,main input,main select').forEach(e=>e.disabled=value);if(!value&&collection)render();}
  function controls(){
    const legacy=selected==='legacy';$('dashboard-edit').textContent=legacy?'기존 화면 복제·편집':'편집';$('dashboard-edit').disabled=editing||busy;
    for(const id of ['dashboard-favorite','dashboard-rename','dashboard-delete'])$(id).disabled=legacy||editing||busy;
    $('dashboard-default').disabled=editing||busy||collection.default_id===selected;
    $('dashboard-duplicate').disabled=editing||busy;$('dashboard-create').disabled=editing||busy;
    $('dashboard-favorite').textContent=item()?.favorite?'★ 즐겨찾기 해제':'☆ 즐겨찾기';
    $('dashboard-editor').hidden=!editing;$('dashboard-period').disabled=busy||legacy;
    $('dashboard-period').value=String(layout.period);$('dashboard-name').value=layout.name;
    $('dashboard-undo').disabled=busy||!history.length;
  }
  async function mutate(action,values){
    locked(true);error('');
    try{const response=await query('/api/dashboards',{method:'POST',headers:{'Content-Type':'application/json','X-Cloud-SOC':'portal'},body:JSON.stringify({revision:collection.revision,action,...values})});
      if(!Number.isSafeInteger(response.revision)||!Array.isArray(response.dashboards)||!response.legacy)throw new Error('저장 응답 형식을 확인하세요.');
      collection={...collection,...response};selected=response.selected_id||selected;layout=copy(item().layout);baseline=copy(layout);editing=false;history=[];$('dashboard-conflict').hidden=true;render();return true;
    }catch(e){error(e.message);message('저장 실패 · 현재 편집은 유지됩니다.');if(e.status===409)$('dashboard-conflict').hidden=false;return false;}
    finally{locked(false);}
  }
  function rememberUrl(){const url=new URL(window.location.href);url.searchParams.set('dashboard',selected);window.history.replaceState(null,'',url.pathname+url.search);}
  function select(id){if(busy)return;if(dirty()){showDialog('discard',id);return;}switchTo(id);}
  function switchTo(id){selected=id;layout=copy(item().layout);baseline=copy(layout);editing=false;history=[];rememberUrl();setPanel('canvas');render();refresh();}
  async function begin(){if(busy)return;if(selected==='legacy'){if(!await mutate('duplicate',{id:'legacy',name:layout.name.slice(0,42)+' 복사본'}))return;rememberUrl();}editing=true;baseline=copy(layout);history=[];render();$('dashboard-name').focus();}
  function cancel(){if(busy)return;layout=copy(baseline);editing=false;history=[];render();refresh();message('마지막 저장 구성으로 복원했습니다.');}
  function renderList(){
    $('dashboard-list').replaceChildren();$('dashboard-total').textContent=collection.dashboards.length+' / 20';
    const rows=[collection.legacy,...[...collection.dashboards].sort((a,b)=>Number(b.favorite)-Number(a.favorite))];
    for(const row of rows){const b=node('button',row.layout.name,'builder-dashboard-choice'+(row.id===selected?' active':''));b.type='button';b.dataset.dashboardId=row.id;b.setAttribute('aria-current',row.id===selected?'page':'false');b.append(node('small',row.id==='legacy'?'기존 설정 · 보존':(row.favorite?'★ ':'')+(collection.default_id===row.id?'기본 화면':'개인 화면')));b.addEventListener('click',()=>select(row.id));b.disabled=busy;$('dashboard-list').append(b);}
    $('dashboard-templates').replaceChildren();templates.filter(t=>t.id!=='empty').forEach(t=>{const b=node('button',t.name,'builder-template');b.type='button';b.disabled=editing||busy;b.addEventListener('click',()=>showDialog('create',t.id));$('dashboard-templates').append(b);});
  }
  function library(){
    const search=$('widget-search').value.trim().toLowerCase(),category=$('widget-category').value;
    $('dashboard-widget-options').replaceChildren();$('widget-total').textContent=catalog.filter(m=>m.enabled).length+'개 사용 가능';
    const rows=catalog.filter(m=>(category==='all'||m.category===category)&&(m.title+' '+m.description).toLowerCase().includes(search));
    for(const meta of rows){const card=node('article',undefined,'builder-library-card'+(!meta.enabled?' unavailable':''));card.append(node('small',meta.category),node('h3',meta.title),node('p',meta.description));
      if(!meta.enabled)card.append(node('p',meta.reason,'builder-unavailable'));
      const b=node('button',meta.enabled?'＋ 추가':'사용 불가');b.type='button';b.disabled=!meta.enabled||busy||layout.widgets.length>=24;
      b.setAttribute('aria-label',meta.title+' 추가');b.addEventListener('click',async()=>{if(!editing)await begin();if(!editing)return;update(()=>{layout.widgets.push({id:crypto.randomUUID(),type:meta.type,x:0,y:0,w:6,h:3,config:{title:meta.title,period:0,chart:meta.charts[0],limit:8,sort:'newest',severity:'all',color:'blue'}});},{reflow:true,fetch:true});setPanel('canvas');});
      card.append(b);$('dashboard-widget-options').append(card);
    }
    if(!rows.length)$('dashboard-widget-options').append(node('p','검색과 분류에 맞는 위젯이 없습니다.','dash-empty'));
  }
  function widgetTools(box,w,index){
    const actions=node('div',undefined,'builder-widget-tools');
    const move=(delta)=>{if(index+delta<0||index+delta>=layout.widgets.length)return;update(()=>{[layout.widgets[index],layout.widgets[index+delta]]=[layout.widgets[index+delta],layout.widgets[index]];},{reflow:true});$('platform-grid').querySelector('[data-instance="'+w.id+'"]')?.focus();};
    for(const [label,fn] of [['설정',()=>configure(w.id)],['위로',()=>move(-1)],['아래로',()=>move(1)],['제거',()=>update(()=>{layout.widgets=layout.widgets.filter(row=>row.id!==w.id);},{reflow:true,fetch:true})]]){const b=node('button',label);b.type='button';b.setAttribute('aria-label',w.config.title+' '+label);b.addEventListener('click',fn);b.disabled=busy||(label==='위로'&&index===0)||(label==='아래로'&&index===layout.widgets.length-1);actions.append(b);}
    const grip=node('button','⠿ 이동','builder-grip');grip.type='button';grip.setAttribute('aria-label',w.config.title+' 이동 핸들 · Alt와 위 아래 방향키로 순서 변경');
    grip.addEventListener('keydown',event=>{if(event.altKey&&['ArrowUp','ArrowDown'].includes(event.key)){event.preventDefault();move(event.key==='ArrowUp'?-1:1);}});
    const resize=node('button','↘ 크기','builder-resize');resize.type='button';resize.setAttribute('aria-label',w.config.title+' 크기 핸들 · 설정에서 너비와 높이 선택');
    resize.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();configure(w.id);}});
    box.prepend(grip);box.append(actions,resize);pointer(grip,w,false);pointer(resize,w,true);
  }
  function pointer(handle,w,resize){
    handle.addEventListener('pointerdown',event=>{
      if(busy||event.button!==0||window.innerWidth<=700)return;
      event.preventDefault();handle.setPointerCapture(event.pointerId);const start={x:event.clientX,y:event.clientY},rect=$('platform-grid').getBoundingClientRect(),column=(rect.width+16)/12;let proposed=null;
      handle.closest('.builder-widget').classList.add('dragging');
      function moving(e){const dx=e.clientX-start.x,dy=e.clientY-start.y;
        const change=resize?{w:Math.max(3,Math.min(12,Math.round((w.w+dx/column)/3)*3)),h:Math.max(2,Math.min(8,w.h+Math.round(dy/92)))}:{x:Math.max(0,Math.min(12-w.w,w.x+Math.round(dx/column))),y:Math.max(0,Math.min(240,w.y+Math.round(dy/92)))};
        proposed=W.place(layout.widgets,w.id,change);message(proposed?'배치 미리보기 · 열 '+(change.x??w.x)+' / 행 '+(change.y??w.y)+' / 너비 '+(change.w??w.w):'다른 위젯과 겹칩니다. 빈 공간으로 옮기세요.');
      }
      function done(){handle.removeEventListener('pointermove',moving);handle.removeEventListener('pointerup',done);handle.removeEventListener('pointercancel',cancelPointer);if(proposed)update(()=>{layout.widgets=proposed;});else render();}
      function cancelPointer(){proposed=null;done();}
      handle.addEventListener('pointermove',moving);handle.addEventListener('pointerup',done);handle.addEventListener('pointercancel',cancelPointer);
    });
  }
  function render(){if(!layout||!collection)return;
    $('dashboard-title').textContent=layout.name;$('dashboard-description').textContent=editing?'변경사항을 미리 보는 중입니다. 저장하면 다시 로그인해도 유지됩니다.':selected==='legacy'?'기존 개인 설정을 보존한 화면입니다. 편집은 복사본에서 시작합니다.':'이 계정의 개인 관제 화면 · 위젯별 기간과 데이터 범위를 확인하세요.';
    controls();renderList();library();const grid=$('platform-grid');grid.replaceChildren();grid.classList.toggle('editing',editing);
    layout.widgets.forEach((w,index)=>{const meta=catalog.find(m=>m.type===w.type),box=node('section',undefined,'dash-widget builder-widget span-'+w.w+' column-'+w.x+' row-'+w.y+' height-'+w.h+' accent-'+w.config.color);box.dataset.instance=w.id;box.dataset.type=w.type;box.tabIndex=0;box.append(node('h2',w.config.title));
      const content=node('div',undefined,'builder-widget-content'),key=meta?.source+(meta&&['operations','logs','notices'].includes(meta.source)?':'+(w.config.period||layout.period):'');
      W.render(content,w,meta,results[key]||{loading:true},{cases:results.cases,period:layout.period});box.append(content);if(editing)widgetTools(box,w,index);grid.append(box);
    });
    if(!layout.widgets.length){const blank=node('div',undefined,'builder-blank');blank.append(node('h2','나만의 관제 화면을 구성하세요'),node('p','위젯 찾기에서 필요한 정보를 추가하거나 기본 템플릿으로 시작할 수 있습니다.'));const b=node('button','위젯 찾기','dash-primary');b.type='button';b.addEventListener('click',()=>setPanel('library'));blank.append(b);grid.append(blank);}
    const coverage=results.status?.body?.coverage,state=coverage?.state,warning=$('dashboard-coverage');
    const initialWarnings={initial_notice_failed:'초기 탐지 통지 처리에 실패했습니다.',initial_notice_reconciliation_required:'초기 통지와 최종 근거의 연결을 다시 확인해야 합니다.',initial_notice_pending:'초기 통지의 조회·전달 또는 최종 연결이 아직 완료되지 않았습니다.',initial_notice_unconfirmed:'초기 통지 상태를 확인하지 못했습니다.'};
    const message=state==='warning'&&Object.hasOwn(initialWarnings,coverage?.reason)?initialWarnings[coverage.reason]:({blocked:'새 로그 분석이 중단됐습니다.',delayed:'분석이 지연되고 있습니다.',catching_up:'대기 로그를 분석하고 있습니다.',warning:'일부 로그의 위험 평가가 완료되지 않았습니다.',not_started:'분석 미실행 · 탐지가 아직 시작되지 않았습니다.'}[state]||'분석 상태 미확인 · 조회 권한과 연결을 확인하세요.');
    warning.hidden=state==='observed';warning.textContent=message+' 경보 0건이 안전을 뜻하지 않습니다.';
  }
  async function refresh(){
    if(!collection||!layout)return;clearTimeout(timer);clearTimeout(noticeTimer);noticeController?.abort();controller?.abort();controller=new AbortController();const active=controller,current=++generation,end=Date.now();results={};render();$('dashboard-updated').textContent='데이터 조회 중';
    const timeout=setTimeout(()=>active.abort(),45000);
    try{const response=await W.load(W.plan(layout,catalog),active.signal,end);if(current!==generation)return;results=response;render();const failures=Object.values(results).filter(r=>r.error).length;$('dashboard-updated').textContent=W.time(new Date(end).toISOString())+(failures?' · '+failures+'개 데이터 조회 실패':' · 조회 완료');}
    finally{clearTimeout(timeout);if(current===generation&&!document.hidden&&$('dashboard-auto').checked){timer=setTimeout(refresh,60000);noticeTimer=setTimeout(()=>refreshNotices(current),10000);}}
  }
  async function refreshNotices(current){
    if(current!==generation||document.hidden||!$('dashboard-auto').checked)return;
    const keys=W.plan(layout,catalog).filter(key=>key.startsWith('notices:')&&results[key]?.status!==403);if(!keys.length)return;
    noticeController?.abort();noticeController=new AbortController();const active=noticeController,timeout=setTimeout(()=>active.abort(),8000);
    try{const response=await W.load(keys,active.signal);if(current!==generation)return;Object.assign(results,response);
      // Only replace notice contents: preserve current keyboard focus and drag handles.
      document.querySelectorAll('#platform-grid [data-type="early-notices"]').forEach(box=>{const w=layout.widgets.find(w=>w.id===box.dataset.instance);if(!w)return;const meta=catalog.find(m=>m.type===w.type),content=box.querySelector('.builder-widget-content');W.render(content,w,meta,results['notices:'+(w.config.period||layout.period)],{period:layout.period});});
    }finally{clearTimeout(timeout);if(current===generation&&!document.hidden&&$('dashboard-auto').checked)noticeTimer=setTimeout(()=>refreshNotices(current),10000);}
  }
  async function initialize(){
    try{const response=await query('/api/dashboards');if(!Array.isArray(response.catalog)||!Array.isArray(response.dashboards))throw new Error('저장 구성 형식을 확인하세요.');collection=response;catalog=response.catalog;templates=response.templates;selected=new URLSearchParams(location.search).get('dashboard')||response.default_id;if(selected!=='legacy'&&!response.dashboards.some(r=>r.id===selected))selected=response.default_id;layout=copy(item().layout);baseline=copy(layout);editing=false;history=[];error('');window.CloudSOCTheme?.adopt(layout.theme);rememberUrl();render();refresh();}catch(e){error('구성을 불러오지 못했습니다. '+e.message);$('dashboard-updated').textContent='구성 조회 실패';}}
  function showDialog(action,value){
    modalAction={action,value};const confirm=['delete','discard','reload'].includes(action);
    $('dialog-title').textContent=({create:'새 대시보드',rename:'이름 변경',duplicate:'대시보드 복제',delete:'대시보드 삭제',discard:'저장하지 않은 편집 취소',reload:'서버 구성 다시 불러오기'}[action]);
    $('dialog-description').textContent=action==='delete'?'이 개인 화면 구성만 삭제합니다. 경보·사건·기존 개인 설정은 유지됩니다.':confirm?'저장하지 않은 현재 편집을 취소합니다.':'템플릿의 실제 데이터 범위는 각 위젯 설명에서 확인하세요.';
    $('dialog-name-label').hidden=confirm;$('dialog-name').required=!confirm;$('dialog-template-label').hidden=action!=='create';$('dialog-error').textContent='';
    $('dialog-template').replaceChildren();[...templates,{id:'legacy',name:'기존 개인 화면 복사'}].forEach(t=>{const o=node('option',t.name);o.value=t.id;$('dialog-template').append(o);});$('dialog-template').value=value||'empty';
    $('dialog-name').value=action==='create'?(templates.find(t=>t.id===value)?.name||'새 대시보드'):action==='duplicate'?layout.name.slice(0,42)+' 복사본':layout.name;
    $('dialog-submit').textContent=confirm?'확인':action==='create'?'만들기':'저장';$('dashboard-dialog').showModal();
  }
  function configure(id){configId=id;const w=layout.widgets.find(r=>r.id===id);$('widget-type').replaceChildren();catalog.filter(m=>m.enabled).forEach(m=>{const o=node('option',m.title);o.value=m.type;$('widget-type').append(o);});$('widget-type').value=w.type;
    for(const name of ['title','period','limit','sort','severity','color'])$('widget-'+name).value=String(w.config[name]);$('widget-width').value=String(w.w);
    $('widget-height').replaceChildren();for(let height=2;height<=8;height++){const option=node('option',height===3?'기본 · 3칸':height+'칸 높이');option.value=String(height);$('widget-height').append(option);}
    $('widget-height').value=String(w.h);chartOptions(w.config.chart);$('widget-dialog').showModal();
  }
  function chartOptions(preferred){const meta=catalog.find(m=>m.type===$('widget-type').value);$('widget-chart').replaceChildren();meta.charts.forEach(c=>{const o=node('option',W.chartNames[c]);o.value=c;$('widget-chart').append(o);});if(meta.charts.includes(preferred))$('widget-chart').value=preferred;$('widget-description').textContent=meta.description;
    $('widget-severity').disabled=!['alerts','parts','entities'].includes(meta.renderer)||meta.source!=='operations';$('widget-period').disabled=['cases','agents'].includes(meta.source)||meta.type==='pipeline';
  }
  $('widget-type').addEventListener('change',()=>{chartOptions();$('widget-title').value=catalog.find(m=>m.type===$('widget-type').value).title;});
  $('widget-form').addEventListener('submit',event=>{event.preventDefault();const title=$('widget-title').value.trim();if(!title||/[<>\x00-\x1f]/.test(title)){ $('widget-description').textContent='HTML·제어문자 없이 이름을 입력하세요.';return;}
    update(()=>{const w=layout.widgets.find(r=>r.id===configId);w.type=$('widget-type').value;w.config={title,period:Number($('widget-period').value),chart:$('widget-chart').value,limit:Number($('widget-limit').value),sort:$('widget-sort').value,severity:$('widget-severity').disabled?'all':$('widget-severity').value,color:$('widget-color').value};w.w=Number($('widget-width').value);w.h=Number($('widget-height').value);},{reflow:true,fetch:true});$('widget-dialog').close();});
  $('widget-cancel').addEventListener('click',()=>$('widget-dialog').close());
  $('dashboard-dialog-form').addEventListener('submit',async event=>{event.preventDefault();const {action,value}=modalAction;
    if(action==='reset'){const source=templates.find(t=>t.id===$('dialog-template').value)?.layout||collection.legacy.layout;update(()=>{layout={...copy(source),name:$('dialog-name').value,theme:window.CloudSOCTheme?.get()||layout.theme};},{fetch:true});$('dashboard-dialog').close();return;}
    if(action==='discard'){ $('dashboard-dialog').close();switchTo(value);return;}
    if(action==='reload'){ $('dashboard-dialog').close();$('dashboard-conflict').hidden=true;await initialize();return;}
    const values=action==='create'?{template:$('dialog-template').value,name:$('dialog-name').value}:action==='delete'?{id:selected}:{id:selected,name:$('dialog-name').value};
    if(await mutate(action,values)){$('dashboard-dialog').close();rememberUrl();setPanel('canvas');refresh();}else $('dialog-error').textContent=$('dashboard-error').textContent;
  });
  $('dialog-cancel').addEventListener('click',()=>$('dashboard-dialog').close());
  $('dashboard-create').addEventListener('click',()=>showDialog('create','empty'));$('dashboard-rename').addEventListener('click',()=>showDialog('rename'));$('dashboard-duplicate').addEventListener('click',()=>showDialog('duplicate'));$('dashboard-delete').addEventListener('click',()=>showDialog('delete'));
  $('dashboard-favorite').addEventListener('click',()=>mutate('favorite',{id:selected,favorite:!item().favorite}));$('dashboard-default').addEventListener('click',()=>mutate('default',{id:selected}));
  $('dashboard-edit').addEventListener('click',begin);$('dashboard-cancel').addEventListener('click',cancel);
  $('dashboard-save').addEventListener('click',async()=>{layout.theme=window.CloudSOCTheme?.get()||layout.theme;if(await mutate('save',{id:selected,layout})){rememberUrl();refresh();}});
  $('dashboard-undo').addEventListener('click',()=>{if(!history.length||busy)return;layout=history.pop();render();refresh();message('이전 편집으로 되돌렸습니다.');});
  // Reset choices reuse the dialog, but only change the draft until explicit save.
  $('dashboard-reset').addEventListener('click',()=>{const title=layout.name;showDialog('create','security');modalAction={action:'reset'};$('dialog-title').textContent='템플릿으로 초기화';$('dialog-name').value=title;$('dialog-description').textContent='현재 편집을 선택한 템플릿으로 바꿉니다. 저장 전 되돌리거나 취소할 수 있습니다.';});
  $('dashboard-name').addEventListener('input',()=>{if(!editing||busy)return;remember();layout.name=$('dashboard-name').value;$('dashboard-title').textContent=layout.name;message('미저장 변경사항이 있습니다.');});
  $('dashboard-period').addEventListener('change',async()=>{const period=Number($('dashboard-period').value);if(!editing)await begin();if(editing)update(()=>{layout.period=period;},{fetch:true});});
  $('dashboard-refresh').addEventListener('click',()=>collection?refresh():initialize());$('dashboard-auto').addEventListener('change',()=>{if($('dashboard-auto').checked)refresh();else{clearTimeout(timer);clearTimeout(noticeTimer);noticeController?.abort();}});
  $('dashboard-reload').addEventListener('click',()=>showDialog('reload'));$('widget-search').addEventListener('input',library);$('widget-category').addEventListener('change',library);
  document.querySelectorAll('.builder-tabs button').forEach(b=>b.addEventListener('click',()=>setPanel(b.dataset.panel)));
  window.addEventListener('cloud-soc-themechange',event=>{if(layout)layout.theme=event.detail.theme;});
  window.addEventListener('beforeunload',event=>{if(dirty()){event.preventDefault();event.returnValue='';}});
  window.addEventListener('pagehide',()=>{generation++;controller?.abort();noticeController?.abort();clearTimeout(timer);clearTimeout(noticeTimer);});
  document.addEventListener('visibilitychange',()=>{if(document.hidden){generation++;controller?.abort();noticeController?.abort();clearTimeout(timer);clearTimeout(noticeTimer);}else if(collection)refresh();});
  initialize();
})();
