/* Multiple private dashboards. Only explicit actions persist server-side metadata. */
(() => {
  'use strict';
  const W=window.CloudSOCWidgets,$=id=>document.getElementById(id);
  if(!W||!$('platform-grid'))return;
  const {copy,node,query}=W;
  let collection=null,catalog=[],templates=[],selected='legacy',layout=null,baseline=null,editing=false,busy=false,history=[],results={},generation=0,controller,timer,noticeController,noticeTimer,modalAction,configId;
  let movement=null;
  const item=()=>selected==='legacy'?collection?.legacy:collection?.dashboards.find(row=>row.id===selected);
  const dirty=()=>editing&&JSON.stringify(layout)!==JSON.stringify(baseline);
  function error(message){$('dashboard-error').textContent=message;$('dashboard-error').hidden=!message;}
  function setPanel(panel){document.querySelector('.builder-workspace').dataset.panel=panel;document.querySelectorAll('.builder-tabs button').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.panel===panel)));}
  function message(text){$('dashboard-save-state').textContent=text;}
  function remember(){history.push(copy(layout));if(history.length>30)history.shift();}
  function update(fn,{reflow=false,fetch=false}={}){if(busy)return;clearMovement();remember();fn();if(reflow)W.compact(layout.widgets);render();if(fetch)refresh();message('미리보기 · 변경사항을 저장하세요.');}
  function locked(value){if(value)clearMovement();busy=value;document.querySelectorAll('main button,main input,main select').forEach(e=>e.disabled=value);if(!value&&collection)render();}
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
  function focusWidget(id){$('platform-grid').querySelector('[data-instance="'+id+'"] .builder-title-move')?.focus();}
  function clearMovement(restoreFocus=false){
    const previous=movement;movement=null;
    previous?.cleanup?.();previous?.preview?.remove();
    document.body.classList.remove('builder-is-dragging');
    document.querySelectorAll('.builder-move-destination').forEach(e=>e.remove());
    document.querySelectorAll('.builder-move-origin,.builder-target-before,.builder-target-after').forEach(e=>e.classList.remove('builder-move-origin','builder-target-before','builder-target-after'));
    document.querySelectorAll('.builder-title-move[aria-pressed="true"]').forEach(e=>e.setAttribute('aria-pressed','false'));
    $('platform-grid').classList.remove('choosing-position');$('dashboard-movebar').hidden=true;
    if(restoreFocus&&previous)focusWidget(previous.id);
  }
  function cancelMovement(){if(!movement)return;clearMovement(true);message('이동을 취소했습니다. 기존 배치는 유지됩니다.');}
  function moveMessage(text){if($('dashboard-move-message').textContent!==text)$('dashboard-move-message').textContent=text;}
  function finishMove(candidate,id){
    if(!candidate){moveMessage('이 자리에 배치할 공간이 부족합니다. 다른 위치를 선택하세요.');return false;}
    const changed=candidate.some(w=>{const old=layout.widgets.find(r=>r.id===w.id);return old.x!==w.x||old.y!==w.y||old.w!==w.w||old.h!==w.h;});
    if(changed){update(()=>{layout.widgets=candidate;});message('위젯을 옮겼습니다. 구성 저장을 누르면 유지됩니다.');}
    else{clearMovement();message('기존 위치를 유지했습니다.');}
    focusWidget(id);return true;
  }
  function previewMove(session,candidate,targetId,side){
    if(movement!==session)return;
    session.candidate=candidate;
    document.querySelectorAll('.builder-target-before,.builder-target-after').forEach(e=>e.classList.remove('builder-target-before','builder-target-after'));
    if(targetId&&candidate)$('platform-grid').querySelector('[data-instance="'+targetId+'"]')?.classList.add('builder-target-'+side);
    if(!candidate){session.preview?.remove();session.preview=null;moveMessage('이 자리에 배치할 공간이 부족합니다. 다른 위치를 선택하세요.');return;}
    moveMessage('강조된 위치에 놓습니다. 주변 위젯은 놓은 뒤 정리됩니다. Esc로 취소할 수 있습니다.');
    if(window.innerWidth<=700)return;
    const grid=$('platform-grid'),rect=grid.getBoundingClientRect(),style=window.getComputedStyle(grid),gap=parseFloat(style.columnGap)||16,rowGap=parseFloat(style.rowGap)||16,rowHeight=parseFloat(style.gridAutoRows)||76;
    const column=(rect.width+gap)/12,w=candidate.find(r=>r.id===session.id);
    if(!session.preview){session.preview=node('div','여기에 배치','builder-drop-preview');session.preview.setAttribute('aria-hidden','true');document.body.append(session.preview);}
    const ghost=session.preview;
    ghost.style.left=(rect.left+w.x*column)+'px';ghost.style.top=(rect.top+w.y*(rowHeight+rowGap))+'px';
    ghost.style.width=(w.w*column-gap)+'px';ghost.style.height=(w.h*(rowHeight+rowGap)-rowGap)+'px';
  }
  function positionAt(session,point){
    const grid=$('platform-grid'),rect=grid.getBoundingClientRect();
    if(point.x<rect.left||point.x>rect.right||point.y<rect.top||point.y>rect.bottom+160)return {candidate:null};
    const hit=document.elementFromPoint(point.x,point.y)?.closest('#platform-grid [data-instance]');
    if(hit&&hit.dataset.instance!==session.id){
      const target=hit.getBoundingClientRect(),side=point.y<target.top+target.height/2?'before':'after';
      return {candidate:W.relocate(layout.widgets,session.id,{targetId:hit.dataset.instance,side}),targetId:hit.dataset.instance,side};
    }
    if(window.innerWidth<=700)return {candidate:null};
    const style=window.getComputedStyle(grid),gap=parseFloat(style.columnGap)||16,rowGap=parseFloat(style.rowGap)||16,rowHeight=parseFloat(style.gridAutoRows)||76,column=(rect.width+gap)/12;
    const w=layout.widgets.find(r=>r.id===session.id),offset=session.offset||{x:column*w.w/2,y:24};
    const x=Math.max(0,Math.min(12-w.w,Math.round((point.x-rect.left-offset.x)/column))),y=Math.max(0,Math.min(240,Math.round((point.y-rect.top-offset.y)/(rowHeight+rowGap))));
    return {candidate:W.relocate(layout.widgets,session.id,{x,y})};
  }
  function startClickMove(id){
    if(!editing||busy)return;
    if(movement?.id===id&&movement.mode==='click'){cancelMovement();return;}
    clearMovement();
    const session={id,mode:'click',candidate:null};movement=session;
    $('platform-grid').classList.add('choosing-position');$('dashboard-movebar').hidden=false;
    moveMessage('옮길 위젯의 앞·뒤 버튼이나 빈 공간을 선택하세요. Esc로 취소할 수 있습니다.');
    document.querySelectorAll('#platform-grid [data-instance]').forEach(box=>{
      const active=box.dataset.instance===id;
      box.classList.toggle('builder-move-origin',active);box.querySelector('.builder-title-move')?.setAttribute('aria-pressed',String(active));
      if(active)return;
      const targets=node('div',undefined,'builder-move-destination');
      for(const [side,text] of [['before','이 위젯 앞에 놓기'],['after','이 위젯 뒤에 놓기']]){
        const b=node('button',text);b.type='button';b.setAttribute('aria-label',box.querySelector('h2').textContent+' '+text);
        const proposal=()=>W.relocate(layout.widgets,id,{targetId:box.dataset.instance,side});
        const show=()=>previewMove(session,proposal(),box.dataset.instance,side);
        b.addEventListener('pointerenter',show);b.addEventListener('focus',show);
        b.addEventListener('click',event=>{event.stopPropagation();if(movement===session)finishMove(proposal(),id);});targets.append(b);
      }
      box.append(targets);
    });
    message('이동할 위치를 선택하는 중입니다.');
  }
  function titleMovement(handle,w){
    let suppressClick=false;
    handle.addEventListener('click',()=>{if(suppressClick){suppressClick=false;return;}startClickMove(w.id);});
    handle.addEventListener('keydown',event=>{
      if(event.altKey&&['ArrowUp','ArrowDown'].includes(event.key)){
        event.preventDefault();const at=layout.widgets.findIndex(r=>r.id===w.id),target=layout.widgets[at+(event.key==='ArrowUp'?-1:1)];
        if(target)finishMove(W.relocate(layout.widgets,w.id,{targetId:target.id,side:event.key==='ArrowUp'?'before':'after'}),w.id);
      }
    });
    handle.addEventListener('pointerdown',event=>{
      if(!editing||busy||event.button!==0||!event.isPrimary||window.innerWidth<=700)return;
      clearMovement();event.preventDefault();
      const box=handle.closest('.builder-widget'),rect=box.getBoundingClientRect(),start={x:event.clientX,y:event.clientY};
      const session={id:w.id,mode:'drag',active:false,candidate:null,point:start,offset:{x:start.x-rect.left,y:start.y-rect.top}};movement=session;
      let frame=0;
      function paint(){const p=positionAt(session,session.point);previewMove(session,p.candidate,p.targetId,p.side);}
      function scrolling(){
        if(movement!==session||!session.active)return;
        const p=session.point,grid=$('platform-grid').getBoundingClientRect();
        const delta=p.x>=grid.left&&p.x<=grid.right?(p.y<88?-14:p.y>window.innerHeight-88?14:0):0;
        if(delta){const before=window.scrollY;window.scrollBy(0,delta);if(window.scrollY!==before)paint();}
        frame=window.requestAnimationFrame(scrolling);
      }
      function moving(e){
        if(movement!==session||e.pointerId!==event.pointerId)return;
        session.point={x:e.clientX,y:e.clientY};
        if(!session.active&&Math.hypot(e.clientX-start.x,e.clientY-start.y)<7)return;
        if(!session.active){session.active=true;suppressClick=true;box.classList.add('builder-move-origin');handle.setAttribute('aria-pressed','true');document.body.classList.add('builder-is-dragging');$('dashboard-movebar').hidden=false;frame=window.requestAnimationFrame(scrolling);}
        paint();
      }
      function up(e){
        if(e.pointerId!==event.pointerId||movement!==session)return;
        if(!session.active){clearMovement();return;}
        session.point={x:e.clientX,y:e.clientY};paint();const candidate=session.candidate;
        if(!finishMove(candidate,w.id)){clearMovement(true);message('다른 위치에 다시 놓아 주세요. 기존 배치는 유지됩니다.');}
      }
      function abort(){if(movement===session)cancelMovement();}
      session.cleanup=()=>{window.cancelAnimationFrame(frame);handle.removeEventListener('pointermove',moving);handle.removeEventListener('pointerup',up);handle.removeEventListener('pointercancel',abort);handle.removeEventListener('lostpointercapture',abort);if(handle.hasPointerCapture(event.pointerId))handle.releasePointerCapture(event.pointerId);};
      handle.addEventListener('pointermove',moving);handle.addEventListener('pointerup',up);handle.addEventListener('pointercancel',abort);handle.addEventListener('lostpointercapture',abort);handle.setPointerCapture(event.pointerId);
    });
  }
  function resizeMovement(handle,w){
    handle.addEventListener('pointerdown',event=>{
      if(!editing||busy||event.button!==0||window.innerWidth<=700)return;
      clearMovement();event.preventDefault();
      const start={x:event.clientX,y:event.clientY},rect=$('platform-grid').getBoundingClientRect(),column=(rect.width+16)/12;
      const session={id:w.id,mode:'resize',candidate:null};movement=session;$('dashboard-movebar').hidden=false;
      function moving(e){
        if(e.pointerId!==event.pointerId||movement!==session)return;
        const width=w.w+(e.clientX-start.x)/column;
        const change={w:[3,6,12].reduce((best,v)=>Math.abs(v-width)<Math.abs(best-width)?v:best,3),h:Math.max(2,Math.min(8,w.h+Math.round((e.clientY-start.y)/92)))};
        previewMove(session,W.place(layout.widgets,w.id,change));
      }
      function up(e){if(e.pointerId!==event.pointerId||movement!==session)return;const candidate=session.candidate;clearMovement();if(candidate)finishMove(candidate,w.id);}
      function abort(){if(movement===session)cancelMovement();}
      session.cleanup=()=>{handle.removeEventListener('pointermove',moving);handle.removeEventListener('pointerup',up);handle.removeEventListener('pointercancel',abort);handle.removeEventListener('lostpointercapture',abort);if(handle.hasPointerCapture(event.pointerId))handle.releasePointerCapture(event.pointerId);};
      handle.addEventListener('pointermove',moving);handle.addEventListener('pointerup',up);handle.addEventListener('pointercancel',abort);handle.addEventListener('lostpointercapture',abort);handle.setPointerCapture(event.pointerId);
    });
  }
  function widgetTools(box,w){
    const actions=node('div',undefined,'builder-widget-tools');
    for(const [label,fn] of [['설정',()=>{clearMovement();configure(w.id);}],['이동',()=>startClickMove(w.id)],['제거',()=>update(()=>{layout.widgets=layout.widgets.filter(row=>row.id!==w.id);},{reflow:true,fetch:true})]]){
      const b=node('button',label);b.type='button';b.setAttribute('aria-label',w.config.title+' '+label);b.addEventListener('click',fn);b.disabled=busy;actions.append(b);
    }
    const title=box.querySelector('h2'),handle=node('button',undefined,'builder-title-move');
    handle.type='button';handle.setAttribute('aria-label',w.config.title+' 이동 · 끌어서 놓거나 클릭해서 위치 선택');handle.setAttribute('aria-pressed','false');handle.append(node('span','⠿','builder-title-icon'),node('span',w.config.title));title.replaceChildren(handle);titleMovement(handle,w);
    const resize=node('button','↘ 크기','builder-resize');resize.type='button';resize.setAttribute('aria-label',w.config.title+' 크기 조정');
    resize.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();clearMovement();configure(w.id);}});
    box.append(actions,resize);resizeMovement(resize,w);
  }
  function render(){if(!layout||!collection)return;clearMovement();
    $('dashboard-title').textContent=layout.name;$('dashboard-description').textContent=editing?'변경사항을 미리 보는 중입니다. 저장하면 다시 로그인해도 유지됩니다.':selected==='legacy'?'기존 개인 설정을 보존한 화면입니다. 편집은 복사본에서 시작합니다.':'이 계정의 개인 관제 화면 · 위젯별 기간과 데이터 범위를 확인하세요.';
    controls();renderList();library();const grid=$('platform-grid');grid.replaceChildren();grid.classList.toggle('editing',editing);
    layout.widgets.forEach((w,index)=>{const meta=catalog.find(m=>m.type===w.type),box=node('section',undefined,'dash-widget builder-widget span-'+w.w+' column-'+w.x+' row-'+w.y+' height-'+w.h+' accent-'+w.config.color);box.dataset.instance=w.id;box.dataset.type=w.type;box.tabIndex=0;box.append(node('h2',w.config.title));
      const content=node('div',undefined,'builder-widget-content'),key=meta?.source+(meta&&['operations','logs','notices','web','cloud','geo','accounts','evaluation','cloud-alerts'].includes(meta.source)?':'+(w.config.period||layout.period):'');
      W.render(content,w,meta,results[key]||{loading:true},{cases:results.cases,period:layout.period});box.append(content);if(editing)widgetTools(box,w,index);grid.append(box);
    });
    if(!layout.widgets.length){const blank=node('div',undefined,'builder-blank');blank.append(node('h2','나만의 관제 화면을 구성하세요'),node('p','위젯 찾기에서 필요한 정보를 추가하거나 기본 템플릿으로 시작할 수 있습니다.'));const b=node('button','위젯 찾기','dash-primary');b.type='button';b.addEventListener('click',()=>setPanel('library'));blank.append(b);grid.append(blank);}
    const coverage=results.status?.body?.coverage,state=coverage?.state,warning=$('dashboard-coverage');
    const initialWarnings={initial_notice_failed:'초기 탐지 통지 처리에 실패했습니다.',initial_notice_reconciliation_required:'초기 통지와 최종 근거의 연결을 다시 확인해야 합니다.',initial_notice_pending:'초기 통지의 조회·전달 또는 최종 연결이 아직 완료되지 않았습니다.',initial_notice_unconfirmed:'초기 통지 상태를 확인하지 못했습니다.'};
    let message=state==='warning'&&Object.hasOwn(initialWarnings,coverage?.reason)?initialWarnings[coverage.reason]:({blocked:'새 로그 분석이 중단됐습니다.',delayed:'분석이 지연되고 있습니다.',catching_up:'대기 로그를 분석하고 있습니다.',warning:'일부 로그의 위험 평가가 완료되지 않았습니다.',not_started:'분석 미실행 · 탐지가 아직 시작되지 않았습니다.'}[state]||'분석 상태 미확인 · 조회 권한과 연결을 확인하세요.');
    const processing=window.CloudSOCProcessing?.view(results.status?.body);
    for(const [id,key] of [['dashboard-realtime','realtime'],['dashboard-backlog','historical']]){const box=$(id);if(box){box.hidden=!processing;box.textContent=processing?.[key]||'';}}
    if(processing&&['observed','warning'].includes(processing.state)&&state==='delayed')message='과거 로그 분석이 지연되고 있습니다.';
    if(coverage?.reason==='retrospective_failed')message='늦게 도착한 과거 로그의 재평가가 중단됐습니다.';
    warning.hidden=state==='observed';warning.textContent=message+' 경보 0건이 안전을 뜻하지 않습니다.';
  }
  const pending=window.CloudSOCLive.notice($('dashboard-updated').parentElement,'새 경보');
  function drawData(){
    document.querySelectorAll('#platform-grid [data-instance]').forEach(box=>{
      const w=layout.widgets.find(w=>w.id===box.dataset.instance),meta=w&&catalog.find(m=>m.type===w.type);if(!w)return;
      const key=meta?.source+(meta&&['operations','logs','notices','web','cloud','geo','accounts','evaluation','cloud-alerts'].includes(meta.source)?':'+(w.config.period||layout.period):'');
      if(window.CloudSOCInsights?.handles(meta)){window.CloudSOCInsights.render(box.querySelector('.builder-widget-content'),w,meta,results[key]||{loading:true},{cases:results.cases,period:layout.period});return;}
      const fresh=node('div');W.render(fresh,w,meta,results[key]||{loading:true},{cases:results.cases,period:layout.period});
      window.CloudSOCLive.children(box.querySelector('.builder-widget-content'),fresh.childNodes);
    });
    const status=results.status?.body,processing=window.CloudSOCProcessing?.view(status);
    for(const [id,key] of [['dashboard-realtime','realtime'],['dashboard-backlog','historical']])if($(id)){$(id).hidden=!processing;$(id).textContent=processing?.[key]||'';}
    const state=status?.realtime_coverage?.state||status?.coverage?.state;
    $('dashboard-coverage').hidden=state==='observed';$('dashboard-coverage').textContent=state==='not_started'?'적용된 탐지 규칙이 없습니다.':'분석 상태·지연을 확인하세요. 경보 0건이 안전을 뜻하지 않습니다.';
  }
  const live=window.CloudSOCLive.create({host:$('dashboard-updated').parentElement,interval:10000,timeout:45000,
    enabled:()=>!!collection&&!editing&&!busy&&$('dashboard-auto').checked,
    load:signal=>W.load(W.plan(layout,catalog),signal),
    apply:(fresh,{manual})=>{
      if(!fresh)throw new Error('자료 조회에 실패했습니다.');
      const merged=W.mergeResults(results,fresh);fresh=merged.values;
      let added=0;const staged={};
      for(const [key,value]of Object.entries(fresh)){
        if(key.startsWith('operations:')&&results[key]?.body?.sections?.alerts?.rows){
          const previous=results[key].body.sections.alerts.rows,newRows=value.body.sections.alerts.rows;
          added+=newRows.filter(r=>!previous.some(old=>old.id===r.id)).length;
          staged[key]=copy(value);
          if(!manual)value.body.sections.alerts.rows=previous;
        }
      }
      // Save the complete new rows separately before retaining the displayed list.
      error('');results={...results,...fresh};
      if(manual){pending.clear();render();}
      else{drawData();if(added)pending.offer(added,()=>{for(const [key,value]of Object.entries(staged))results[key]=value;drawData();});}
      if(merged.failed.length){$('dashboard-updated').textContent='일부 자료 갱신 실패';throw new Error('일부 자료 갱신 실패 · 해당 위젯의 마지막 조회 내용은 유지됩니다.');}
      $('dashboard-updated').textContent=W.time(new Date().toISOString())+' · 조회 완료';
    },onError:e=>error(e.message)});
  function refresh(){if(!collection||!layout)return;error('');pending.clear();return live.refresh(true);}
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
    $('widget-severity').disabled=!['alerts','parts','entities'].includes(meta.renderer)||meta.source!=='operations';$('widget-period').disabled=['cases','agents','fleet'].includes(meta.source)||meta.type==='pipeline';
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
  $('dashboard-move-cancel').addEventListener('click',cancelMovement);
  document.addEventListener('keydown',event=>{if(event.key==='Escape'&&movement){event.preventDefault();cancelMovement();}});
  window.addEventListener('resize',()=>{if(movement)cancelMovement();});
  window.addEventListener('blur',()=>{if(movement&&movement.mode!=='click')cancelMovement();});
  $('platform-grid').addEventListener('pointermove',event=>{if(movement?.mode==='click'&&!event.target.closest('.builder-move-destination')){const p=positionAt(movement,{x:event.clientX,y:event.clientY});previewMove(movement,p.candidate,p.targetId,p.side);}});
  $('platform-grid').addEventListener('click',event=>{
    if(movement?.mode!=='click'||event.target.closest('[data-instance],button,a,input,select'))return;
    const session=movement,p=positionAt(session,{x:event.clientX,y:event.clientY});finishMove(p.candidate,session.id);
  });
  $('dashboard-edit').addEventListener('click',begin);$('dashboard-cancel').addEventListener('click',cancel);
  $('dashboard-save').addEventListener('click',async()=>{layout.theme=window.CloudSOCTheme?.get()||layout.theme;if(await mutate('save',{id:selected,layout})){rememberUrl();refresh();}});
  $('dashboard-undo').addEventListener('click',()=>{if(!history.length||busy)return;layout=history.pop();render();refresh();message('이전 편집으로 되돌렸습니다.');});
  // Reset choices reuse the dialog, but only change the draft until explicit save.
  $('dashboard-reset').addEventListener('click',()=>{const title=layout.name;showDialog('create','security');modalAction={action:'reset'};$('dialog-title').textContent='템플릿으로 초기화';$('dialog-name').value=title;$('dialog-description').textContent='현재 편집을 선택한 템플릿으로 바꿉니다. 저장 전 되돌리거나 취소할 수 있습니다.';});
  $('dashboard-name').addEventListener('input',()=>{if(!editing||busy)return;remember();layout.name=$('dashboard-name').value;$('dashboard-title').textContent=layout.name;message('미저장 변경사항이 있습니다.');});
  $('dashboard-period').addEventListener('change',async()=>{const period=Number($('dashboard-period').value);if(!editing)await begin();if(editing)update(()=>{layout.period=period;},{fetch:true});});
  $('dashboard-refresh').addEventListener('click',()=>collection?refresh():initialize());$('dashboard-auto').addEventListener('change',()=>{if($('dashboard-auto').checked)refresh();else live.cancel();});
  $('dashboard-reload').addEventListener('click',()=>showDialog('reload'));$('widget-search').addEventListener('input',library);$('widget-category').addEventListener('change',library);
  document.querySelectorAll('.builder-tabs button').forEach(b=>b.addEventListener('click',()=>setPanel(b.dataset.panel)));
  window.addEventListener('cloud-soc-themechange',event=>{if(layout)layout.theme=event.detail.theme;});
  window.addEventListener('beforeunload',event=>{if(dirty()){event.preventDefault();event.returnValue='';}});
  window.addEventListener('pagehide',()=>{clearMovement();generation++;controller?.abort();noticeController?.abort();clearTimeout(timer);clearTimeout(noticeTimer);});
  initialize();
})();
