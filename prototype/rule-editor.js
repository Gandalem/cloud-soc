/* Server-owned capabilities drive forms, imports and readable summaries. */
(() => {
  'use strict';
  const $=id=>document.getElementById(id),base='/api/settings/rule-library';
  const names={ssh_failures:'반복 로그인 실패',web_errors:'반복 웹 오류',login_sequence:'로그인 실패 후 성공',waf_sqli:'SQLi 의심 요청',access_denied:'권한 없는 주문 접근'};
  const kinds={single:'이벤트 한 건',threshold:'횟수 기반',sequence:'실패 후 성공',waf:'WAF 공격 탐지'};
  const statuses={draft:'초안',approved:'승인됨',deleted:'삭제됨',delete_pending:'삭제 반영 대기',running:'사용 중',stopped:'사용 중지',not_started:'적용 전',pending:'반영 대기',failed:'처리 오류',stale:'연결 확인 필요'};
  const errors={rule_changed:'다른 변경이 있습니다. 목록에서 규칙을 다시 선택하세요.',rule_key_unavailable:'이미 사용한 규칙 ID입니다.',rule_key_reserved:'기본 제공 규칙과 다른 ID를 사용하세요.',
    rule_storage_unavailable:'규칙 저장소에 연결하지 못했습니다.',import_rows_invalid:'파일의 오류 항목을 수정하세요.',request_id_conflict:'파일을 다시 선택하세요.',
    condition_value_invalid:'조건 값의 형식을 확인하세요.',number_out_of_range:'횟수·시간·응답 코드의 허용 범위를 확인하세요.',start_in_future:'적용 시작 시각은 현재 시각보다 늦을 수 없습니다.',
    sequence_outcome_reserved:'실패 후 성공의 결과 조건은 자동으로 설정됩니다.',approval_required:'먼저 규칙을 승인하세요.',csv_columns_invalid:'제공된 CSV 양식의 열 순서를 사용하세요.'};
  let data=null,selected=null,editing=null,busy=false,importBody=null;
  const clone=d=>JSON.parse(JSON.stringify(d));
  const node=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n;};
  const option=(value,label)=>{const n=node('option',label);n.value=value;return n;};
  async function api(path='',body,signal){const response=await fetch(base+path,body===undefined?{cache:'no-store',signal}:{method:'POST',signal,headers:{'Content-Type':'application/json','X-Cloud-SOC':'portal'},body:JSON.stringify(body)});
    const result=await response.json();if(!response.ok)throw new Error(errors[result.code]||'요청을 처리하지 못했습니다. 입력과 권한을 확인하세요.');return result;}
  async function run(action){if(busy)return;busy=true;try{await action();}catch(e){$('rule-result').textContent=e.message;}finally{busy=false;}}
  function options(id,values,current){$(id).replaceChildren(...values.map(([v,l])=>option(v,l)));if(current!==undefined)$(id).value=current;}
  function sourceChange(conditions=[],groups=[]){const c=data.capabilities,source=$('rule-source').value,s=c.sources[source];
    const allowed=['waf','mall_waf'].includes(source)?['waf']:['ssh','mall'].includes(source)?['single','threshold','sequence']:['single','threshold'];
    const old=$('rule-kind').value;options('rule-kind',allowed.map(k=>[k,kinds[k]]),allowed.includes(old)?old:allowed[0]);
    $('rule-conditions').replaceChildren();for(const condition of conditions)addCondition(condition);
    $('rule-groups').replaceChildren(...c.groups.filter(f=>s.fields.includes(f)).map(f=>{const label=node('label'),input=node('input');input.type='checkbox';input.value=f;
      input.checked=s.groups.includes(f)||groups.includes(f);input.disabled=s.groups.includes(f);input.addEventListener('change',preview);label.append(input,node('span',c.fields[f].label));return label;}));kindChange();}
  function addCondition(condition){if($('rule-conditions').children.length>=12)return;const c=data.capabilities,s=c.sources[$('rule-source').value],row=node('div');row.className='rule-condition';
    const field=node('select'),op=node('select'),value=node('input'),remove=node('button','삭제');field.setAttribute('aria-label','조건 항목');op.setAttribute('aria-label','비교 방식');value.setAttribute('aria-label','조건 값');
    field.append(...s.fields.map(f=>option(f,c.fields[f].label)));if(condition)field.value=condition.field;
    function fieldChange(){const old=op.value;op.replaceChildren(...Object.entries(c.operators).filter(([k])=>c.fields[field.value].type==='number'?k!=='contains':k!=='greater_than').map(([k,v])=>option(k,v)));if([...op.options].some(o=>o.value===old))op.value=old;}
    function opChange(){value.type=c.fields[field.value].type==='number'&&!['in','exists'].includes(op.value)?'number':'text';value.placeholder=op.value==='in'?'값1;값2':op.value==='exists'?'true 또는 false':'';}
    fieldChange();if(condition)op.value=condition.operator;opChange();if(condition)value.value=Array.isArray(condition.value)?condition.value.join(';'):String(condition.value);
    field.addEventListener('change',()=>{fieldChange();opChange();preview();});op.addEventListener('change',()=>{opChange();preview();});value.addEventListener('input',preview);
    remove.type='button';remove.addEventListener('click',()=>{row.remove();preview();});row.append(field,op,value,remove);$('rule-conditions').append(row);preview();}
  function kindChange(){const k=$('rule-kind').value,single=k==='single';for(const id of ['rule-count-label','rule-window-label','rule-cooldown-label'])$(id).hidden=single;
    for(const id of ['rule-count','rule-window','rule-cooldown'])$(id).disabled=single;
    if($('rule-source').value==='mall_waf'){$('rule-count').value='1';$('rule-cooldown').value='0';$('rule-count').disabled=true;$('rule-cooldown').disabled=true;if(Number($('rule-window').value)>300)$('rule-window').value='300';}
    $('rule-success-label').hidden=k!=='sequence';$('rule-success').disabled=k!=='sequence';$('rule-success').required=k==='sequence';if(k==='sequence'&&!Number($('rule-success').value))$('rule-success').value='600';preview();}
  function definition(){const c=data.capabilities,kind=$('rule-kind').value;
    const conditions=[...$('rule-conditions').children].map(row=>{const [f,o,v]=row.querySelectorAll('select,input');let value=v.value;const convert=x=>c.fields[f.value].type==='number'?Number(x):x;
      if(o.value==='in')value=value.split(';').map(x=>convert(x.trim()));else if(o.value==='exists'){if(!['true','false'].includes(value))throw new Error('값 존재 조건은 true 또는 false를 입력하세요.');value=value==='true';}else value=convert(value);
      return {field:f.value,operator:o.value,value};});
    return {schema_version:1,key:$('rule-key').value.trim(),name:$('rule-name').value.trim(),description:$('rule-description').value,source:$('rule-source').value,kind,conditions,
      group_by:[...$('rule-groups').querySelectorAll('input:checked')].map(n=>n.value),count:kind==='single'?1:Number($('rule-count').value),window_seconds:kind==='single'?1:Number($('rule-window').value),
      cooldown_seconds:kind==='single'?0:Number($('rule-cooldown').value),success_seconds:kind==='sequence'?Number($('rule-success').value):0,severity:$('rule-severity').value};}
  function preview(){if(!data)return;try{const d=definition(),c=data.capabilities,conditions=d.conditions.map(x=>c.fields[x.field].label+' '+c.operators[x.operator]+' '+(Array.isArray(x.value)?x.value.join(', '):x.value)).join(' · ')||'해당 로그 이벤트';
    $('rule-summary').textContent=c.sources[d.source].label+' / '+conditions+' / '+(d.kind==='single'?'한 건 관측':`최근 ${d.window_seconds}초 동안 ${d.count}회`)+(d.kind==='sequence'?` → 마지막 해당 실패 후 ${d.success_seconds}초 안에 성공`:'')+' 시 경보';
  }catch(e){$('rule-summary').textContent=e.message;}}
  function fill(d,row=null){editing=row;$('rule-editor-title').textContent=row?'규칙 수정':'새 규칙';$('rule-key').disabled=!!row;$('rule-organization').disabled=!!row;if(row)$('rule-organization').value=row.organization;
    for(const [id,key] of [['rule-key','key'],['rule-name','name'],['rule-description','description'],['rule-count','count'],['rule-window','window_seconds'],['rule-cooldown','cooldown_seconds'],['rule-success','success_seconds'],['rule-severity','severity']])$(id).value=d[key];
    $('rule-source').value=d.source;sourceChange(d.conditions,d.group_by);$('rule-kind').value=d.kind;kindChange();}
  function state(row){return row.status==='delete_pending'?'삭제 반영 대기':row.active?'사용 중':(statuses[row.runtime_state]||'연결 확인 필요')+' · '+statuses[row.status];}
  function show(row){selected=row;$('rule-detail').hidden=false;$('rule-detail-name').textContent=row.definition.name;$('rule-detail-summary').textContent=row.summary;$('rule-detail-state').textContent=row.organization+' · '+state(row)+(row.requested_version?' · 적용 요청 v'+row.requested_version:'')+(row.observed_version?' · 워커 보고 v'+row.observed_version:'');
    const deleted=['deleted','delete_pending'].includes(row.status);for(const id of ['rule-edit','rule-delete'])$(id).disabled=deleted;$('rule-approve').disabled=row.status!=='draft';$('rule-apply').disabled=row.status!=='approved';$('rule-stop').disabled=deleted||row.desired!=='running';
    $('rule-history').replaceChildren(...row.history.map(h=>node('p',new Date(h.at).toLocaleString()+' · '+h.actor+' · '+({created:'생성',edit:'수정',approve:'승인',apply:'적용 요청',stop:'사용 중지',delete:'삭제 요청'}[h.action]||h.action)+' · v'+h.version)));
    const reasons={late_input_reprocessing_required:'늦게 도착한 입력',future_event_time:'미래 시각 입력',required_fields_missing:'필수 필드 누락',group_values_invalid:'집계 기준 값 오류',event_time_invalid:'이벤트 시각 오류',analysis_context_changed:'기존 경보의 분석 문맥 변경'};
    $('rule-input-issues').replaceChildren(...(row.input_issues||[]).map(i=>node('p',(reasons[i.reason]||'입력 확인 필요')+' '+i.count+'건')));}
  function render(){const search=$('rule-search').value.toLowerCase(),org=$('rule-filter-org').value,filter=$('rule-filter-state').value;
    const rows=data.rules.filter(r=>(!org||r.organization===org)&&(!filter||r.status===filter||r.runtime_state===filter)&&(!search||[r.definition.name,r.definition.key,r.summary,JSON.stringify(r.definition.conditions)].join(' ').toLowerCase().includes(search)));
    window.CloudSOCLive.children($('rule-list'),rows.map(r=>{const card=node('article');card.className='rule-card';card.dataset.liveKey=r.id;const button=node('button','상세 보기');button.type='button';button.addEventListener('click',()=>run(async()=>show(await api('/'+r.id))));card.append(node('h3',r.definition.name),node('p',r.summary),node('p',r.organization+' · '+state(r)),button);return card;}));if(!rows.length)$('rule-list').append(node('p','등록된 규칙이 없습니다.'));}
  const live=window.CloudSOCLive.create({host:$('rule-result').parentElement,interval:10000,enabled:()=>!busy,
    load:async signal=>{const listing=await api('',undefined,signal);const row=selected&&listing.rules.find(r=>r.id===selected.id);return {listing,detail:row?await api('/'+row.id,undefined,signal):null};},
    apply:({listing,detail})=>{data=listing;render();if(selected){if(detail)show(detail);else{$('rule-detail').hidden=true;selected=null;}}},
    onError:()=>{$('rule-result').textContent='상태 갱신 실패 · 작성 중인 내용과 마지막 조회는 유지됩니다.';}});
  function refresh(){return live.refresh(true);}
  function copy(d){const value=clone(d);value.key='CUSTOM-'+crypto.randomUUID().slice(0,8).toUpperCase();value.name+=' 복사';return value;}
  async function start(){data=await api();const c=data.capabilities;for(const id of ['rule-organization','rule-import-org'])options(id,data.organizations.map(o=>[o,o]));$('rule-filter-org').append(...data.organizations.map(o=>option(o,o)));
    options('rule-template',Object.keys(c.templates).map(k=>[k,names[k]]));options('rule-source',Object.entries(c.sources).map(([k,v])=>[k,v.label]));fill(clone(c.templates.ssh_failures));render();$('rule-save').disabled=!data.organizations.length;
    $('rule-builtin-list').replaceChildren(...data.builtin.map(r=>{const card=node('article');card.className='rule-card';const detail=node('details');detail.append(node('summary',r.name+' · '+r.key),node('p',`최근 ${r.window_seconds}초 / 기준 ${r.count}회`));
      for(const x of r.conditions)detail.append(node('p',(c.fields[x.field]?.label||({'cloud_soc.detail.adapter':'로그 형식','cloud_soc.detail.fields.sqli':'SQLi 의심','waf.engine_mode':'WAF 모드','organization.id':'조직'}[x.field])||x.field)+' '+(c.operators[x.operator]||x.operator)+' '+JSON.stringify(x.value)));
      card.append(detail);if(r.definition){const button=node('button','복제해서 작성');button.type='button';button.addEventListener('click',()=>{fill(copy(r.definition));$('rule-editor').scrollIntoView({behavior:'smooth'});});card.append(button);}return card;}));
    const now=new Date();$('rule-start').value=new Date(now.getTime()-now.getTimezoneOffset()*60000).toISOString().slice(0,19);}
  $('rule-create').addEventListener('submit',event=>{event.preventDefault();run(async()=>{const d=definition(),row=editing?await api('/'+editing.id+'/edit',{version:editing.version,content_hash:editing.content_hash,definition:d}):await api('',{organization:$('rule-organization').value,definition:d});fill(row.definition,row);show(row);await refresh();$('rule-result').textContent='규칙을 저장했습니다.';});});
  for(const id of ['rule-name','rule-key','rule-description','rule-count','rule-window','rule-cooldown','rule-success','rule-severity'])$(id).addEventListener('input',preview);
  for(const id of ['rule-search','rule-filter-org','rule-filter-state'])$(id).addEventListener('input',()=>data&&render());$('rule-kind').addEventListener('change',kindChange);$('rule-source').addEventListener('change',()=>sourceChange());
  $('rule-template').addEventListener('change',()=>fill(clone(data.capabilities.templates[$('rule-template').value])));$('rule-add-condition').addEventListener('click',()=>addCondition());
  for(const id of ['rule-new','rule-cancel'])$(id).addEventListener('click',()=>{fill(copy(data.capabilities.templates[$('rule-template').value]));$('rule-editor').scrollIntoView({behavior:'smooth'});});
  $('rule-edit').addEventListener('click',()=>{fill(selected.definition,selected);$('rule-editor').scrollIntoView({behavior:'smooth'});});$('rule-copy').addEventListener('click',()=>{const org=selected.organization;fill(copy(selected.definition));$('rule-organization').value=org;$('rule-editor').scrollIntoView({behavior:'smooth'});});
  for(const action of ['approve','apply','stop','delete'])$('rule-'+action).addEventListener('click',()=>run(async()=>{if(!selected)return;if(action==='delete'&&!window.confirm('이 규칙을 삭제하시겠습니까? 기존 경보와 변경 이력은 보존됩니다.'))return;
    const body={version:selected.version,content_hash:selected.content_hash};if(action==='apply'){const date=new Date($('rule-start').value);if(!Number.isFinite(date.getTime()))throw new Error('적용 시작 시각을 입력하세요.');body.effective_from=date.toISOString();}
    show(await api('/'+selected.id+'/'+action,body));await refresh();$('rule-result').textContent={approve:'규칙을 승인했습니다.',apply:'적용을 요청했습니다.',stop:'사용 중지를 요청했습니다.',delete:'삭제 요청을 저장했습니다.'}[action];}));
  function clearImport(){importBody=null;$('rule-import-list').replaceChildren();$('rule-import-create').disabled=true;}
  $('rule-file').addEventListener('change',clearImport);$('rule-import-org').addEventListener('change',clearImport);
  $('rule-import-preview').addEventListener('click',()=>run(async()=>{clearImport();const file=$('rule-file').files[0];if(!file)throw new Error('규칙 파일을 선택하세요.');if(file.size>262144)throw new Error('파일은 256KiB 이하여야 합니다.');
    const format=file.name.toLowerCase().endsWith('.json')?'json':file.name.toLowerCase().endsWith('.csv')?'csv':null;if(!format)throw new Error('CSV 또는 JSON 파일을 선택하세요.');importBody={organization:$('rule-import-org').value,format,content:await file.text(),request_id:crypto.randomUUID()};
    const result=await api('/import/preview',importBody);$('rule-import-list').replaceChildren(...result.items.map(item=>{const row=node('label'),check=node('input');check.type='checkbox';check.value=item.row;check.checked=item.valid;check.disabled=!item.valid;check.addEventListener('change',()=>{$('rule-import-create').disabled=!$('rule-import-list').querySelector('input:checked');});row.append(check,node('span',item.valid?`${item.row}. ${item.key} · ${item.summary}`:`${item.row}. ${errors[item.code]||'입력 조건 또는 중복 ID를 확인하세요.'}`));return row;}));$('rule-import-create').disabled=!result.items.some(i=>i.valid);$('rule-result').textContent='등록할 항목을 선택하세요.';}));
  $('rule-import-create').addEventListener('click',()=>run(async()=>{if(!importBody)return;const selected_rows=[...$('rule-import-list').querySelectorAll('input:checked')].map(n=>Number(n.value));const result=await api('/import/create',{...importBody,selected_rows});$('rule-result').textContent=result.created.length+'개 규칙을 등록했습니다.';clearImport();await refresh();}));
  run(async()=>{await start();await live.start();});
})();
