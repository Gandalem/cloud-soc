/* Device lifecycle UI: keep drafts and request IDs; never render or copy publisher secrets. */
const SocDevices = (() => {
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const states = {requested:'설치 대기',awaiting_receipt:'최초 수신 대기',received:'등록 확인됨',attention:'조치 필요',registration_expired:'등록 정보 만료',revocation_pending:'접근 차단 처리 중',ended:'사용 종료'};
  const operatingSystems = {ubuntu:'Ubuntu',windows:'Windows',amazon_linux_2023:'Amazon Linux 2023'};
  const purposes = {server:'일반 서버',web:'웹 서버',custom:'직접 선택'};
  const keyStates = {active:'유효 · 마지막 조회 기준',unverified:'서버 조회 전',expired:'만료',revoked:'폐기 완료',missing:'서버에서 찾지 못함',unavailable:'서버 조회 실패'};
  const date = value => value ? new Date(value).toLocaleString('ko-KR') : '기록 없음';
  const tone = value => ['attention','registration_expired','revocation_pending','expired','missing','unavailable'].includes(value)?'attention':['ended','revoked'].includes(value)?'ended':'neutral';
  function stateMarkup(value){return `<span class="device-state-chip" data-tone="${tone(value)}">${escape(states[value]||'상태 미확인')}</span>`;}
  function stateNote(device){
    if(device.state==='ended')return '서버 접근이 차단된 장치입니다. 장치의 프로그램과 미전송 자료는 장치에서 별도로 정리하세요.';
    if(device.state==='revocation_pending')return '접근 차단 결과를 모두 확인하지 못했습니다. 같은 장치의 접근 차단을 다시 요청해 결과를 확인하세요.';
    if(device.state!=='attention')return '';
    if(device.keys.some(k=>k.status==='revoked'))return '폐기된 수집 키가 있습니다. 아래 키 이력을 확인하세요. 폐기된 키는 유효기간을 연장할 수 없습니다.';
    if(device.keys.some(k=>k.status==='expired'))return '만료된 수집 키가 있습니다. 아래 키 이력을 확인하세요. 만료된 키는 유효기간을 연장할 수 없습니다.';
    if(device.keys.some(k=>['missing','unavailable'].includes(k.status)))return '서버에서 상태를 확인하지 못한 수집 키가 있습니다. 키 이력에서 서버 조회 결과를 확인하세요.';
    return '등록 요청 또는 수집 키에 확인이 필요한 항목이 있습니다. 설치 정보와 키 이력을 확인하세요.';
  }
  function keyMarkup(key) { return `<article class="device-key"><div class="device-key-heading"><strong>${escape(key.target_label || '대상 연결 전')} · ${key.scope === 'network' ? '네트워크 수집' : key.scope === 'host' ? '로그 수집' : '용도 미확인'}</strong><span class="device-state-chip" data-tone="${tone(key.status)}">${escape(keyStates[key.status] || '상태 미확인')}</span></div><p class="device-key-meta">조직 ${escape(key.organization)} · 발급일 ${escape(date(key.created_at))}</p><p>만료일 <strong>${escape(date(key.expiration))}</strong></p><details><summary>키 ID 보기</summary><code>${escape(key.id)}</code></details></article>`; }
  return {escape,states,date,keyMarkup,stateMarkup,stateNote,operatingSystems,purposes};
})();
if (typeof module !== 'undefined') module.exports = SocDevices;
if (typeof document !== 'undefined') (() => {
  'use strict';
  const $ = selector => document.querySelector(selector);
  const {escape,states,date,keyMarkup,stateMarkup,stateNote,operatingSystems,purposes} = SocDevices;
  const state = {page:1,keyPage:1,detail:null,busy:false,enabled:false,formRequest:null,startAt:null,loads:0,keyLoads:0,requests:new Map(),extension:null};
  const id = () => crypto.randomUUID().replaceAll('-','');
  function requestId(action, data) {
    const name = `${action}:${JSON.stringify(data)}`;
    if (!state.requests.has(name)) state.requests.set(name,id());
    return state.requests.get(name);
  }
  function releaseRequest(action,data){state.requests.delete(`${action}:${JSON.stringify(data)}`);}
  async function api(path, {method='GET',data,request}={}) {
    const headers = method === 'GET' ? {} : {'Content-Type':'application/json','X-Cloud-SOC':'portal',...(request ? {'Idempotency-Key':request} : {})};
    const response = await fetch(path,{method,headers,credentials:'same-origin',cache:'no-store',...(method==='GET'?{}:{body:JSON.stringify(data ?? {})})});
    const result = await response.json().catch(()=>({}));
    if (!response.ok) {const error=new Error(result.error || `요청 실패 (${response.status})`);error.code=result.code;throw error;}
    return result;
  }
  async function load() {
    const generation=++state.loads;
    try {
      const params=new URLSearchParams({view:$('#device-view').value,q:$('#device-search').value,page:state.page,size:25});
      const result=await api('/api/managed-devices?'+params);
      if(generation!==state.loads)return;
      state.enabled=result.enrollment_enabled;
      $('#add-device').disabled=!state.enabled;
      $('#page-message').textContent=state.enabled?'':'서버의 HTTPS 장치 등록 설정을 준비하세요. 기존 장치와 키는 고급 관리에서 조회할 수 있습니다.';
      $('#device-rows').innerHTML=result.devices.map(d=>`<tr><td>${escape(d.label)}</td><td>${escape(d.organization)} / ${escape(operatingSystems[d.os]||d.os)}</td><td>${stateMarkup(d.state)}</td><td>${escape(date(d.receipt_at))}</td><td><button data-device="${d.id}">장치 관리</button></td></tr>`).join('')||'<tr><td colspan="5">표시할 장치가 없습니다.</td></tr>';
      $('#device-count').textContent=`${result.total}대 · ${state.page} / ${Math.max(1,Math.ceil(result.total/25))}`;
      $('#device-prev').disabled=state.page<=1;$('#device-next').disabled=state.page*25>=result.total;
    }catch(error){if(generation===state.loads)$('#page-message').textContent=error.message;}
  }
  async function keys() {
    const generation=++state.keyLoads;
    try{
      const result=await api('/api/key-history?'+new URLSearchParams({view:$('#key-view').value,q:$('#key-search').value,page:state.keyPage,size:25}));
      if(generation!==state.keyLoads)return;
      $('#key-rows').innerHTML=result.keys.map(keyMarkup).join('')||'<p>표시할 수집 키가 없습니다.</p>';
      $('#key-count').textContent=`${result.total}개 · ${state.keyPage} / ${Math.max(1,Math.ceil(result.total/25))}`;
      $('#key-prev').disabled=state.keyPage<=1;$('#key-next').disabled=state.keyPage*25>=result.total;
    }catch(error){if(generation===state.keyLoads)$('#key-count').textContent=error.message;}
  }
  function show(device) {
    const previous=state.detail;
    state.detail=device;$('#device-title').textContent=device.label;
    const fields=[['조직',device.organization],['운영체제',operatingSystems[device.os]||device.os],['수집 목적',purposes[device.purpose]||device.purpose],['상태',states[device.state]||'상태 미확인'],['최초 수신 확인',date(device.receipt_at)],['수집기 실행 상태','장치의 상태 메뉴에서 확인'],['로그 분석 상태','탐지 현황에서 확인']];
    $('#device-info').innerHTML=fields.map(([k,v])=>`<dt>${escape(k)}</dt><dd>${escape(v)}</dd>`).join('');
    const note=stateNote(device);$('#device-state-note').textContent=note;$('#device-state-note').hidden=!note;
    $('#device-keys').innerHTML=device.keys.map(keyMarkup).join('');
    showExtension(device);
    const registration=device.registration;
    if(previous?.id!==device.id||previous?.registration?.state!==registration?.state){
      $('#device-installation').toggleAttribute('open',!device.receipt_at&&registration?.state!=='complete'&&!['received','ended','revocation_pending'].includes(device.state));
    }
    const downloadable=registration?.state==='unused' && registration.expires*1000>Date.now() && !['ended','revocation_pending'].includes(device.state);
    $('#device-download').hidden=!downloadable;$('#device-download').href=`/api/managed-devices/${device.id}/download`;
    $('#device-diagnostics').href=`/api/managed-devices/${device.id}/diagnostics`;
    const issued=['issued','complete'].includes(registration?.state);
    $('#device-prepare').disabled=state.busy||!state.enabled||issued||['ended','revocation_pending'].includes(device.state);
    $('#device-renew').disabled=state.busy||!state.enabled||issued||['ended','revocation_pending'].includes(device.state);
    $('#device-end').disabled=state.busy||device.state==='ended';
    $('#device-end').textContent=device.state==='ended'?'사용 종료된 장치':'접근 차단 및 사용 종료';
    $('#device-end-confirm').hidden=true;
    if(!$('#device-detail').open)$('#device-detail').showModal();
  }
  function showExtension(device){
    const pending=(device.key_extensions||[]).find(e=>['preview','attempted','uncertain'].includes(e.state));
    if(state.extension?.device!==device.id)state.extension=null;
    if(pending&&(!state.extension||pending.state!=='preview'||state.extension.state==='preview'))state.extension={device:device.id,...pending};
    const available=device.keys.filter(k=>k.scope==='host'&&!k.revoked_at&&k.expiration>Date.now());
    $('#device-extension').hidden=!(state.enabled&&device.key_extension_allowed&&(available.length||pending));
    const choice=$('#extension-key').value;
    $('#extension-key').innerHTML=available.map(k=>`<option value="${escape(k.id)}">로그 수집 · 만료 ${escape(date(k.expiration))} · ID ${escape(k.id.slice(-8))}</option>`).join('');
    if(available.some(k=>k.id===choice))$('#extension-key').value=choice;
    const current=state.extension;
    $('#extension-confirm').hidden=!current;
    for(const selector of ['#extension-key','#extension-days','#extension-preview'])$(selector).disabled=state.busy||!!current;
    $('#extension-apply').disabled=state.busy;$('#extension-cancel').disabled=state.busy||!!current&&current.state!=='preview';
    if(current){
      $('#extension-summary').textContent=`기존 만료 ${date(current.before_expiration)} → 예정 만료 ${date(current.target_expiration)} · ${current.days}일 추가`;
      $('#extension-apply').textContent=current.state==='preview'?'연장 적용':'서버 결과 다시 확인';
      $('#extension-state').textContent=current.state==='preview'?'변경할 만료일을 확인한 뒤 연장을 적용하세요.':'연장 결과를 확인하지 못했습니다. 같은 요청의 결과를 다시 확인하세요. 기간을 중복으로 더하지 않습니다.';
    }
  }
  $('#extension-preview').addEventListener('click',async()=>{
    if(state.busy||!state.detail)return;
    const device=state.detail.id,data={key_id:$('#extension-key').value,days:Number($('#extension-days').value)};
    state.busy=true;show(state.detail);
    try{
      const result=await api(`/api/managed-devices/${device}/key-extension/preview`,{method:'POST',data,request:requestId('extend:'+device,data)});
      state.extension={device,...result.extension};if(state.detail?.id===device)show(state.detail);
    }catch(error){$('#device-detail-message').textContent=error.message;}
    finally{state.busy=false;if(state.detail?.id===device)show(state.detail);}
  });
  async function extensionApply(confirm){
    if(state.busy||!state.detail||!state.extension)return;
    const current=state.extension,device=state.detail.id;
    state.busy=true;show(state.detail);
    try{
      const result=await api(`/api/managed-devices/${device}/key-extension/${current.id}`,{method:'POST',data:{confirm}});
      releaseRequest('extend:'+device,{key_id:current.key_id,days:current.days});state.extension=null;
      if(state.detail?.id===device){show(result.device);$('#device-detail-message').textContent=confirm?`유효기간 연장 완료 · 새 만료일 ${date(result.extension.expiration)}`:'연장 요청을 취소했습니다.';}
      await keys();
    }catch(error){
      // Do not offer a second dispatch after a lost apply response. Reload recovers
      // the durable request; in-memory retries use the same ID even if reload fails.
      if(confirm)state.extension={...current,state:'attempted'};
      $('#device-detail-message').textContent=error.message;
      try{const latest=await api('/api/managed-devices/'+device);if(state.detail?.id===device)show(latest.device);}catch{/* Preserve request identity until server is available. */}
    }finally{state.busy=false;if(state.detail?.id===device)show(state.detail);}
  }
  $('#extension-apply').addEventListener('click',()=>extensionApply(true));
  $('#extension-cancel').addEventListener('click',()=>extensionApply(false));
  async function detail(deviceId){try{const result=await api('/api/managed-devices/'+deviceId);$('#device-detail-message').textContent='';$('#device-activity').textContent='';show(result.device);}catch(error){$('#page-message').textContent=error.message;}}
  async function prepare(renew){
    if(state.busy||!state.detail)return;
    const device=state.detail.id,data={renew,days:Number($('#device-days').value)};
    state.busy=true;show(state.detail);$('#device-detail-message').textContent='설치 묶음 준비 중…';
    try{const result=await api(`/api/managed-devices/${device}/prepare`,{method:'POST',data,request:requestId('prepare:'+device,data)});releaseRequest('prepare:'+device,data);if(state.detail?.id===device){show(result.device);$('#device-detail-message').textContent='다운로드 후 대상 장치에서 실행하세요. 수집 키를 복사할 필요는 없습니다.';}}
    catch(error){if(error.code==='registration_uncertain'&&renew)releaseRequest('prepare:'+device,data);$('#device-detail-message').textContent=error.message;}
    finally{state.busy=false;if(state.detail?.id===device)show(state.detail);load();}
  }
  function formOptions(){
    const f=$('#device-form').elements,web=f.purpose.value==='web';$('#device-web').hidden=!web;$('#device-web').disabled=!web;
    if(!f.log_path.dataset.edited)f.log_path.value=f.os.value==='windows'?'C:\\Apache\\logs\\access.log':f.server_type.value==='nginx'?'/var/log/nginx/access.log':'/var/log/apache2/access.log';
    f.network.setCustomValidity(f.os.value==='windows'&&f.network.checked?'Windows 설치는 시스템·웹 로그를 지원합니다. 네트워크 패킷 수집을 해제하세요.':'');
  }
  $('#add-device').addEventListener('click',()=>{
    if(state.busy)return;$('#device-form').reset();state.formRequest=id();state.startAt=new Date().toISOString();$('#device-form').elements.log_path.dataset.edited='';
    try{const pending=JSON.parse(sessionStorage.getItem('soc-device-add')||'null');if(pending){const f=$('#device-form').elements;state.formRequest=pending.id;state.startAt=pending.startAt;for(const k of ['label','organization','os','purpose'])f[k].value=pending.data[k];f.system.checked=pending.data.system;f.network.checked=pending.data.network;const site=pending.data.sites[0];if(site){f.server_type.value=site.server_type;f.log_path.value=site.log_path;f.log_path.dataset.edited='yes';f.waf_path.value=site.modsecurity?.log_path||'';f.waf_timezone.value=site.modsecurity?.timezone||'';}}}catch{/* Storage is optional; never create a replacement request during an active submit. */}
    formOptions();$('#device-form-error').textContent='';$('#device-form-dialog').showModal();
  });
  $('#device-form').addEventListener('change',formOptions);
  $('#device-form').elements.log_path.addEventListener('input',event=>event.target.dataset.edited='yes');
  $('#device-form').addEventListener('submit',async event=>{
    event.preventDefault();if(state.busy)return;
    const f=event.currentTarget.elements,data={label:f.label.value,organization:f.organization.value,os:f.os.value,purpose:f.purpose.value,system:f.system.checked,network:f.network.checked,sites:[]};
    if(data.os==='windows'&&data.network){$('#device-form-error').textContent='Windows 설치는 시스템·웹 로그를 지원합니다. 네트워크 패킷 수집을 해제하세요.';return;}
    if(data.purpose==='web'){
      const site={id:'web',name:data.label.slice(0,64),server_type:f.server_type.value,log_path:f.log_path.value,start_at:state.startAt};
      if(f.waf_path.value)site.modsecurity={log_path:f.waf_path.value,timezone:f.waf_timezone.value};data.sites=[site];
    }
    state.busy=true;$('#device-create').disabled=true;$('#device-form-error').textContent='';
    try{
      try{sessionStorage.setItem('soc-device-add',JSON.stringify({id:state.formRequest,startAt:state.startAt,data}));}catch{/* Keep the in-memory request if storage is unavailable. */}
      const result=await api('/api/managed-devices',{method:'POST',data,request:state.formRequest});
      try{sessionStorage.removeItem('soc-device-add');}catch{/* No credentials are stored here. */}
      $('#device-form-dialog').close();show(result.device);
      const prepareData={renew:false,days:30};
      try{const ready=await api(`/api/managed-devices/${result.device.id}/prepare`,{method:'POST',data:prepareData,request:requestId('prepare:'+result.device.id,prepareData)});releaseRequest('prepare:'+result.device.id,prepareData);show(ready.device);$('#device-detail-message').textContent='설치 묶음을 다운로드하고 대상 장치에서 실행하세요.';}catch(error){$('#device-detail-message').textContent=error.message;}
      await load();
    }
    catch(error){$('#device-form-error').textContent=error.message;}
    finally{state.busy=false;$('#device-create').disabled=false;if(state.detail)show(state.detail);}
  });
  $('#device-rows').addEventListener('click',event=>{const button=event.target.closest('[data-device]');if(button)detail(button.dataset.device);});
  $('#device-prepare').addEventListener('click',()=>prepare(false));$('#device-renew').addEventListener('click',()=>prepare(true));
  $('#device-end').addEventListener('click',()=>$('#device-end-confirm').hidden=false);
  $('#device-end-cancel').addEventListener('click',()=>$('#device-end-confirm').hidden=true);
  $('#device-end-apply').addEventListener('click',async()=>{
    if(state.busy||!state.detail)return;const device=state.detail.id;state.busy=true;$('#device-end-apply').disabled=true;
    try{const result=await api(`/api/managed-devices/${device}/end`,{method:'POST',data:{confirm:true},request:requestId('end',device)});show(result.device);$('#device-detail-message').textContent='서버 접근 차단 완료. 장치 프로그램과 미전송 자료는 장치에서 별도로 정리하세요.';await Promise.all([load(),keys()]);}
    catch(error){$('#device-detail-message').textContent=error.message;}
    finally{state.busy=false;$('#device-end-apply').disabled=false;if(state.detail)show(state.detail);}
  });
  $('#device-observe').addEventListener('click',async()=>{if(!state.detail)return;$('#device-observe').disabled=true;try{const result=await api(`/api/managed-devices/${state.detail.id}/activity`);$('#device-activity').textContent=result.observed_at?`마지막 일반 로그 수신: ${date(result.observed_at)}`:'조회 범위에서 일반 로그를 찾지 못했습니다. 장치 응답·서비스·분석 정상 여부와는 별개입니다.';}catch(error){$('#device-activity').textContent=error.message;}finally{$('#device-observe').disabled=false;}});
  $('#device-refresh').addEventListener('click',load);$('#key-refresh').addEventListener('click',keys);
  $('#device-view').addEventListener('change',()=>{state.page=1;load();});$('#key-view').addEventListener('change',()=>{state.keyPage=1;keys();});
  let searchTimer,keyTimer;$('#device-search').addEventListener('input',()=>{clearTimeout(searchTimer);searchTimer=setTimeout(()=>{state.page=1;load();},300);});$('#key-search').addEventListener('input',()=>{clearTimeout(keyTimer);keyTimer=setTimeout(()=>{state.keyPage=1;keys();},300);});
  $('#device-prev').addEventListener('click',()=>{state.page--;load();});$('#device-next').addEventListener('click',()=>{state.page++;load();});$('#key-prev').addEventListener('click',()=>{state.keyPage--;keys();});$('#key-next').addEventListener('click',()=>{state.keyPage++;keys();});
  document.querySelectorAll('[data-close]').forEach(button=>button.addEventListener('click',()=>{if(!state.busy)document.getElementById(button.dataset.close).close();}));
  document.querySelectorAll('dialog').forEach(dialog=>dialog.addEventListener('cancel',event=>{if(state.busy)event.preventDefault();}));
  async function poll(){if(!document.hidden&&!state.busy&&!document.querySelector('dialog[open]'))await load();setTimeout(poll,15000);}
  load();keys();setTimeout(poll,15000);
})();
