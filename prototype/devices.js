/* Device lifecycle UI: keep drafts and request IDs; never render or copy publisher secrets. */
const SocDevices = (() => {
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const states = {requested:'설치 대기',awaiting_receipt:'등록 시험 수신 대기',received:'등록 시험 수신 기록',attention:'조치 필요',registration_expired:'등록 정보 만료',revocation_pending:'접근 차단 처리 중',ended:'사용 종료'};
  const keyStates = {active:'유효 · 마지막 조회 기준',unverified:'서버 조회 전',expired:'만료',revoked:'폐기 완료',missing:'서버에서 찾지 못함',unavailable:'서버 조회 실패'};
  const date = value => value ? new Date(value).toLocaleString('ko-KR') : '기록 없음';
  function keyMarkup(key) { return `<article class="device-key"><strong>${escape(key.target_label || '대상 연결 전')} · ${key.scope === 'network' ? '네트워크 수집' : key.scope === 'host' ? '로그 수집' : '용도 미확인'}</strong><p>${escape(key.organization)} · ${escape(keyStates[key.status] || '상태 미확인')}</p><p>발급 ${escape(date(key.created_at))} · 만료 ${escape(date(key.expiration))}</p><details><summary>식별 정보</summary><code>${escape(key.id)}</code></details></article>`; }
  return {escape,states,date,keyMarkup};
})();
if (typeof module !== 'undefined') module.exports = SocDevices;
if (typeof document !== 'undefined') (() => {
  'use strict';
  const $ = selector => document.querySelector(selector);
  const {escape,states,date,keyMarkup} = SocDevices;
  const state = {page:1,keyPage:1,detail:null,busy:false,enabled:false,formRequest:null,startAt:null,loads:0,keyLoads:0,requests:new Map()};
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
      $('#device-rows').innerHTML=result.devices.map(d=>`<tr><td>${escape(d.label)}</td><td>${escape(d.organization)} / ${escape(d.os)}</td><td>${escape(states[d.state]||d.state)}</td><td>${escape(date(d.receipt_at))}</td><td><button data-device="${d.id}">장치 관리</button></td></tr>`).join('')||'<tr><td colspan="5">표시할 장치가 없습니다.</td></tr>';
      $('#device-count').textContent=`${result.total}대 · ${state.page} / ${Math.max(1,Math.ceil(result.total/25))}`;
      $('#device-prev').disabled=state.page<=1;$('#device-next').disabled=state.page*25>=result.total;
    }catch(error){if(generation===state.loads)$('#page-message').textContent=error.message;}
  }
  async function keys() {
    const generation=++state.keyLoads;
    try{
      const result=await api('/api/key-history?'+new URLSearchParams({view:$('#key-view').value,q:$('#key-search').value,page:state.keyPage,size:25}));
      if(generation!==state.keyLoads)return;
      $('#key-rows').innerHTML=result.keys.map(keyMarkup).join('')||'<p>표시할 자격 증명이 없습니다.</p>';
      $('#key-count').textContent=`${result.total}개 · ${state.keyPage} / ${Math.max(1,Math.ceil(result.total/25))}`;
      $('#key-prev').disabled=state.keyPage<=1;$('#key-next').disabled=state.keyPage*25>=result.total;
    }catch(error){if(generation===state.keyLoads)$('#key-count').textContent=error.message;}
  }
  function show(device) {
    state.detail=device;$('#device-title').textContent=device.label;
    const fields=[['조직',device.organization],['OS',device.os],['수집 목적',device.purpose],['상태',states[device.state]],['최초 등록 시험 수신',date(device.receipt_at)],['장치 서비스','로컬 상태에서 조회'],['분석','탐지 현황에서 별도 조회']];
    $('#device-info').innerHTML=fields.map(([k,v])=>`<dt>${escape(k)}</dt><dd>${escape(v)}</dd>`).join('');
    $('#device-keys').innerHTML=device.keys.map(keyMarkup).join('');
    const registration=device.registration;
    const downloadable=registration?.state==='unused' && registration.expires*1000>Date.now() && !['ended','revocation_pending'].includes(device.state);
    $('#device-download').hidden=!downloadable;$('#device-download').href=`/api/managed-devices/${device.id}/download`;
    $('#device-diagnostics').href=`/api/managed-devices/${device.id}/diagnostics`;
    const issued=['issued','complete'].includes(registration?.state);
    $('#device-prepare').disabled=state.busy||!state.enabled||issued||['ended','revocation_pending'].includes(device.state);
    $('#device-renew').disabled=state.busy||!state.enabled||issued||['ended','revocation_pending'].includes(device.state);
    $('#device-end').disabled=state.busy||device.state==='ended';
    $('#device-end-confirm').hidden=true;
    if(!$('#device-detail').open)$('#device-detail').showModal();
  }
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
