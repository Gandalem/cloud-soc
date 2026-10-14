(() => {
  'use strict';
  const $=id=>document.getElementById(id);let revision=0,dirty=false,busy=false,timer,offset=0,nextOffset=null;
  const outcomes={queued:'전송 대기',retry:'재시도 대기',sent:'Slack 접수 확인 · 채널 수신을 확인하세요',permanent:'전송 실패 · 설정/권한 확인 필요',unknown:'수신 미확인 · 자동 재전송 보류',cancelled:'설정 변경으로 취소',inflight:'전송 중'};
  function result(text,error=false){$('slack-result').textContent=text;$('slack-result').dataset.error=String(error);}
  async function api(method='GET',body,path=''){
    const response=await fetch('/api/settings/notifications/slack'+path,{method,credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json','X-Cloud-SOC':'portal'},...(body===undefined?{}:{body:JSON.stringify(body)})});
    const data=await response.json();if(!response.ok)throw new Error(data.error||'Slack 설정을 처리하지 못했습니다.');return data;
  }
  function display(data){
    if(!dirty)revision=data.revision;$('slack-status').textContent=data.configured?(data.enabled?'Webhook 등록됨 · 알림 ON':'Webhook 등록됨 · 알림 OFF'):'Webhook 미등록 · 알림 OFF';
    if(!dirty){$('slack-enabled').checked=data.enabled;$('slack-severity').value=data.minimum_severity;}
    $('slack-test').disabled=busy||!data.configured;$('slack-delete').disabled=busy||!data.configured;
    const states={not_started:'워커 시작 대기',disabled:'알림 대기',active:'새 경보 처리 중',configuration_changed:'새 설정 준비 중',failed:'알림 워커 확인 필요'};
    const stale=data.worker.heartbeat&&Date.now()/1000-data.worker.heartbeat>60;
    $('slack-worker').textContent=stale?'워커 상태 미확인':states[data.worker.state]||'상태 미확인';
    $('slack-deliveries').textContent=Object.entries(data.deliveries).map(([key,n])=>(outcomes[key]||'기타')+': '+n+'건').join(' · ')||'발송 이력이 없습니다.';
    $('slack-last-test').textContent=data.last_test?'최근 테스트: '+(outcomes[data.last_test.status]||'확인 필요')+' · '+data.last_test.id:'최근 테스트가 없습니다.';
  }
  async function loadUnconfirmed(){
    const data=await api('GET',undefined,'/unconfirmed?offset='+offset);nextOffset=data.next_offset;
    $('slack-unconfirmed-summary').textContent='수신 미확인 '+data.total+'건 · '+(data.items.length?offset+1:0)+'–'+(offset+data.items.length)+' 표시';
    $('slack-unconfirmed').replaceChildren();
    for(const item of data.items){
      const row=document.createElement('article'),details=document.createElement('p'),button=document.createElement('button');row.className='slack-unconfirmed-item';
      details.textContent=(item.kind==='test'?'테스트':'경보/통지')+' ID: '+item.source_id+' · '+item.severity.toUpperCase()+' · '+item.state+' · revision '+item.revision+' · 시도 '+item.attempts+'회 · 수신 미확인';
      button.type='button';button.textContent='중복 위험 확인 후 수동 재전송';button.disabled=busy||!item.can_retry;
      button.addEventListener('click',()=>{
        if(window.confirm('Slack에 이미 수신됐을 수 있습니다. 채널에서 ID '+item.source_id+'를 확인했나요? 재전송하면 중복 메시지가 생길 수 있습니다. 이 위험을 확인하고 다시 보낼까요?'))action(async()=>{
          await api('POST',{revision,notification_id:item.id,accept_duplicate_risk:true},'/retry');result('수동 재전송을 요청했습니다. 중복 가능성과 채널 수신을 확인하세요.');
        });
      });row.append(details,button);$('slack-unconfirmed').append(row);
    }
    $('slack-unconfirmed-prev').disabled=busy||offset===0;$('slack-unconfirmed-next').disabled=busy||nextOffset===null;
  }
  async function refresh(){try{display(await api());await loadUnconfirmed();}catch(_){result('설정을 읽지 못했습니다. 로그인·권한·서버 상태를 확인하세요.',true);}}
  async function action(callback){if(busy)return;busy=true;for(const b of document.querySelectorAll('.slack-actions button'))b.disabled=true;
    try{await callback();}catch(e){result(e.message,true);}finally{busy=false;$('slack-save').disabled=false;$('slack-refresh').disabled=false;await refresh();}}
  $('slack-form').addEventListener('input',()=>{dirty=true;});
  $('slack-form').addEventListener('submit',e=>{e.preventDefault();action(async()=>{
    const body={revision,enabled:$('slack-enabled').checked,minimum_severity:$('slack-severity').value};
    const secret=$('slack-webhook').value;if(secret)body.webhook_url=secret;
    try{await api('POST',body);dirty=false;result('설정을 저장했습니다. 새 설정의 기준점을 준비합니다.');}
    finally{$('slack-webhook').value='';delete body.webhook_url;}
  });});
  $('slack-test').addEventListener('click',()=>action(async()=>{const data=await api('POST',{},'/test');result('테스트 전송 대기 · '+data.test_id);}));
  $('slack-delete').addEventListener('click',()=>{if(window.confirm('등록한 Webhook을 삭제하고 Slack 알림을 끌까요?'))action(async()=>{await api('DELETE',{revision});dirty=false;$('slack-webhook').value='';result('Webhook을 삭제했습니다.');});});
  $('slack-refresh').addEventListener('click',refresh);
  $('slack-unconfirmed-prev').addEventListener('click',()=>{offset=Math.max(0,offset-20);loadUnconfirmed().catch(()=>result('미확인 이력을 읽지 못했습니다.',true));});
  $('slack-unconfirmed-next').addEventListener('click',()=>{if(nextOffset!==null){offset=nextOffset;loadUnconfirmed().catch(()=>result('미확인 이력을 읽지 못했습니다.',true));}});
  refresh();timer=setInterval(()=>{if(!busy)refresh();},5000);window.addEventListener('pagehide',()=>{clearInterval(timer);$('slack-webhook').value='';});
})();
