/* Same-origin polling without navigation; a suspended/obsolete response never applies. */
(() => {
  'use strict';
  const key=n=>n.nodeType===1?(n.id||n.dataset.liveKey||n.dataset.widget||n.dataset.instance||n.getAttribute('href')||''):'';
  function patch(old,fresh){
    if(old.nodeType!==fresh.nodeType||old.nodeName!==fresh.nodeName){old.replaceWith(fresh);return;}
    if(old.nodeType===3){if(old.data!==fresh.data)old.data=fresh.data;return;}
    if(old.nodeType!==1)return;
    for(const a of [...old.attributes])if(!fresh.hasAttribute(a.name)&&a.name!=='open')old.removeAttribute(a.name);
    for(const a of [...fresh.attributes])if(a.name!=='open'&&old.getAttribute(a.name)!==a.value)old.setAttribute(a.name,a.value);
    children(old,[...fresh.childNodes]);
  }
  function children(target,fresh){
    const wanted=[...fresh],prior=[...target.childNodes],used=new Set();
    for(let i=0;i<wanted.length;i++){
      const next=wanted[i],id=key(next);
      let old=id?prior.find(n=>!used.has(n)&&key(n)===id):prior.find(n=>!used.has(n)&&!key(n)&&n.nodeType===next.nodeType&&n.nodeName===next.nodeName);
      if(old){used.add(old);if(target.childNodes[i]!==old)target.insertBefore(old,target.childNodes[i]||null);patch(old,next);}
      else target.insertBefore(next,target.childNodes[i]||null);
    }
    for(const n of prior)if(!used.has(n)&&n.parentNode===target)n.remove();
  }
  function notice(host,label='새 기록'){
    const button=document.createElement('button');button.type='button';button.hidden=true;button.className='live-pending';
    let action=null;button.addEventListener('click',()=>{const run=action;action=null;button.hidden=true;run?.();});host.prepend(button);
    return {offer(count,apply){action=apply;button.hidden=false;button.textContent=count?`${label} ${count}건 · 반영`:'변경된 내용 반영';},clear(){action=null;button.hidden=true;},button};
  }
  function create({load,apply,host,interval=10000,timeout=20000,enabled=()=>true,onError=()=>{},label='자동 갱신'}){
    let serial=0,controller=null,timer=null,paused=false,disposed=false,last=null,failures=0;
    const controls=document.createElement('div');controls.className='live-controls';
    const toggle=document.createElement('button'),manual=document.createElement('button'),state=document.createElement('span');
    toggle.type=manual.type='button';manual.textContent='지금 갱신';state.setAttribute('role','status');state.setAttribute('aria-live','polite');
    controls.append(toggle,manual,state);host?.append(controls);
    function stamp(){return last?new Date(last).toLocaleTimeString('ko-KR',{timeZone:'Asia/Seoul',hour12:false}):'없음';}
    function status(error=false){toggle.textContent=paused?'자동 갱신 재개':'자동 갱신 일시정지';toggle.setAttribute('aria-pressed',String(paused));state.textContent=(error?'갱신 실패 · 이전 조회 내용':paused?'자동 갱신 일시정지':document.hidden?'다른 탭에서 대기':label)+' · 마지막 성공 '+stamp();}
    function cancel(){serial++;controller?.abort();controller=null;clearTimeout(timer);}
    function schedule(){clearTimeout(timer);if(!disposed&&!paused&&!document.hidden)timer=setTimeout(()=>refresh(false),Math.min(60000,interval*2**Math.min(failures,3)));}
    async function refresh(manualRequest=true){
      if(disposed||(!manualRequest&&(paused||document.hidden||!enabled()))){schedule();return;}
      cancel();const ticket=serial,active=new AbortController();controller=active;
      const deadline=setTimeout(()=>active.abort(),timeout);manual.disabled=true;
      try{
        const value=await load(active.signal,{manual:manualRequest});
        if(ticket!==serial||disposed||active.signal.aborted)return;
        await apply(value,{manual:manualRequest});
        if(ticket!==serial)return;
        last=Date.now();failures=0;status();
      }catch(error){if(ticket===serial&&!disposed){failures++;status(true);onError(error,{manual:manualRequest,lastSuccess:last});}}
      finally{clearTimeout(deadline);if(ticket===serial){controller=null;manual.disabled=false;schedule();}}
    }
    function visibility(){cancel();manual.disabled=false;status();if(!document.hidden&&!paused)refresh(false);}
    toggle.addEventListener('click',()=>{paused=!paused;cancel();manual.disabled=false;status();if(!paused)refresh(false);});
    manual.addEventListener('click',()=>refresh(true));document.addEventListener('visibilitychange',visibility);
    function dispose(){disposed=true;cancel();document.removeEventListener('visibilitychange',visibility);}
    window.addEventListener('pagehide',dispose,{once:true});status();
    return {refresh,cancel,dispose,start:()=>refresh(true),paused:()=>paused,controls};
  }
  const api={create,children,patch,notice};
  if(typeof window!=='undefined')window.CloudSOCLive=api;
  if(typeof module!=='undefined')module.exports=api;
})();
