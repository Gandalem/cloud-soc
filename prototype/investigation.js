(() => {
  "use strict";
  const $=id=>document.getElementById(id), query=new URLSearchParams(window.location.search);
  const states={new:"신규",triage:"초기 분류",investigating:"조사 중",escalated:"상위 이관",closed:"종결"};
  const verdicts={unreviewed:"미판정",malicious:"악성",benign:"정상",false_positive:"오탐",inconclusive:"판단 보류"};
  const priorities={critical:"긴급",high:"높음",medium:"중간",low:"낮음"};
  const evidenceStates={exact_reference:"정확한 문서 참조 확인 · 내용 해시 재검증은 아님",normalized_missing_or_expired:"정규화 근거 누락 / 만료",raw_missing_or_expired:"원본 근거 누락 / 만료",provenance_mismatch:"근거 참조 불일치",unsupported_or_invalid_reference:"지원하지 않는 근거 참조",invalid_reference:"잘못된 참조"};
  const fmt=v=>v?new Date(v).toLocaleString("ko-KR",{timeZone:"Asia/Seoul"}):"미기록";
  let current=null, caseId=query.get("case"), alertId=query.get("alert"), historyNext=null, generation=0, pending=null, saving=false;
  const back=new URLSearchParams(query.get("return")||"");
  const safeBack=new URLSearchParams();
  for(const [key,value]of back)if(["case_status","case_owner","case_priority","case_days","case_sort","case_page"].includes(key)&&value.length<40)safeBack.set(key,value);
  $("case-back").href="index.html?"+safeBack+"#case-queue";
  function node(tag,text){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n;}
  function error(message){$("investigation-error").hidden=false;$("investigation-error").textContent=message;}
  async function request(url,options={}){
    const response=await fetch(url,{credentials:"same-origin",cache:"no-store",...options});
    if(!response.ok){
      let code="";try{code=(await response.json()).code||"";}catch{}
      const messages={case_version_conflict:"다른 수정이 먼저 저장되었습니다. 메모는 유지했습니다. 최신 버전을 불러와 비교한 뒤 다시 저장하세요.",alert_already_linked:"이미 사건에 연결된 경보입니다. 업무 목록 또는 경보 조사 화면을 다시 확인하세요.",organization_mismatch:"같은 조직의 경보만 연결할 수 있습니다.",closure_reason_required:"종결 시 판정과 사유 메모를 입력하세요.",verdict_reason_required:"판정 변경 사유를 입력하세요.",invalid_transition:"허용하지 않는 상태 전이입니다.",case_closed:"종결 사건은 사유를 입력하고 조사 중으로 재개해야 합니다.",invalid_case_input:"입력 형식과 길이를 확인하고 비밀번호·키 등 비밀정보를 제외하세요."};
      const failure=new Error(messages[code]||"조회 / 저장 실패 ("+response.status+"). 연결·권한·입력값을 확인하세요.");failure.status=response.status;throw failure;
    }
    return response.json();
  }
  async function mutate(url,method,body){
    const fingerprint=JSON.stringify([url,method,body]);
    if(!pending||pending.fingerprint!==fingerprint)pending={fingerprint,key:crypto.randomUUID()};
    const result=await request(url,{method,headers:{"Content-Type":"application/json","X-Cloud-SOC":"portal","Idempotency-Key":pending.key},body:JSON.stringify(body)});
    pending=null;return result;
  }
  function locked(value){saving=value;for(const id of ["case-create-button","case-save-button","case-link-button","case-reload","work-note","work-status","work-owner","work-priority","work-verdict","create-title","create-priority","case-link-id"])$(id).disabled=value;}
  function history(items){
    for(const item of items){
      const li=node("li");
      li.append(node("strong",fmt(item.at)+" · "+item.actor+" · v"+item.version+" · "+(item.action==="created"?"사건 생성":"업무 수정")));
      const names={status:"상태",owner:"담당자",priority:"우선순위",verdict:"판정",alert_id:"연결 경보",title:"제목"};
      for(const [key,change]of Object.entries(item.changes)){
        const show=value=>value===null?"미배정":(key==="status"?states[value]:key==="verdict"?verdicts[value]:key==="priority"?priorities[value]:value)||"미기록";
        li.append(node("p",(names[key]||key)+": "+(change&&typeof change==="object"?show(change.before)+" → "+show(change.after):show(change))));
      }
      if(item.note)li.append(node("p",item.note));$("case-history").append(li);
    }
  }
  async function alertCard(container,id,snapshot,version){
    const box=node("article");box.className="case-evidence";
    box.append(node("h3",snapshot?.title||id),node("p","경보 시각 (KST): "+fmt(snapshot?.timestamp)));
    const detail=node("div","경보 조회 중");box.append(detail);container.append(box);
    try{
      const data=await request("/api/alerts/detail?"+new URLSearchParams({id}));if(version!==generation)return;
      const c=data.condition;detail.replaceChildren(node("p","규칙 "+(data.alert.rule||"미기록")+" · 버전 "+(data.rule_version||"미기록")),node("p","관측 수 "+(c.event_count??"미기록")+" / 임계값 "+(c.threshold??"미기록")+" / 시간 창 "+(c.time_window_seconds??"미기록")+"초"));
      detail.append(node("p","관련 대상 (경보 필드): 조직 "+(data.alert.organization||"미기록")+" · 출발지 IP "+(data.alert.source_ip||"미관측")));
      if(!data.evidence_count)detail.append(node("p","이 경보에는 정확한 근거 참조가 없습니다."));
      if(data.evidence_count>data.evidence_limit)detail.append(node("p","근거 "+data.evidence_count+"건 중 처음 "+data.evidence_limit+"건만 지원합니다."));
      for(let i=0;i<data.evidence_limit;i++){
        const button=node("button","근거 "+(i+1)+" 조회"),result=node("div");button.type="button";
        button.addEventListener("click",async()=>{
          button.disabled=true;result.textContent="근거 조회 중";
          try{
            const reply=await request("/api/alerts/detail?"+new URLSearchParams({id,evidence:String(i)}));if(version!==generation)return;
            const e=reply.evidence;result.replaceChildren(node("p",evidenceStates[e.state]||"근거 상태 미확인"));
            if(e.raw)result.append(node("p","원본 참조: "+e.raw.index+" / "+e.raw.id));
            if(e.normalized)result.append(node("p","정규화 참조: "+e.normalized.index+" / "+e.normalized.id));
            if(e.normalized_event)result.append(node("p","근거 이벤트 시각 (KST): "+fmt(e.normalized_event.timestamp)+" · 행위 "+(e.normalized_event.action||"미관측")+" · 결과 "+(e.normalized_event.outcome||"미관측")));
            if(e.metadata)result.append(node("pre",JSON.stringify(e.metadata,null,2)));
            if(e.security)result.append(node("pre",JSON.stringify(e.security,null,2)));
          }catch(failure){result.textContent=failure.message;}finally{button.disabled=false;}
        });detail.append(button,result);
      }
    }catch(failure){if(version===generation)detail.textContent=(failure.status===404?"경보가 누락/만료되었습니다. 위 요약은 연결 당시 저장된 기록입니다.":failure.message);}
  }
  async function loadCase(){
    const version=++generation;
    $("investigation-status").textContent="사건 조회 중";$("investigation-error").hidden=true;
    $("case-alerts").replaceChildren();$("case-history").replaceChildren();$("case-history-more").disabled=true;
    $("case-work-panel").hidden=true;
    try{
      const data=await request("/api/cases/"+encodeURIComponent(caseId));if(version!==generation)return;
      current=data.case;$("case-title").textContent=current.title;
      $("case-summary").textContent="조직 "+current.organization+" · "+states[current.status]+" · "+verdicts[current.verdict]+" · 수정 버전 "+current.version;
      const owner=$("work-owner");owner.replaceChildren();const none=node("option","미배정");none.value="";const me=node("option",data.actor);me.value=data.actor;owner.append(none,me);
      for(const key of ["status","owner","priority","verdict"])$("work-"+key).value=current[key]||"";
      $("case-work-panel").hidden=false;$("case-create-panel").hidden=true;$("case-history-panel").hidden=false;
      history(data.history);historyNext=data.history_next;$("case-history-more").disabled=!historyNext;
      const rows=data.alerts.slice().sort((a,b)=>(a.snapshot.timestamp||"").localeCompare(b.snapshot.timestamp||""));
      // Limit concurrent ES requests: further alerts are opened explicitly, not prefetched.
      for(const row of rows){
        const box=node("section"),button=node("button",(row.snapshot.title||row.id)+" · "+fmt(row.snapshot.timestamp)+" · 경보 열기");button.type="button";
        button.addEventListener("click",()=>{button.disabled=true;alertCard(box,row.id,row.snapshot,version);});box.append(button);$("case-alerts").append(box);
      }
      $("investigation-status").textContent="저장된 사건을 불러왔습니다. 미저장 메모는 서버에 전송되지 않습니다.";
    }catch(failure){if(version===generation){current=null;error(failure.message);$("investigation-status").textContent="사건 조회 실패";}}
  }
  async function save(body){
    if(saving||!current)return;locked(true);$("investigation-error").hidden=true;
    try{await mutate("/api/cases/"+caseId,"PATCH",{version:current.version,...body});if(Object.hasOwn(body,"note"))$("work-note").value="";$("case-link-id").value="";await loadCase();}
    catch(failure){error(failure.message);}finally{locked(false);}
  }
  $("case-work-form").addEventListener("submit",event=>{event.preventDefault();save({status:$("work-status").value,owner:$("work-owner").value||null,priority:$("work-priority").value,verdict:$("work-verdict").value,note:$("work-note").value});});
  $("case-link-form").addEventListener("submit",event=>{event.preventDefault();save({alert_id:$("case-link-id").value});});
  $("case-reload").addEventListener("click",()=>{if(!saving)loadCase();});
  $("case-history-more").addEventListener("click",async()=>{
    if(!historyNext)return;const version=generation;$("case-history-more").disabled=true;
    try{const data=await request("/api/cases/"+caseId+"?"+new URLSearchParams({before:historyNext}));if(version!==generation)return;history(data.history);historyNext=data.history_next;}
    catch(failure){error(failure.message);}finally{if(version===generation)$("case-history-more").disabled=!historyNext;}
  });
  $("case-create-form").addEventListener("submit",async event=>{
    event.preventDefault();if(saving)return;locked(true);$("investigation-error").hidden=true;
    try{const result=await mutate("/api/cases","POST",{title:$("create-title").value,priority:$("create-priority").value,alert_id:alertId});caseId=result.id;window.history.replaceState(null,"","workbench.html?"+new URLSearchParams({case:caseId,return:safeBack.toString()}));await loadCase();}
    catch(failure){error(failure.message);}finally{locked(false);}
  });
  async function init(){
    if(caseId){if(!/^[0-9a-f]{32}$/.test(caseId)){error("사건 ID를 확인하세요.");return;}await loadCase();return;}
    if(!alertId){$("investigation-status").textContent="관제 현황에서 사건이나 경보를 선택하세요.";return;}
    try{
      const linked=await request("/api/case-link?"+new URLSearchParams({alert_id:alertId}));
      if(linked.case_id){caseId=linked.case_id;await loadCase();return;}
      const data=await request("/api/alerts/detail?"+new URLSearchParams({id:alertId}));
      $("create-title").value=(data.alert.title||data.alert.rule||"경보 조사").slice(0,160);$("case-create-panel").hidden=false;
      $("case-summary").textContent="아직 사건으로 등록하지 않은 경보입니다.";
      await alertCard($("case-alerts"),alertId,data.alert,generation);
    }catch(failure){error(failure.message);}
  }
  window.addEventListener("pagehide",()=>{generation++;$("work-note").value="";$("case-alerts").replaceChildren();$("case-history").replaceChildren();});
  init();
})();
