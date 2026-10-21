(() => {
  "use strict";
  const $=id=>document.getElementById(id), query=new URLSearchParams(window.location.search);
  const states={new:"신규",triage:"초기 분류",investigating:"조사 중",escalated:"상위 이관",closed:"종결"};
  const verdicts={unreviewed:"미판정",malicious:"악성",benign:"정상",false_positive:"오탐",inconclusive:"판단 보류"};
  const priorities={critical:"긴급",high:"높음",medium:"중간",low:"낮음"};
  const evidenceStates={exact_reference:"정확한 문서 참조 확인",normalized_hash_mismatch:"정규화 근거 내용 변경 감지",invalid_evidence_hash:"저장된 근거 해시 형식 오류",normalized_missing_or_expired:"정규화 근거 누락 / 만료",raw_missing_or_expired:"원본 근거 누락 / 만료",provenance_mismatch:"근거 참조 불일치",unsupported_or_invalid_reference:"지원하지 않는 근거 참조",invalid_reference:"잘못된 참조"};
  const fmt=v=>v?new Date(v).toLocaleString("ko-KR",{timeZone:"Asia/Seoul"}):"미기록";
  let current=null, caseId=query.get("case"), alertId=query.get("alert"), historyNext=null, generation=0, pending=null, saving=false;
  const back=new URLSearchParams(query.get("return")||"");
  const safeBack=new URLSearchParams();
  for(const [key,value]of back)if(["case_status","case_owner","case_priority","case_days","case_sort","case_page"].includes(key)&&value.length<40)safeBack.set(key,value);
  const returnPage=['index.html','dashboard.html','operations.html'].includes(query.get('return_page'))?query.get('return_page'):'cases.html';
  $("case-back").href=returnPage+"?"+safeBack+(['index.html','dashboard.html'].includes(returnPage)?'#dashboard-grid':'#case-queue');
  $("case-back").textContent=returnPage==='index.html'?'홈 대시보드로':returnPage==='dashboard.html'?'내 대시보드로':returnPage==='operations.html'?'관제 상세로':'사건 목록으로';
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
        const value=(change&&typeof change==="object"?show(change.before)+" → "+show(change.after):show(change));
        if(key==='alert_id') {const refs=node('details');refs.append(node('summary','연결 경보 ID'),node('p',value));li.append(refs);}
        else li.append(node("p",(names[key]||key)+": "+value));
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
      const c=data.condition;detail.replaceChildren(node("p","규칙 "+(data.alert.rule||"미기록")),node("p","관측 로그 "+(c.event_count??"미기록")+"건"));
      window.CloudSOCMall.summary(detail,data);
      detail.append(node("p","조직 "+(data.alert.organization||"미기록")+" · 출발지 IP "+(data.alert.source_ip||"미관측")));
      const ruleInfo=node('details');ruleInfo.append(node('summary','규칙 정보'),node('p','버전 '+(data.rule_version||'미기록')),node('p','임계값 '+(c.threshold??'미기록')+' / 시간 범위 '+(c.time_window_seconds??'미기록')+'초'));detail.append(ruleInfo);
      if(data.assessment) {
        const assessment=data.assessment;
        detail.append(node('p','공격 의심 · 공격 성공 미확정'));
        if(assessment.reason==='call_count_and_api_diversity' && Number.isSafeInteger(assessment.observed_count) && Number.isSafeInteger(assessment.distinct_count)) detail.append(node('p','API 호출 '+assessment.observed_count+'건 · API '+assessment.distinct_count+'종 (중복 제외)'));
        const limits={host_user_time_context_only_not_same_session:'동일 SSH 세션인지는 확인되지 않았습니다.',sudo_record_not_command_execution_or_privilege_success:'명령 실행·권한 상승 성공은 확인되지 않았습니다.',no_user_agent_or_normal_activity_baseline:'평소 활동과의 차이는 평가하지 않았습니다.',api_result_not_effective_privilege_or_all_audit_logs_removed:'실제 권한 적용·전체 감사 중단 여부는 확인되지 않았습니다.',candidate_threshold_not_live_validated:'시험 규칙 · 운영 기준 미확정'};
        if(Array.isArray(assessment.limitations)) for(const code of assessment.limitations.slice(0,12)) if(Object.hasOwn(limits,code)) detail.append(node('p',limits[code]));
      }
      if(data.risk){
        const level={critical:'긴급',high:'높음',medium:'중간',low:'낮음'};
        detail.append(node("p",data.risk.score===null?(data.risk.level==='unassessed'?"위험 점수 미평가":"위험 점수 미기록"):"위험 점수 "+data.risk.score+" / 100 · "+(level[data.risk.level]||'미확인')));
        const scoring=node('details');scoring.append(node('summary','점수 계산'),node('p','계산 버전 '+data.risk.version));
        const factors={rule_severity:'규칙 심각도',frequency_above_twice_threshold:'임계값 2배 초과',failure_then_success:'인증 실패 후 성공',observed_rule_conditions:'탐지 조건 관측',numeric_risk_not_assessed:'숫자 위험도 미평가'};
        if(Array.isArray(data.risk.factors))for(const factor of data.risk.factors)scoring.append(node("p",(factors[factor.name]||factor.name)+": +"+factor.points));
        detail.append(scoring);
      }
      for(const [label,value] of [["탐지 규칙",data.rule_snapshot],["MITRE ATT&CK",data.mitre]])if(value){
        const section=node("details");section.append(node("summary",label),node("pre",JSON.stringify(value,null,2)));detail.append(section);
      }
      if(!data.evidence_count)detail.append(node("p","근거 로그가 없습니다."));
      const evidenceDetails=node('details'),evidenceBody=node('div'),navigation=node('div');
      evidenceDetails.append(node('summary','근거 로그 보기 ('+(data.evidence_count||0)+'건)'),evidenceBody,navigation);
      if(data.evidence_count)detail.append(evidenceDetails);
      function evidencePage(pageData){
      const page=pageData.evidence_page||{positions:Array.from({length:pageData.evidence_limit},(_,i)=>i),next_offset:null};
      for(const i of page.positions){
        const button=node("button","근거 "+(i+1)+" 조회"),result=node("div");button.type="button";
        button.addEventListener("click",async()=>{
          button.disabled=true;result.textContent="근거 조회 중";
          try{
            const reply=await request("/api/alerts/detail?"+new URLSearchParams({id,evidence:String(i)}));if(version!==generation)return;
            const e=reply.evidence;result.replaceChildren(node("p",evidenceStates[e.state]||"근거 상태 미확인"));
            if(e.integrity)result.append(node('p',e.integrity==='normalized_hash_verified'?'정규화 내용 해시 일치 · 원본 내용 해시는 미검증':'과거 근거의 내용 해시는 미기록'));
            if(e.raw)result.append(node("p","원본 참조: "+e.raw.index+" / "+e.raw.id));
            if(e.normalized)result.append(node("p","정규화 참조: "+e.normalized.index+" / "+e.normalized.id));
            if(e.normalized_event)result.append(node("p","근거 이벤트 시각 (KST): "+fmt(e.normalized_event.timestamp)+" · 행위 "+(e.normalized_event.action||"미관측")+" · 결과 "+(e.normalized_event.outcome||"미관측")));
            if(e.metadata)result.append(node("pre",JSON.stringify(e.metadata,null,2)));
            if(e.security)result.append(node("pre",JSON.stringify(e.security,null,2)));
            window.CloudSOCMall.evidence(result,e,i);
          }catch(failure){result.textContent=failure.message;}finally{button.disabled=false;}
        });evidenceBody.append(button,result);
      }
      navigation.replaceChildren();
      if(page.next_offset!==null){
        const more=node('button','다음 근거 페이지');more.type='button';navigation.append(more);
        more.addEventListener('click',async()=>{more.disabled=true;try{
          const next=await request('/api/alerts/detail?'+new URLSearchParams({id,offset:String(page.next_offset)}));
          if(version===generation)evidencePage(next);
        }catch(error){more.textContent=error.message;}finally{more.disabled=false;}});
      }
      }
      evidencePage(data);
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
      $("case-summary").textContent="조직 "+current.organization+" · "+states[current.status]+" · "+verdicts[current.verdict];
      const owner=$("work-owner");owner.replaceChildren();const none=node("option","미배정");none.value="";const me=node("option",data.actor);me.value=data.actor;owner.append(none,me);
      if(current.owner&&current.owner!==data.actor){const assigned=node("option",current.owner+" (현재 담당자)");assigned.value=current.owner;owner.append(assigned);}
      for(const key of ["status","owner","priority","verdict"])$("work-"+key).value=current[key]||"";
      $("case-work-panel").hidden=false;$("case-create-panel").hidden=true;$("case-history-panel").hidden=false;
      history(data.history);historyNext=data.history_next;$("case-history-more").disabled=!historyNext;
      const rows=data.alerts.slice().sort((a,b)=>(a.snapshot.timestamp||"").localeCompare(b.snapshot.timestamp||""));
      // Limit concurrent ES requests: further alerts are opened explicitly, not prefetched.
      for(const row of rows){
        const box=node("section"),button=node("button",(row.snapshot.title||row.id)+" · "+fmt(row.snapshot.timestamp)+" · 경보 열기");button.type="button";
        button.addEventListener("click",()=>{button.disabled=true;alertCard(box,row.id,row.snapshot,version);});box.append(button);$("case-alerts").append(box);
      }
      $("investigation-status").textContent="조회 완료";
    }catch(failure){if(version===generation){current=null;error(failure.message);$("investigation-status").textContent="사건 조회 실패";}}
  }
  async function save(body){
    if(saving||!current)return;locked(true);$("investigation-error").hidden=true;
    try{await mutate("/api/cases/"+caseId,"PATCH",{version:current.version,...body});if(Object.hasOwn(body,"note"))$("work-note").value="";$("case-link-id").value="";await loadCase();}
    catch(failure){error(failure.message);}finally{locked(false);}
  }
  $("case-work-form").addEventListener("submit",event=>{
    event.preventDefault();if(!current)return;
    const body={status:$("work-status").value,priority:$("work-priority").value,verdict:$("work-verdict").value,note:$("work-note").value};
    const owner=$("work-owner").value||null;
    if(owner!==(current.owner||null))body.owner=owner;
    save(body);
  });
  $("case-link-form").addEventListener("submit",event=>{event.preventDefault();save({alert_id:$("case-link-id").value});});
  $("case-reload").addEventListener("click",()=>{if(!saving)loadCase();});
  $("case-history-more").addEventListener("click",async()=>{
    if(!historyNext)return;const version=generation;$("case-history-more").disabled=true;
    try{const data=await request("/api/cases/"+caseId+"?"+new URLSearchParams({before:historyNext}));if(version!==generation)return;history(data.history);historyNext=data.history_next;}
    catch(failure){error(failure.message);}finally{if(version===generation)$("case-history-more").disabled=!historyNext;}
  });
  $("case-create-form").addEventListener("submit",async event=>{
    event.preventDefault();if(saving)return;locked(true);$("investigation-error").hidden=true;
    try{const result=await mutate("/api/cases","POST",{title:$("create-title").value,priority:$("create-priority").value,alert_id:alertId});caseId=result.id;window.history.replaceState(null,"","workbench.html?"+new URLSearchParams({case:caseId,return:safeBack.toString(),return_page:returnPage}));await loadCase();}
    catch(failure){error(failure.message);}finally{locked(false);}
  });
  async function init(){
    if(caseId){if(!/^[0-9a-f]{32}$/.test(caseId)){error("사건 ID를 확인하세요.");return;}await loadCase();return;}
    if(!alertId){$("investigation-status").textContent="선택한 사건이 없습니다. 사건 목록에서 선택하세요.";return;}
    try{
      const linked=await request("/api/case-link?"+new URLSearchParams({alert_id:alertId}));
      if(linked.case_id){caseId=linked.case_id;await loadCase();return;}
      const data=await request("/api/alerts/detail?"+new URLSearchParams({id:alertId}));
      $("create-title").value=(data.alert.title||data.alert.rule||"경보 조사").slice(0,160);$("case-create-panel").hidden=false;
      $("case-summary").textContent="아직 사건으로 등록하지 않은 경보입니다.";
      await alertCard($("case-alerts"),alertId,data.alert,generation);
    }catch(failure){error(failure.message);}
  }
  const changes=window.CloudSOCLive.notice($('case-summary').parentElement,'추가 근거');
  let remoteSignature=null;
  const live=window.CloudSOCLive.create({host:$('investigation-status').parentElement,interval:10000,enabled:()=>!saving&&!!(caseId||alertId),
    load:signal=>request(caseId?'/api/cases/'+caseId:'/api/alerts/detail?'+new URLSearchParams({id:alertId}),{signal}),
    apply:data=>{const signature=JSON.stringify(caseId?[data.case?.version,data.case?.updated_at,data.alerts]:[data.evidence_count,data.rule_version]);
      if(remoteSignature!==null&&signature!==remoteSignature){changes.offer(0,()=>{const link=node('a','최신 내용 별도 창에서 보기');link.href=window.location.href;link.target='_blank';link.rel='noopener';$('investigation-status').replaceChildren(document.createTextNode('작성 중인 내용은 유지됩니다. '),link);});}
      remoteSignature=signature;},onError:()=>error('변경 사항 조회 실패 · 읽던 내용과 작성 중인 입력은 유지됩니다.')});
  window.addEventListener("pagehide",()=>{generation++;$("work-note").value="";$("case-alerts").replaceChildren();$("case-history").replaceChildren();});
  init().then(()=>live.start());
})();
