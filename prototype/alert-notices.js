/* Immutable notice revisions describe one logical detection, never two attacks. */
(() => {
  'use strict';
  const labels={initial:'초기 탐지',verifying:'근거 검증 중',confirmed:'근거 확정',corrected:'초기 판단 정정',delayed:'검증 지연'};
  const node=(tag,text,cls)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;};
  const time=value=>typeof value==='string'&&Number.isFinite(Date.parse(value))?new Date(value).toLocaleString('ko-KR',{timeZone:'Asia/Seoul',hour12:false}):'미관측';
  async function request(url,signal){const r=await fetch(url,{credentials:'same-origin',cache:'no-store',signal});const body=await r.json();if(!r.ok)throw Object.assign(new Error(body.error||'조회 실패'),{status:r.status});return body;}
  function dialog(){let d=document.getElementById('notice-dialog');if(d)return d;d=node('dialog',undefined,'notice-dialog');d.id='notice-dialog';d.setAttribute('aria-label','초기 통지와 근거');document.body.append(d);return d;}
  let detailGeneration=0,detailController,evidenceGeneration=0;
  async function show(id){const d=dialog();detailController?.abort();detailController=new AbortController();const generation=++detailGeneration;
    d.replaceChildren(node('h2','초기 통지와 근거'));const content=node('div'),close=node('button','닫기');close.type='button';close.addEventListener('click',()=>d.close());d.append(content,close);d.onclose=()=>{detailGeneration++;detailController?.abort();};d.showModal();content.append(node('p','조회 중…'));
    try{const result=await request('/api/alerts/notices/detail?'+new URLSearchParams({id}),detailController.signal);if(generation!==detailGeneration)return;const r=result.notice;content.replaceChildren(node('h3',r.title),node('p',(labels[r.effective_state]||'상태 미확인')+' · 공격 성공 여부 미확정'),node('p','같은 조직·출발지의 5분 내 유효 SSH 실패 관측 10건이 초기 조건을 충족했습니다. 도구 종류·침해 성공을 확정하지 않습니다.'));
      const dl=node('dl');for(const [title,value]of [['출발지',r.source_ip],['첫 발생',time(r.window_start)],['창 종료',time(r.window_end)],['최초 중앙 수신',time(r.first_received_at)],['조건 근거 정규화',time(r.normalized_at)],['탐지기 검색 관측',time(r.search_observed_at)],['초기 생성',time(r.initial_at)],['근거 확정',time(r.final_at)]])dl.append(node('dt',title),node('dd',value||'미관측'));content.append(dl,node('p','정규화 시각은 실제 검색 가능 시각과 다를 수 있습니다. 60초는 목표이며 보장이 아닙니다.','dash-subtitle'));
      const list=node('div',undefined,'notice-evidence-buttons'),evidence=node('div');
      for(let i=0;i<Math.min(10,r.evidence_count);i++){
        const b=node('button','근거 '+(i+1));b.type='button';
        b.addEventListener('click',async()=>{
          const currentEvidence=++evidenceGeneration;evidence.replaceChildren(node('p','근거 확인 중…'));
          try{
            const found=await request('/api/alerts/notices/detail?'+new URLSearchParams({id,evidence:String(i)}),detailController.signal);
            if(generation!==detailGeneration||currentEvidence!==evidenceGeneration)return;
            evidence.replaceChildren(node('p',({exact_reference:'원본 참조 일치',raw_missing_or_expired:'원본 없음·보존 만료',normalized_missing_or_expired:'정규화 근거 없음·만료',normalized_hash_mismatch:'정규화 내용 해시 불일치',provenance_mismatch:'근거 참조 불일치'}[found.evidence?.state]||'근거 검증 상태 확인 필요')+' · '+(found.evidence?.integrity==='normalized_hash_verified'?'정규화 해시 검증':'무결성 미확인')));
            if(found.evidence?.normalized_event)evidence.append(node('p',time(found.evidence.normalized_event.timestamp)+' · '+(found.evidence.normalized_event.action||'행위 미관측')));
          }catch(error){if(generation===detailGeneration&&currentEvidence===evidenceGeneration)evidence.replaceChildren(node('p','근거 조회 실패 · 연결·권한을 확인하세요.'));}
        });list.append(b);
      }content.append(list,evidence);
      if(r.final_alert_id){const a=node('a','최종 경보 근거·사건 조사');a.href='workbench.html?'+new URLSearchParams({alert:r.final_alert_id,return_page:document.body.dataset.dashboard==='personal'?'dashboard.html':'index.html'});content.append(a);}
    }catch(error){if(generation===detailGeneration)content.replaceChildren(node('p','통지 조회 실패 · 연결·권한·보존 상태를 확인하세요.'));}
  }
  function render(box,result){
    box.replaceChildren();const data=result?.body;
    if(!data){box.append(node('p',result?.loading?'초기 통지 조회 중…':result?.status===403?'초기 통지 조회 권한이 없습니다.':'초기 통지 조회 실패 · 연결을 확인하세요.','dash-empty'));return;}
    if(data.state==='not_configured'){box.append(node('p','빠른 초기 통지가 아직 설정되지 않았습니다. 기존 확정 경보는 경보 목록에서 확인하세요.','dash-empty'));return;}
    if(data.state!=='ok'||!Array.isArray(data.rows)||data.rows.length>50||data.rows.some(r=>!r||typeof r!=='object'||typeof r.id!=='string'||!/^[0-9a-f]{64}$/.test(r.id)||typeof labels[r.effective_state]!=='string'||r.observed_count!==10||r.window_seconds!==300||r.evidence_count!==10)||new Set(data.rows.map(r=>r.id)).size!==data.rows.length){box.append(node('p','통지 응답 형식을 확인하지 못했습니다.','dash-empty'));return;}
    if(!data.rows.length){box.append(node('p','조회 기간의 초기 통지가 0건입니다. 탐지 미실행·분석 상태는 상단 경고와 함께 확인하세요.','dash-empty'));return;}
    const list=node('div',undefined,'notice-cards');for(const r of data.rows){const card=node('article',undefined,'notice-card');card.dataset.notice=r.id;card.dataset.state=r.effective_state;const header=node('div',undefined,'notice-header');header.append(node('strong',r.title||'SSH 인증 공격 의심'),node('span',labels[r.effective_state]||'미확인','notice-state'));card.append(header,node('p','출발지 '+(r.source_ip||'미관측')+' · 초기 유효 근거 '+r.observed_count+'건 / '+r.window_seconds+'초'),node('p','초기 생성 '+time(r.initial_at)+(r.final_at?' · 근거 확정 '+time(r.final_at):''),'dash-subtitle'));const b=node('button','통지 근거 보기');b.type='button';b.disabled=r.evidence_count!==10;b.addEventListener('click',()=>show(r.id));card.append(b);if(r.final_alert_id){const a=node('a','최종 경보 조사');a.href='workbench.html?'+new URLSearchParams({alert:r.final_alert_id});card.append(a);}list.append(card);}box.append(list,node('p','최신 최대 50개 논리적 통지 · 초기/확정 상태는 같은 통지입니다. 확정 경보와 합산해 공격 횟수로 표시하지 않습니다.','dash-subtitle'));
  }
  window.CloudSOCNotices={labels,render,show};
  const panel=document.getElementById('early-alert-panel');if(!panel)return;
  let controller,generation=0,timer,forbidden=false;
  async function refresh(){if(forbidden)return;clearTimeout(timer);controller?.abort();controller=new AbortController();const active=controller,current=++generation,timeout=setTimeout(()=>active.abort(),8000);const end=Date.now(),period=Number(document.getElementById('dashboard-period')?.value)||1440;
    try{const data=await request('/api/alerts/notices?'+new URLSearchParams({start:new Date(end-period*60000).toISOString(),end:new Date(end).toISOString()}),active.signal);if(current===generation)render(panel,{body:data});}catch(error){if(current===generation){render(panel,{status:error.status});forbidden=error.status===403;}}finally{clearTimeout(timeout);if(current===generation&&!document.hidden&&!forbidden)timer=setTimeout(refresh,10000);}}
  document.getElementById('dashboard-period')?.addEventListener('change',refresh);document.getElementById('dashboard-refresh')?.addEventListener('click',refresh);
  window.addEventListener('pagehide',()=>{generation++;clearTimeout(timer);controller?.abort();detailController?.abort();});document.addEventListener('visibilitychange',()=>{if(document.hidden){generation++;clearTimeout(timer);controller?.abort();}else refresh();});refresh();
})();
