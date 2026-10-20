/* Country coverage, transparent account assessments and recorded evaluation results. */
(() => {
 'use strict';
 const SVG='http://www.w3.org/2000/svg';
 const kst=()=>new Date(Date.now()+9*3600000).toISOString().slice(0,16);
 const utc=value=>{if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value))throw new Error('한국 시각을 입력하세요.');return new Date(value+':00+09:00').toISOString();};
 const id=()=>crypto.randomUUID();
 function choice(h,form,name,title,options){const l=h.N('label',title),s=h.N('select');s.name=name;options.forEach(([value,label])=>{const o=h.N('option',label);o.value=value;s.append(o);});l.append(s);form.append(l);return s;}
 function disclosure(h,box,title){const d=h.N('details');d.append(h.N('summary',title));box.append(d);return d;}
 function submit(h,form,kind,body){const b=h.N('button','기록 저장');b.type='submit';const result=h.N('div');form.append(b,result);form.addEventListener('submit',async event=>{event.preventDefault();b.disabled=true;result.replaceChildren();try{await h.request('/api/dashboard-records/'+kind,{method:'POST',headers:{'Content-Type':'application/json','X-Cloud-SOC':'portal'},body:JSON.stringify(body())});h.text(result,'기록을 저장했습니다. 목록 갱신 시 반영됩니다.');}catch(error){h.text(result,error.message);}finally{b.disabled=false;}});}
 async function raw(h,ref){
  const dialog=h.N('dialog',undefined,'insight-dialog'),body=h.N('div');dialog.append(h.N('h2','로그 상세'),h.button('닫기',()=>{dialog.close();dialog.remove();}),body);document.body.append(dialog);dialog.showModal();dialog.addEventListener('cancel',()=>dialog.remove(),{once:true});
  try{const data=await h.request('/api/logs/detail?'+new URLSearchParams(ref));h.list(body,['항목','관측 내용'],[['로그 종류',data.row?.log_type?.label],['수신 시각',h.when(data.row?.received_at)],['로그 시각',h.when(data.row?.event_at)],['조직',data.row?.organization],['출발지 IP',data.row?.source_ip],['인덱스',data.row?.reference?.index],['문서 ID',data.row?.reference?.id]]);}catch(error){h.text(body,error.message);}
 }
 function geography(box,w,data,h){
  const labels={configuration_required:'공인 IP 위치를 표시하려면 서버에 Country 위치 DB를 연결해 주세요.',dependency_required:'서버의 위치 조회 구성 요소를 설치해 주세요.',database_stale:'위치 자료의 갱신이 필요합니다.',internal_only:'현재 범위에는 위치를 추정할 수 없는 내부 주소만 있습니다.',no_access_data:'선택 기간에 위치 집계 대상 웹 접근이 없습니다.'};
  h.text(box,'접근 기록 '+data.total+'건 · 위치 확인 '+data.located+'건 · 내부·특수 주소 '+data.internal+'건 · IP 없음 '+data.missing_ip+'건');
  h.text(box,'전체 대상 위치 확인 '+data.coverage_percent+'% · 위치 미확인 공인 접근 '+data.unknown+'건');
  if(labels[data.state])h.text(box,labels[data.state]);
  if(data.attribution)h.text(box,data.attribution);
  const map=h.N('div',undefined,'insight-map'),detail=h.N('div');box.append(map,detail);
  const counts=new Map((data.countries||[]).map(r=>[r.country,r.count]));
  async function drill(code){detail.replaceChildren();h.text(detail,code+' 접근 기록 조회 중');try{const reply=await h.request('/api/dashboard-data/geo?'+new URLSearchParams({...data.filters,country:code}));detail.replaceChildren();h.text(detail,code+' 접근 '+(counts.get(code)||0)+'건 · 최근 '+reply.rows.length+'건 표시');h.list(detail,['시각','출발지','원본'],reply.rows.map(r=>[h.when(r.received_at),r.source_ip||r.interpretation?.fields?.source_ip,h.button('상세',()=>raw(h,r.reference))]));}catch(error){h.text(detail,error.message);}}
  fetch('assets/world-countries-110m.json',{cache:'force-cache'}).then(r=>{if(!r.ok)throw new Error();return r.json();}).then(shapes=>{
   const svg=document.createElementNS(SVG,'svg');svg.setAttribute('viewBox','0 0 720 360');svg.setAttribute('role','img');svg.setAttribute('aria-label','국가별 관측 접속 분포. 접속 상대의 추정 위치입니다.');
   const max=Math.max(1,...counts.values());
   for(const feature of shapes.features){const code=feature.properties.code,count=counts.get(code)||0,group=document.createElementNS(SVG,'g');
    group.setAttribute('tabindex','0');group.setAttribute('role','button');group.setAttribute('aria-label',feature.properties.name+' '+count+'건');
    const title=document.createElementNS(SVG,'title');title.textContent=feature.properties.name+' · '+count+'건';group.append(title);
    const polygons=feature.geometry.type==='MultiPolygon'?feature.geometry.coordinates:[feature.geometry.coordinates];
    for(const rings of polygons){const path=document.createElementNS(SVG,'path');let d='';for(const ring of rings){d+=ring.map(([x,y],i)=>(i?'L':'M')+((x+180)*2).toFixed(2)+','+((90-y)*2).toFixed(2)).join(' ')+'Z';}path.setAttribute('d',d);path.setAttribute('fill',count?'#3377bd':'#d9e2ed');path.setAttribute('fill-rule','evenodd');path.setAttribute('fill-opacity',count?String(.2+.8*count/max):'1');group.append(path);}
    group.addEventListener('click',()=>drill(code));group.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();drill(code);}});svg.append(group);
   }
   map.append(svg);h.text(map,'국가 경계: Natural Earth · 접속 위치는 추정이며 사람의 위치나 국적을 뜻하지 않습니다.');
  }).catch(()=>h.text(map,'지도 도형을 불러오지 못했습니다. 국가별 목록을 사용해 주세요.'));
  h.list(box,['국가','접근 건수','조회'],(data.countries||[]).slice(0,w.config.limit).map(r=>[r.country,r.count,h.button('로그 보기',()=>drill(r.country))]));
 }
 function policies(box,data,h){
  const d=disclosure(h,box,'평가 정책 등록'),form=h.N('form',undefined,'insight-form');d.append(form);
  const org=h.formField(form,'organization','조직 ID'),version=h.formField(form,'version','정책 버전'),purpose=h.formField(form,'purpose','평가 목적');
  const rows=h.N('div');form.append(rows);const fields=[];
  function add(){if(fields.length>=32)return;const row=h.N('fieldset');row.append(h.N('legend','평가 항목 '+(fields.length+1)));
   const key=h.formField(row,'item','항목 ID'),title=h.formField(row,'title','항목 이름'),weight=h.formField(row,'weight','가중치','1','number'),criterion=h.formField(row,'criterion','통과·위반 판단 기준'),rationale=h.formField(row,'rationale','가중치와 항목을 정한 근거');weight.min='1';weight.max='100';fields.push({key,title,weight,criterion,rationale});rows.append(row);
  }add();form.append(h.button('평가 항목 추가',add));
  const approval=h.N('label'),check=h.N('input');check.type='checkbox';check.required=true;approval.append(check,document.createTextNode('이 기준과 가중치를 평가 정책으로 승인합니다.'));form.append(approval);
  const policyId=id();submit(h,form,'policy',()=>({id:policyId,organization:org.value.trim(),version:version.value.trim(),purpose:purpose.value.trim(),approved:check.checked,items:fields.map(f=>({id:f.key.value.trim(),title:f.title.value.trim(),weight:Number(f.weight.value),criterion:f.criterion.value.trim(),rationale:f.rationale.value.trim()}))}));
 }
 function assessments(box,data,h){
  const d=disclosure(h,box,'계정 근거 평가 등록');
  if(!data.policies?.length){h.text(d,'평가 정책을 먼저 등록하세요.');return;}
  const form=h.N('form',undefined,'insight-form');d.append(form);
  const selected=choice(h,form,'policy','평가 정책',data.policies.map((p,i)=>[String(i),p.organization+' / '+p.id+' / '+p.version]));
  const provider=choice(h,form,'provider','클라우드',[['aws','AWS'],['oci','OCI']]),account=h.formField(form,'account','계정 또는 테넌시 ID');
  const observed=h.formField(form,'observed','평가 시각 (KST)',kst(),'datetime-local'),expires=h.formField(form,'expires','유효 기간 (일)','1','number');expires.min='1';expires.max='31';
  const rows=h.N('div');form.append(rows);let items=[];
  function populate(){rows.replaceChildren();items=data.policies[Number(selected.value)].items.map(item=>{const field=h.N('fieldset');field.append(h.N('legend',item.title+' · 가중치 '+item.weight));h.text(field,item.criterion);h.text(field,'가중치 근거: '+item.rationale);const status=choice(h,field,item.id,'평가 결과',[['unknown','미평가'],['pass','통과'],['fail','위반'],['exempt','예외 승인']]),evidence=h.formField(field,'evidence','근거 참조 또는 확인 내용'),reason=h.formField(field,'reason','예외 승인 사유');reason.required=false;rows.append(field);return {id:item.id,status,evidence,reason};});}populate();selected.addEventListener('change',populate);
  const assessmentId=id();submit(h,form,'assessment',()=>{const policy=data.policies[Number(selected.value)],stamp=utc(observed.value);return {id:assessmentId,organization:policy.organization,provider:provider.value,account:account.value.trim(),policy_id:policy.id,observed_at:stamp,expires_at:new Date(Date.parse(stamp)+Number(expires.value)*86400000).toISOString(),source:'operator_evidence_review',items:items.map(r=>({id:r.id,state:r.status.value,evidence:r.evidence.value.trim(),...(r.status.value==='exempt'?{exception_reason:r.reason.value.trim()}:{})}))};});
 }
 function accounts(box,w,data,h){
  h.text(box,'계정 '+data.total+'개 · 관측 이벤트와 등록된 근거 평가 기준');
  h.list(box,['조직 / 계정','관측 건수','평가 범위','정책 위반 점수','근거'],(data.accounts||[]).slice(0,w.config.limit).map(a=>{
   const detail=h.N('details');detail.append(h.N('summary','계산 근거'));h.text(detail,'평가 '+(a.assessment_id||'없음')+' · 정책 '+(a.policy_version||'없음')+' · 승인자 '+(a.policy_approved_by||'없음'));h.text(detail,'평가자 '+(a.assessor||'없음')+' · 유효 기한 '+h.when(a.expires_at));
   h.list(detail,['항목','가중치','결과','근거'],(a.contributions||[]).map(c=>[c.title,c.weight,{pass:'통과',fail:'위반',unknown:'미평가',exempt:'예외 승인'}[c.state],c.evidence]));
   detail.append(h.button('연결 가능한 최근 경보 조회',async()=>{const result=h.N('div');detail.append(result);try{const reply=await h.request('/api/dashboard-data/account-alerts?'+new URLSearchParams({...data.filters,organization:a.organization,provider:a.provider,account:a.account}));h.text(result,'최근 클라우드 경보 중 '+reply.examined+'개를 대조한 결과입니다. 계정 전체 경보 수와 다릅니다.');h.list(result,['경보','규칙','근거'],reply.rows.map(r=>[r.title||r.rule,r.rule,h.link('근거 보기','workbench.html?'+new URLSearchParams({alert:r.id}))]));}catch(error){h.text(result,error.message);}}));

   return [a.organization+' / '+a.provider+' / '+a.account,a.event_count,a.coverage_percent+'%',a.score==null?({expired:'평가 만료',unassessed:'미평가'}[a.state]||'미평가'):a.score+' / 100',detail];
  }));
  h.text(box,'점수 = 적용 항목의 위반 가중치 ÷ 전체 가중치 × 100. 미평가 항목이나 만료 자료가 있으면 점수를 계산하지 않습니다. 침해 확률이 아닙니다.');
  if(data.can_manage){policies(box,data,h);assessments(box,data,h);}
 }
 function evaluationForm(box,h){
  const d=disclosure(h,box,'평가 결과 등록'),form=h.N('form',undefined,'insight-form');d.append(form);
  h.text(form,'이미 수행한 합성 시나리오 결과를 기록합니다. 이 화면에서 공격이나 평가를 실행하지 않습니다.');
  const fields={};for(const [key,title] of [['organization','조직 ID'],['rule_id','규칙 ID'],['rule_version','규칙 버전'],['code_revision','코드 버전'],['input_digest','입력 자료 SHA256'],['scenario_revision','시나리오 버전']])fields[key]=h.formField(form,key,title);
  const kind=choice(h,form,'kind','평가 범위',[['rule','규칙 평가'],['pipeline','수집부터 경보까지 전체 경로 평가']]),status=choice(h,form,'status','실행 결과',[['complete','실행 완료'],['failed','실행 실패'],['cancelled','취소'],['inconclusive','판정 불가']]);
  const start=h.formField(form,'start','시작 (KST)','','datetime-local'),end=h.formField(form,'end','완료 (KST)','','datetime-local'),rows=h.N('div');form.append(rows);const scenarios=[];
  function add(){if(scenarios.length>=64)return;const f=h.N('fieldset');f.append(h.N('legend','시나리오 '+(scenarios.length+1)));const key=h.formField(f,'case','시나리오 ID'),expected=choice(h,f,'expected','기대 결과',[['true','탐지 대상'],['false','정상 입력']]),verdict=choice(h,f,'verdict','실제 결과',[['inconclusive','판정 불가'],['alert','경보 발생'],['no_alert','경보 없음'],['execution_failed','실행 오류']]),evidence=h.formField(f,'evidence','입력·처리 결과 근거'),alerts=h.formField(f,'alerts','연결할 경보 ID (쉼표 구분, 선택)');alerts.required=false;scenarios.push({key,expected,verdict,evidence,alerts});rows.append(f);}add();form.append(h.button('시나리오 추가',add));
  const runId=id();submit(h,form,'evaluation',()=>({id:runId,...Object.fromEntries(Object.entries(fields).map(([k,v])=>[k,v.value.trim()])),kind:kind.value,status:status.value,started_at:utc(start.value),completed_at:utc(end.value),scope:'synthetic_scenarios',cases:scenarios.map(r=>({id:r.key.value.trim(),expected:r.expected.value==='true',verdict:r.verdict.value,evidence:r.evidence.value.trim(),alert_ids:r.alerts.value.split(',').map(v=>v.trim()).filter(Boolean)}))}));
 }
 function evaluation(box,w,data,h){
  h.text(box,'등록된 합성 시나리오 평가 '+data.run_total+'회 · 운영 전체 탐지 성공률과 구분합니다.');
  const pct=v=>v==null?'계산 불가':v+'%';
  h.list(box,['평가 기준','정밀도 / 재현율','TP / FN / FP / TN','판정 제외','실행 실패'],(data.groups||[]).slice(0,w.config.limit).map(g=>[g.organization+' / '+(g.kind==='rule'?'규칙':'전체 경로')+' / '+g.rule_id+' / '+g.rule_version,pct(g.precision)+' / '+pct(g.recall),[g.TP,g.FN,g.FP,g.TN].join(' / '),g.excluded_cases,g.failed_runs]));
  for(const record of (data.runs||[]).slice(0,w.config.limit)){const r=record.body,d=disclosure(h,box,r.id+' · '+r.status);h.text(d,'코드 '+r.code_revision+' · 입력 '+r.input_digest+' · 시나리오 '+r.scenario_revision+' · 등록자 '+record.actor);h.list(d,['시나리오','기대','결과','근거'],r.cases.map(c=>[c.id,c.expected?'탐지 대상':'정상 입력',{alert:'경보 발생',no_alert:'경보 없음',inconclusive:'판정 불가',execution_failed:'실행 오류'}[c.verdict],c.evidence]));}
  h.text(box,'정밀도 = TP ÷ (TP + FP) · 재현율 = TP ÷ (TP + FN). 규칙·코드·입력·시나리오 버전이 다른 실행은 분리합니다.');
  if(data.can_manage)evaluationForm(box,h);
 }
 function render(box,w,meta,data,h){if(meta.source==='geo')geography(box,w,data,h);else if(meta.source==='accounts')accounts(box,w,data,h);else if(meta.source==='evaluation')evaluation(box,w,data,h);}
 window.CloudSOCInsightMetrics={render};
})();
