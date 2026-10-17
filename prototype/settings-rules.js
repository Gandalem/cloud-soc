/* Manual management only: no AI request, active-rule write, or automatic deployment. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const states = {draft:'초안',validated:'형식 검증 완료',approved:'관리자 승인',rejected:'거부'};
  const applications = {not_approved:'미승인 · 적용 불가',awaiting_application:'승인됨 · 적용 요청 전',pending_deployment:'배포 대기 · 아직 비활성'};
  let selected = null, busy = false;
  const node = (tag, text) => {const n=document.createElement(tag);n.textContent=text;return n;};
  async function api(path='', body) {
    const response = await fetch('/api/settings/rules'+path, body === undefined ? {cache:'no-store'} :
      {method:'POST',headers:{'Content-Type':'application/json','X-Cloud-SOC':'portal'},body:JSON.stringify(body)});
    const data = await response.json();
    if(!response.ok) throw new Error(data.code || '권한·입력·저장 상태를 확인하세요.');
    return data;
  }
  function show(row){
    selected=row;$('rule-detail').hidden=false;
    $('rule-summary').textContent=states[row.status]+' / '+applications[row.application_state]+' / 조직 '+row.organization;
    $('rule-preview').textContent=row.yaml;
    $('rule-validation').textContent=row.validation.valid === true ? '기존 엔진 형식 검증 성공 · 실제 탐지 효과 미검증' :
      row.validation.valid === false ? '검증 실패: '+row.validation.code : '검증 전';
    $('rule-approval').textContent='내용 SHA-256: '+row.content_hash+(row.approved_by?' / 승인자 '+row.approved_by+' / '+row.approved_at:'');
    $('rule-validate').disabled=!['draft','validated'].includes(row.status);
    $('rule-approve').disabled=row.status!=='validated';$('rule-reject').disabled=!['draft','validated'].includes(row.status);
    $('rule-apply').disabled=row.status!=='approved'||row.application_state!=='awaiting_application';
    $('rule-export').hidden=row.status!=='approved';$('rule-export').href='/api/settings/rules/'+row.id+'/export';
    $('rule-history').replaceChildren(...row.history.map(h=>node('p',h.at+' / '+h.actor+' / '+h.action+' / v'+h.version+' / '+h.content_hash+' / '+h.result)));
  }
  async function list(){
    const data=await api();$('rule-state').textContent='수동 입력 가능 / AI 연동 대기 · 승인 후 별도 배포 필요';
    const previous=$('rule-organization').value;
    $('rule-organization').replaceChildren(...data.organizations.map(o=>{const n=node('option',o);n.value=o;return n;}));
    if(data.organizations.includes(previous))$('rule-organization').value=previous;
    $('rule-save').disabled=!data.organizations.length;$('rule-example').disabled=!data.organizations.length;
    if(!data.organizations.length)$('rule-state').textContent='조직 정책 설정 필요 · 수동 입력/AI 연동 대기';
    $('rule-fields').textContent='필드: '+data.fields.join(', ')+'\n연산자: '+data.operators.join(', ');
    $('rule-list').replaceChildren(...data.drafts.map(row=>{
      const button=node('button',(row.rule_id||'미검증 초안')+' / '+row.organization+' / '+states[row.status]+' / '+applications[row.application_state]);
      button.type='button';button.addEventListener('click',()=>run(async()=>show(await api('/'+row.id))));return button;
    }));
  }
  async function run(action){
    if(busy)return;busy=true;$('rule-result').textContent='처리 중';
    try{await action();$('rule-result').textContent='처리 완료 · 운영 규칙은 변경되지 않았습니다.';}
    catch(e){$('rule-result').textContent=e.message;}finally{busy=false;}
  }
  $('rule-create').addEventListener('submit',event=>{event.preventDefault();run(async()=>{
    show(await api('',{organization:$('rule-organization').value,yaml:$('rule-yaml').value,intent:$('rule-intent').value}));await list();
  });});
  for(const action of ['validate','approve','reject','apply'])$('rule-'+action).addEventListener('click',()=>run(async()=>{
    if(!selected)return;
    if(action==='approve'&&!window.confirm('현재 표시된 YAML과 내용 해시를 승인하시겠습니까? 실제 적용은 별도 배포입니다.'))return;
    show(await api('/'+selected.id+'/'+action,{version:selected.version,content_hash:selected.content_hash}));await list();
  }));
  $('rule-refresh').addEventListener('click',()=>run(list));
  $('rule-example').addEventListener('click',()=>{
    const org=$('rule-organization').value;if(!org)return;
    $('rule-yaml').value='rules:\n  - id: CUSTOM-AUTH-001\n    type: threshold\n    name: Repeated login failures\n    description: Same IP login failures in five minutes\n    enabled: true\n    severity: medium\n    group_by: [organization.id, source.ip]\n    threshold: {count: 10}\n    time_window: {seconds: 300}\n    cooldown: {seconds: 900}\n    conditions:\n      - {field: organization.id, operator: equals, value: '+JSON.stringify(org)+'}\n      - {field: event.category, operator: contains, value: authentication}\n      - {field: event.action, operator: equals, value: login}\n      - {field: event.outcome, operator: equals, value: failure}\n    alert:\n      title: Repeated authentication failures\n      message: Review repeated failures; compromise is not confirmed\n      category: authentication\n      tags: [manual-rule]\n';
  });
  run(list);
})();
