const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const script = fs.readFileSync(path.join(__dirname, '../operations.js'), 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));
const section = {state:'ok',count:0,buckets:[],rows:[],statuses:[]};
const data = {start:'2026-09-22T01:00:00Z',end:'2026-09-22T02:00:00Z',sections:{intake:section,processing:section,alerts:section,quality:section,pipeline:{state:'not_started'}}};
const ok = value => () => ({ok:true,json:async()=>value});
function browser(responses) {
  const dom=require('./live-dom.cjs').dom();
  const elements = new Map(), calls = [], timers = new Map();
  let timerId = 0;
  function element(tag){return dom.element(tag);}
  const get = id => {if(!elements.has(id))elements.set(id,element());return elements.get(id);};
  const context={document:{getElementById:get,createElement:element,createElementNS:element},
    window:{addEventListener(){},setTimeout(fn){timers.set(++timerId,fn);return timerId;},clearTimeout(id){timers.delete(id);}},URLSearchParams,Date,fetch:async(url,options)=>{calls.push({url,options});return responses.shift()();}};
  // operations.html loads the shared Mall alert renderer before operations.js.
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../mall-alerts.js'),'utf8'),context);
  dom.install(context);
  vm.runInNewContext(script,context);
  return {get,calls,timers};
}
function allText(element){return element.textContent+element.children.map(allText).join(' ');}
function alertButton(ui){const rows=ui.get('ops-alert-rows').children;assert.equal(rows.length,1);return rows[0].children.at(-1).children[0];}

test('site context refreshes while open, retains failed results with status and stops on close',async()=>{
  const row={id:'site-alert',title:'사이트 404',timestamp:data.start,site_id:'site-A'};
  const context={state:'ok',checked_at:data.end,count:1,events:[{timestamp:data.start,method:'GET',status_code:404}]};
  const ui=browser([ok({...data,sections:{...data.sections,alerts:{...section,rows:[row]}}}),
    ok({alert:row,evidence_count:20,evidence_limit:0,condition:{}}),ok(context),
    ()=>({ok:false,status:503})]);await settle();
  alertButton(ui).listeners.click();await settle();await settle();
  assert.ok(ui.calls.some(c=>c.url==='/api/alerts/site-context?id=site-alert'));
  assert.match(allText(ui.get('ops-detail-content')),/같은 요청이나 탐지 근거를 뜻하지 않습니다/);
  assert.match(allText(ui.get('ops-detail-content')),/GET · HTTP 404/);
  assert.equal(ui.timers.size,1);
  const [id,tick]=ui.timers.entries().next().value;ui.timers.delete(id);await tick();await settle();
  assert.match(allText(ui.get('ops-detail-content')),/GET · HTTP 404/);assert.match(allText(ui.get('ops-detail-content')),/마지막 조회 내용 유지/);
  assert.match(allText(ui.get('ops-detail-content')),/503/);
  ui.get('ops-detail').close();assert.equal(ui.timers.size,0);
});

test('runtime inventory distinguishes observed rules from missing and old workers',async()=>{
  const rules=[{id:'AUTH-001',scope:'general',catalog_revision:'a'.repeat(64),observations:[
    {worker:'detector',state:'running',revision:'a'.repeat(64),last_success:data.end,checkpoint:data.end}]},
    {id:'WEB-ACCESS-01',scope:'application_audit',state:'not_observed',observations:[]},
    {id:'WEB-WAF-01',scope:'application_waf',state:'unknown',observations:[]}];
  const ui=browser([ok({...data,sections:{...data.sections,pipeline:{state:'success',rules}}})]);await settle();
  const content=allText(ui.get('ops-runtime-rules'));
  assert.match(content,/AUTH-001.*상주 실행 관측/);
  assert.match(content,/WEB-ACCESS-01.*선택 앱 감사.*실행 보고 없음/);
  assert.match(content,/WEB-WAF-01.*미확인 · 조회 실패 또는 이전 워커/);
  assert.ok(content.includes('a'.repeat(64)));
});

test('generic WAF summary shows actual rules and keeps detection mode separate from blocking',async()=>{
  const row={id:'waf-alert',title:'사이트 WAF',timestamp:data.start};
  const ui=browser([ok({...data,sections:{...data.sections,alerts:{...section,rows:[row]}}}),
    ok({alert:row,evidence_count:3,evidence_limit:0,condition:{},assessment:{waf:{engine_modes:['DetectionOnly'],interruption_states:['unknown'],matched_rule_ids:['942100']}}})]);
  await settle();alertButton(ui).listeners.click();await settle();
  const content=allText(ui.get('ops-detail-content'));
  assert.match(content,/탐지 전용 · 차단 미수행/);assert.match(content,/엔진 개입 여부 미관측/);
  assert.match(content,/관측 CRS 규칙 ID: 942100/);
});

test('restricted or legacy pipeline cannot claim that catalog rules are running',async()=>{
  const ui=browser([ok(data)]);await settle();
  assert.match(allText(ui.get('ops-runtime-rules')),/실행 규칙 정보를 확인할 수 없습니다/);
});
test('real page loads no demo scripts',()=>{
  const html=fs.readFileSync(path.join(__dirname,'../operations.html'),'utf8');
  assert.ok(!html.includes('demo-data.js')); assert.ok(html.includes('operations.js')); assert.ok(html.includes('처리 상태'));
});

test('detector state is displayed separately from normalization',async()=>{
  const ui=browser([ok({...data,sections:{...data.sections,pipeline:{state:'success',detector:{state:'failed'}}}})]);await settle();
  assert.match(ui.get('ops-pipeline').textContent,/SSH 탐지기: 탐지 실패/);
});

test('zero stored alerts remain limited when raw intake continues but normalization failed',async()=>{
 const ui=browser([ok({...data,sections:{...data.sections,intake:{...section,count:120,buckets:[{time:data.start,count:120}]},
  pipeline:{state:'failed',detector:{state:'success'},coverage:{state:'blocked'}}}})]);await settle();
 assert.match(allText(ui.get('ops-metrics').children[0]),/저장된 경보.*0.*분석 미완료/);
 assert.match(ui.get('ops-alert-state').textContent,/위험 없음으로 해석할 수 없습니다/);
 assert.match(ui.get('ops-pipeline').textContent,/새 로그 분석 중단/);
});
test('cloud profile is identified in the operations view',async()=>{
  const ui=browser([ok({...data,sections:{...data.sections,pipeline:{state:'success',detector:{state:'success',detection:'AUTH-001,AWS-IAM-001'}}}})]);await settle();
  assert.match(ui.get('ops-pipeline').textContent,/SSH·클라우드 탐지기/);
});

test('experimental attack profile is not mislabeled as the default SSH detector',async()=>{
  const ui=browser([ok({...data,sections:{...data.sections,pipeline:{state:'success',detector:{state:'success',detection:'AUTH-001,ATTACK-01,ATTACK-02'}}}})]);await settle();
  assert.match(ui.get('ops-pipeline').textContent,/공격 행위 탐지기.*시험 프로필/);
});

test('attack rationale shows measured diversity and limitations as safe text',async()=>{
  const row={id:'alert',title:'AWS 정찰 의심',timestamp:data.start};
  const ui=browser([ok({...data,sections:{...data.sections,alerts:{...section,rows:[row]}}}),
    ok({alert:row,evidence_count:20,evidence_limit:0,condition:{event_count:20,threshold:20,time_window_seconds:300},
      assessment:{type:'attack_indicator',reason:'call_count_and_api_diversity',observed_count:20,distinct_count:4,
        limitations:['no_user_agent_or_normal_activity_baseline','candidate_threshold_not_live_validated','<img src=x>']}})]);await settle();
  alertButton(ui).listeners.click();await settle();
  const content=allText(ui.get('ops-detail-content'));
  assert.match(content,/API 호출 20건.*API 4종/);
  assert.match(content,/공격 성공 미확정/);
  assert.match(content,/평소 활동과의 차이는 평가하지/);
  assert.ok(!content.includes('<img src=x>'));
});

test('SSH correlation detail states the missing session link',async()=>{
  const row={id:'alert',title:'SSH 후속 활동',timestamp:data.start};
  const ui=browser([ok({...data,sections:{...data.sections,alerts:{...section,rows:[row]}}}),
    ok({alert:row,evidence_count:7,evidence_limit:0,condition:{},assessment:{type:'attack_correlation',reason:'ordered_metadata_stages',
      stages:[{name:'ssh_failures',count:5},{name:'ssh_success',count:1},{name:'sudo_root_metadata',count:1}],
      limitations:['host_user_time_context_only_not_same_session']}})]);await settle();
  alertButton(ui).listeners.click();await settle();
  const content=allText(ui.get('ops-detail-content'));
  assert.match(content,/SSH 인증 실패 5건/);
  assert.match(content,/동일 SSH 세션인지는 확인되지/);
});

test('attack detail keeps versions and evidence lists collapsed without hiding limitations',async()=>{
  const row={id:'alert',title:'SSH 후속 활동',timestamp:data.start};
  const ui=browser([ok({...data,sections:{...data.sections,alerts:{...section,rows:[row]}}}),
    ok({alert:row,rule_version:'version-canary',evidence_count:7,evidence_limit:0,condition:{event_count:7,threshold:5,time_window_seconds:900},
      assessment:{type:'attack_correlation',limitations:['candidate_threshold_not_live_validated']}})]);await settle();
  alertButton(ui).listeners.click();await settle();
  const content=ui.get('ops-detail-content');
  assert.equal(content.children[1].textContent,row.title);
  assert.equal(content.children[2].textContent,'관측 로그 7건');
  assert.match(allText(content.children[3]),/공격 성공 미확정.*운영 기준 미확정/);
  const evidence=content.children[4],rule=content.children[5];
  assert.equal(evidence.open,false);assert.equal(rule.open,false);
  assert.equal(evidence.children[0].textContent,'근거 로그 보기 (7건)');
  assert.equal(rule.children[0].textContent,'규칙 정보');
  assert.match(allText(rule),/version-canary.*임계값 5.*900초/);
});
test('detector health alarms and excluded counts are visible',async()=>{
  for (const [health,label] of [['failed','탐지 장애: 처리 실패'],['stale','상태 갱신 중단'],['delayed','탐지 지연'],['warning','탐지 경고: 평가 범위·초기 통지 확인 필요']]) {
    const ui=browser([ok({...data,sections:{...data.sections,pipeline:{state:'success',detector:{state:'success',health,lag_seconds:1300,late_total:3,legacy_excluded:12}}}})]);await settle();
    assert.ok(ui.get('ops-pipeline').textContent.includes(label));
    assert.match(ui.get('ops-pipeline').textContent,/처리 지연 1300초.*지연 제외 누적 3건.*과거 형식 제외 12건/);
  }
});
test('initial notice failures, pending delivery and reconciliation are distinct from exclusions',async()=>{
  for (const [state,label] of [['failed','초기 통지 처리 실패'],['pending','초기 통지 처리·전달 대기'],['reconcile_required','초기 통지·최종 근거 재확인 필요'],['unknown','초기 통지 상태 미확인']]) {
    const ui=browser([ok({...data,sections:{...data.sections,pipeline:{state:'success',detector:{state:'success',health:'warning',early:{state},excluded_total:0}}}})]);await settle();
    assert.ok(ui.get('ops-pipeline').textContent.includes(label));
    assert.ok(!ui.get('ops-pipeline').textContent.includes('탐지 제외 이벤트'));
  }
});
test('successful zero, missing index and failed queries stay distinct',async()=>{
  const ui=browser([ok({...data,sections:{...data.sections,processing:{state:'no_index'},quality:{state:'unavailable'}}})]);await settle();
  const cards=ui.get('ops-metrics').children;
 assert.match(allText(cards[0]),/0.*조회 성공/);assert.match(allText(cards[2]),/미확인.*인덱스 없음/);assert.match(allText(cards[3]),/조회 실패/);
  assert.match(ui.get('ops-pipeline').textContent,/실행 기록 없음/);
});
test('failed refresh retains totals with a stale indicator and does not echo server body',async()=>{
  const ui=browser([ok(data),()=>({ok:false,status:503,json:async()=>({error:'PRIVATE_CANARY'})})]);await settle();
  ui.get('ops-filter').listeners.submit({preventDefault(){}});await settle();
  assert.equal(ui.get('ops-metrics').children.length,4);assert.equal(ui.get('ops-error').hidden,false);
  assert.ok(!ui.get('ops-error').textContent.includes('PRIVATE_CANARY'));
  assert.match(ui.get('ops-error').textContent,/503/);
});
test('malformed responses cannot leave partially rendered counts',async()=>{
  const ui=browser([ok({...data,sections:{...data.sections,quality:{state:'ok',count:-1}}})]);await settle();
  assert.equal(ui.get('ops-metrics').children.length,0);assert.equal(ui.get('ops-error').hidden,false);
});
test('older response cannot overwrite newer period',async()=>{
  let release;const ui=browser([()=>new Promise(resolve=>release=resolve),ok(data)]);
  ui.get('ops-filter').listeners.submit({preventDefault(){}});await settle();
  release({ok:true,json:async()=>({...data,sections:{}})});await settle();
  assert.equal(ui.get('ops-metrics').children.length,4);
});
test('alert IDs are encoded and untrusted titles are text nodes',async()=>{
  const row={id:'a/b?c&d',title:'<img src=x>',timestamp:data.start};
  const ui=browser([ok({...data,sections:{...data.sections,alerts:{...section,count:1,rows:[row],buckets:[{time:data.start,count:1}]}}}),
    ok({alert:row,evidence_count:0,evidence_limit:0,condition:{}})]);await settle();
  const cells=ui.get('ops-alert-rows').children[0].children;
  assert.equal(cells[3].textContent,'<img src=x>');cells.at(-1).children[0].listeners.click();await settle();
  assert.equal(new URL(ui.calls[1].url,'https://example.test').searchParams.get('id'),row.id);
  const investigation = new URL(ui.get('ops-detail-content').children[0].href,'https://example.test');
  assert.equal(investigation.searchParams.get('return_page'),'operations.html');
  assert.match(ui.get('ops-detail-state').textContent,/주변 로그로 대체하지/);
});

test('evidence pagination reaches global positions and reports normalized integrity',async()=>{
 const row={id:'alert',title:'sequence',timestamp:data.start};
 const ui=browser([ok({...data,sections:{...data.sections,alerts:{...section,rows:[row]}}}),
 ok({alert:row,condition:{},evidence_count:251,evidence_page:{positions:[0],next_offset:250}}),
 ok({evidence_count:251,evidence_page:{positions:[250],next_offset:null}}),
 ok({evidence:{state:'exact_reference',integrity:'normalized_hash_verified'}})]);await settle();
 alertButton(ui).listeners.click();await settle();
 const content=ui.get('ops-detail-content');const container=content.children[3],nav=content.children[4];
 nav.children[0].listeners.click();await settle();
 assert.equal(new URL(ui.calls[2].url,'https://test').searchParams.get('offset'),'250');
 container.children[1].children[0].listeners.click();await settle();
 assert.equal(new URL(ui.calls[3].url,'https://test').searchParams.get('evidence'),'250');
 assert.match(allText(container.children[1]),/해시 일치.*원본 내용 해시는 미검증/);
});
