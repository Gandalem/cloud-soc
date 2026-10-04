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
  const elements = new Map(), calls = [];
  function element() { return {textContent:'',children:[],listeners:{},value:'60',hidden:false,open:false,
    addEventListener(name, fn){this.listeners[name]=fn;},setAttribute(){},
    append(...nodes){this.children.push(...nodes);},replaceChildren(...nodes){this.children=nodes;},
    showModal(){this.open=true;},close(){this.open=false;this.listeners.close?.();}}; }
  const get = id => {if(!elements.has(id))elements.set(id,element());return elements.get(id);};
  vm.runInNewContext(script,{document:{getElementById:get,createElement:element,createElementNS:element},
    window:{addEventListener(){}},URLSearchParams,Date,fetch:async(url,options)=>{calls.push({url,options});return responses.shift()();}});
  return {get,calls};
}
function allText(element){return element.textContent+element.children.map(allText).join(' ');}
test('real page loads no demo scripts',()=>{
  const html=fs.readFileSync(path.join(__dirname,'../index.html'),'utf8');
  assert.ok(!html.includes('demo-data.js')); assert.ok(html.includes('operations.js')); assert.ok(html.includes('SSH 탐지 현황'));
});

test('detector state is displayed separately from normalization',async()=>{
  const ui=browser([ok({...data,sections:{...data.sections,pipeline:{state:'success',detector:{state:'failed'}}}})]);await settle();
  assert.match(ui.get('ops-pipeline').textContent,/SSH 탐지기: 탐지 실패/);
});
test('cloud profile is identified in the operations view',async()=>{
  const ui=browser([ok({...data,sections:{...data.sections,pipeline:{state:'success',detector:{state:'success',detection:'AUTH-001,AWS-IAM-001'}}}})]);await settle();
  assert.match(ui.get('ops-pipeline').textContent,/SSH·클라우드 탐지기/);
});
test('detector health alarms and excluded counts are visible',async()=>{
  for (const [health,label] of [['failed','탐지 장애: 처리 실패'],['stale','상태 갱신 중단'],['delayed','탐지 지연'],['warning','탐지 제외 이벤트']]) {
    const ui=browser([ok({...data,sections:{...data.sections,pipeline:{state:'success',detector:{state:'success',health,lag_seconds:1300,late_total:3,legacy_excluded:12}}}})]);await settle();
    assert.ok(ui.get('ops-pipeline').textContent.includes(label));
    assert.match(ui.get('ops-pipeline').textContent,/처리 지연 1300초.*지연 제외 누적 3건.*과거 형식 제외 12건/);
  }
});
test('successful zero, missing index and failed queries stay distinct',async()=>{
  const ui=browser([ok({...data,sections:{...data.sections,processing:{state:'no_index'},quality:{state:'unavailable'}}})]);await settle();
  const cards=ui.get('ops-metrics').children;
  assert.match(allText(cards[0]),/0.*조회 성공/);assert.match(allText(cards[1]),/미확인.*인덱스 없음/);assert.match(allText(cards[3]),/조회 실패/);
  assert.match(ui.get('ops-pipeline').textContent,/실행 기록 없음/);
});
test('failed refresh clears old totals and does not echo server body',async()=>{
  const ui=browser([ok(data),()=>({ok:false,status:503,json:async()=>({error:'PRIVATE_CANARY'})})]);await settle();
  ui.get('ops-filter').listeners.submit({preventDefault(){}});await settle();
  assert.equal(ui.get('ops-metrics').children.length,0);assert.equal(ui.get('ops-error').hidden,false);
  assert.ok(!ui.get('ops-error').textContent.includes('PRIVATE_CANARY'));
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
  assert.equal(cells[3].textContent,'<img src=x>');cells[5].children[0].listeners.click();await settle();
  assert.equal(new URL(ui.calls[1].url,'https://example.test').searchParams.get('id'),row.id);
  const investigation = new URL(ui.get('ops-detail-content').children[0].href,'https://example.test');
  assert.equal(investigation.searchParams.get('return_page'),'index.html');
  assert.match(ui.get('ops-detail-state').textContent,/주변 로그로 대체하지/);
});

test('evidence pagination reaches global positions and reports normalized integrity',async()=>{
 const row={id:'alert',title:'sequence',timestamp:data.start};
 const ui=browser([ok({...data,sections:{...data.sections,alerts:{...section,rows:[row]}}}),
 ok({alert:row,condition:{},evidence_count:251,evidence_page:{positions:[0],next_offset:250}}),
 ok({evidence_count:251,evidence_page:{positions:[250],next_offset:null}}),
 ok({evidence:{state:'exact_reference',integrity:'normalized_hash_verified'}})]);await settle();
 ui.get('ops-alert-rows').children[0].children[5].children[0].listeners.click();await settle();
 const content=ui.get('ops-detail-content');const container=content.children[3],nav=content.children[4];
 nav.children[0].listeners.click();await settle();
 assert.equal(new URL(ui.calls[2].url,'https://test').searchParams.get('offset'),'250');
 container.children[1].children[0].listeners.click();await settle();
 assert.equal(new URL(ui.calls[3].url,'https://test').searchParams.get('evidence'),'250');
 assert.match(allText(container.children[1]),/해시 일치.*원본 내용 해시는 미검증/);
});
