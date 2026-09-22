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
  assert.ok(!html.includes('demo-data.js')); assert.ok(html.includes('operations.js')); assert.ok(html.includes('승인 대기'));
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
  assert.match(ui.get('ops-detail-state').textContent,/주변 로그로 대체하지/);
});
