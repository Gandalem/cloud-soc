const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), vm = require('node:vm');
const script = fs.readFileSync(require('node:path').join(__dirname,'../detection-history.js'),'utf8');
const settle = () => new Promise(r=>setImmediate(r));
function browser(responses) {
 const elements=new Map(), calls=[];
 const make=()=>({textContent:'',value:'',children:[],listeners:{},append(...v){this.children.push(...v)},replaceChildren(...v){this.children=v},addEventListener(n,f){this.listeners[n]=f}});
 const get=id=>{if(!elements.has(id))elements.set(id,make());return elements.get(id)};
 get('history-kind').value='runs';
 vm.runInNewContext(script,{document:{getElementById:get,createElement:make},Date,URLSearchParams,AbortController,
  setInterval:()=>1,clearInterval(){},setTimeout:()=>1,clearTimeout(){},window:{addEventListener(){}},fetch:async url=>{
  if(url==='/api/operations/status')return {ok:true,json:async()=>({state:'failed',detector:{state:'success'}})};
  calls.push(url);return responses.shift()();
 }});
 return {get,calls};
}
const ok=data=>()=>({ok:true,json:async()=>data});
test('history keeps time bounds across seek pages and renders text only',async()=>{
 const ui=browser([ok({state:'ok',rows:[{rule:{id:'<img src=x>'},state:'committed'}],next:'cursor'}),ok({state:'ok',rows:[],next:null})]);await settle();
 assert.equal(ui.get('history-rows').children[0].children[0].textContent,'<img src=x> · 실행 완료');
 ui.get('history-next').listeners.click();await settle();
 const a=new URL(ui.calls[0],'https://test'),b=new URL(ui.calls[1],'https://test');
 assert.equal(a.searchParams.get('start'),b.searchParams.get('start'));assert.equal(a.searchParams.get('end'),b.searchParams.get('end'));assert.equal(b.searchParams.get('after'),'cursor');
});
test('old response cannot overwrite refreshed history',async()=>{
 let release;const ui=browser([()=>new Promise(r=>release=r),ok({state:'ok',rows:[],next:null})]);
 ui.get('history-filter').listeners.submit({preventDefault(){}});await settle();
 release({ok:true,json:async()=>({state:'ok',rows:[{rule:{id:'OLD'}}],next:'old'})});await settle();
 assert.equal(ui.get('history-rows').children.length,0);assert.equal(ui.get('history-next').hidden,true);
});
test('history failures expose no upstream payload and clear stale rows on refresh',async()=>{
 const ui=browser([ok({state:'ok',rows:[{}],next:'x'}),()=>({ok:false,json:async()=>({error:'SECRET'})})]);await settle();
 ui.get('history-filter').listeners.submit({preventDefault(){}});await settle();
 assert.equal(ui.get('history-rows').children.length,0);assert.equal(ui.get('history-next').hidden,true);assert.ok(!ui.get('history-state').textContent.includes('SECRET'));
});

const zero={input_events:0,matched:0,not_matched:0,unknown:0,excluded:0,late:0,policy_excluded:0,evaluated_events:0,detection_matches:0,alerts_created:0,alerts_existing:0};
const textOf=n=>n.textContent+n.children.map(textOf).join(' ');

test('all fourteen rule histories distinguish evaluated input, missing fields and absent sources',async()=>{
 const ids=['AUTH-001','AUTH-SEQ-001','AUTH-SPRAY-001','ATTACK-01','ATTACK-02','ATTACK-03','AWS-IAM-001',
  'AWS-AUDIT-001','AWS-NETWORK-001','OCI-IAM-001','WIN-AUTH-001','WEB-404-001','NET-PORT-001','AWS-CONSOLE-001'];
 const rows=ids.map((id,i)=>({rule:{id},run_id:'run-'+i,state:'committed',counts:{...zero,input_events:1},
  assessment:i%3===0?{state:'evaluated',reason:'bounded_observed_input'}:i%3===1?
   {state:'unverified',reason:'no_source_observations'}:{state:'not_evaluable',reason:'incomplete_or_excluded_input'}}));
 const ui=browser([ok({state:'ok',rows,next:null})]);await settle();
 assert.equal(ui.get('history-rows').children.length,14);
 const text=textOf(ui.get('history-rows'));
 assert.match(text,/관측 입력 평가 완료/);assert.match(text,/미검증/);assert.match(text,/평가 불가/);
 assert.match(text,/경보 0건은 공격 부재나 전체 실환경 검증 완료를 의미하지 않습니다/);
 assert.doesNotMatch(text,/undefined|NaN|Invalid Date/);
});

test('an empty committed run remains unverified when folded',async()=>{
 const ui=browser([ok({state:'ok',rows:[{run_id:'quiet',rule:{id:'AWS-CONSOLE-001'},state:'committed',counts:zero,
  assessment:{state:'unverified',reason:'no_source_observations'}}],next:null})]);await settle();
 assert.match(textOf(ui.get('history-rows')),/새 입력 없음 · 미검증/);
});
test('one run keeps its terminal outcome across raw records and seek page boundaries',async()=>{
 const base={run_id:'one',rule:{id:'AUTH-001'},counts:{...zero,input_events:5},'@timestamp':'2026-10-12T09:00:00Z'};
 const ui=browser([ok({state:'ok',rows:[{...base,state:'committed'},{...base,state:'evaluated'}],next:'next'}),ok({state:'ok',rows:[{...base,state:'evaluated'}],next:null})]);await settle();
 assert.equal(ui.get('history-rows').children.length,1);assert.match(textOf(ui.get('history-rows')),/실행 완료/);
 assert.doesNotMatch(textOf(ui.get('history-rows')),/최종 저장 미확인/);
 ui.get('history-next').listeners.click();await settle();assert.equal(ui.get('history-rows').children.length,1);
 assert.equal(new URL(ui.calls[0],'https://test').searchParams.get('view'),'summary');
});
test('empty successful executions fold, but failed pending and missing counters remain visible',async()=>{
 const ui=browser([ok({state:'ok',rows:[{run_id:'quiet',state:'committed',counts:zero},
  {run_id:'fail',state:'failed',counts:zero},{run_id:'pending',state:'evaluated',counts:zero},
  {run_id:'unknown',state:'committed',counts:{input_events:0}}],next:null})]);await settle();
 const rows=ui.get('history-rows');assert.equal(rows.children.length,4);
 const quiet=rows.children.find(n=>n.className==='history-idle panel');assert.ok(quiet);assert.notEqual(quiet.open,true);
 assert.match(textOf(quiet),/완료 실행 1회/);assert.match(textOf(rows),/실행 실패.*최종 저장 미확인.*미기록/);
 assert.doesNotMatch(textOf(rows),/undefined|NaN|Invalid Date/);
 assert.match(textOf(ui.get('history-pipeline')),/로그 해석: 실패.*위험 평가: 최근 실행 확인.*분석 실패/);
});
