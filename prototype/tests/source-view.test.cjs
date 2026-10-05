const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const script=fs.readFileSync(path.join(__dirname,'../source-view.js'),'utf8');
const ref={index:'soc-host-raw-test',id:'fixture'};
const result={contract_version:1,policy_version:'protected-fields-v1',raw_access:'protected_fields',complete_source:false,
  audit_id:'1',reference:ref,source:{host:{name:'<img src=x onerror=CANARY>'}}};
const ok=body=>({ok:true,json:async()=>body});
const capability=ok({policy_version:'protected-fields-v1',protected_source:true});
const settle=()=>new Promise(r=>setImmediate(r));
function browser(responses){
 const elements=new Map(),calls=[],events={};
 const get=id=>{if(!elements.has(id))elements.set(id,{hidden:false,disabled:false,open:true,value:'investigation',textContent:'',innerHTML:'',listeners:{},addEventListener(n,fn){this.listeners[n]=fn;}});return elements.get(id);};
 const context={document:{getElementById:get},window:{addEventListener:(n,fn)=>{events[n]=fn;}},AbortController,TypeError,JSON,
  setTimeout:()=>1,clearTimeout:()=>{},fetch:async(url,options)=>{calls.push({url,options});const r=responses.shift();return typeof r==='function'?r():r;}};
 vm.runInNewContext(script,context);return{get,calls,events,source:context.window.cloudSocSource};
}
test('source is explicit audited POST and literal text with no persistence',async()=>{
 const ui=browser([capability,ok(result)]);await ui.source.open(ref);
 assert.equal(ui.calls.length,1);assert.equal(ui.get('source-panel').hidden,false);
 ui.get('source-purpose').value='receipt_validation';await ui.get('source-read').listeners.click();
 const call=ui.calls[1];assert.equal(call.url,'/api/logs/source');assert.equal(call.options.method,'POST');assert.equal(call.options.cache,'no-store');
 assert.equal(call.options.headers['X-Cloud-SOC'],'portal');assert.deepEqual(JSON.parse(call.options.body),{...ref,purpose:'receipt_validation'});
 assert.match(ui.get('source-json').textContent,/<img src=x/);assert.equal(ui.get('source-json').innerHTML,'');assert.match(ui.get('source-state').textContent,/접근 감사 1/);
 ui.events.pagehide();assert.equal(ui.get('source-json').textContent,'');assert.equal(ui.get('source-panel').hidden,true);
});
test('viewer or disabled capabilities never expose the source action',async()=>{
 for(const response of [ok({policy_version:'protected-fields-v1',protected_source:false}),{ok:false,status:403}]){
  const ui=browser([response]);await ui.source.open(ref);assert.equal(ui.get('source-panel').hidden,true);
  await ui.get('source-read').listeners.click();assert.equal(ui.calls.length,1);
 }
});
test('closing details cancels requests and late results cannot restore a source',async()=>{
 let release;const ui=browser([capability,()=>new Promise(r=>{release=r;})]);await ui.source.open(ref);
 const pending=ui.get('source-read').listeners.click();ui.source.close();assert.equal(ui.calls[1].options.signal.aborted,true);
 release(ok(result));await pending;assert.equal(ui.get('source-json').textContent,'');assert.equal(ui.get('source-panel').hidden,true);
});
test('foreign references, unrestricted sources and missing audit IDs are rejected',async()=>{
 for(const bad of [{...result,reference:{...ref,id:'foreign'}},{...result,complete_source:true},{...result,audit_id:null},{...result,raw_access:'full'}]){
  const ui=browser([capability,ok(bad)]);await ui.source.open(ref);await ui.get('source-read').listeners.click();
  assert.equal(ui.get('source-json').hidden,true);assert.equal(ui.get('source-json').textContent,'');assert.match(ui.get('source-state').textContent,/응답을 확인/);
 }
});
test('failed responses and malformed JSON never display upstream secret text',async()=>{
 for(const failure of [{ok:false,status:503,json:async()=>({error:'PRIVATE_CANARY'})},
   {ok:true,json:async()=>{throw new SyntaxError('PRIVATE_CANARY');}}]){
  const ui=browser([capability,ok(result),failure]);await ui.source.open(ref);await ui.get('source-read').listeners.click();
  await ui.get('source-read').listeners.click();assert.equal(ui.get('source-json').textContent,'');assert.equal(ui.get('source-json').hidden,true);
  assert.ok(!ui.get('source-state').textContent.includes('PRIVATE_CANARY'));assert.equal(ui.get('source-read').disabled,false);
 }
});
