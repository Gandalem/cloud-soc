const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), vm = require('node:vm');
const script = fs.readFileSync(require('node:path').join(__dirname,'../detection-history.js'),'utf8');
const settle = () => new Promise(r=>setImmediate(r));
function browser(responses) {
 const elements=new Map(), calls=[];
 const make=()=>({textContent:'',value:'',children:[],listeners:{},append(...v){this.children.push(...v)},replaceChildren(...v){this.children=v},addEventListener(n,f){this.listeners[n]=f}});
 const get=id=>{if(!elements.has(id))elements.set(id,make());return elements.get(id)};
 get('history-kind').value='runs';
 vm.runInNewContext(script,{document:{getElementById:get,createElement:make},Date,URLSearchParams,fetch:async url=>{calls.push(url);return responses.shift()()}});
 return {get,calls};
}
const ok=data=>()=>({ok:true,json:async()=>data});
test('history keeps time bounds across seek pages and renders text only',async()=>{
 const ui=browser([ok({state:'ok',rows:[{rule:{id:'<img src=x>'},state:'committed'}],next:'cursor'}),ok({state:'ok',rows:[],next:null})]);await settle();
 assert.equal(ui.get('history-rows').children[0].children[0].textContent,'<img src=x> · 처리 완료 · 처리 위치 저장됨');
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
