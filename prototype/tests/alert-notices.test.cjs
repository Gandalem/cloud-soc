const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
function node(tag){return {tag,children:[],dataset:{},append(...v){this.children.push(...v);},replaceChildren(...v){this.children=v;},setAttribute(){},addEventListener(){}};}
function scope(fetch=async()=>({ok:true,json:async()=>({rows:[]})})){
 const context={window:{},URLSearchParams,fetch,AbortController,console,document:{getElementById(){return null;},createElement:node}};
 vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../alert-notices.js'),'utf8'),context);
 vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../dashboard-widgets.js'),'utf8'),context);return context.window;
}
const text=e=>(e.textContent||'')+e.children.map(text).join(' ');
const row={id:'a'.repeat(64),title:'<img src=x onerror=alert(1)>',source_ip:'192.0.2.1',effective_state:'verifying',observed_count:10,window_seconds:300,evidence_count:10};
test('one card per logical notice and state changes preserve identity',()=>{
 const w=scope(),box=node('div');w.CloudSOCNotices.render(box,{body:{state:'ok',rows:[row]}});
 assert.equal(box.children[0].children.length,1);assert.equal(box.children[0].children[0].dataset.notice,row.id);
 assert.match(text(box),/근거 검증 중/);assert.match(text(box),/합산해 공격 횟수로 표시하지 않습니다/);
 w.CloudSOCNotices.render(box,{body:{state:'ok',rows:[{...row,effective_state:'confirmed',final_alert_id:'b'.repeat(64)}]}});
 assert.equal(box.children[0].children.length,1);assert.match(text(box),/근거 확정/);assert.match(text(box),/최종 경보 조사/);
});
test('unconfigured, actual zero, failures and unavailable permission remain distinct',()=>{
 const w=scope(),box=node('div');
 for(const [result,message]of [[{body:{state:'not_configured'}},/아직 설정되지/],[{body:{state:'ok',rows:[]}},/0건/],[{status:403},/권한이 없습니다/],[{status:503},/조회 실패/],[{loading:true},/조회 중/]]){
  w.CloudSOCNotices.render(box,result);assert.match(text(box),message);
 }
});
test('duplicates and oversized response fail closed; titles render as text',()=>{
 const w=scope(),box=node('div');w.CloudSOCNotices.render(box,{body:{state:'ok',rows:[row,row]}});assert.match(text(box),/응답 형식/);
 w.CloudSOCNotices.render(box,{body:{state:'ok',rows:Array(51).fill(row)}});assert.match(text(box),/응답 형식/);
 w.CloudSOCNotices.render(box,{body:{state:'ok',rows:[row]}});assert.match(text(box),/<img/);assert.equal(box.children[0].children[0].children[0].children[0].tag,'strong');
});
test('24 notice widgets share one bounded query per period and configured display limit',async()=>{
 const paths=[],w=scope(async url=>{paths.push(url);return {ok:true,json:async()=>({rows:[]})};}),config={period:0,limit:5,sort:'newest'};
 const layout={period:1440,widgets:Array.from({length:24},()=>({type:'early-notices',config}))},catalog=[{type:'early-notices',source:'notices',renderer:'notices',enabled:true}];
 assert.equal(w.CloudSOCWidgets.plan(layout,catalog).length,2);
 await w.CloudSOCWidgets.load(w.CloudSOCWidgets.plan(layout,catalog),new AbortController().signal);
 assert.equal(paths.filter(p=>p.startsWith('/api/alerts/notices?')).length,1);
 const box=node('div');w.CloudSOCWidgets.render(box,{config},catalog[0],{body:{state:'ok',rows:Array.from({length:10},(_,i)=>({...row,id:String(i).padStart(64,'0'),initial_at:new Date(i*1000).toISOString()}))}});
 assert.equal(box.children[0].children.length,5);assert.equal(box.children[0].children[0].dataset.notice,'9'.padStart(64,'0'));
});
test('display uses safe DOM, latest response guards and separate ten-second refresh',()=>{
 const js=fs.readFileSync(path.join(__dirname,'../alert-notices.js'),'utf8');assert.doesNotMatch(js,/innerHTML|localStorage|eval\(/);
 assert.match(js,/currentEvidence!==evidenceGeneration/);assert.match(js,/!forbidden/);assert.match(js,/setTimeout\(refresh,10000\)/);
 const builder=fs.readFileSync(path.join(__dirname,'../dashboard-builder.js'),'utf8');assert.match(builder,/CloudSOCLive.create/);const live=fs.readFileSync(path.join(__dirname,'../live-refresh.js'),'utf8');assert.match(live,/ticket!==serial/);
});
test('null and malformed rows fail closed without a rendering exception',()=>{
 const w=scope(),box=node('div');for(const r of [null,1,{}, {...row,effective_state:'__proto__'}, {...row,observed_count:'10'}]){
  assert.doesNotThrow(()=>w.CloudSOCNotices.render(box,{body:{state:'ok',rows:[r]}}));assert.match(text(box),/응답 형식/);
 }
});
