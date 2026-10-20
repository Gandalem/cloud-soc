const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
function scope(fetch=async()=>({ok:true,json:async()=>({rows:[]})})){
 const context={window:{},URLSearchParams,fetch,AbortController,console,document:{createElement(){return {children:[],append(...v){this.children.push(...v);},setAttribute(){},addEventListener(){}};}}};
 vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../dashboard-widgets.js'),'utf8'),context);return context.window.CloudSOCWidgets;
}
const config={period:0,severity:'all',limit:8,sort:'newest',chart:'line',title:'경보',color:'blue'};
test('historical alerts are explicitly labelled without changing their title or identity',()=>{
 const w=scope(),row={title:'웹 경보',rule:'WEB-404-001',id:'immutable'};
 assert.equal(w.alertTitle(row),'웹 경보');
 assert.equal(w.alertTitle({...row,historical_review:true}),'과거 로그 재평가 · 웹 경보');
 assert.equal(w.alertTitle({...row,historical_review:'PRIVATE_CANARY'}),'웹 경보');
 assert.equal(row.id,'immutable');
});
test('24 duplicate widgets share one dataset per source and period',()=>{
 const w=scope(),layout={period:1440,widgets:Array.from({length:24},(_,i)=>({id:String(i),type:'trend',config}))};
 assert.deepEqual(Array.from(w.plan(layout,[{type:'trend',enabled:true,source:'operations'}])),['status','operations:1440']);
 layout.widgets[0].config={...config,period:60};layout.widgets[1].config={...config,period:10080};
 assert.equal(w.plan(layout,[{type:'trend',enabled:true,source:'operations'}]).length,4);
 assert.equal(w.plan(layout,[{type:'trend',enabled:false,source:'operations'}]).length,1);
});
test('data provider resolves current-state and time-window APIs, with bounded concurrency',async()=>{
 const paths=[];let active=0,peak=0;
 const w=scope(async path=>{paths.push(path);active++;peak=Math.max(peak,active);await new Promise(r=>setTimeout(r,3));active--;return {ok:true,json:async()=>({rows:[]})};});
 const results=await w.load(['status','cases','agents','operations:60','logs:1440'],new AbortController().signal,Date.parse('2026-10-13T00:00:00Z'));
 assert.equal(Object.keys(results).length,5);assert.ok(peak<=3);
 assert.ok(paths.includes('/api/operations/status'));assert.ok(paths.includes('/api/agents/status'));
 assert.match(paths.find(p=>p.startsWith('/api/logs?')),/page_size=50/);
 const query=new URLSearchParams(paths.find(p=>p.startsWith('/api/operations?')).split('?')[1]);
 assert.equal(Date.parse(query.get('end'))-Date.parse(query.get('start')),3600000);
});
test('403 and 503 are failures; valid zero is still a successful body',async()=>{
 const w=scope(async path=>path.startsWith('/api/operations/status')?{ok:false,status:403,json:async()=>({error:'권한'})}:path.startsWith('/api/cases')?{ok:false,status:503,json:async()=>({error:'연결'})}:{ok:true,json:async()=>({count:0})});
 const result=await w.load(['status','cases','operations:60'],new AbortController().signal);
 assert.equal(result.status.status,403);assert.equal(result.cases.status,503);assert.equal(result['operations:60'].body.count,0);
});
test('aborted provider does not schedule more datasets',async()=>{
 let calls=0;const stop=new AbortController(),w=scope(async()=>{calls++;stop.abort();return {ok:true,json:async()=>({})};});
 await w.load(['status','cases','agents','operations:60','logs:60'],stop.signal);assert.equal(calls,1);
});
test('grid placement rejects overlap and bounds but supports independent instances and gaps',()=>{
 const w=scope(),widgets=[{id:'a',x:0,y:0,w:6,h:3},{id:'b',x:6,y:0,w:6,h:3}];
 assert.equal(w.place(widgets,'a',{x:6}),null);assert.equal(w.place(widgets,'a',{x:8}),null);
 assert.equal(w.place(widgets,'a',{w:13}),null);assert.equal(w.place(widgets,'a',{y:-1}),null);
 const moved=w.place(widgets,'a',{y:4,x:3});assert.equal(moved.find(r=>r.id==='a').y,4);assert.equal(widgets[0].y,0);
 w.compact(widgets);assert.equal(widgets[0].x,0);assert.equal(widgets[1].x,6);
});
test('cloud and severity filters use only explicit observed metadata',()=>{
 const w=scope(),rows=[{severity:'high',rule:'AWS-001',timestamp:'2026-10-13T00:00:00Z'},{severity:'low',rule:'AUTH-001',timestamp:'2026-10-12T00:00:00Z'}];
 assert.equal(w.filteredAlerts(rows,{type:'high-alerts',config}).length,1);
 assert.equal(w.filteredAlerts(rows,{type:'cloud-alerts',config}).length,1);
 const logs=[{source_kind:'aws_cloudtrail',cloud_provider:'aws',action:'StopLogging'},{source_kind:'linux_file',action:'StopLogging'}];
 assert.equal(w.filteredLogs(logs,'cloud-audit').length,1);assert.equal(w.filteredLogs(logs,'cloud-iam').length,0);
});
test('unavailable catalog widget displays its reason and never fabricates telemetry',()=>{
 const w=scope(),box={children:[],append(...v){this.children.push(...v);}};
 w.render(box,{config},{enabled:false,reason:'위치 데이터 미지원'},{});
 assert.equal(box.children[0].textContent,'위치 데이터 미지원');
 assert.equal(w.number(0),true);assert.equal(w.number(null),false);assert.equal(w.number(-1),false);
});
test('missing log index remains distinct from an actual zero result',()=>{
 const w=scope(),meta={enabled:true,source:'logs',renderer:'logs'},widget={type:'host-events',config};
 const box={children:[],append(...v){this.children.push(...v);}};
 w.render(box,widget,meta,{body:{data_state:'no_index',rows:[]}},{period:1440});
 assert.ok(box.children.some(e=>/데이터 미수집/.test(e.textContent)));
 assert.ok(!box.children.some(e=>/0건/.test(e.textContent)));
});
test('personal builder keeps settings out of browser storage and uses safe text rendering',()=>{
 for(const file of ['dashboard-builder.js','dashboard-widgets.js'])assert.doesNotMatch(fs.readFileSync(path.join(__dirname,'..',file),'utf8'),/innerHTML|localStorage|eval\(/);
 const js=fs.readFileSync(path.join(__dirname,'../dashboard-builder.js'),'utf8');assert.match(js,/CloudSOCLive.create/);assert.match(js,/enabled:/);assert.match(js,/revision:collection.revision/);
});
