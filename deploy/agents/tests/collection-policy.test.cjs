const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const catalogue=JSON.parse(fs.readFileSync(path.join(__dirname,'../security-catalog.json'),'utf8'));
function event(source){return {source,cancelled:false,Get(p){return p?p.split('.').reduce((v,k)=>v?.[k],this.source):this.source;},Put(p,v){const keys=p.split('.');let at=this.source;for(const k of keys.slice(0,-1))at=at[k]??={};at[keys.at(-1)]=v;},Delete(p){const keys=p.split('.');let at=this.source;for(const k of keys.slice(0,-1))at=at?.[k];if(at)delete at[keys.at(-1)];return true;},Cancel(){this.cancelled=true;}};}
function web(value){const ctx=vm.createContext({});vm.runInContext(fs.readFileSync(path.join(__dirname,'../site-privacy.js'),'utf8'),ctx);ctx.register({id:'site-one',name:'One',server_type:'nginx',start_at:'2026-10-01T00:00:00Z'});const e=event({message:typeof value==='string'?value:JSON.stringify(value)});ctx.process(e);return e;}
const checked={schema:'cloud-soc-web-security-v1',timestamp:'2026-10-20T12:00:00Z',request_id:'request-one',source_ip:'192.0.2.1',method:'GET',status:200,route_kind:'static',has_query:false,security_checked:true,security_matched:false};
test('only positively classified normal requests are excluded; attack and missing context win',()=>{
 assert.equal(web(checked).cancelled,true);
 for(const change of [{security_matched:true},{security_checked:false},{has_query:true},{method:'POST'},{status:403},{status:500},{route_kind:'sensitive'},{route_kind:'other'}]){
  const e=web({...checked,...change});assert.equal(e.cancelled,false);assert.equal(e.source.labels.collection_policy,'security-focused-v1');assert.equal(e.source.http.request.id,'request-one');assert.equal(e.source.message,undefined);
 }
 const e=web('192.0.2.1 - - [20/Oct/2026:12:00:00 +0000] "GET /images/image.png HTTP/1.1" 200 12');
 assert.equal(e.cancelled,false);assert.equal(e.source.labels.collection_status,'retained_missing_security_context');
});
test('event selection keeps important successful events without relying on level',()=>{
 const source=fs.readFileSync(path.join(__dirname,'../discover-windows.ps1'),'utf8');
 const filter=source.match(/\$filter = "([^"\r\n]+)"/)[1];const ctx=vm.createContext({});vm.runInContext(filter,ctx);ctx.register({ids:catalogue.windows_channels.Security,noise:catalogue.windows_noise.Security});
 for(const code of [4624,4625,1102,4719]){const e=event({winlog:{event_id:code},log:{level:'information'}});ctx.process(e);assert.equal(e.cancelled,false);}
 const noise=event({winlog:{event_id:5156}});ctx.process(noise);assert.equal(noise.cancelled,true);
 const unfamiliar=event({winlog:{event_id:9999}});ctx.process(unfamiliar);assert.equal(unfamiliar.cancelled,false);
 const missing=event({winlog:{}});ctx.process(missing);assert.equal(missing.cancelled,false);
});
test('visible log types are escaped and source uncertainty stays explicit',()=>{
 const {rowMarkup}=require('../../../prototype/logs.js');
 const html=rowMarkup({reference:{index:'soc-host-raw-one',id:'one'},source_kind:'linux_file',log_type:{label:'<img src=x onerror=evil()>'}},0);
 assert.ok(html.includes('&lt;img'));assert.ok(!html.includes('<img'));
 assert.ok(rowMarkup({reference:{index:'soc-host-raw-one',id:'two'}},1).includes('종류 미확인'));
});
