const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
function run(line, server='apache', start='2026-10-14T00:00:00Z', fail=false) {
  const context=vm.createContext({});vm.runInContext(fs.readFileSync(path.join(__dirname,'../site-privacy.js'),'utf8'),context);
  context.register({id:'dvwa',name:'DVWA',server_type:server,start_at:start});
  const event={source:{message:line,labels:{log_source:'generic_web_access'},log:{offset:42,file:{path:'/var/log/apache2/access.log'}}},cancelled:false,
    Get(key){return key?key.split('.').reduce((v,k)=>v?.[k],this.source):this.source;},
    Put(key,value){let s=this.source;const p=key.split('.');for(const k of p.slice(0,-1))s=s[k]??={};s[p.at(-1)]=value;},
    Delete(key){if(fail)return false;let s=this.source;const p=key.split('.');for(const k of p.slice(0,-1)){s=s?.[k];if(!s)return false;}delete s[p.at(-1)];return true;},
    Cancel(){this.cancelled=true;}};
  context.process(event);return event;
}
const access='192.0.2.1 - PRIVATE_CANARY [14/Oct/2026:09:00:00 +0900] "POST /login?password=PRIVATE_CANARY HTTP/1.1" 401 22 "https://host/?token=PRIVATE_CANARY" "Cookie PRIVATE_CANARY"';
for(const server of ['apache','nginx','docker'])test(`metadata only before queue: ${server}`,()=>{
 const e=run(server==='docker'?JSON.stringify({log:access+'\n',stream:'stdout',Cookie:'PRIVATE_CANARY',body:'PRIVATE_CANARY'}):access,server);
 assert.equal(e.cancelled,false);assert.ok(!JSON.stringify(e.source).includes('PRIVATE_CANARY'));
 assert.equal(e.source.http.response.status_code,401);assert.equal(e.source.source.ip,'192.0.2.1');
 assert.equal(e.source.web.occurred_at,'2026-10-14T00:00:00.000Z');assert.equal(e.source.log.offset,42);
});
test('start boundary is inclusive and immutable on process restart',()=>{
 assert.equal(run(access,'apache','2026-10-14T00:00:00Z').cancelled,false);
 assert.equal(run(access,'apache','2026-10-14T00:00:00.001Z').cancelled,true);
});
test('unknown formats, times, bodies, oversized lines and parser failures are withheld',()=>{
 for(const line of ['PRIVATE_CANARY','x'.repeat(8193),access.replace('14/Oct','31/Feb'),access.replace('401','999'),access+' PRIVATE_CANARY'])assert.equal(run(line).cancelled,true);
 assert.equal(run('{"body":"PRIVATE_CANARY"}','docker').cancelled,true);
 assert.equal(run(access,'apache',undefined,true).cancelled,true);
});
test('hostnames and forwarded headers are not invented as source IP',()=>{
 const e=run(access.replace('192.0.2.1','proxy.local'));assert.equal(e.cancelled,false);assert.equal(e.source.source,undefined);
});
