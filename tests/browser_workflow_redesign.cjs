// All telemetry and device responses here are synthetic; production is never contacted.
const {chromium}=require('playwright'),assert=require('node:assert/strict');
(async()=>{
 const b=await chromium.launch({executablePath:'/opt/google/chrome/chrome',headless:true});const c=await b.newContext({httpCredentials:{username:'admin',password:'fixture-password'},viewport:{width:1536,height:1100}});const p=await c.newPage(),errors=[],cloudCalls=[],deviceCalls=[];p.on('pageerror',e=>errors.push(e.message));
 const stamp=new Date().toISOString(),num=Date.now();let cloudFail=false;
 await p.route('**/api/multicloud?*',r=>{
  cloudCalls.push(r.request().url());if(cloudFail)return r.fulfill({status:503,contentType:'application/json',body:'{"error":"합성 조회 실패"}'});
  const q=new URL(r.request().url()).searchParams,provider=q.get('provider')||'aws';
  const event={'@timestamp':stamp,cloud:{provider,account:{id:'fixture-account'}},organization:{id:'본사'},event:{action:'DescribeInstances',dataset:provider+'.audit',outcome:'success'},user:{id:'fixture-user'}};
  const metrics={providers:{buckets:[{key:provider,doc_count:12,failures:{doc_count:1},last_event:{value_as_string:stamp}}]},timeline:{buckets:Array.from({length:12},(_,i)=>({key:num-(11-i)*3600000,key_as_string:new Date(num-(11-i)*3600000).toISOString(),doc_count:i+1}))},actions:{buckets:[{key:'DescribeInstances',doc_count:8},{key:'ConsoleLogin',doc_count:4}]}};
  return r.fulfill({status:200,contentType:'application/json',body:JSON.stringify({total:12,events:[event],metrics})});
 });
 await p.goto('http://127.0.0.1:18765/multicloud');await p.locator('#events tr').waitFor();assert.equal(await p.locator('.card').count(),3);assert.equal(await p.locator('#timeline svg rect').count(),12);
 await p.selectOption('#provider','aws');await p.waitForTimeout(100);assert.equal(new URL(cloudCalls.at(-1)).searchParams.get('provider'),'aws');
 await p.selectOption('#outcome','failure');await p.waitForTimeout(100);assert.equal(new URL(cloudCalls.at(-1)).searchParams.get('outcome'),'failure');
 await p.screenshot({path:'output/multicloud-reference-color.png',fullPage:true});cloudFail=true;await p.click('#refresh');await p.waitForFunction(()=>document.querySelector('#updated').textContent.includes('갱신 실패'));assert.equal(await p.locator('#events tr').count(),1);
 await p.goto('http://127.0.0.1:18765/cases.html');await p.locator('#case-metrics article').first().waitFor();assert.equal(await p.locator('#case-metrics article').count(),4);await p.locator('#case-rows a').first().waitFor();assert.match(await p.locator('#case-rows a').first().getAttribute('href'),/workbench.html\?case=/);
 await p.selectOption('#case-filters select[name="priority"]','high');const cr=p.waitForResponse(r=>r.url().includes('/api/cases?')&&r.url().includes('priority=high'));await p.locator('#case-filters button').click();assert.equal((await cr).status(),200);await p.screenshot({path:'output/cases-reference-color.png',fullPage:true});
 const device={id:'a'.repeat(32),label:'합성 웹 서버',organization:'본사',os:'ubuntu',purpose:'server',state:'received',receipt_at:stamp,keys:[],key_extensions:[],registration:{state:'complete'},key_extension_allowed:false};
 await p.route('**/api/managed-devices**',r=>{deviceCalls.push(r.request().method());if(r.request().method()!=='GET')throw Error('Unexpected device mutation');const u=new URL(r.request().url());return r.fulfill({status:200,contentType:'application/json',body:JSON.stringify(u.pathname.endsWith('/'+device.id)?{device}:{devices:[device],total:1,enrollment_enabled:true})});});
 await p.route('**/api/key-history?*',r=>r.fulfill({status:200,contentType:'application/json',body:JSON.stringify({keys:[],total:0})}));
 await p.goto('http://127.0.0.1:18765/devices.html');await p.locator('#device-rows button').waitFor();assert.equal(await p.locator('#device-metrics article').count(),4);assert.match(await p.locator('#device-metrics').innerText(),/현재 페이지/);
 await p.locator('#device-rows button').click();await p.locator('#device-detail[open]').waitFor();assert.match(await p.locator('#device-detail').innerText(),/합성 웹 서버/);await p.locator('#device-detail footer button').click();
 await p.screenshot({path:'output/devices-reference-color.png',fullPage:true});
 for(const path of ['multicloud','cases.html','devices.html']){await p.goto('http://127.0.0.1:18765/'+path);await p.setViewportSize({width:390,height:844});await p.waitForTimeout(150);assert.ok(await p.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),path+' horizontal overflow');}
 assert.ok(deviceCalls.every(x=>x==='GET'));assert.equal(errors.length,0,errors.join('\n'));await b.close();console.log('PASS: cloud filters/chart/failure retention, case metrics/filter/detail links, device metrics/detail, mobile; no lifecycle writes');
})().catch(e=>{console.error(e);process.exit(1)});
