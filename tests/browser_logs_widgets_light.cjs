// Synthetic local preview only. Never uses production telemetry or credentials.
const {chromium}=require('playwright'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({executablePath:'/opt/google/chrome/chrome',headless:true});
 const context=await browser.newContext({httpCredentials:{username:'admin',password:'fixture-password'},viewport:{width:1536,height:1100}});
 const p=await context.newPage(),errors=[],queries=[];p.on('pageerror',e=>errors.push(e.message));
 const stamp=new Date().toISOString();
 const rows=[['linux_file','Ubuntu 인증 로그','auth-gateway','login'],['generic_web_access','웹 접근 로그','web-service','GET /login'],['network_packetbeat','네트워크 흐름','network-sensor','connection'],['aws_cloudtrail','AWS 관리 API','cloud-account','DescribeInstances']].map(([source_kind,label,host,action],i)=>({reference:{index:'fixture-logs',id:String(i)},source_kind,log_type:{label},host_name:host,action,received_at:stamp,event_at:stamp,os:i===0?'linux':'unknown',source_ip:'192.0.2.'+(i+1),outcome:i===0?'failure':'success',stream:i===3?'cloud':'host',cloud_provider:i===3?'aws':null,parse_status:'recognized'}));
 await p.route('**/api/logs?*',r=>{queries.push(r.request().url());const q=new URL(r.request().url()).searchParams;return r.fulfill({json:{contract_version:1,raw_access:'restricted',rows:q.get('host')?[rows[0]]:rows,next_cursor:null,filters:{time_basis:q.get('time_basis')||'ingested',start:new Date(Date.now()-3600000).toISOString(),end:stamp}}});});
 await p.route('**/api/logs/detail?*',r=>r.fulfill({json:{contract_version:1,raw_access:'restricted',row:rows[0]}}));
 await p.route('**/api/logs/updates?*',r=>r.fulfill({json:{rows:[],contract_version:1,raw_access:'restricted',next_cursor:null,filters:{time_basis:'ingested',start:new Date(Date.now()-3600000).toISOString(),end:stamp}}}));
 await p.route('**/api/operations/status',r=>r.fulfill({json:{coverage:{state:'observed'},realtime_coverage:{state:'observed'}}}));
 await p.route('**/api/operations?*',r=>{const section={state:'ok',count:21,buckets:Array.from({length:12},(_,i)=>({time:new Date(Date.now()-(11-i)*300000).toISOString(),count:i%5})),rows:[],statuses:[]};return r.fulfill({json:{start:new Date(Date.now()-3600000).toISOString(),end:stamp,sections:{intake:section,alerts:section,processing:section,pipeline:{state:'success',coverage:{state:'observed'}}}}});});
 await p.goto('http://127.0.0.1:18765/logs.html');await p.waitForFunction(()=>document.querySelector('#log-state-label').textContent==='조회 완료');
 assert.equal(await p.locator('#log-rows tr').count(),4);await p.screenshot({path:'output/logs-light.png',fullPage:true});
 await p.fill('#log-host','auth-gateway');await p.click('#log-apply');await p.waitForFunction(()=>document.querySelectorAll('#log-rows tr').length===1);assert.equal(new URL(queries.at(-1)).searchParams.get('host'),'auth-gateway');
 await p.locator('#log-rows button').first().click();await p.waitForFunction(()=>document.querySelector('#log-detail-state').textContent.includes('조회 완료'));await p.screenshot({path:'output/logs-detail-light.png'});await p.click('#log-detail-close');
 await p.goto('http://127.0.0.1:18765/dashboard.html');await p.waitForFunction(()=>document.querySelector('#dashboard-updated').textContent.includes('조회 완료'));
 assert.ok(await p.locator('.builder-widget').count()>0);await p.screenshot({path:'output/widgets-light.png',fullPage:true});
 // Editing creates a copy only in the temporary fixture database.
 await p.click('#dashboard-edit');await p.locator('#dashboard-editor').waitFor();await p.fill('#dashboard-name','밝은 위젯 검증');await p.click('#dashboard-save');await p.waitForFunction(()=>document.querySelector('#dashboard-title').textContent==='밝은 위젯 검증'&&document.querySelector('#dashboard-editor').hidden);
 await p.reload();await p.waitForFunction(()=>document.querySelector('#dashboard-updated').textContent.includes('조회 완료'));assert.equal(await p.locator('#dashboard-title').innerText(),'밝은 위젯 검증');
 await p.click('#dashboard-edit');await p.fill('#dashboard-name','취소할 변경');await p.click('#dashboard-cancel');assert.equal(await p.locator('#dashboard-title').innerText(),'밝은 위젯 검증');
 for(const page of ['logs.html','dashboard.html'])for(const width of [768,390]){
  await p.setViewportSize({width,height:900});await p.goto('http://127.0.0.1:18765/'+page);await p.waitForTimeout(300);
  assert.ok(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),page+' overflow '+width);
  await p.evaluate(()=>window.CloudSOCTheme.set('dark'));assert.equal(await p.locator('body').evaluate(e=>getComputedStyle(e).getPropertyValue('--ui-panel').trim()),'#fff');
 }
 assert.equal(errors.length,0,errors.join('\n'));await browser.close();console.log('PASS logs filter/detail, widget save/reload/cancel, bright palette and mobile; temporary data only');
})().catch(e=>{console.error(e);process.exit(1)});
