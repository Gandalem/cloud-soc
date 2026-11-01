// Local fixture acceptance only; no production access or writes.
const {chromium}=require('playwright'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({executablePath:'/opt/google/chrome/chrome',headless:true});
 const context=await browser.newContext({httpCredentials:{username:'admin',password:'fixture-password'},viewport:{width:1536,height:1100}});
 await context.addInitScript(()=>localStorage.setItem('cloud-soc.theme','dark'));
 const page=await context.newPage(),errors=[],requests=[];page.on('pageerror',e=>errors.push(e.message));
 const now=new Date(),checkpoint=new Date(now-3600000).toISOString(),stamp=now.toISOString();
 const worker={state:'success',health:'healthy',last_success:stamp,checkpoint,lag_seconds:39,excluded_total:0};let fail=false;
 await page.route('**/api/operations?*',route=>{
  requests.push(route.request().url());if(fail)return route.fulfill({status:503,body:'{}',contentType:'application/json'});
  const q=new URL(route.request().url()).searchParams,start=q.get('start'),end=q.get('end');
  const buckets=Array.from({length:12},(_,i)=>({time:new Date(Date.parse(start)+(Date.parse(end)-Date.parse(start))*i/12).toISOString(),count:10+i*3}));
  const sec=count=>({state:'ok',count,rows:[],statuses:[],buckets});
  const alert={id:'fixture-alert',timestamp:stamp,risk_level:'high',rule:'AUTH-001',title:'반복된 인증 실패',service:'SSH',organization:'본사',status:'stored',event_count:15};
  const data={start,end,sections:{intake:sec(12480),processing:{...sec(12000),statuses:[{key:'normalized',doc_count:12000}]},quality:sec(25),alerts:{...sec(17),rows:[alert]},pipeline:{...worker,coverage:{state:'delayed',reason:'detector_delayed'},detector:{...worker,health:'delayed',lag_seconds:364584},priority_normalizer:worker,priority_detector:{...worker,health:'delayed',lag_seconds:296484},additional_detector:{...worker,health:'delayed',lag_seconds:307885,excluded_total:40945},late_review:{...worker,health:'warning',lag_seconds:301000,excluded_total:27470},rules:[]}}};
  return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(data)});
 });
 await page.route('**/api/alerts/detail?*',route=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({alert:{id:'fixture-alert',title:'반복된 인증 실패',rule:'AUTH-001'},condition:{event_count:15},evidence_count:0,evidence_limit:0,rule_version:'fixture-v1'})}));
 await page.goto('http://127.0.0.1:18765/operations.html');await page.locator('.ops-stage').first().waitFor();
 assert.equal(await page.locator('.ops-stage').count(),7);
 const det=page.locator('[data-worker="detector"]');assert.match(await det.innerText(),/처리 성공/);assert.match(await det.innerText(),/지연 있음/);assert.match(await det.innerText(),/364,584초/);
 assert.match(await page.locator('[data-worker="multicloud_normalizer"]').innerText(),/실행 기록 없음/);
 assert.equal(await page.locator('#ops-intake-chart svg rect').count(),12);
 await page.screenshot({path:'output/operations-redesign-dark.png',fullPage:true});
 await page.getByRole('button',{name:'상세 / 근거',exact:true}).click();await page.locator('#ops-detail a').first().waitFor();
 assert.match(await page.locator('#ops-detail').innerText(),/근거 로그가 없습니다/);assert.match(await page.locator('#ops-detail a').first().getAttribute('href'),/workbench.html\?alert=fixture-alert/);
 await page.getByRole('button',{name:'닫기',exact:true}).click();await page.locator('#ops-period').selectOption('10080');
 const opResponse=page.waitForResponse(r=>r.url().includes('/api/operations?'));await page.locator('#ops-filter button').click();await opResponse;
 const q=new URL(requests.at(-1)).searchParams;assert.equal(Date.parse(q.get('end'))-Date.parse(q.get('start')),7*86400000);
 await page.locator('#case-filters select[name="priority"]').selectOption('high');const cr=page.waitForResponse(r=>r.url().includes('/api/cases?')&&r.url().includes('priority=high'));await page.locator('#case-filters button').click();assert.equal((await cr).status(),200);
 await page.evaluate(()=>window.CloudSOCTheme.set('light'));await page.screenshot({path:'output/operations-redesign-light.png',fullPage:true});
 await page.evaluate(()=>window.CloudSOCTheme.set('dark'));await page.setViewportSize({width:390,height:844});
 assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));await page.evaluate(()=>{document.activeElement?.blur();window.scrollTo(0,0)});await page.screenshot({path:'output/operations-redesign-mobile.png',fullPage:true});
 fail=true;await page.locator('#ops-filter button').click();await page.locator('#ops-error').waitFor({state:'visible'});assert.equal(await page.locator('.ops-stage').count(),7);assert.match(await page.locator('#ops-error').innerText(),/503/);
 assert.equal(errors.length,0,errors.join('\n'));await browser.close();console.log('PASS: stage state/lag, missing worker, charts, detail, period/case filters, themes, mobile, failure retention');
})().catch(e=>{console.error(e);process.exit(1)});
