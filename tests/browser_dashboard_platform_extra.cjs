async (page) => {
  const base='http://127.0.0.1:8773',errors=[],checks=[];
  page.on('pageerror',error=>errors.push(error.message));
  async function settled(){await page.waitForLoadState('networkidle');await page.locator('#dashboard-updated').filter({hasText:/조회 완료|데이터 조회 실패/}).waitFor();}
  async function state(){return (await page.request.get(base+'/api/dashboards')).json();}
  await page.setViewportSize({width:1440,height:1000});await page.goto(base+'/dashboard.html');await settled();
  await page.evaluate(()=>window.CloudSOCTheme.set('light'));
  await page.locator('#dashboard-create').click();await page.locator('#dialog-template').selectOption('empty');await page.locator('#dialog-name').fill('핸들 조작 검증');await page.locator('#dialog-submit').click();await page.locator('#dashboard-dialog').waitFor({state:'hidden'});await settled();
  const id=new URL(page.url()).searchParams.get('dashboard');await page.locator('#dashboard-edit').click();
  for(const name of ['경보 추이','로그 수신 추이']){await page.locator('#widget-search').fill(name);await page.getByRole('button',{name:name+' 추가',exact:true}).click();await settled();}
  const card=page.locator('.builder-widget[data-type=trend]'),grip=card.locator('.builder-grip');
  await grip.scrollIntoViewIfNeeded();let bounds=await grip.boundingBox();await page.mouse.move(bounds.x+bounds.width/2,bounds.y+bounds.height/2);await page.mouse.down();await page.mouse.move(bounds.x+bounds.width/2,bounds.y+bounds.height/2+368,{steps:10});await page.mouse.up();
  if(!await card.evaluate(e=>e.classList.contains('row-4')))throw new Error('Pointer drag did not move to row 4');checks.push('pointer-move');
  const resize=card.locator('.builder-resize');await resize.scrollIntoViewIfNeeded();bounds=await resize.boundingBox();const grid=await page.locator('#platform-grid').boundingBox();
  await page.mouse.move(bounds.x+bounds.width/2,bounds.y+bounds.height/2);await page.mouse.down();await page.mouse.move(bounds.x+bounds.width/2+(grid.width+16)/2,bounds.y+bounds.height/2+92,{steps:10});await page.mouse.up();
  if(!await card.evaluate(e=>e.classList.contains('span-12')&&e.classList.contains('height-4')))throw new Error('Resize handle did not update independent dimensions');checks.push('pointer-resize');
  await card.locator('.builder-grip').focus();await page.keyboard.press('Alt+ArrowUp');checks.push('keyboard-order');
  await page.getByRole('button',{name:'경보 추이 제거',exact:true}).click();if(await page.locator('.builder-widget').count()!==1)throw new Error('Remove failed');await page.locator('#dashboard-undo').click();if(await page.locator('.builder-widget').count()!==2)throw new Error('Remove undo failed');checks.push('remove-undo');
  await page.locator('#dashboard-save').click();await page.locator('#dashboard-editor').waitFor({state:'hidden'});await settled();
  await page.locator('#dashboard-edit').click();await page.locator('#dashboard-reset').click();await page.locator('#dialog-template').selectOption('security');await page.locator('#dialog-submit').click();await page.locator('#dashboard-dialog').waitFor({state:'hidden'});await settled();
  if(await page.locator('.builder-widget').count()!==8)throw new Error('Template reset preview failed');await page.locator('#dashboard-cancel').click();await settled();if(await page.locator('.builder-widget').count()!==2)throw new Error('Reset cancel failed');checks.push('reset-cancel');
  const identities=await (await page.request.get(base+'/api/auth/me')).json(),headers={'X-Cloud-SOC':'portal','X-CSRF-Token':identities.csrf};
  const current=await state(),layout=current.dashboards.find(r=>r.id===id).layout;
  layout.widgets=Array.from({length:24},(_,i)=>({id:'load-'+i,type:'trend',x:i%2*6,y:Math.floor(i/2)*3,w:6,h:3,config:{title:'경보 추이 '+i,period:60,chart:'line',limit:8,sort:'newest',severity:'all',color:'blue'}}));
  const saved=await page.request.post(base+'/api/dashboards',{headers,data:{action:'save',revision:current.revision,id,layout}});if(saved.status()!==200)throw new Error('24-widget setup failed');
  await page.goto(base+'/dashboard.html?dashboard='+id);await settled();let requests=[];const listener=r=>{if(/\/api\/(operations|logs|cases|agents)/.test(r.url()))requests.push(r.url());};page.on('request',listener);
  await page.locator('#dashboard-refresh').click();await settled();page.off('request',listener);if(requests.length!==2)throw new Error('Expected 2 dataset requests, got '+requests.length);checks.push('24-widgets-two-requests');
  // Older response is deliberately delayed past a newer successful request.
  let first=true;await page.route('**/api/operations?*',async route=>{if(first){first=false;await new Promise(resolve=>setTimeout(resolve,500));try{await route.fulfill({json:{sections:{alerts:{state:'ok',count:999,buckets:[],rows:[]}}}});}catch{}}else await route.continue();});
  await page.locator('#dashboard-refresh').click();await page.locator('#dashboard-refresh').click();await settled();await new Promise(resolve=>setTimeout(resolve,650));if((await page.locator('#platform-grid').textContent()).includes('999'))throw new Error('Stale response entered display');await page.unroute('**/api/operations?*');checks.push('stale-response');
  await page.request.get(base+'/__fixture/scenario?value=error');await page.locator('#dashboard-refresh').click();await settled();if(!await page.locator('#platform-grid').getByText(/조회 실패/).count())throw new Error('503 became zero');checks.push('503');
  await page.request.get(base+'/__fixture/scenario?value=empty');await page.locator('#dashboard-refresh').click();await settled();if((await page.locator('#platform-grid').textContent()).includes('조회 실패'))throw new Error('Empty data shown as failure');checks.push('empty');
  await page.request.get(base+'/__fixture/scenario?value=blocked');await page.locator('#dashboard-refresh').click();await settled();if(!(await page.locator('#dashboard-coverage').textContent()).includes('중단'))throw new Error('Blocked analysis warning missing');checks.push('blocked');
  await page.request.get(base+'/__fixture/scenario?value=populated');await page.route('**/api/operations?*',route=>route.fulfill({status:403,json:{error:'SYNTHETIC-DENIED'}}));await page.locator('#dashboard-refresh').click();await settled();if(!await page.locator('#platform-grid').getByText('조회 권한이 없습니다.',{exact:true}).count())throw new Error('Forbidden became zero');await page.unroute('**/api/operations?*');checks.push('403');
  // Restore the two saved independent instances instead of leaving a large fixture dashboard.
  const revision=(await state()).revision;
  layout.widgets=[{id:'restored-trend',type:'trend',x:0,y:0,w:6,h:3,config:{title:'경보 추이',period:60,chart:'line',limit:8,sort:'newest',severity:'all',color:'blue'}},{id:'restored-intake',type:'intake',x:6,y:0,w:6,h:3,config:{title:'로그 수신 추이',period:1440,chart:'line',limit:8,sort:'newest',severity:'all',color:'teal'}}];
  await page.request.post(base+'/api/dashboards',{headers,data:{action:'save',revision,id,layout}});
  for(const row of (await state()).dashboards.filter(r=>['통합 보안 현황','공격 탐지·사건 조사','클라우드 감사·IAM 현황','에이전트·수집 현황'].includes(r.layout.name))){
    const names={'통합 보안 현황':'security','공격 탐지·사건 조사':'investigation','클라우드 감사·IAM 현황':'cloud','에이전트·수집 현황':'collection'};
    for(const width of [1440,768,390]){await page.setViewportSize({width,height:1000});await page.goto(base+'/dashboard.html?dashboard='+row.id);await settled();
      for(const theme of ['light','dark']){await page.evaluate(t=>window.CloudSOCTheme.set(t),theme);const dims=await page.evaluate(()=>({client:document.documentElement.clientWidth,width:innerWidth,scroll:document.documentElement.scrollWidth,escaped:[...document.querySelectorAll('.builder-widget,.builder-tabs button,.app-header button')].filter(e=>e.getBoundingClientRect().width&&e.getBoundingClientRect().right>document.documentElement.clientWidth+1).map(e=>e.className)}));if(dims.scroll>width+1||dims.escaped.length)throw new Error('Template boundary failed '+JSON.stringify(dims));await page.screenshot({path:'output/playwright/dashboard-platform/'+names[row.layout.name]+'-'+width+'-'+theme+'.png',fullPage:true});checks.push(names[row.layout.name]+'-'+width+'-'+theme);}
    }
  }
  await page.setViewportSize({width:1440,height:1000});await page.goto(base+'/dashboard.html?dashboard='+id);await settled();await page.locator('#dashboard-edit').click();await page.locator('#widget-search').fill('경보');await page.screenshot({path:'output/playwright/dashboard-platform/editor-1440-dark.png',fullPage:true});await page.locator('#dashboard-cancel').click();await settled();
  if(errors.length)throw new Error(JSON.stringify(errors));return {synthetic:true,checks,requestCount:requests.length,javascriptErrors:errors.length};
}
