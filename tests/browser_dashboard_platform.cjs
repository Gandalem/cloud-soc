async (page) => {
  const base='http://127.0.0.1:8773',errors=[],requests=[],report=[],screens=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('request',r=>{if(r.url().includes('/api/'))requests.push(r.url());});
  async function settled(){await page.waitForLoadState('networkidle');await page.locator('#dashboard-updated').filter({hasText:'조회 완료'}).waitFor();}
  async function state(){return (await page.request.get(base+'/api/dashboards')).json();}
  async function create(key,name){await page.locator('#dashboard-create').click();await page.locator('#dialog-template').selectOption(key);await page.locator('#dialog-name').fill(name);await page.locator('#dialog-submit').click();await page.locator('#dashboard-dialog').waitFor({state:'hidden'});await settled();return new URL(page.url()).searchParams.get('dashboard');}
  async function dimensions(name,width){const size=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth,dialogs:[...document.querySelectorAll('dialog[open]')].map(d=>({width:d.clientWidth,scroll:d.scrollWidth}))}));if(size.scroll>width+1||size.dialogs.some(d=>d.scroll>d.width+1))throw new Error(name+' overflow '+JSON.stringify(size));report.push({name,...size});}
  await page.setViewportSize({width:1440,height:1000});
  if(page.url().endsWith('/login')){await page.getByRole('textbox',{name:'계정',exact:true}).fill('admin');await page.getByRole('textbox',{name:'비밀번호',exact:true}).fill('synthetic-password');await page.getByRole('button',{name:'로그인',exact:true}).click();await page.waitForURL(base+'/');}
  await page.goto(base+'/dashboard.html');await settled();
  const legacy=(await page.request.get(base+'/api/dashboard')).json();
  const ids={};
  for(const [key,name] of [['security','통합 보안 현황'],['investigation','공격 탐지·사건 조사'],['cloud','클라우드 감사·IAM 현황'],['collection','에이전트·수집 현황']]){
    ids[key]=await create(key,name);await dimensions(key,1440);await page.screenshot({path:'output/playwright/dashboard-platform/'+key+'-1440-light.png',fullPage:true});screens.push(key);
  }
  const id=await create('empty','개인 편집 검증');
  await page.locator('#dashboard-edit').click();await page.locator('#widget-search').fill('경보 추이');
  await page.getByRole('button',{name:'경보 추이 추가',exact:true}).click();await settled();
  await page.getByRole('button',{name:'경보 추이 추가',exact:true}).click();await settled();
  let cards=page.locator('.builder-widget');if(await cards.count()!==2)throw new Error('Duplicate instance add failed');
  await cards.first().getByRole('button',{name:'경보 추이 설정',exact:true}).click();await page.locator('#widget-title').fill('한 시간 경보');await page.locator('#widget-period').selectOption('60');await page.locator('#widget-chart').selectOption('bar');await page.locator('#widget-width').selectOption('12');
  await page.locator('#widget-form button[type=submit]').click();await settled();
  await cards.last().getByRole('button',{name:'경보 추이 설정',exact:true}).click();await page.locator('#widget-title').fill('일주일 경보');await page.locator('#widget-period').selectOption('10080');await page.locator('#widget-chart').selectOption('heatmap');await page.locator('#widget-form button[type=submit]').click();await settled();
  await page.locator('#dashboard-save').click();await page.locator('#dashboard-editor').waitFor({state:'hidden'});await settled();
  let saved=(await state()).dashboards.find(d=>d.id===id).layout;if(saved.widgets.length!==2||saved.widgets[0].config.period!==60||saved.widgets[1].config.period!==10080||saved.widgets[0].id===saved.widgets[1].id)throw new Error('Independent settings failed');
  await page.locator('#dashboard-edit').click();await page.getByRole('button',{name:'한 시간 경보 아래로',exact:true}).click();await page.locator('#dashboard-undo').click();await page.locator('#dashboard-name').fill('취소할 이름');await page.locator('#dashboard-cancel').click();await settled();
  if(await page.locator('#dashboard-title').textContent()!=='개인 편집 검증')throw new Error('Cancel failed');
  await page.locator('#dashboard-favorite').click();await page.waitForLoadState('networkidle');await page.locator('#dashboard-default').click();await page.waitForLoadState('networkidle');
  if((await state()).default_id!==id)throw new Error('Default failed');
  await page.goto(base+'/dashboard.html');await settled();if(new URL(page.url()).searchParams.get('dashboard')!==id)throw new Error('Default transition failed');
  await page.locator('#dashboard-rename').click();await page.locator('#dialog-name').fill('최종 개인 화면');await page.locator('#dialog-submit').click();await page.locator('#dashboard-dialog').waitFor({state:'hidden'});await settled();
  await page.locator('#dashboard-duplicate').click();await page.locator('#dialog-name').fill('삭제할 복사본');await page.locator('#dialog-submit').click();await page.locator('#dashboard-dialog').waitFor({state:'hidden'});await settled();
  await page.locator('#dashboard-delete').click();await page.locator('#dialog-cancel').click();await page.locator('#dashboard-delete').click();await page.locator('#dialog-submit').click();await page.locator('#dashboard-dialog').waitFor({state:'hidden'});await settled();
  if((await state()).dashboards.some(d=>d.layout.name==='삭제할 복사본'))throw new Error('Delete failed');
  await page.locator('#dashboard-edit').click();await page.locator('#dashboard-name').fill('충돌 편집 보존');
  let remote=await state();const identity=await (await page.request.get(base+'/api/auth/me')).json();
  await page.request.post(base+'/api/dashboards',{headers:{'X-Cloud-SOC':'portal','X-CSRF-Token':identity.csrf},data:{revision:remote.revision,action:'rename',id,name:'다른 창 변경'}});
  await page.locator('#dashboard-save').click();await page.locator('#dashboard-conflict').waitFor();
  if(await page.locator('#dashboard-name').inputValue()!=='충돌 편집 보존')throw new Error('Conflict lost draft');
  await page.locator('#dashboard-reload').click();await page.locator('#dialog-submit').click();await page.locator('#dashboard-dialog').waitFor({state:'hidden'});await settled();
  await page.locator('#dashboard-title').filter({hasText:'다른 창 변경'}).waitFor();
  if(await page.locator('#dashboard-title').textContent()!=='다른 창 변경')throw new Error('Reload failed');
  for(const width of [1440,768,390]){await page.setViewportSize({width,height:1000});
    for(const theme of ['light','dark']){await page.evaluate(t=>window.CloudSOCTheme.set(t),theme);await dimensions('personal-'+theme,width);await page.screenshot({path:'output/playwright/dashboard-platform/personal-'+width+'-'+theme+'.png',fullPage:true});}
  }
  await page.locator('#dashboard-edit').click();await page.getByRole('button',{name:'일주일 경보 위로',exact:true}).click();await page.getByRole('button',{name:'대시보드',exact:true}).click();await page.locator('#dashboard-cancel').click();await settled();
  await page.getByRole('button',{name:'위젯 찾기',exact:true}).click();await page.locator('#widget-search').fill('위치');await dimensions('mobile-library',390);await page.screenshot({path:'output/playwright/dashboard-platform/library-390.png',fullPage:true});
  await page.getByRole('button',{name:'대시보드',exact:true}).click();await page.locator('#dashboard-edit').click();await page.locator('.builder-widget').first().getByRole('button',{name:/설정$/}).click();await dimensions('mobile-settings',390);await page.locator('#widget-cancel').click();await page.locator('#dashboard-cancel').click();await settled();
  // Same fixture scope, real logout/login and persisted SQLite preferences.
  await page.getByRole('button',{name:'로그아웃',exact:true}).click();await page.waitForURL(base+'/login');await page.getByRole('textbox',{name:'계정',exact:true}).fill('admin');await page.getByRole('textbox',{name:'비밀번호',exact:true}).fill('synthetic-password');await page.getByRole('button',{name:'로그인',exact:true}).click();await page.waitForURL(base+'/');await page.goto(base+'/dashboard.html');await settled();
  if(new URL(page.url()).searchParams.get('dashboard')!==id)throw new Error('Relogin lost default');
  if(JSON.stringify(await legacy)!==JSON.stringify(await (await page.request.get(base+'/api/dashboard')).json()))throw new Error('Legacy configuration changed');
  for(const route of ['/index.html','/logs.html','/cases.html']){await page.goto(base+route);await page.waitForLoadState('networkidle');await dimensions(route,390);}
  if(errors.length)throw new Error(JSON.stringify(errors));
  return {synthetic:true,checks:report.length,javascriptErrors:errors.length,screens,report,templates:ids,personal:id};
}
