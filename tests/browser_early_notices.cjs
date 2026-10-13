async(page)=>{
 const base='http://127.0.0.1:8773',errors=[],report={synthetic:true,screens:[]};page.on('pageerror',e=>errors.push(e.message));
 if(page.url().endsWith('/login')){await page.getByRole('textbox',{name:'계정',exact:true}).fill('admin');await page.getByRole('textbox',{name:'비밀번호',exact:true}).fill('synthetic-password');await page.getByRole('button',{name:'로그인',exact:true}).click();await page.waitForURL(base+'/');}else await page.goto(base+'/');
 const control=async action=>(await page.request.get(base+'/__fixture/notices?action='+action)).json();
 await control('nine');await page.locator('#dashboard-refresh').click();await page.locator('#early-alert-panel').filter({hasText:'0건'}).waitFor();
 const measured=await control('ten');await page.locator('.notice-card[data-state="verifying"]').waitFor({timeout:20000});
 report.searchable_to_initial_seconds=(Date.parse(measured.initial_at)-Date.parse(measured.tenth_searchable_at))/1000;
 report.searchable_to_visible_seconds=(Date.now()-Date.parse(measured.tenth_searchable_at))/1000;
 if(report.searchable_to_visible_seconds>=60)throw new Error('local goal missed');
 const id=await page.locator('.notice-card').getAttribute('data-notice');
 await page.getByRole('button',{name:'통지 근거 보기',exact:true}).click();await page.locator('#notice-dialog').filter({hasText:'5분 내 유효 SSH 실패'}).waitFor();
 await page.getByRole('button',{name:'근거 1',exact:true}).click();await page.locator('#notice-dialog').filter({hasText:'정규화 해시 검증'}).waitFor();
 await page.getByRole('button',{name:'닫기',exact:true}).click();
 for(const state of ['initial','verifying','delayed','corrected','confirmed']){
  if(state==='confirmed')await control('verifying'); // separate terminal branch, fixture-only state replay
  await control(state);await page.locator('#dashboard-refresh').click();await page.locator('.notice-card[data-state="'+state+'"]').waitFor();
  if(await page.locator('.notice-card').count()!==1||await page.locator('.notice-card').getAttribute('data-notice')!==id)throw new Error('duplicate logical episode');
 }
 async function dimensions(){const d=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth,dialogs:[...document.querySelectorAll('dialog[open]')].map(d=>({width:d.clientWidth,scroll:d.scrollWidth}))}));if(d.scroll>d.width+1||d.dialogs.some(d=>d.scroll>d.width+1))throw new Error('overflow '+JSON.stringify(d));}
 for(const width of [1440,768,390])for(const theme of ['light','dark']){
  await page.setViewportSize({width,height:1000});await page.evaluate(t=>window.CloudSOCTheme.set(t),theme);await dimensions();
  const file='output/playwright/early-notices/home-'+width+'-'+theme+'.png';await page.screenshot({path:file,fullPage:true});report.screens.push(file);
  await page.getByRole('button',{name:'통지 근거 보기',exact:true}).click();await page.locator('#notice-dialog h3').waitFor();await dimensions();
  if(width===390)await page.screenshot({path:'output/playwright/early-notices/proof-390-'+theme+'.png'});
  await page.getByRole('button',{name:'닫기',exact:true}).click();
 }
 await page.setViewportSize({width:1440,height:1000});
 const me=await (await page.request.get(base+'/api/auth/me')).json(),headers={'X-Cloud-SOC':'portal','X-CSRF-Token':me.csrf};
 let collection=await (await page.request.get(base+'/api/dashboards')).json();
 const created=await (await page.request.post(base+'/api/dashboards',{headers,data:{revision:collection.revision,action:'create',template:'empty',name:'초기 탐지 검증'}})).json();
 const dashboard=created.dashboards.find(d=>d.id===created.selected_id),layout=dashboard.layout;
 layout.widgets=[{id:'notice-1',type:'early-notices',x:0,y:0,w:12,h:4,config:{title:'초기 탐지 통지',period:0,chart:'timeline',limit:8,sort:'newest',severity:'all',color:'blue'}}];
 const saved=await page.request.post(base+'/api/dashboards',{headers,data:{revision:created.revision,action:'save',id:dashboard.id,layout}});if(saved.status()!==200)throw new Error('notice widget save');
 await page.goto(base+'/dashboard.html?dashboard='+dashboard.id);await page.locator('.notice-card[data-state="confirmed"]').waitFor();
 await control('verifying');await control('delayed');await page.locator('.notice-card[data-state="delayed"]').waitFor({timeout:20000});
 for(const width of [1440,390]){await page.setViewportSize({width,height:1000});await dimensions();await page.screenshot({path:'output/playwright/early-notices/personal-'+width+'.png',fullPage:true});}
 await page.reload();await page.locator('.notice-card[data-state="delayed"]').waitFor();
 await page.goto(base+'/');await control('empty');await page.locator('#dashboard-refresh').click();await page.locator('#early-alert-panel').filter({hasText:'0건'}).waitFor();
 await control('unconfigured');await page.locator('#dashboard-refresh').click();await page.locator('#early-alert-panel').filter({hasText:'아직 설정되지'}).waitFor();await control('configured');
 await page.route('**/api/alerts/notices?*',route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:'Synthetic unavailable'})}));
 await page.locator('#dashboard-refresh').click();await page.locator('#early-alert-panel').filter({hasText:'조회 실패'}).waitFor();await page.unroute('**/api/alerts/notices?*');
 report.errors=errors;if(errors.length)throw new Error(errors.join(';'));await page.evaluate(value=>{window.__earlyNoticeQA=value;},report);return report;
}
