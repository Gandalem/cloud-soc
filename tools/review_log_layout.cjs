/* Read-only, affected final browser review. No rule or source-data writes. */
const {chromium,expect}=require('playwright/test');
const fs=require('node:fs'),path=require('node:path');
async function main(){
 if(!process.env.SOC_PORTAL_REVIEW_PASSWORD)throw new Error('Process credential required');
 const folder=path.resolve('state/collection-policy'),origin='http://127.0.0.1:18081';
 const browser=await chromium.launch({channel:'msedge',headless:true});
 const ctx=await browser.newContext({locale:'ko-KR',timezoneId:'Asia/Seoul',viewport:{width:1440,height:1000}});
 const page=await ctx.newPage(),errors=[];page.on('pageerror',e=>errors.push(String(e)));
 const report={read_only:true,reboot:false,sizes:[],errors};
 try{
  await page.goto(origin+'/login');await page.locator('[name=username]').fill('lab-admin');await page.locator('[name=password]').fill(process.env.SOC_PORTAL_REVIEW_PASSWORD);await page.locator('#login-form button').click();await page.waitForURL(origin+'/');
  await page.goto(origin+'/logs.html');await expect(page.locator('#log-rows tr').first()).toBeVisible();
  await page.locator('#log-period').selectOption('1440');await page.locator('#log-page-size').selectOption('50');await page.locator('#log-apply').click();await expect(page.locator('#log-state-label')).toHaveText('조회 완료');
  await expect(page.locator('.log-sheet th')).toHaveText(['로그 종류','시각 (KST)','출처','IP · 주체','주요 내용','상세']);
  const access=page.locator('#log-rows tr').filter({hasText:'쇼핑몰 웹 접근'}).first();await expect(access).toContainText('HTTP 200');
  await expect(access).not.toContainText('미관측');await expect(access).not.toContainText('결과 정보 없음');
  for(const width of (process.argv.includes('--detail-only') ? [] : [1440,1024,390])){
   await page.setViewportSize({width,height:1000});
   const size=await page.locator('.log-sheet-scroll').evaluate(el=>({client:el.clientWidth,scroll:el.scrollWidth,pageWidth:document.documentElement.clientWidth,pageScroll:document.documentElement.scrollWidth}));
   if(width>=1024)expect(size.scroll).toBeLessThanOrEqual(size.client+1);
   expect(size.pageScroll).toBeLessThanOrEqual(size.pageWidth+1);
   report.sizes.push({width,...size});await page.screenshot({path:path.join(folder,'compact-log-list-'+width+'.png'),fullPage:true});
  }
  await page.setViewportSize({width:1440,height:1000});await access.locator('.log-row-open').click();
  await expect(page.locator('#log-detail-state')).toHaveText('조회 완료 · 전체 원문 제한');
  await expect(page.locator('#log-detail-fields')).toContainText('HTTP 응답 코드');await expect(page.locator('#log-detail-fields')).toContainText('200');
  const titles=await page.locator('#log-detail-fields dt').allTextContents();
  for(const title of ['수집기','이벤트 코드','이벤트 공급자','목적지 IP','프로세스 연관 근거'])expect(titles).not.toContain(title);
  await expect(page.locator('#log-detail-fields')).not.toContainText('추가 제한 사항 있음');
  expect(titles).toContain('문서 ID');expect(titles).toContain('인덱스');
  await page.screenshot({path:path.join(folder,'compact-log-detail.png'),fullPage:true});
  if(errors.length)throw new Error('Page script errors');report.passed=true;
 }finally{
  try{const r=await ctx.request.get(origin+'/api/auth/me');if(r.ok()){const me=await r.json();await ctx.request.post(origin+'/api/auth/logout',{headers:{'X-Cloud-SOC':'portal','X-CSRF-Token':me.csrf}});}}catch{}
  fs.writeFileSync(path.join(folder,process.argv.includes('--detail-only') ? 'compact-detail-result.json' : 'compact-layout-result.json'),JSON.stringify(report,null,2));await browser.close();
 }
 console.log(JSON.stringify(report));
}
main().catch(e=>{console.error(String(e));process.exitCode=1;});
