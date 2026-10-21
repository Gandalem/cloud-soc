/* Final browser acceptance. Credentials come from this process only; no trace. */
const {chromium,expect}=require('playwright/test');
const fs=require('node:fs');const path=require('node:path');
async function main(){
 const phase=process.argv[2]||'prepare',origin='http://127.0.0.1:18081';
 const folder=path.resolve('state/collection-policy');fs.mkdirSync(folder,{recursive:true});
 const manifest=path.join(folder,'browser-rules.json');
 if(!process.env.SOC_PORTAL_REVIEW_PASSWORD)throw new Error('Review password must be supplied to this process');
 const browser=await chromium.launch({channel:'msedge',headless:true});const ctx=await browser.newContext({locale:'ko-KR',timezoneId:'Asia/Seoul',viewport:{width:1440,height:1000}});const page=await ctx.newPage();const errors=[];page.on('pageerror',e=>errors.push(String(e)));
 try{
  await page.goto(origin+'/login');await page.locator('[name=username]').fill('lab-admin');await page.locator('[name=password]').fill(process.env.SOC_PORTAL_REVIEW_PASSWORD);await page.locator('#login-form button').click();await page.waitForURL(origin+'/');
  async function api(url){const r=await ctx.request.get(origin+url);if(!r.ok())throw new Error('Authenticated API failed: '+r.status());return r.json();}
  async function row(key){return (await api('/api/settings/rule-library')).rules.find(r=>r.definition.key===key);}
  async function until(fn,label,seconds=90){const end=Date.now()+seconds*1000;while(Date.now()<end){const result=await fn();if(result)return result;await new Promise(r=>setTimeout(r,500));}throw new Error('Timed out: '+label);}
  if(phase==='prepare'){
   if(fs.existsSync(manifest))throw new Error('Preserve previous browser proof');
   const tag=Date.now().toString(36).toUpperCase(),data={tag,rules:[],username:'policy-review-'+tag.toLowerCase(),page_errors:[]};
   await page.goto(origin+'/settings-rules.html');await page.locator('#rule-template option').first().waitFor({state:'attached'});
   for(const kind of ['AUTH','WAF']){
    const key='POLICY-'+kind+'-'+tag;
    await page.locator('#rule-template').selectOption('ssh_failures');await page.locator('#rule-new').click();await page.locator('#rule-source').selectOption(kind==='AUTH'?'mall':'mall_waf');await page.locator('#rule-kind').selectOption(kind==='AUTH'?'threshold':'waf');await page.locator('#rule-key').fill(key);await page.locator('#rule-name').fill(kind==='AUTH'?'수집 정책 로그인 실패':'수집 정책 WAF 탐지');
    if(kind==='AUTH'){
     await page.locator('#rule-count').fill('3');await page.locator('#rule-window').fill('300');await page.locator('#rule-cooldown').fill('0');
     for(const [field,value] of [['event.action','login'],['event.outcome','failure']]){await page.locator('#rule-add-condition').click();const line=page.locator('.rule-condition').last();await line.locator('select').nth(0).selectOption(field);await line.locator('input').fill(value);}
    }
    await page.locator('#rule-save').click();await expect(page.locator('#rule-result')).toHaveText('규칙을 저장했습니다.');await page.locator('#rule-approve').click();await expect(page.locator('#rule-result')).toHaveText('규칙을 승인했습니다.');await page.locator('#rule-apply').click();await expect(page.locator('#rule-result')).toHaveText('적용을 요청했습니다.');
    const active=await until(async()=>{const r=await row(key);return r?.active?r:null;},'worker accepts rule');data.rules.push({key,id:active.id});fs.writeFileSync(manifest,JSON.stringify(data,null,2));
   }
   const shop=await ctx.newPage();await shop.route('**/favicon.ico',r=>r.abort());
   for(let n=0;n<3;n++){await shop.goto('http://127.0.0.1:18080/login');await shop.locator('[name=username]').fill(data.username);await shop.locator('[name=password]').fill('synthetic-invalid-input');await shop.locator('form button,form input[type=submit]').first().click();await shop.waitForURL(u=>u.toString().endsWith('?error'));}
   await shop.close();console.log('Two rules created through UI; three actual failed logins sent');
  }else{
   const data=JSON.parse(fs.readFileSync(manifest,'utf8'));
   await until(async()=>{const end=new Date(),start=new Date(end-3600000);const v=await api('/api/operations?'+new URLSearchParams({start:start.toISOString(),end:end.toISOString()}));return data.rules.every(r=>v.sections.alerts.rows.some(a=>a.rule===r.key));},'actual login and WAF alerts');
   await page.goto(origin+'/logs.html');await expect(page.locator('#log-rows tr').first()).toBeVisible();await expect(page.locator('.log-sheet th').first()).toHaveText('로그 종류');
   await page.locator('#log-period').selectOption('1440');await page.locator('#log-filters button[type=submit]').click();
   await until(async()=>{const text=await page.locator('#log-rows').innerText();return ['쇼핑몰 로그인 감사','쇼핑몰 웹 접근','쇼핑몰 WAF 탐지'].every(s=>text.includes(s));},'three truthful log types');
   const tr=page.locator('#log-rows tr').filter({hasText:'쇼핑몰 WAF 탐지'}).first();await tr.locator('.log-row-open').click();await expect(page.locator('#log-detail-fields')).toContainText('쇼핑몰 WAF 탐지');await page.screenshot({path:path.join(folder,'unified-log-types.png'),fullPage:true});await page.locator('#log-detail-dialog button').filter({hasText:'닫기'}).first().click();
   await page.screenshot({path:path.join(folder,'unified-log-list.png'),fullPage:true});
   await page.goto(origin+'/settings-rules.html');await page.locator('#rule-template option').first().waitFor({state:'attached'});
   for(const r of data.rules){await page.locator('#rule-search').fill(r.key);await expect(page.locator('#rule-list article')).toHaveCount(1);await page.locator('#rule-list article').getByRole('button',{name:'상세 보기'}).click();page.once('dialog',d=>d.accept());await page.locator('#rule-delete').click();await expect(page.locator('#rule-result')).toHaveText('삭제 요청을 저장했습니다.');await until(async()=>!await row(r.key),'test rule deleted');await page.locator('#rule-search').fill('');}
   data.ui_passed=true;data.test_rules_deleted=true;data.page_errors=errors;fs.writeFileSync(manifest,JSON.stringify(data,null,2));console.log('Real alerts, unified source types, details and rule deletion passed');
  }
  if(errors.length)throw new Error('Browser page errors: '+errors.join(';'));
 }finally{
  try{const me=await ctx.request.get(origin+'/api/auth/me');if(me.ok()){const value=await me.json();await ctx.request.post(origin+'/api/auth/logout',{headers:{'X-Cloud-SOC':'portal','X-CSRF-Token':value.csrf}});}}catch{}
  await browser.close();
 }
}
main().catch(e=>{console.error(String(e));process.exitCode=1;});
