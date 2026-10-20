/* Real browser against the disposable local Portal used by review_rule_editor.py. */
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {chromium}=require('playwright');

async function main(){
  const [origin,output]=process.argv.slice(2);
  assert.match(origin,/^http:\/\/127\.0\.0\.1:\d+$/);
  const browser=await chromium.launch({channel:'msedge',headless:true});
  const report={checks:[],pageErrors:[]};
  try{
    const context=await browser.newContext({locale:'ko-KR',timezoneId:'Asia/Seoul',viewport:{width:1365,height:900}});
    const response=await context.request.post(origin+'/api/auth/login',{headers:{'X-Cloud-SOC':'portal'},data:{username:'admin',password:'synthetic-password'}});
    assert.equal(response.status(),200);
    const page=await context.newPage();
    page.on('pageerror',error=>report.pageErrors.push(error.message));
    await page.goto(origin+'/settings-rules.html');
    await page.locator('#rule-template option').first().waitFor({state:'attached'});
    await page.locator('#rule-summary').filter({hasText:'경보'}).waitFor();
    assert.equal(await page.locator('#rule-yaml').count(),0);
    assert.doesNotMatch(await page.locator('main').innerText(),/검증 예정|미완성|개발 중|MVP|AI 연동 대기/);
    report.checks.push('capability-driven form and product copy');
    await page.locator('#rule-name').fill('합성 로그인 규칙');
    await page.locator('#rule-key').fill('BROWSER-AUTH-001');
    await page.locator('#rule-save').click();
    await page.locator('#rule-result').filter({hasText:'규칙을 저장했습니다.'}).waitFor();
    assert.equal(await page.locator('#rule-list article').count(),1);
    await page.locator('#rule-approve').click();
    await page.locator('#rule-result').filter({hasText:'규칙을 승인했습니다.'}).waitFor();
    await page.locator('#rule-apply').click();
    await page.locator('#rule-result').filter({hasText:'적용을 요청했습니다.'}).waitFor();
    assert.match(await page.locator('#rule-detail-state').innerText(),/반영 대기/);
    assert.doesNotMatch(await page.locator('#rule-detail-state').innerText(),/사용 중/);
    report.checks.push('create, approve and truthful pending apply');
    await page.locator('#rule-edit').click();
    await page.locator('#rule-count').fill('12');
    await page.locator('#rule-save').click();
    await page.locator('#rule-result').filter({hasText:'규칙을 저장했습니다.'}).waitFor();
    assert.match(await page.locator('#rule-detail-summary').innerText(),/12회/);
    await page.locator('#rule-copy').click();
    await page.locator('#rule-save').click();
    await page.locator('#rule-list article').nth(1).waitFor();
    page.once('dialog',dialog=>dialog.accept());
    await page.locator('#rule-delete').click();
    await page.locator('#rule-result').filter({hasText:'삭제 요청을 저장했습니다.'}).waitFor();
    assert.equal(await page.locator('#rule-list article').count(),1);
    report.checks.push('edit, copy and delete');
    await page.locator('#rule-template').selectOption('waf_sqli');
    assert.equal(await page.locator('#rule-source').inputValue(),'waf');
    assert.equal(await page.locator('#rule-kind').inputValue(),'waf');
    assert.equal(await page.locator('#rule-count').inputValue(),'1');
    const listing=await (await context.request.get(origin+'/api/settings/rule-library')).json();
    const rows=[listing.capabilities.templates.ssh_failures,listing.capabilities.templates.web_errors].map((r,i)=>({...r,key:'BROWSER-IMPORT-'+i}));
    await page.locator('#rule-file').setInputFiles({name:'rules.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify({schema_version:1,rules:rows}))});
    await page.locator('#rule-import-preview').click();
    await page.locator('#rule-import-list input').nth(1).waitFor();
    await page.locator('#rule-import-list input').nth(1).uncheck();
    await page.locator('#rule-import-create').click();
    await page.locator('#rule-result').filter({hasText:'1개 규칙을 등록했습니다.'}).waitFor();
    assert.equal(await page.locator('#rule-list article').count(),2);
    report.checks.push('WAF template and selected batch import');
    const exported=await (await context.request.get(origin+'/api/settings/rule-library/export')).json();
    assert.equal(exported.rules.length,2);
    assert.equal(exported.schema_version,1);
    await page.screenshot({path:path.join(output,'rule-editor-desktop.png'),fullPage:true});
    await page.setViewportSize({width:390,height:844});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1));
    await page.screenshot({path:path.join(output,'rule-editor-mobile.png'),fullPage:true});
    report.checks.push('JSON export and mobile layout');
    assert.deepEqual(report.pageErrors,[]);
    report.passed=true;
  }finally{
    fs.writeFileSync(path.join(output,'browser-review.json'),JSON.stringify(report,null,2));
    await browser.close();
  }
  process.stdout.write(JSON.stringify(report)+'\n');
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
