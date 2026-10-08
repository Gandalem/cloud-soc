/* Capture actual portal DOM with the loopback synthetic preview running. */
const { chromium } = require('playwright');
const fs = require('node:fs/promises');
const path = require('node:path');
(async () => {
  const options = {headless:true};
  if (process.env.PORTFOLIO_CHROMIUM) options.executablePath=process.env.PORTFOLIO_CHROMIUM;
  const browser=await chromium.launch(options);
  const page=await browser.newPage({viewport:{width:1440,height:1100},deviceScaleFactor:1});
  const errors=[];
  page.on('pageerror', error=>errors.push(error.message));
  const base='http://127.0.0.1:8770';
  const output=path.resolve('docs/portfolio/images');
  await fs.mkdir(output,{recursive:true});
  async function capture(name) {
    await page.evaluate(() => window.scrollTo(0,0));
    await page.screenshot({path:path.join(output,name+'.png'),fullPage:name !== 'alert-detail'});
  }
  try {
    await page.goto(base+'/index.html');
    await page.locator('#ops-alert-rows tr').nth(2).waitFor();
    await page.getByText('SYNTHETIC DEMO · admin · 중앙 관리',{exact:true}).waitFor();
    await capture('dashboard');
    await page.getByRole('button',{name:'상세 / 근거',exact:true}).nth(1).click();
    await page.locator('#ops-detail-content').getByRole('button',{name:'근거 1 확인',exact:true}).click();
    await page.getByText('정규화 내용 해시 일치 · 원본 내용 해시는 미검증',{exact:true}).waitFor();
    await capture('alert-detail');
    await page.getByRole('link',{name:'사건 조사 / 등록',exact:true}).click();
    await page.locator('#case-create-panel').waitFor({state:'visible'});
    await page.locator('#create-title').fill('[합성 데모] CloudTrail 중지 조사');
    await page.getByRole('button',{name:'사건 생성',exact:true}).click();
    await page.locator('#case-work-panel').waitFor({state:'visible'});
    await page.locator('#work-status').selectOption('investigating');
    await page.locator('#work-owner').selectOption('admin');
    await page.locator('#work-verdict').selectOption('inconclusive');
    await page.locator('#work-note').fill('합성 검증: StopLogging 성공과 정확한 근거를 확인. 변경 승인, 다른 Trail, 실제 수집 영향을 추가 확인한다.');
    await page.getByRole('button',{name:'업무 저장',exact:true}).click();
    await page.getByText('판단 보류',{exact:false}).first().waitFor();
    await page.locator('#case-alerts button').first().click();
    await page.locator('#case-alerts').getByRole('button',{name:'근거 1 조회',exact:true}).click();
    await page.getByText('정규화 내용 해시 일치 · 원본 내용 해시는 미검증',{exact:true}).waitFor();
    await page.reload();
    await page.locator('#case-work-panel').waitFor({state:'visible'});
    await page.locator('#case-alerts button').first().click();
    await page.locator('#case-alerts').getByText('MITRE ATT&CK',{exact:true}).click();
    await capture('investigation');
    if (errors.length) throw Error(errors.join('\n'));
    console.log('Captured dashboard, alert and saved SQLite investigation; no page errors.');
  } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exitCode=1});
