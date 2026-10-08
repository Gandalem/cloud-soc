const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');

async function main() {
  const output = path.resolve(process.argv[2]);
  const origin = 'http://127.0.0.1:28865';
  const report = {passed: false, checks: [], consoleErrors: [], failedApiResponses: []};
  const browser = await chromium.launch({channel: 'msedge', headless: true});
  try {
    const context = await browser.newContext({locale: 'ko-KR', timezoneId: 'Asia/Seoul', viewport: {width: 1365, height: 900}});
    const login = await context.request.post(origin + '/api/auth/login', {
      headers: {'X-Cloud-SOC': 'portal'}, data: {username: 'admin', password: 'synthetic-password'}
    });
    assert.equal(login.status(), 200);
    const page = await context.newPage();
    page.on('pageerror', error => report.consoleErrors.push(error.message));
    page.on('response', response => {
      if (response.url().includes('/api/') && response.status() >= 400) report.failedApiResponses.push(response.status());
    });
    await page.goto(origin + '/detection-history.html');
    await page.locator('#history-state').filter({hasText: '조회 성공'}).waitFor();
    assert.ok(await page.locator('#history-rows section').count() >= 2);
    await page.locator('#history-rule').fill('AUTH-001');
    await page.locator('#history-filter button').click();
    await page.locator('#history-state').filter({hasText: '조회 성공'}).waitFor();
    assert.ok(await page.locator('#history-rows section h2').first().textContent().then(value => value.includes('AUTH-001')));
    report.checks.push('detection history reads actual API and filters AUTH-001');
    await page.screenshot({path: path.join(output, 'ui-detection-history.png'), fullPage: true});
    await page.goto(origin + '/reprocessing-history.html');
    await page.locator('#summary').filter({hasText: '전체 57건'}).waitFor();
    assert.equal(await page.locator('#rows tr').count(), 50);
    await page.locator('#next').click();
    assert.equal(await page.locator('#rows tr').count(), 7);
    assert.equal(await page.locator('#next').isDisabled(), true);
    await page.locator('#previous').click();
    await page.locator('#status').selectOption('partial');
    assert.equal(await page.locator('#rows tr').count(), 50);
    await page.locator('#next').click();
    assert.equal(await page.locator('#rows tr').count(), 3);
    await page.locator('#search').fill('no-match');
    assert.equal(await page.locator('#rows tr').count(), 0);
    await page.locator('#search').fill('integration-host');
    assert.equal(await page.locator('#rows tr').count(), 50);
    await page.locator('#rows button').first().click();
    assert.equal(await page.locator('#detail-panel').evaluate(element => element.open), true);
    assert.ok((await page.locator('#detail').textContent()).includes('soc-host-raw-integration'));
    await page.locator('#detail-close').click();
    report.checks.push('actual 57 history rows: 50/7 pages, partial filter 50/3, empty search, exact raw reference');
    await page.setViewportSize({width: 390, height: 844});
    await page.screenshot({path: path.join(output, 'ui-reprocessing-mobile.png'), fullPage: true});
    assert.equal(await page.locator('body').textContent().then(value => value.includes('PRIVATE_CANARY')), false);
    assert.equal(report.consoleErrors.length, 0);
    assert.equal(report.failedApiResponses.length, 0);
    report.checks.push('mobile 390px render, no raw secret, no JavaScript errors or API failures');
    report.passed = true;
    await context.close();
  } finally {
    await browser.close();
    fs.writeFileSync(path.join(output, 'browser-evidence.json'), JSON.stringify(report, null, 2));
  }
  console.log('Actual Edge UI/API validation passed');
}

main().catch(error => {console.error(error); process.exitCode = 1;});
