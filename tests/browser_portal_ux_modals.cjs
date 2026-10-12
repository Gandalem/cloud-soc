async (page) => {
  const base = 'http://127.0.0.1:8773', report = [];
  async function visit(route) {
    await page.goto(base + route);
    await page.waitForLoadState('networkidle');
    await page.locator('body').ariaSnapshot();
  }
  async function capture(name, width) {
    await page.evaluate(() => window.scrollTo(0,0));
    await page.locator('dialog[open]').waitFor({state: 'visible'});
    const layout = await page.evaluate(() => {const d=document.querySelector('dialog[open]');return {viewport:innerWidth,pageWidth:document.documentElement.scrollWidth,dialogWidth:d.clientWidth,dialogScroll:d.scrollWidth};});
    if (layout.pageWidth > width + 1 || layout.dialogScroll > layout.dialogWidth + 1) throw new Error('Overflow: '+name);
    await page.screenshot({path:'output/playwright/ux-20261012/'+name+'-'+width+'.png',fullPage:true});
    report.push({name,...layout});
  }
  for (const width of [1440,390]) {
    await page.setViewportSize({width,height:1000});
    await visit('/agents.html');
    const row=page.locator('#package-rows tr').first();
    await page.locator('#add-package').click();await capture('package-form',width);
    await page.locator('#add-dialog [data-close]').last().click();
    await row.locator('[data-command]').click();await capture('install-command',width);
    await page.locator('#detail-dialog [data-close]').last().click();
    await row.locator('[data-enrollment]').click();await capture('enrollment',width);
    await page.locator('#enrollment-dialog [data-close]').last().click();
    await row.locator('[data-keys]').click();await capture('key-form',width);
    await page.locator('#keys-dialog [data-close]').last().click();
    await page.locator('#key-history').click();await page.waitForLoadState('networkidle');await capture('key-history',width);
    await page.locator('#history-dialog [data-close]').last().click();
    await row.locator('[data-delete]').click();await capture('package-delete',width);
    await page.locator('#delete-dialog [data-close]').last().click();
    await visit('/logs.html');await page.locator('#log-rows button').first().click();await page.waitForLoadState('networkidle');await capture('log-detail',width);
    await page.locator('#log-detail-close').click();
    await visit('/index.html');await page.locator('#ops-alert-rows button').first().click();await page.waitForLoadState('networkidle');await capture('alert-detail',width);
    await page.locator('#ops-detail-close').click();
    await visit('/reprocessing-history.html');await page.locator('#rows button').first().click();await capture('reprocessing-detail',width);
    await page.locator('#detail-close').click();
  }
  return {synthetic:true,modalChecks:report.length,report};
}
