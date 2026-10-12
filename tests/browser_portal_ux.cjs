async (page) => {
  const base = 'http://127.0.0.1:8773';
  const errors = [], failed = [], report = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('response', response => { if (response.status() >= 400) failed.push({url: response.url(), status: response.status()}); });
  const cases = await (await page.request.get(base + '/api/cases')).json();
  if (!cases.rows?.length) throw new Error('Login and a synthetic case are required');
  const operations = await (await page.request.get(base + '/api/operations')).json();
  const routes = [
    ['login', '/login'], ['operations', '/index.html'], ['logs', '/logs.html'],
    ['agent-status', '/agent-status.html'], ['collection-health', '/collection-health.html'],
    ['agents', '/agents.html'], ['keys', '/agents.html#keys'], ['cases', '/cases.html'],
    ['workbench', '/workbench.html?case=' + cases.rows[0].id],
    ['workbench-empty', '/workbench.html'],
    ['workbench-alert', '/workbench.html?alert=' + operations.sections.alerts.rows[1].id],
    ['detection-history', '/detection-history.html'], ['reprocessing-history', '/reprocessing-history.html']
  ];
  for (const width of [1440, 390]) {
    await page.setViewportSize({width, height: 1000});
    for (const [name, route] of routes) {
      await page.goto(base + route);
      await page.waitForLoadState('networkidle');
      const layout = await page.evaluate(() => ({
        viewport: innerWidth, pageWidth: document.documentElement.scrollWidth,
        title: document.querySelector('h1')?.textContent,
        headingCount: document.querySelectorAll('h1').length,
        dialog: [...document.querySelectorAll('dialog[open]')].map(d => ({width: d.clientWidth, scroll: d.scrollWidth})),
        help: [...document.querySelectorAll('details.usage-details')].map(d => ({label: d.querySelector('summary').textContent, open: d.open}))
      }));
      if (layout.pageWidth > width + 1) throw new Error(name + ' has horizontal page overflow: ' + layout.pageWidth);
      if (layout.headingCount !== 1) throw new Error(name + ' needs exactly one page heading');
      if (layout.dialog.some(d => d.scroll > d.width + 1)) throw new Error(name + ' dialog has horizontal overflow');
      await page.screenshot({path: 'output/playwright/ux-20261012/' + name + '-' + width + '.png', fullPage: true});
      report.push({name, width, ...layout});
    }
  }
  if (errors.length || failed.length) throw new Error(JSON.stringify({errors, failed}));
  return {routes: report.length, javascriptErrors: errors.length, failedResponses: failed.length, report};
}
