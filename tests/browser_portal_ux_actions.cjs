async (page) => {
  const base = 'http://127.0.0.1:8773', checks = [], errors = [];
  page.on('pageerror', error => errors.push(error.message));
  async function visit(route) {
    await page.goto(base + route);
    await page.waitForFunction(() => {
      const ids = ['ops-range','query-state','server-status','log-state-label','history-state','summary','investigation-status','case-counts'];
      return !ids.map(id => document.getElementById(id)).filter(Boolean).some(node => /조회 중|조회 준비|확인 중|업무 조회 중/.test(node.textContent));
    });
    await page.locator('body').ariaSnapshot();
  }
  async function capture(name) {
    await page.evaluate(() => window.scrollTo(0,0));
    const layout = await page.evaluate(() => ({page: document.documentElement.scrollWidth, viewport: innerWidth,
      dialogs: [...document.querySelectorAll('dialog[open]')].map(d => [d.clientWidth, d.scrollWidth])}));
    if (layout.page > layout.viewport + 1 || layout.dialogs.some(([width, scroll]) => scroll > width + 1))
      throw new Error('Overflow: ' + name);
    await page.screenshot({path: 'output/playwright/ux-20261012/' + name + '.png', fullPage: true});
    checks.push(name);
  }
  await page.setViewportSize({width: 390, height: 844});
  await page.request.get(base + '/__fixture/scenario?value=populated');
  await visit('/login');
  await page.getByRole('textbox', {name: '계정', exact: true}).fill('admin');
  await page.getByRole('textbox', {name: '비밀번호', exact: true}).fill('synthetic-password');
  await page.getByRole('button', {name: '로그인', exact: true}).click();
  await page.waitForURL('**/index.html*');
  await page.waitForLoadState('networkidle');
  if (!page.url().includes('index.html')) throw new Error('Login did not reach operations');
  checks.push('real-session-login');
  await page.getByRole('button', {name: '메뉴', exact: true}).click();
  await page.getByRole('link', {name: '통합 로그', exact: true}).focus();
  await page.keyboard.press('Escape');
  if (await page.getByRole('button', {name: '메뉴', exact: true}).getAttribute('aria-expanded') !== 'false') throw new Error('Menu stayed open');
  checks.push('mobile-menu-escape');
  await visit('/agents.html');
  await page.locator('#add-package').click();
  await capture('package-form-mobile');
  const packageName = 'ux-' + Date.now().toString(36);
  await page.locator('#package-form input[name=name]').fill(packageName);
  await page.locator('#package-form input[name=organization]').fill('school');
  await page.locator('#create-submit').click();
  await page.waitForLoadState('networkidle');
  const row = page.locator('#package-rows tr').filter({hasText: packageName + '-setup.zip'});
  await row.waitFor({state: 'visible'});
  if (await row.count() !== 1) throw new Error('Package creation failed');
  checks.push('temporary-package-create');
  await page.locator('#detail-dialog').waitFor({state: 'visible'});
  await capture('install-command-mobile');
  await page.locator('#detail-dialog [data-close]').last().click();
  await row.getByRole('button', {name: '설치 토큰', exact: true}).click();
  await capture('enrollment-mobile');
  await page.locator('#enrollment-dialog [data-close]').last().click();
  await row.getByRole('button', {name: '수동 키 발급', exact: true}).click();
  await page.locator('#key-target').fill('UX-WINDOWS');
  await page.locator('#issue-keys').click();
  await page.locator('#issued-keys .key-item').first().waitFor({state: 'visible'});
  await page.waitForLoadState('networkidle');
  if (await page.locator('#issued-keys .key-item').count() !== 2) throw new Error('Synthetic key issue failed');
  await capture('issued-keys-mobile');
  await page.locator('#keys-dialog [data-close]').last().click();
  await page.locator('#key-history').click();
  await page.waitForLoadState('networkidle');
  const key = page.locator('#history-content .history-row').first();
  await key.locator('[data-key-action=revoke]').click();
  await capture('key-confirm-mobile');
  await key.locator('[data-key-action=confirm-revoke]').click();
  await page.waitForFunction(() => document.querySelector('#history-message').textContent.includes('키 폐기 완료'));
  await page.waitForLoadState('networkidle');
  if (!(await page.locator('#history-message').innerText()).includes('폐기 완료')) throw new Error('Synthetic key revoke failed');
  checks.push('temporary-key-revocation');
  await page.locator('#history-dialog [data-close]').last().click();
  await row.locator('[data-delete]').click();
  await capture('package-delete-mobile');
  await page.locator('#delete-dialog [data-close]').click();
  await visit('/logs.html');
  await page.locator('#log-rows button').first().click();
  await page.waitForLoadState('networkidle');
  await capture('log-detail-mobile');
  await page.locator('#log-detail-close').click();
  await page.locator('#log-host').fill('nonexistent-fixture-host');
  await page.locator('#log-apply').click();
  await page.locator('#log-empty').waitFor({state: 'visible'});
  await page.waitForLoadState('networkidle');
  if (!(await page.locator('#log-empty').isVisible())) throw new Error('Empty filter result not shown');
  checks.push('empty-log-filter');
  await visit('/reprocessing-history.html');
  await page.locator('#rows button').first().click();
  await capture('reprocessing-detail-mobile');
  await page.locator('#detail-close').click();
  await visit('/cases.html');
  await page.locator('#case-rows a').first().click();
  await page.waitForLoadState('networkidle');
  const note='UX fixture ('+Date.now().toString(36)+'): reviewed the displayed evidence.';
  await page.locator('#work-note').fill(note);
  await page.locator('#case-save-button').click();
  await page.waitForFunction(value => document.querySelector('#case-history').textContent.includes(value),note);
  await page.waitForLoadState('networkidle');
  if (!(await page.locator('#case-history').innerText()).includes(note)) throw new Error('Temporary note save failed');
  checks.push('temporary-case-note-save');
  await page.locator('#case-alerts > section > button').first().click();
  await page.getByText('공격 의심 · 공격 성공 미확정', {exact: true}).waitFor({state: 'visible'});
  await page.waitForLoadState('networkidle');
  if (!(await page.locator('#case-alerts').innerText()).includes('공격 성공 미확정')) throw new Error('Assessment limitation missing');
  await capture('case-alert-mobile');
  await page.getByText('근거 로그 보기 (7건)',{exact:true}).click();
  await page.getByRole('button',{name:'근거 1 조회',exact:true}).click();
  await page.getByText('원본 근거 누락 / 만료',{exact:true}).waitFor({state:'visible'});
  checks.push('case-evidence-missing');
  await visit('/detection-history.html');
  await page.locator('#history-kind').selectOption('exclusions');
  await page.locator('#history-filter button').click();
  await page.waitForFunction(() => document.querySelector('#history-rows').textContent.includes('그룹 필드 누락'));
  await page.waitForLoadState('networkidle');
  if (!(await page.locator('#history-rows').innerText()).includes('그룹 필드 누락')) throw new Error('Exclusion filter failed');
  checks.push('exclusion-history-filter');
  for (const mode of ['empty', 'error']) {
    await page.request.get(base + '/__fixture/scenario?value=' + mode);
    for (const route of ['/index.html', '/logs.html', '/agent-status.html', '/collection-health.html', '/agents.html', '/detection-history.html', '/reprocessing-history.html']) {
      await visit(route);
      if (mode === 'error') {
        const rows = page.locator('#log-rows tr, #agent-rows tr, #health-rows tr, #history-rows > section, #ops-alert-rows tr');
        if (await rows.count()) throw new Error('Stale rows remained: ' + route);
      }
      await capture(mode + '-' + route.replace('/','').replace('.html',''));
    }
  }
  await page.request.get(base + '/__fixture/scenario?value=populated');
  if (errors.length) throw new Error(JSON.stringify(errors));
  return {synthetic: true, productionChanges: false, javascriptErrors: errors.length, checks};
}
