const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {groups, current, markup, coverageView} = require('../shell.js');
const pages = ['index.html','dashboard.html','operations.html','logs.html','cases.html','workbench.html','collection-health.html','devices.html','agents.html','agent-status.html','detection-history.html','reprocessing-history.html','settings-slack.html','settings-rules.html'];

test('every live page loads one shared shell and no duplicate header or sidebar', () => {
  for (const page of pages) {
    const html = fs.readFileSync(path.join(__dirname, '..', page), 'utf8');
    assert.equal((html.match(/id="app-shell"/g) || []).length, 1, page);
    assert.equal((html.match(/src="shell.js" defer/g) || []).length, 1, page);
    assert.equal((html.match(/href="shell.css"/g) || []).length, 1, page);
    assert.doesNotMatch(html, /class="(?:app-header|sidebar|ops-mobile|logs-mobile-nav|status-mobile-nav|case-page-links)"/, page);
    assert.ok(html.indexOf('shell.js') < html.indexOf('<main'), page);
    assert.equal((html.match(/src="\/theme.js"/g)||[]).length,1,page);
    assert.equal((html.match(/href="\/theme.css"/g)||[]).length,1,page);
  }
});

test('same navigation labels, groups and order on every page', () => {
  const expected = groups.flatMap(group => group.items);
  assert.equal(expected.length, 10);
  assert.ok(expected.some(([href,label])=>href==='devices.html'&&label==='장치 관리'));
  assert.deepEqual(groups[2].items.map(([href])=>href), ['settings-slack.html','settings-rules.html']);
  for (const page of pages) {
    const html = markup('/'+page, '');
    const links = [...html.matchAll(/<a class="nav-item(?: active)?" href="([^"]+)"[^>]*>([^<]+)<\/a>/g)].map(match => [match[1],match[2]]);
    assert.deepEqual(links, expected, page);
    assert.equal((html.match(/aria-current="page"/g)||[]).length, expected.some(([href])=>href===current('/'+page,''))?1:0, page);
    assert.match(html, /aria-label="보안 관제"/);
    assert.match(html, /aria-label="에이전트"/);
  }
});

test('root, case details and key history resolve to correct active item without echoing URL', () => {
  assert.equal(current('/', ''), 'index.html');
  assert.equal(current('/workbench.html', ''), 'cases.html');
  assert.equal(current('/agents.html', '#keys'), 'agents.html#keys');
  assert.match(markup('/agents.html','#keys'), /href="agents.html#keys" aria-current="page"/);
  assert.match(markup('/agents.html',''), /href="agents.html" aria-current="page"/);
  assert.doesNotMatch(markup('/<script>', '#<script>'), /<script>/);
});

test('one collapsible mobile navigation retains complete links and keyboard affordance', () => {
  const html = markup('/logs.html', '');
  assert.match(html, /aria-expanded="false" aria-controls="portal-sidebar"/);
  assert.equal((html.match(/<nav /g)||[]).length, 1);
  const script = fs.readFileSync(path.join(__dirname, '../shell.js'),'utf8');
  assert.match(script, /event.key === "Escape"/);
  assert.match(script, /toggle.focus\(\)/);
});

test('customer navigation has no duplicate operations or developer diagnostics',()=>{
 assert.deepEqual(groups[0].items.map(v=>v[0]),['index.html','dashboard.html','logs.html','cases.html']);
 assert.equal(groups[1].title,'에이전트');
 const html=markup('/logs.html','');
 assert.doesNotMatch(html,/operations.html|collection-health.html|detection-history.html|reprocessing-history.html/);
});
test('global customer state cannot show observed coverage when upstream fails or is unknown',()=>{
 for(const state of ['failed','stale','unavailable','not_started']){
  const view=coverageView({state,detector:{state:'success'}});assert.notEqual(view.state,'observed');
 }
 assert.match(coverageView({state:'failed',detector:{state:'success'}}).description,/경보 0건/);
 assert.equal(coverageView({state:'success',detector:{state:'success'}}).state,'observed');
 assert.equal(coverageView({coverage:{state:'catching_up'}}).state,'catching_up');
});

test('theme button follows current workspace name and no dashboard selector remains',()=>{
 assert.match(markup('/index.html',''),/workspace-label">홈 대시보드<\/span><button[^>]+id="portal-theme-toggle"/);
 for(const page of ['index.html','dashboard.html'])assert.doesNotMatch(fs.readFileSync(path.join(__dirname,'..',page),'utf8'),/id="dashboard-theme"/);
});

test('initial notice failures and unfinished delivery are distinct from rule exclusions',()=>{
 for(const [reason,text] of [['initial_notice_failed',/처리에 실패/],['initial_notice_reconciliation_required',/연결/],['initial_notice_pending',/완료되지/],['initial_notice_unconfirmed',/정상 처리로 판단할 수 없/]]){
  const view=coverageView({state:'success',detector:{state:'success'},coverage:{state:'warning',reason}});
  assert.equal(view.state,'warning');assert.match(view.description,text);
  assert.doesNotMatch(view.description,/일부 로그의 위험 평가/);
 }
 assert.match(coverageView({coverage:{state:'warning',reason:'evaluation_exclusions'}}).description,/일부 로그/);
 assert.doesNotMatch(coverageView({coverage:{state:'warning',reason:'<script>PRIVATE_CANARY'}}).description,/PRIVATE_CANARY|<script>/);
});
