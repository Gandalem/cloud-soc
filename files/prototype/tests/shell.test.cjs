const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {groups, current, markup} = require('../shell.js');
const pages = ['index.html','logs.html','cases.html','workbench.html','collection-health.html','agents.html','agent-status.html','detection-history.html'];

test('every live page loads one shared shell and no duplicate header or sidebar', () => {
  for (const page of pages) {
    const html = fs.readFileSync(path.join(__dirname, '..', page), 'utf8');
    assert.equal((html.match(/id="app-shell"/g) || []).length, 1, page);
    assert.equal((html.match(/src="shell.js" defer/g) || []).length, 1, page);
    assert.equal((html.match(/href="shell.css"/g) || []).length, 1, page);
    assert.doesNotMatch(html, /class="(?:app-header|sidebar|ops-mobile|logs-mobile-nav|status-mobile-nav|case-page-links)"/, page);
    assert.ok(html.indexOf('shell.js') < html.indexOf('<main'), page);
  }
});

test('same navigation labels, groups and order on every page', () => {
  const expected = groups.flatMap(group => group.items);
  assert.equal(expected.length, 8);
  for (const page of pages) {
    const html = markup('/'+page, '');
    const links = [...html.matchAll(/<a class="nav-item(?: active)?" href="([^"]+)"[^>]*>([^<]+)<\/a>/g)].map(match => [match[1],match[2]]);
    assert.deepEqual(links, expected, page);
    assert.equal((html.match(/aria-current="page"/g)||[]).length, 1, page);
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
