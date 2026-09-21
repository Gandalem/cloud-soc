const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const windows = process.platform === 'win32';
const bash = process.env.BASH_EXE || (windows ? 'C:/Program Files/Git/bin/bash.exe' : 'bash');
const powershell = process.env.POWERSHELL_EXE || (windows ? 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe' : 'pwsh');
const parser = '[Console]::InputEncoding = [System.Text.Encoding]::UTF8; $source = [Console]::In.ReadToEnd(); $tokens = $null; $errors = $null; $null = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors); if ($errors.Count) { $errors | ForEach-Object { $_.Message }; exit 1 }';

function localLinks(content) {
  // PowerShell casts such as [guid](Read-Host ...) are not Markdown links.
  const prose = content.replace(/^```[^\r\n]*\r?\n[\s\S]*?^```[ \t]*\r?$/gm, '');
  return [...prose.matchAll(/\]\(([^)]+)\)/g)].map(match => match[1]).filter(link => !/^[a-z]+:\/\//i.test(link));
}

test('guide links exclude fenced code examples', () => {
  const content = '[Guide](README.md)\n```powershell\n$g = ([guid](Read-Host "GUID")).ToString()\n```\n[Section](README.md#section)';
  assert.deepEqual(localLinks(content), ['README.md', 'README.md#section']);
});

for (const name of ['README.md', 'deploy/server/README.md', 'docs/aws_windows_e2e_test.md', 'docs/agent_status.md']) {
  test(`installation guide syntax and repository links: ${name}`, () => {
    const file = path.join(root, name);
    const content = fs.readFileSync(file, 'utf8');
    const blocks = [...content.matchAll(/^```(bash|powershell)\r?\n([\s\S]*?)^```/gm)];
    assert.equal((content.match(/^```/gm) || []).length % 2, 0, 'Unclosed code fence');
    for (const [index, block] of blocks.entries()) {
      // Parse only. Never evaluate a documented installer or service command.
      const program = block[1] === 'bash' ? bash : powershell;
      const args = block[1] === 'bash' ? ['-n'] : ['-NoProfile', '-NonInteractive', '-Command', parser];
      const result = spawnSync(program, args, { input: block[2].replace(/\r\n/g, '\n'), encoding: 'utf8', timeout: 15000 });
      assert.ifError(result.error);
      assert.equal(result.status, 0, `${name} block ${index + 1}: ${result.stderr}\n${result.stdout}`);
    }
    const links = localLinks(content);
    for (const link of links) assert.ok(fs.existsSync(path.resolve(path.dirname(file), link.split('#')[0])), link);
    if (name === 'docs/agent_status.md') assert.ok(content.includes('sudo python3 deploy/server/prepare-monitor.py'));
    else assert.ok(content.includes('sudo sh deploy/server/install-ubuntu.sh'));
  });
}
