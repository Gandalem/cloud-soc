(() => {
  'use strict';
  const $ = selector => document.querySelector(selector);
  const escape = value => String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  const state = { packages: [], selected: new Set(), page: 1, size: 25, detail: null, pendingDelete: [], keyPackage: null, keyGeneration: 0, loadGeneration: 0 };
  let toastTimer;
  function toast(text) { $('#agent-toast').textContent = text; $('#agent-toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('#agent-toast').hidden = true; }, 4500); }
  const date = value => new Intl.DateTimeFormat('ko-KR', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value));
  async function api(url, { method = 'GET', data, signal } = {}) {
    const response = await fetch(url, { method, credentials: 'same-origin', cache: 'no-store', signal,
      headers: method === 'GET' ? {} : { 'Content-Type': 'application/json', 'X-Cloud-SOC': 'portal' },
      ...(method === 'GET' ? {} : { body: JSON.stringify(data ?? {}) }) });
    const json = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(json.error || (response.status === 401 ? '관리자 로그인이 필요합니다.' : `요청 실패 (${response.status})`));
    return json;
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); toast('복사했습니다.'); }
    catch { toast('클립보드 접근이 차단되었습니다. 표시된 텍스트를 선택해 복사하세요.'); }
  }
  function commands(item) {
    const directory = `${item.name}-agent`;
    if (item.os === 'windows') return `# 관리자 PowerShell, 다운로드 폴더에서 실행\n& {\n$ErrorActionPreference = 'Stop'\nif ((Get-FileHash -LiteralPath '.\\${item.filename}' -Algorithm SHA256).Hash -ne '${item.sha256}') { throw 'SHA-256 mismatch; stop installation.' }\nExpand-Archive -LiteralPath '.\\${item.filename}' -DestinationPath '.\\${directory}'\nSet-Location '.\\${directory}'\n${item.network ? "Get-NetAdapter -IncludeHidden | Select-Object Name, Status, InterfaceGuid\n# 아래 GUID를 실제 수집 NIC GUID로 교체하고, Npcap을 먼저 준비\n.\\install.ps1 -InterfaceGuid '실제-NIC-GUID'" : '.\\install.ps1'}\n}\n# 먼저 설정만 확인하려면 install.ps1 명령에 -DryRun 추가`;
    return `# 다운로드 폴더에서 실행. 공백 없는 경로를 사용\n(\nset -e\nprintf '%s  %s\\n' '${item.sha256}' '${item.filename}' | sha256sum --check\nmkdir '${directory}'\ntar -xzf '${item.filename}' -C '${directory}'\ncd '${directory}'\n${item.network ? "ip -brief link\n# ens3를 실제 수집 NIC로 교체 (전체 로컬 NIC는 any를 명시)\nsudo bash install.sh --interface ens3" : 'sudo bash install.sh'}\n)\n# 먼저 설정만 확인하려면 install.sh 명령에 --dry-run 추가`;
  }
  function render() {
    const query = $('#package-search').value.trim().toLowerCase();
    const rows = state.packages.filter(item => `${item.filename} ${item.organization}`.toLowerCase().includes(query));
    const pages = Math.max(1, Math.ceil(rows.length / state.size));
    state.page = Math.min(state.page, pages);
    const page = rows.slice((state.page - 1) * state.size, state.page * state.size);
    $('#package-total').textContent = `전체 ${state.packages.length}개 · 검색 ${rows.length}개`;
    $('#package-rows').innerHTML = page.map(item => `<tr><td><input type="checkbox" data-select="${item.id}" aria-label="${escape(item.filename)} 선택" ${state.selected.has(item.id) ? 'checked' : ''}></td><td><span class="os-tag ${item.os === 'ubuntu' ? 'ubuntu' : ''}">${item.os === 'ubuntu' ? 'UBUNTU' : 'WINDOWS'}</span></td><td><button class="file-name" data-info="${item.id}">${escape(item.filename)}</button></td><td title="${escape(item.endpoint)}">${escape(item.endpoint)}</td><td>${escape(item.organization)}</td><td>${item.network ? '로그 + 네트워크' : '로그'}</td><td>${escape(item.version)}</td><td>${escape(date(item.created_at))}</td><td><div class="package-actions"><a href="/api/packages/${item.id}/download" download>다운로드</a><button data-command="${item.id}">설치 명령</button><button data-keys="${item.id}">키 발급</button><button data-delete="${item.id}" aria-label="${escape(item.filename)} 삭제">삭제</button></div></td></tr>`).join('');
    $('#empty-state').hidden = rows.length !== 0;
    $('#empty-state strong').textContent = state.packages.length ? '검색 결과가 없습니다.' : '등록된 설치 파일이 없습니다.';
    $('#page-number').textContent = `${state.page} / ${pages}`;
    $('#previous-page').disabled = state.page <= 1;
    $('#next-page').disabled = state.page >= pages;
    $('#delete-selected').disabled = state.selected.size === 0;
    $('#select-all').checked = page.length > 0 && page.every(item => state.selected.has(item.id));
    $('#select-all').indeterminate = page.some(item => state.selected.has(item.id)) && !$('#select-all').checked;
    $('#select-all').dataset.ids = page.map(item => item.id).join(',');
  }
  async function load() {
    const generation = ++state.loadGeneration;
    $('#refresh').disabled = true;
    $('#add-package').disabled = true;
    $('#page-message').hidden = true;
    try {
      const data = await api('/api/portal');
      if (generation !== state.loadGeneration) return;
      state.packages = data.packages;
      state.selected = new Set([...state.selected].filter(id => state.packages.some(item => item.id === id)));
      $('#server-endpoint').textContent = data.endpoint;
      $('#form-endpoint').value = data.endpoint;
      $('#form-endpoint').defaultValue = data.endpoint;
      $('#beat-version').textContent = data.version;
      $('#server-status').textContent = data.elasticsearch === 'connected' ? '연결 확인' : '연결 확인 실패';
      $('#server-status').className = data.elasticsearch === 'connected' ? 'status-ok' : 'status-error';
      $('#add-package').disabled = false;
      if (data.elasticsearch !== 'connected') {
        $('#page-message').hidden = false;
        $('#page-message').textContent = '패키지는 생성할 수 있지만 Elasticsearch 연결을 확인하지 못했습니다. 키 발급과 실제 수집은 서버 연결을 복구한 후 확인하세요.';
      }
      render();
    } catch (error) {
      if (generation !== state.loadGeneration) return;
      $('#page-message').hidden = false;
      $('#page-message').textContent = `서버 조회 실패: ${error.message} 이 화면은 중앙 서버에서 열어야 하며, 정적 파일 미리보기는 API에 연결되지 않습니다. 기존 표시 데이터는 최신으로 간주하지 마세요.`;
      $('#server-status').textContent = '확인 불가';
      $('#server-status').className = 'status-error';
    } finally { if (generation === state.loadGeneration) $('#refresh').disabled = false; }
  }
  function detail(identifier) {
    const item = state.packages.find(row => row.id === identifier);
    if (!item) return;
    state.detail = item;
    $('#detail-title').textContent = item.filename;
    const fields = [['운영체제', item.os === 'ubuntu' ? 'Ubuntu 22.04 · x86_64 / ARM64' : 'Windows x86_64'], ['수신 서버', item.endpoint], ['조직', item.organization], ['생성 시각', date(item.created_at)], ['SHA-256', item.sha256], ['설명', item.description || '없음']];
    $('#package-info').innerHTML = fields.map(([name, value]) => `<dt>${escape(name)}</dt><dd>${escape(value)}</dd>`).join('');
    $('#install-command').textContent = commands(item);
    $('#detail-download').href = `/api/packages/${item.id}/download`;
    $('#detail-dialog').showModal();
  }
  function setFormOS() {
    const windows = $('#package-form input[name=os]:checked').value === 'windows';
    $('#filename-suffix').textContent = windows ? '-setup.zip' : '-setup.tar.gz';
    const network = $('#package-form input[name=network]').checked;
    $('#install-path').textContent = windows ? `%ProgramFiles%\\Cloud-SOC-Agent${network ? ' (+ Cloud-SOC-Network)' : ''}` : `/opt/cloud-soc-agent${network ? ' (+ /opt/cloud-soc-network)' : ''}`;
  }
  function confirmDelete(ids) {
    state.pendingDelete = ids;
    $('#delete-description').textContent = `선택한 설치 패키지 ${ids.length}개를 삭제합니다. 이 작업은 되돌릴 수 없습니다.`;
    $('#delete-dialog').showModal();
  }
  function openKeys(id) {
    state.keyPackage = id;
    $('#issued-keys').replaceChildren();
    $('#key-message').textContent = '';
    $('#issue-keys').disabled = false;
    $('#keys-dialog').showModal();
  }
  async function history() {
    $('#history-content').textContent = '불러오는 중';
    $('#history-dialog').showModal();
    try {
      const { keys } = await api('/api/keys');
      $('#history-content').innerHTML = keys.length ? keys.map(key => `<div class="history-row"><div><code>${escape(key.id)}</code><small>${escape(date(key.created_at))} · 패키지 ${escape(key.package_id)}</small></div><button data-revoke="${escape(key.id)}">폐기</button></div>`).join('') : '<p>발급 이력이 없습니다.</p>';
    } catch (error) { $('#history-content').textContent = error.message; }
  }
  $('#refresh').addEventListener('click', load);
  $('#package-search').addEventListener('input', () => { state.page = 1; render(); });
  $('#page-size').addEventListener('change', event => { state.size = Number(event.target.value); state.page = 1; render(); });
  $('#previous-page').addEventListener('click', () => { state.page--; render(); });
  $('#next-page').addEventListener('click', () => { state.page++; render(); });
  $('#select-all').addEventListener('change', event => { for (const id of event.target.dataset.ids.split(',').filter(Boolean)) { if (event.target.checked) state.selected.add(id); else state.selected.delete(id); } render(); });
  $('#package-rows').addEventListener('change', event => { const id = event.target.dataset.select; if (!id) return; if (event.target.checked) state.selected.add(id); else state.selected.delete(id); render(); });
  $('#package-rows').addEventListener('click', event => {
    const button = event.target.closest('button'); if (!button) return;
    if (button.dataset.info || button.dataset.command) detail(button.dataset.info || button.dataset.command);
    if (button.dataset.delete) confirmDelete([button.dataset.delete]);
    if (button.dataset.keys) openKeys(button.dataset.keys);
  });
  $('#delete-selected').addEventListener('click', () => confirmDelete([...state.selected]));
  $('#confirm-delete').addEventListener('click', async () => {
    $('#confirm-delete').disabled = true;
    let removed = 0;
    try { for (const id of state.pendingDelete) { await api(`/api/packages/${id}`, { method: 'DELETE' }); removed++; } toast(`${removed}개 패키지를 삭제했습니다. 에이전트와 키는 유지됩니다.`); }
    catch (error) { toast(`${removed}개 삭제 후 중단: ${error.message}`); }
    finally { $('#confirm-delete').disabled = false; $('#delete-dialog').close(); await load(); }
  });
  $('#add-package').addEventListener('click', () => { $('#package-form').reset(); setFormOS(); $('#form-error').hidden = true; $('#add-dialog').showModal(); });
  document.querySelectorAll('input[name=os]').forEach(input => input.addEventListener('change', setFormOS));
  $('#package-form input[name=network]').addEventListener('change', setFormOS);
  $('#package-form').addEventListener('submit', async event => {
    event.preventDefault(); const form = new FormData(event.target);
    $('#create-submit').disabled = true; $('#form-error').hidden = true;
    try {
      const item = await api('/api/packages', { method: 'POST', data: { name: form.get('name'), os: form.get('os'), organization: form.get('organization'), description: form.get('description'), network: form.get('network') === 'on' } });
      $('#add-dialog').close(); await load(); detail(item.id);
    } catch (error) { $('#form-error').textContent = error.message; $('#form-error').hidden = false; }
    finally { $('#create-submit').disabled = false; }
  });
  $('#copy-command').addEventListener('click', () => copy($('#install-command').textContent));
  $('#issue-keys').addEventListener('click', async () => {
    const generation = ++state.keyGeneration;
    $('#issue-keys').disabled = true; $('#key-message').textContent = '발급 중';
    try {
      const data = await api(`/api/packages/${state.keyPackage}/keys`, { method: 'POST', data: { days: Number($('#key-days').value) } });
      if (generation !== state.keyGeneration || !$('#keys-dialog').open) return;
      $('#issued-keys').replaceChildren();
      for (const key of data.keys) {
        const block = document.createElement('section'); block.className = 'key-item';
        const title = document.createElement('h3'); title.textContent = key.scope === 'host' ? 'Filebeat 로그 수집 키' : 'Packetbeat 네트워크 수집 키';
        const input = document.createElement('input'); input.type = 'password'; input.readOnly = true; input.value = key.key; input.setAttribute('aria-label', title.textContent);
        const button = document.createElement('button'); button.textContent = '키 복사'; button.addEventListener('click', () => copy(input.value));
        const info = document.createElement('small'); info.textContent = `키 ID: ${key.id} · 만료: ${key.expiration ? date(key.expiration) : '서버 확인 필요'}`;
        block.append(title, input, button, info); $('#issued-keys').append(block);
      }
      $('#key-message').textContent = data.warning;
    } catch (error) { if (generation === state.keyGeneration) { $('#key-message').textContent = error.message; $('#issue-keys').disabled = false; } }
  });
  $('#keys-dialog').addEventListener('close', () => { state.keyGeneration++; $('#issued-keys').replaceChildren(); $('#key-message').textContent = ''; });
  $('#key-history').addEventListener('click', history);
  $('#mobile-key-history').addEventListener('click', history);
  $('#history-content').addEventListener('click', async event => {
    const button = event.target.closest('[data-revoke]'); if (!button) return;
    if (!window.confirm('이 키를 폐기하면 해당 키를 사용하는 수집기의 전송이 중단됩니다. 계속할까요?')) return;
    button.disabled = true;
    try { await api(`/api/keys/${encodeURIComponent(button.dataset.revoke)}/revoke`, { method: 'POST' }); button.textContent = '폐기 확인'; }
    catch (error) { toast(error.message); button.disabled = false; }
  });
  document.querySelectorAll('[data-close]').forEach(button => button.addEventListener('click', () => document.getElementById(button.dataset.close).close()));
  load();
})();
