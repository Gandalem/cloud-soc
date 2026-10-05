const SocKeyHistory = (() => {
  const escape = value => String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  const date = value => value != null && Number.isFinite(new Date(value).getTime()) ? new Intl.DateTimeFormat('ko-KR', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value)) : '기록 없음';
  const scopes = { host: 'Filebeat · 로그 수집', network: 'Packetbeat · 네트워크 수집' };
  const statuses = { unverified: '서버 확인 전', active: '유효 (마지막 확인 기준)', expired: '만료', revoked: '폐기 완료', missing: '서버에서 찾지 못함', unavailable: '서버 확인 실패' };
  const scope = key => Object.hasOwn(scopes, key.scope) ? scopes[key.scope] : '용도 미확인 · 서버 확인 필요';
  function rows(keys, query, filter) {
    const search = query.trim().toLowerCase();
    return keys.filter(key => (filter === 'all' || (filter === 'not_revoked' ? key.status !== 'revoked' : key.status === filter)) &&
      [key.id, key.package_id, key.package_name, key.package_os, key.organization, key.target_label, scope(key)].join(' ').toLowerCase().includes(search));
  }
  function markup(key, busy = false, confirming = false) {
    const status = Object.hasOwn(statuses, key.status) ? key.status : 'unverified';
    return `<article class="history-row" data-key="${escape(key.id)}"><div class="history-heading"><strong>${escape(scope(key))}</strong><span class="key-state ${status}">${statuses[status]}</span></div>
      <p>${escape(key.package_name || '패키지 정보 없음')} · ${escape(key.package_os || 'OS 미확인')} · 조직 ${escape(key.organization || '미확인')}</p>
      <label class="key-label">대상 별칭 (직접 입력)<input data-target-label maxlength="100" value="${escape(key.target_label || '')}" placeholder="예: VMware 실습 Windows 01" ${busy ? 'disabled' : ''}></label>
      <small>발급 ${escape(date(key.created_at))} · 만료 ${escape(date(key.expiration))}</small>
      <small>서버 조회 ${escape(date(key.checked_at))}${key.revoked_at ? ` · 폐기 확인 ${escape(date(key.revoked_at))}` : ''}</small>
      <details><summary>키 ID / 패키지 ID</summary><code>${escape(key.id)}</code><code>${escape(key.package_id)}</code></details>
      <div class="key-actions"><button data-key-action="label" ${busy ? 'disabled' : ''}>별칭 저장</button><button data-key-action="check" ${busy ? 'disabled' : ''}>서버 확인</button><button data-key-action="revoke" class="danger-button" ${busy || status === 'revoked' ? 'disabled' : ''}>${status === 'revoked' ? '폐기 완료' : '키 폐기 (사용 중지)'}</button></div>
      ${confirming ? `<div class="key-confirm" role="alert"><strong>${escape(key.target_label || '대상 미지정')} / ${escape(scope(key))}</strong><p>이 키를 사용하는 수집기의 전송이 중단됩니다. 키 ID를 확인하세요. 이력은 삭제하지 않습니다.</p><code>${escape(key.id)}</code><div class="key-actions"><button data-key-action="cancel-revoke" ${busy ? 'disabled' : ''}>취소</button><button data-key-action="confirm-revoke" class="danger-button" ${busy ? 'disabled' : ''}>확인 후 키 폐기</button></div></div>` : ''}</article>`;
  }
  return { rows, markup, scope };
})();
if (typeof module !== 'undefined') module.exports = SocKeyHistory;

(() => {
  'use strict';
  if (typeof document === 'undefined') return;
  const $ = selector => document.querySelector(selector);
  const escape = value => String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  const state = { packages: [], selected: new Set(), page: 1, size: 25, detail: null, pendingDelete: [], keyPackage: null, keyGeneration: 0, loadGeneration: 0, keys: [], historyGeneration: 0, keyBusy: new Set(), keyDrafts: new Map(), pendingRevoke: null, enrollmentEnabled: false, enrollmentPackage: null, enrollmentGeneration: 0 };
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
    if (item.os === 'windows') {
      const enroll = state.enrollmentEnabled && item.enrollment_protocol === 1;
      return `# 관리자 PowerShell, 다운로드 폴더에서 실행${enroll ? '\n# 먼저 포털의 설치 토큰을 발급. 토큰은 실행 후 숨김 입력 창에 붙여 넣기' : ''}\n& {\n$ErrorActionPreference = 'Stop'\nif ((Get-FileHash -LiteralPath '.\\${item.filename}' -Algorithm SHA256).Hash -ne '${item.sha256}') { throw 'SHA-256 mismatch; stop installation.' }\nExpand-Archive -LiteralPath '.\\${item.filename}' -DestinationPath '.\\${directory}'\nSet-Location '.\\${directory}'\n${item.network ? '# 승인된 Npcap을 먼저 준비. 표시되는 활성 물리 NIC를 확인해 선택\n' : ''}.\\install.ps1${enroll ? ` -Enroll -PackageSha256 '${item.sha256}'` : ''}\n}\n# 새 패키지 기준. 가상/VPN NIC는 -InterfaceGuid를 명시\n# 먼저 설정만 확인하려면 install.ps1 명령에 -DryRun 추가`;
    }
    const enroll = state.enrollmentEnabled && item.enrollment_protocol === 1;
    return `# 다운로드 폴더에서 실행. 공백 없는 경로를 사용${enroll ? '\n# 먼저 포털에서 토큰 발급. 실행 후 숨김 입력 창에 붙여 넣기' : ''}\n(\nset -e\nprintf '%s  %s\\n' '${item.sha256}' '${item.filename}' | sha256sum --check\nmkdir '${directory}'\ntar -xzf '${item.filename}' -C '${directory}'\ncd '${directory}'\n${item.network ? 'ip -brief link\n# ens3를 실제 수집 NIC로 교체 (전체 로컬 NIC는 any를 명시)\n' : ''}sudo bash install.sh${enroll ? ` --enroll --package-sha256 '${item.sha256}'` : ''}${item.network ? ' --interface ens3' : ''}\n)\n# 먼저 설정만 확인하려면 install.sh 명령에 --dry-run 추가`;
  }
  function render() {
    const query = $('#package-search').value.trim().toLowerCase();
    const rows = state.packages.filter(item => `${item.filename} ${item.organization}`.toLowerCase().includes(query));
    const pages = Math.max(1, Math.ceil(rows.length / state.size));
    state.page = Math.min(state.page, pages);
    const page = rows.slice((state.page - 1) * state.size, state.page * state.size);
    $('#package-total').textContent = `전체 ${state.packages.length}개 · 검색 ${rows.length}개`;
    $('#package-rows').innerHTML = page.map(item => `<tr><td><input type="checkbox" data-select="${item.id}" aria-label="${escape(item.filename)} 선택" ${state.selected.has(item.id) ? 'checked' : ''}></td><td><span class="os-tag ${item.os === 'ubuntu' ? 'ubuntu' : ''}">${item.os === 'ubuntu' ? 'UBUNTU' : 'WINDOWS'}</span></td><td><button class="file-name" data-info="${item.id}">${escape(item.filename)}</button></td><td title="${escape(item.endpoint)}">${escape(item.endpoint)}</td><td>${escape(item.organization)}</td><td>${item.network ? '로그 + 네트워크' : '로그'}</td><td>${escape(item.version)}</td><td>${escape(date(item.created_at))}</td><td><div class="package-actions"><a href="/api/packages/${item.id}/download" download>다운로드</a><button data-command="${item.id}">설치 명령</button>${state.enrollmentEnabled && item.enrollment_protocol === 1 ? `<button data-enrollment="${item.id}">설치 토큰</button>` : ''}<button data-keys="${item.id}">수동 키 발급</button><button data-delete="${item.id}" aria-label="${escape(item.filename)} 삭제">삭제</button></div></td></tr>`).join('');
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
      state.enrollmentEnabled = data.enrollment_enabled === true;
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
    $('#delete-error').hidden = true;
    $('#delete-description').textContent = `선택한 설치 패키지 ${ids.length}개를 삭제합니다. 이 작업은 되돌릴 수 없습니다.`;
    $('#delete-dialog').showModal();
  }
  function openKeys(id) {
    state.keyPackage = id;
    $('#key-target').value = '';
    $('#key-package-name').textContent = state.packages.find(item => item.id === id)?.filename || id;
    $('#issued-keys').replaceChildren();
    $('#key-message').textContent = '';
    $('#issue-keys').disabled = false;
    $('#keys-dialog').showModal();
  }
  function renderHistory() {
    const keys = SocKeyHistory.rows(state.keys, $('#history-search').value, $('#history-filter').value);
    $('#history-count').textContent = `최근 ${state.keys.length}개 중 ${keys.length}개 표시`;
    $('#history-content').innerHTML = keys.length ? keys.map(key => SocKeyHistory.markup({ ...key, target_label: state.keyDrafts.get(key.id) ?? key.target_label }, state.keyBusy.has(key.id), state.pendingRevoke === key.id)).join('') : '<p>표시할 발급 이력이 없습니다.</p>';
  }
  async function history() {
    const generation = ++state.historyGeneration;
    state.pendingRevoke = null;
    state.keys = [];
    $('#history-message').textContent = '';
    $('#history-count').textContent = '';
    $('#history-content').textContent = '불러오는 중';
    if (!$('#history-dialog').open) $('#history-dialog').showModal();
    try {
      const { keys } = await api('/api/keys');
      if (generation !== state.historyGeneration) return;
      state.keys = keys; renderHistory();
    } catch (error) { if (generation === state.historyGeneration) $('#history-content').textContent = error.message; }
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
    if (button.dataset.enrollment) openEnrollment(button.dataset.enrollment);
  });
  async function enrollmentHistory(generation) {
    try {
      const data = await api('/api/enrollments');
      if (generation !== state.enrollmentGeneration || !$('#enrollment-dialog').open) return;
      const labels = { unused: '사용 전', issuing: '발급 진행 / 중단 확인 필요', issued: '키 전달 · 중앙 수신 대기', complete: '중앙 수신 확인 완료', cancelled: '취소·폐기 확인', expired: '토큰 만료', cleanup_pending: '키 폐기 확인 필요' };
      $('#enrollment-history').innerHTML = data.enrollments.filter(item => item.package_id === state.enrollmentPackage).map(item =>
        `<article class="history-row"><strong>${escape(item.target_label || '대상 미지정')}</strong><p>${escape(labels[item.state] || '상태 미확인')} · 토큰 만료 ${escape(date(item.expires * 1000))}</p><code>${escape(item.id)}</code>${['unused','issuing','issued','cleanup_pending'].includes(item.state) ? `<button data-cancel-enrollment="${escape(item.id)}" class="danger-button">설치 취소 · 발급 키 폐기</button>` : ''}</article>`).join('') || '<p>이 패키지의 설치 토큰 이력이 없습니다.</p>';
    } catch { if (generation === state.enrollmentGeneration) $('#enrollment-history').textContent = '토큰 이력을 확인하지 못했습니다. 새 발급을 반복하기 전에 다시 조회하세요.'; }
  }
  function openEnrollment(id) {
    const item = state.packages.find(row => row.id === id);
    if (!item || !state.enrollmentEnabled || item.enrollment_protocol !== 1) return;
    state.enrollmentPackage = id;
    const generation = ++state.enrollmentGeneration;
    $('#enrollment-package').textContent = item.filename;
    $('#enrollment-token').value = '';
    $('#enrollment-target').value = '';
    $('#enrollment-message').textContent = '신규 설치에 토큰 한 개를 입력합니다. 확인된 실패 설치는 새 토큰과 Windows -ReEnroll / Ubuntu --reenroll로 재등록하세요. 정상 설치·일반 복구·갱신에는 사용하지 마세요.';
    $('#mint-enrollment').disabled = false;
    $('#enrollment-command').textContent = item.os === 'ubuntu'
      ? `sudo bash install.sh --enroll --package-sha256 '${item.sha256}'${item.network ? ' --interface <수집할-NIC>' : ''}`
      : `.\\install.ps1 -Enroll -PackageSha256 '${item.sha256}'`;
    $('#enrollment-dialog').showModal();
    enrollmentHistory(generation);
  }
  $('#mint-enrollment').addEventListener('click', async () => {
    const generation = state.enrollmentGeneration;
    $('#mint-enrollment').disabled = true;
    $('#enrollment-message').textContent = '일회용 설치 토큰 발급 중';
    try {
      const result = await api(`/api/packages/${state.enrollmentPackage}/enrollment`, {method: 'POST', data: { days: Number($('#enrollment-days').value), target_label: $('#enrollment-target').value }});
      if (generation !== state.enrollmentGeneration) return;
      $('#enrollment-token').value = result.token;
      $('#enrollment-message').textContent = `${result.warning} 만료: ${date(result.expires * 1000)}`;
      enrollmentHistory(generation);
    } catch (error) { if (generation === state.enrollmentGeneration) { $('#enrollment-message').textContent = error.message; $('#mint-enrollment').disabled = false; } }
  });
  $('#copy-enrollment').addEventListener('click', () => { if ($('#enrollment-token').value) copy($('#enrollment-token').value); });
  $('#refresh-enrollment').addEventListener('click', () => enrollmentHistory(state.enrollmentGeneration));
  $('#enrollment-history').addEventListener('click', async event => {
    const button = event.target.closest('[data-cancel-enrollment]');
    if (!button || !window.confirm('이 설치를 취소하고 발급된 로그·네트워크 키를 폐기할까요? 해당 키의 전송이 중단됩니다.')) return;
    const generation = state.enrollmentGeneration;
    button.disabled = true;
    try {
      await api(`/api/enrollments/${encodeURIComponent(button.dataset.cancelEnrollment)}/cancel`, {method: 'POST', data: {}});
      if (generation !== state.enrollmentGeneration) return;
      $('#enrollment-token').value = '';
      $('#enrollment-message').textContent = '취소·키 폐기를 확인했습니다. 재설치 전에 보존된 설치 상태를 확인하세요.';
    } catch (error) { if (generation === state.enrollmentGeneration) $('#enrollment-message').textContent = error.message; }
    finally { if (generation === state.enrollmentGeneration) enrollmentHistory(generation); }
  });
  $('#enrollment-dialog').addEventListener('close', () => { state.enrollmentGeneration++; $('#enrollment-token').value = ''; $('#enrollment-message').textContent = ''; });
  $('#delete-selected').addEventListener('click', () => confirmDelete([...state.selected]));
  $('#confirm-delete').addEventListener('click', async () => {
    $('#confirm-delete').disabled = true;
    $('#delete-error').hidden = true;
    let removed = 0;
    try { for (const id of state.pendingDelete) { await api(`/api/packages/${id}`, { method: 'DELETE' }); removed++; } $('#delete-dialog').close(); toast(`${removed}개 패키지를 삭제했습니다. 에이전트와 키는 유지됩니다.`); }
    catch (error) { state.pendingDelete = state.pendingDelete.slice(removed); $('#delete-error').textContent = `${removed}개 삭제 후 중단: ${error.message} 남은 ${state.pendingDelete.length}개만 재시도합니다.`; $('#delete-error').hidden = false; }
    finally { $('#confirm-delete').disabled = false; await load(); }
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
      const data = await api(`/api/packages/${state.keyPackage}/keys`, { method: 'POST', data: { days: Number($('#key-days').value), target_label: $('#key-target').value } });
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
  $('#key-history').addEventListener('click', () => {
    if (window.location.hash === '#keys') return history();
    window.location.hash = 'keys';
  });
  function routeHistory() {
    if (window.location.hash === '#keys') history();
    else if ($('#history-dialog').open) $('#history-dialog').close();
  }
  window.addEventListener('hashchange', routeHistory);
  $('#history-refresh').addEventListener('click', history);
  $('#history-search').addEventListener('input', renderHistory);
  $('#history-filter').addEventListener('change', renderHistory);
  $('#history-dialog').addEventListener('close', () => {
    state.historyGeneration++;
    if (window.location.hash === '#keys') {
      window.history.replaceState(null, '', window.location.pathname + window.location.search);
      window.dispatchEvent(new Event('hashchange'));
    }
  });
  $('#history-content').addEventListener('input', event => {
    if (event.target.matches('[data-target-label]')) state.keyDrafts.set(event.target.closest('[data-key]').dataset.key, event.target.value);
  });
  $('#history-content').addEventListener('click', async event => {
    const button = event.target.closest('[data-key-action]'); if (!button) return;
    const card = button.closest('[data-key]'), id = card.dataset.key;
    const key = state.keys.find(item => item.id === id);
    let action = button.dataset.keyAction;
    if (!key || state.keyBusy.has(id)) return;
    if (action === 'revoke' || action === 'cancel-revoke') {
      state.pendingRevoke = action === 'revoke' ? id : null; renderHistory();
      $('#history-message').textContent = '';
      if (action === 'revoke') $('#history-content').querySelector('[data-key-action="confirm-revoke"]').focus();
      return;
    }
    if (action === 'confirm-revoke') {
      if (state.pendingRevoke !== id) return;
      action = 'revoke';
    }
    const label = card.querySelector('[data-target-label]').value;
    const generation = state.historyGeneration;
    state.keyBusy.add(id); renderHistory(); $('#history-message').textContent = '처리 중…';
    try {
      const data = await api(`/api/keys/${encodeURIComponent(id)}${action === 'label' ? '' : `/${action}`}`, { method: action === 'label' ? 'PATCH' : 'POST', ...(action === 'label' ? { data: { target_label: label } } : {}) });
      if (generation !== state.historyGeneration) return;
      state.keys = state.keys.map(item => item.id === id ? data.key : item);
      if (action === 'revoke') state.pendingRevoke = null;
      if (action === 'label' && state.keyDrafts.get(id) === label) state.keyDrafts.delete(id);
      $('#history-message').textContent = action === 'revoke' ? '키 폐기를 확인했습니다. 사용은 중지되며 감사 이력은 보존됩니다.' : action === 'label' ? '대상 별칭을 저장했습니다. 실제 설치 대상의 자동 확인은 아닙니다.' : '서버 조회 결과를 반영했습니다. 실제 수집 성공을 뜻하지 않습니다.';
    } catch (error) {
      if (generation !== state.historyGeneration) return;
      if (action === 'check') state.keys = state.keys.map(item => item.id === id && !item.revoked_at ? { ...item, status: 'unavailable' } : item);
      $('#history-message').textContent = `${SocKeyHistory.scope(key)} · ${key.target_label || id}: ${error.message}`;
    } finally { state.keyBusy.delete(id); if ($('#history-dialog').open) renderHistory(); }
  });
  $('#delete-dialog').addEventListener('cancel', event => { if ($('#confirm-delete').disabled) event.preventDefault(); });
  document.querySelectorAll('[data-close]').forEach(button => button.addEventListener('click', () => { if (button.dataset.close !== 'delete-dialog' || !$('#confirm-delete').disabled) document.getElementById(button.dataset.close).close(); }));
  load();
  routeHistory();
})();
