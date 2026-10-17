/* Shared chrome for the static portal pages; no API or credentials required. */
(() => {
  "use strict";
  const groups = [
    { title: "보안 관제", items: [
      ["index.html", "홈 대시보드"], ["dashboard.html", "내 대시보드"], ["logs.html", "통합 로그"],
      ["cases.html", "사건 조사"]
    ] },
    { title: "에이전트", items: [
      ["agents.html", "에이전트 설치 파일"], ["agents.html#keys", "발급 키 관리"],
      ["agent-status.html", "에이전트 수신 현황"]
    ] },
    { title: "설정", items: [["settings-slack.html", "알림 연동 → Slack"], ["settings-rules.html", "탐지 규칙 관리"]] }
  ];
  function current(pathname, hash) {
    const page = pathname.split("/").pop() || "index.html";
    if (page === "workbench.html") return "cases.html";
    return page === "agents.html" && hash === "#keys" ? "agents.html#keys" : page;
  }
  function markup(pathname, hash) {
    const active = current(pathname, hash);
    const title = groups.flatMap(group => group.items).find(([href]) => href === active)?.[1] || "Cloud SOC";
    const nav = groups.map(group => {
      const links = group.items.map(([href, label]) => `<a class="nav-item${href === active ? " active" : ""}" href="${href}"${href === active ? ' aria-current="page"' : ""}>${label}</a>`).join("");
      return group.advanced ? `<details class="shell-group shell-advanced" aria-label="${group.title}"${group.items.some(([href]) => href === active) ? ' open' : ''}><summary class="nav-group">${group.title}</summary>${links}</details>` : `<section class="shell-group" aria-label="${group.title}"><h2 class="nav-group">${group.title}</h2>${links}</section>`;
    }).join("");
    return `<header class="app-header"><a class="brand" href="index.html" aria-label="Cloud SOC 홈"><img src="assets/mark.svg" alt="">Cloud SOC</a><span class="workspace-label">${title}</span><button type="button" id="portal-theme-toggle" class="shell-theme-toggle" aria-label="다크 모드로 전환" aria-pressed="false">다크 모드</button><span class="header-context">중앙 관리</span><button type="button" class="shell-toggle" aria-expanded="false" aria-controls="portal-sidebar">메뉴</button></header><aside id="portal-sidebar" class="sidebar" aria-label="공통 업무 메뉴"><nav aria-label="전체 메뉴">${nav}</nav><div class="sidebar-footer"><strong>Cloud SOC</strong></div></aside>`;
  }
  function coverageView(pipeline) {
    const normalizer = pipeline || {}, detector = normalizer.detector || {};
    let state = normalizer.coverage?.state;
    if (!state) state = [normalizer, detector].some(s => s.state === 'failed' || s.health === 'failed') ? 'blocked' :
      [normalizer, detector].some(s => s.state === 'not_started') ? 'not_started' :
      [normalizer, detector].some(s => !['success', 'running', 'waiting'].includes(s.state)) ? 'unknown' :
      [normalizer, detector].some(s => s.health === 'delayed') ? 'delayed' : detector.health === 'warning' ? 'warning' : 'observed';
    const views = {
      blocked: ['새 로그 분석 중단', '로그가 수신돼도 최신 위험 평가가 완료되지 않을 수 있습니다. 경보 0건으로 안전을 판단할 수 없습니다.'],
      delayed: ['새 로그 분석 지연', '최근 수신 로그의 분석이 따라오지 못하고 있습니다. 분석 완료 시각을 확인하세요.'],
      catching_up: ['대기 로그 분석 중', '대기 중인 로그를 이어 분석하고 있습니다. 해당 구간의 분석이 끝날 때까지 경보 수는 일부 결과입니다.'],
      not_started: ['위험 분석 미시작', '분석 서비스의 실행 기록이 없습니다. 저장된 경보 수로 현재 상태를 판단할 수 없습니다.'],
      unknown: ['분석 상태 확인 불가', '분석 상태를 확인하지 못했습니다. 연결·조회 권한·상태 보고를 확인하세요.'],
      warning: ['분석 누락 확인 필요', '일부 로그의 위험 평가가 완료되지 않았습니다. 운영 담당자의 확인이 필요합니다.'],
      observed: ['최근 분석 실행 확인', '최근 처리 상태가 보고됐습니다. 개별 수집 오류와 규칙의 지원 범위는 별도로 확인하세요.']
    };
    const initialViews = {
      initial_notice_failed: ['초기 통지 처리 확인 필요', '초기 탐지 통지 처리에 실패했습니다. 최종 탐지의 성공과 별도로 확인이 필요합니다.'],
      initial_notice_reconciliation_required: ['초기 통지 재확인 필요', '초기 통지와 최종 근거의 연결을 다시 확인해야 합니다.'],
      initial_notice_pending: ['초기 통지 처리 대기', '초기 통지의 입력 조회·전달 또는 최종 연결이 아직 완료되지 않았습니다.'],
      initial_notice_unconfirmed: ['초기 통지 상태 미확인', '초기 통지의 상태 보고를 확인하지 못했습니다. 정상 처리로 판단할 수 없습니다.']
    };
    const reason = normalizer.coverage?.reason;
    const view = state === 'warning' && Object.hasOwn(initialViews, reason) ? initialViews[reason] : views[state] || views.unknown;
    return {state: views[state] ? state : 'unknown', title: view[0], description: view[1]};
  }
  function processingView(pipeline) {
    if (!pipeline?.priority_normalizer) return null;
    const valid = n => Number.isSafeInteger(n) && n >= 0;
    const lag = worker => valid(worker?.lag_seconds) ? worker.lag_seconds.toLocaleString('ko-KR')+'초' : '미확인';
    const reported = pipeline.realtime_coverage?.state;
    const state = ['observed','warning','blocked','delayed','catching_up','not_started'].includes(reported) ? reported : 'unknown';
    const label = ({observed:'최근 실행 확인',warning:'일부 평가 확인 필요',blocked:'중단',delayed:'지연',catching_up:'따라잡는 중',not_started:'미시작'}[state] || '미확인');
    const backlog = pipeline.historical_backlog;
    const late = pipeline.late_review;
    const historicalReview = late ? ' · 늦은 로그 재평가: '+({success:'최근 실행 확인',running:'처리 중',waiting:'대기',failed:'실패',stale:'미확인'}[late.state] || '미확인')+' · 대기 범위 '+(valid(late.pending_contexts) ? late.pending_contexts.toLocaleString('ko-KR')+'개' : '미확인') : '';
    return {state,
      realtime:'실시간 분석: '+label+' · 정규화 지연 '+lag(pipeline.priority_normalizer)+' · 탐지 지연 '+lag(pipeline.priority_detector || pipeline.additional_detector || pipeline.detector),
      historical:'과거 로그: 미완료 구간 '+(backlog?.state==='ok' && valid(backlog.count) ? backlog.count.toLocaleString('ko-KR')+'건' : '미확인')+' · 처리 지연 '+lag(pipeline)+' · 처리 기록 완료 기준'+historicalReview};
  }
  if (typeof module !== "undefined" && module.exports) module.exports = { groups, current, markup, coverageView, processingView };
  if (typeof window !== "undefined") window.CloudSOCProcessing = {view: processingView};
  if (typeof document === "undefined") return;
  const root = document.getElementById("app-shell");
  if (!root) return;
  let identity = null, statusGeneration = 0, statusController;
  function permissions() {
    const allowed = identity?.navigation;
    for (const link of root.querySelectorAll('.nav-item')) {
      link.hidden = !identity || (Array.isArray(allowed) ? !allowed.includes(link.getAttribute('href')) :
        identity.role !== 'admin' && !['index.html', 'logs.html', 'cases.html'].includes(link.getAttribute('href')));
    }
    for (const group of root.querySelectorAll('.shell-group')) group.hidden = !Array.from(group.querySelectorAll('.nav-item')).some(link => !link.hidden);
  }
  async function status() {
    if (identity?.role !== 'admin' || document.body.dataset.dashboard) return;
    const main = document.querySelector('main');
    if (!main) return;
    let box = document.getElementById('portal-system-state');
    if (!box) {
      box = document.createElement('section'); box.id = 'portal-system-state'; box.className = 'system-status';
      box.setAttribute('role', 'status'); box.setAttribute('aria-live', 'polite'); main.prepend(box);
    }
    const version = ++statusGeneration;
    statusController?.abort(); statusController = new AbortController();
    const requestController = statusController;
    const timer = setTimeout(() => requestController.abort(), 10000);
    let view;
    try {
      const response = await window.fetch('/api/operations/status', {cache: 'no-store', credentials: 'same-origin', signal: statusController.signal});
      if (!response.ok) throw new Error('unavailable');
      view = coverageView(await response.json());
    } catch { view = coverageView(null); }
    finally { clearTimeout(timer); }
    if (version !== statusGeneration) return;
    box.replaceChildren(); box.dataset.state = view.state;
    const heading = document.createElement('strong'); heading.textContent = view.title;
    const description = document.createElement('p'); description.textContent = view.description;
    box.hidden = view.state === 'observed';
    box.append(heading, description);
  }
  function syncTheme() {
    const button = root.querySelector('#portal-theme-toggle');
    if (!button) return;
    const dark = window.CloudSOCTheme?.get() === 'dark';
    button.textContent = dark ? '화이트 모드' : '다크 모드';
    button.setAttribute('aria-label', button.textContent + '로 전환');
    button.setAttribute('aria-pressed', String(dark));
  }
  window.addEventListener('cloud-soc-themechange', syncTheme);
  function render() {
    root.innerHTML = markup(window.location.pathname, window.location.hash);
    permissions();
    syncTheme();
    root.querySelector('#portal-theme-toggle').addEventListener('click', () => {
      window.CloudSOCTheme?.set(window.CloudSOCTheme.get() === 'dark' ? 'light' : 'dark');
    });
    const toggle = root.querySelector(".shell-toggle");
    const sidebar = root.querySelector(".sidebar");
    function close(focus) {
      sidebar.classList.remove("is-open");
      toggle.setAttribute("aria-expanded", "false");
      if (focus) toggle.focus();
    }
    toggle.addEventListener("click", () => {
      const open = toggle.getAttribute("aria-expanded") !== "true";
      toggle.setAttribute("aria-expanded", String(open));
      sidebar.classList.toggle("is-open", open);
    });
    root.addEventListener("keydown", event => {
      if (event.key === "Escape" && toggle.getAttribute("aria-expanded") === "true") {
        close(true);
      }
    }, { once: false, signal: controller.signal });
    sidebar.addEventListener("click", event => { if (event.target.closest("a")) close(false); });
  }
  let controller = new AbortController();
  function refresh() { controller.abort(); controller = new AbortController(); render(); }
  refresh();
  window.portalIdentity?.then(user => {
    identity = user; permissions(); status();
    if (!user) {
      const main = document.querySelector('main');
      if (main) {
        const notice = document.createElement('p'); notice.className = 'system-status';
        notice.setAttribute('role', 'alert'); notice.textContent = '로그인 상태를 확인하지 못했습니다. 다시 로그인하거나 페이지를 새로고침하세요.';
        const link = document.createElement('a'); link.href = '/login'; link.textContent = '로그인 확인'; notice.append(' ', link); main.prepend(notice);
      }
    }
  });
  const statusTimer = setInterval(status, 30000);
  window.addEventListener('pagehide', () => {clearInterval(statusTimer); statusGeneration++; statusController?.abort();});
  window.addEventListener("hashchange", refresh);
})();
