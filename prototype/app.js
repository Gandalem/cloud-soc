(() => {
  "use strict";
  const demo = window.CloudSocDemo;
  const page = document.body.dataset.page;
  const params = new URLSearchParams(location.search);
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[character]));
  // Translate presentation only; filter values, references and raw records stay unchanged.
  const labels = {
    Critical: "긴급", High: "높음", Medium: "보통", Low: "낮음",
    New: "신규", Investigating: "조사 중", Triage: "초기 분류", Escalated: "상위 이관", Closed: "종결",
    Incident: "사건", Alert: "경보", Unassigned: "미배정", analyst01: "분석가 01", analyst02: "분석가 02",
    Authentication: "인증", Cloud: "클라우드", Host: "호스트", User: "사용자",
    "Source IP": "출발지 IP", "Cloud Account": "클라우드 계정", "Cloud Resource": "클라우드 자원",
    Malicious: "악성", Benign: "정상", "False Positive": "오탐", Inconclusive: "판단 유보",
    EVIDENCE: "탐지 근거", RELATED: "관련 활동", TRIGGER: "탐지 발생",
    "SSH Brute Force": "SSH 무차별 대입", "Cloud Policy Change": "클라우드 정책 변경",
    "Authentication Failure Review": "인증 실패 검토", "Privileged Execution Review": "특권 실행 검토",
    "Configuration Change Review": "설정 변경 검토", "Grouped Threshold": "그룹별 임계치",
    "Single Event (demo only)": "단일 이벤트 (데모)", "10 matching events": "일치 이벤트 10건",
    "1 matching event": "일치 이벤트 1건", "300 seconds": "300초", "Single event / N/A": "단일 이벤트 / 해당 없음",
    "Successful Login": "로그인 성공", "Related API Activity": "관련 API 활동", "Related Host Activity": "관련 호스트 활동",
    "Linux Authentication": "리눅스 인증", "Cloud Audit (synthetic)": "클라우드 감사 (합성)",
    "Host Activity (synthetic)": "호스트 활동 (합성)", "Not observed": "관측되지 않음",
    "Not observed in this demo": "이 데모에서 관측되지 않음", "linux_auth (demo label)": "linux_auth (데모 명칭)",
    "Not implemented / demo representation": "미구현 / 데모 표시", ssh_login: "SSH 로그인",
    demo_policy_change: "정책 변경 (데모)", demo_privileged_execution: "특권 실행 (데모)", success: "성공", failure: "실패",
  };
  const ko = (value) => Object.hasOwn(labels, value) ? labels[value] : value;
  const paths = {
    grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
    entity: '<rect x="8" y="3" width="8" height="5" rx="1"/><rect x="2" y="16" width="7" height="5" rx="1"/><rect x="15" y="16" width="7" height="5" rx="1"/><path d="M12 8v4H5v4m7-4h7v4"/>',
    hunt: '<path d="M12 3v3m0 12v3M3 12h3m12 0h3"/><circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2"/>',
    coverage: '<path d="M4 4h16v16H4zM8 4v16M4 9h16M4 14h16"/><path d="m11 17 2 2 4-5"/>',
    health: '<path d="M3 12h4l3-7 4 14 3-7h4"/><circle cx="12" cy="12" r="10"/>',
    kibana: '<path d="M4 3h16L4 12l16 9H4V3zM4 12h16"/>',
    settings: '<path d="m9 3-1 3-3 1-2 3 2 2-1 4 3 2 3-1 2 3 3-1 1-3 3-1 2-3-2-2 1-4-3-2-3 1-2-3z"/><circle cx="12" cy="12" r="3"/>',
    user: '<circle cx="12" cy="7" r="4"/><path d="M4 21v-3a8 8 0 0 1 16 0v3z"/>',
    host: '<rect x="3" y="3" width="18" height="13" rx="1"/><path d="M8 21h8m-4-5v5"/>',
    cloud: '<path d="M7 18H6a4 4 0 0 1-1-7 7 7 0 0 1 13-3 5 5 0 0 1 0 10h-2m-4-8v11m-3-3 3 3 3-3"/>',
    account: '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="2"/><path d="M5 17a4 4 0 0 1 8 0m3-7h3m-3 4h3"/>',
    network: '<circle cx="6" cy="6" r="3"/><circle cx="18" cy="6" r="3"/><circle cx="12" cy="18" r="3"/><path d="m8 8 3 7m5-7-3 7M9 6h6"/>',
    refresh: '<path d="M20 8a8 8 0 1 0 1 7M20 3v5h-5"/>',
    filter: '<path d="M3 5h18l-7 8v7l-4-2v-5z"/>',
    "arrow-left": '<path d="m10 5-7 7 7 7M3 12h18"/>',
    chevron: '<path d="m9 5 7 7-7 7"/>',
    close: '<path d="m6 6 12 12M6 18 18 6"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v1"/>',
    file: '<path d="M6 3h8l4 4v14H6zM14 3v5h4M9 12h6m-6 4h6"/>',
    lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
  };
  const icon = (name) => `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.info}</svg>`;
  const states = {
    normal: ["기본 화면", "기본 데모 화면", ""],
    loading: ["불러오는 중", "불러오는 중", "조회 대기 화면을 표현하는 UI 샘플입니다. 실제 요청은 진행 중이지 않습니다."],
    empty: ["결과 없음", "일치하는 데모 데이터가 없습니다", "선택한 범위에 결과가 없는 상태의 예시입니다. 실제 보안 이벤트가 없다는 의미가 아닙니다."],
    unknown: ["확인 불가", "데이터 신뢰도를 확인할 수 없습니다", "관측 자료가 없어 데이터 신뢰도를 판단할 수 없는 상태의 예시입니다."],
    "not-configured": ["미설정", "데이터 소스가 설정되지 않았습니다", "필요한 데이터 소스가 구성되지 않은 상태의 예시입니다."],
    "not-implemented": ["미구현", "A단계에서 구현하지 않은 기능입니다", "이 기능은 후속 단계에 구현됩니다. 지금은 화면과 상호작용만 검토합니다."],
    partial: ["일부 결과", "일부 결과만 표시됩니다", "일부 자료만 반환된 상태의 예시입니다. 표시된 부분을 전체 결과로 해석하지 않습니다."],
    "query-failed": ["조회 실패", "조회에 실패했습니다", "조회 실패 UI 예시입니다. 실패를 정상 0건으로 표시하지 않습니다. 실제 API 요청은 없습니다."],
    "permission-denied": ["접근 권한 없음", "접근 권한이 없습니다", "원본 또는 업무에 접근할 수 없는 상태의 예시입니다. 실제 인증·인가 검사는 연결되지 않았습니다."],
    "evidence-expired": ["근거 보존 기간 만료", "근거의 보존 기간이 만료되었습니다", "DEMO-RAW 참조의 보존 기간이 만료된 UI 예시입니다. 주변 이벤트로 원래 증거를 대체하지 않습니다."],
  };
  let demoState = Object.hasOwn(states, params.get("state")) ? params.get("state") : "normal";
  let activeWorkbenchTab = "overview";
  let rawTab = "normalized";
  let selectedEvidence = null;
  let expandedEvidence = null;
  let currentItem = null;
  let draft = { status: "New", owner: "", verdict: "", rationale: "", notes: "" };
  let toastTimer;

  function badge(value, type = "status") {
    const key = value.toLowerCase().replaceAll(" ", "-");
    return `<span class="badge ${type}-${escapeHtml(key)}">${escapeHtml(ko(value))}</span>`;
  }
  function fillIcons(root = document) { $$('[data-icon]', root).forEach((element) => { element.innerHTML = icon(element.dataset.icon); }); }
  function timeLabel(value, includeDate = false) {
    return new Intl.DateTimeFormat("ko-KR", { timeZone: "Asia/Seoul", ...(includeDate ? { year: "numeric", month: "2-digit", day: "2-digit" } : {}), hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" }).format(new Date(value));
  }
  function relativeTime(time, minutes) {
    return timeLabel(new Date(Date.parse(`2026-08-31T${time}+09:00`) + minutes * 60000));
  }
  function notify(message) {
    const toast = $("#toast");
    toast.textContent = message;
    toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toast.hidden = true; }, 4500);
  }
  function showDialog(title, message) {
    $("#dialog-title").textContent = title;
    $("#dialog-message").textContent = message;
    $("#prototype-dialog").showModal();
  }
  function placeholder(name) {
    const message = name === "Kibana"
      ? "기존 읽기 전용 대시보드 / Discover 연결 지점\n실제 Kibana를 열거나 저장된 대시보드 구성을 변경하지 않습니다."
      : name === "설정"
        ? "A단계에서 구현하지 않은 기능입니다.\n화면 상태는 상단 데모 상태에서 변경할 수 있습니다. 실제 설정은 저장하지 않습니다."
        : "후속 단계에서 제공할 예정입니다.\nA단계에서는 구현하지 않습니다.";
    showDialog(name, message);
  }
  function shell() {
    const menus = [["관제 현황", "grid", "mission", "index.html"], ["통합 로그", "file", "logs", "logs.html"], ["사건 조사", "search", "workbench", "workbench.html"], ["관련 대상", "entity"], ["위협 헌팅", "hunt"], ["탐지 범위", "coverage"], ["시스템 상태", "health"], ["Kibana", "kibana"], ["에이전트 설치 파일", "settings", "agents", "agents.html"]];
    const workspaceTitle = { mission: "관제 현황", workbench: "사건 조사", logs: "통합 로그" }[page];
    $("#app-shell").innerHTML = `
      <header class="app-header"><a class="brand" href="index.html" aria-label="Cloud SOC 관제 현황"><img src="assets/mark.svg" alt=""><span>Cloud SOC</span></a><span class="workspace-label">${workspaceTitle}</span><div class="header-context"><span class="environment">환경: <strong>${page === "logs" ? "다중 환경" : "운영"}</strong> <span class="demo-env">(데모)</span></span><span class="timezone">UTC+9 / 서울</span><time class="header-clock" id="ui-clock" title="현재 화면 표시 시각이며 이벤트 시각이 아닙니다"></time><button class="avatar" data-placeholder="데모 사용자" aria-label="데모 사용자 정보">${icon("user")}</button></div></header>
      <aside class="sidebar" aria-label="업무 메뉴"><p class="nav-caption">보안 분석 업무 공간</p><nav>${menus.map(([label, symbol, targetPage, href]) => `${symbol === "kibana" ? '<div class="nav-separator"></div>' : ''}${href ? `<a class="nav-item ${page === targetPage ? "active" : ""}" ${page === targetPage ? 'aria-current="page"' : ''} href="${href}" aria-label="${label}" title="${label}">${icon(symbol)}<span class="nav-text">${label}</span></a>` : `<button class="nav-item" data-placeholder="${label}" aria-label="${label}" title="${label}">${icon(symbol)}<span class="nav-text">${label}</span></button>`}`).join("")}</nav><div class="sidebar-footer"><strong>Cloud SOC Mini SIEM</strong>A단계 / 정적 프로토타입<br>수집 데이터 미연결</div></aside>
      <div class="prototype-banner" aria-label="프로토타입 안내"><strong>A단계 화면 프로토타입</strong><span>데모 데이터</span><span class="connection">백엔드 미연결</span><label class="demo-control">데모 상태<select id="demo-state">${Object.entries(states).map(([value, [label]]) => `<option value="${value}" ${value === demoState ? "selected" : ""}>${label}</option>`).join("")}</select></label></div>
      <dialog class="dialog" id="prototype-dialog" aria-labelledby="dialog-title" aria-describedby="dialog-message"><div class="dialog-header"><div><p class="dialog-tag">A단계 프로토타입</p><h2 id="dialog-title"></h2></div><button class="icon-button" data-close-dialog aria-label="안내 창 닫기">${icon("close")}</button></div><p id="dialog-message"></p><div class="dialog-footer"><button data-close-dialog>닫기</button></div></dialog><div id="toast" class="toast" role="status" hidden></div>`;
    const clock = () => { $("#ui-clock").textContent = timeLabel(new Date(), true); $("#ui-clock").dateTime = new Date().toISOString(); };
    clock();
    setInterval(clock, 1000);
    $("#demo-state").addEventListener("change", (event) => {
      demoState = event.target.value;
      if (page === "mission") renderMission();
      else if (page === "logs") window.CloudSocLogView.render(demoState);
      else renderWorkbench();
    });
    document.addEventListener("click", (event) => {
      const placeholderButton = event.target.closest("[data-placeholder]");
      if (placeholderButton) placeholder(placeholderButton.dataset.placeholder);
      if (event.target.closest("[data-close-dialog]")) $("#prototype-dialog").close();
    });
    // Arrow navigation supplements native button keyboard activation for all tab groups.
    document.addEventListener("keydown", (event) => {
      const tab = event.target.closest('[role="tab"]');
      if (!tab || !["ArrowRight", "ArrowLeft", "Home", "End"].includes(event.key)) return;
      const tabs = $$('[role="tab"]', tab.closest('[role="tablist"]'));
      const index = tabs.indexOf(tab);
      const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
      event.preventDefault();
      tabs[next].click();
      // Rendering may replace the old tab nodes.
      document.getElementById(tabs[next].id)?.focus();
    });
    fillIcons();
  }
  function selectTabs(selector, dataKey, selected) {
    $$(selector).forEach((button) => {
      const active = button.dataset[dataKey] === selected;
      button.setAttribute("aria-selected", String(active));
      button.tabIndex = active ? 0 : -1;
    });
  }
  function stateCard(key, light = false) {
    const [label, title, message] = states[key];
    return `<div class="state-card" role="status" ${key === "loading" ? 'aria-busy="true"' : ""}>${icon(key === "permission-denied" ? "lock" : key === "evidence-expired" ? "file" : "info")}<span class="state-tag">데모 상태 / ${escapeHtml(label)}</span><h3>${escapeHtml(title)}</h3><p>${escapeHtml(message)}</p>${key === "partial" ? `<p>일부 샘플만 표시 · 전체 합계 미확인<br>DEMO-RAW 참조 미리보기 / 합성 데이터</p>` : ""}<button class="quiet-button" data-reset-state>${light ? "기본 데모로 돌아가기" : "데모 상태 초기화"}</button></div>`;
  }
  function bindStateReset(root) {
    $("[data-reset-state]", root)?.addEventListener("click", () => { $("#demo-state").value = "normal"; $("#demo-state").dispatchEvent(new Event("change")); });
  }

  let queueTab = params.get("tab") === "alerts" ? "alerts" : "incidents";
  const filterIds = { q: "queue-search", priority: "priority-filter", status: "status-filter", time: "time-filter", owner: "owner-filter", domain: "domain-filter" };
  function queueContext() {
    const context = new URLSearchParams({ tab: queueTab, state: demoState });
    Object.entries(filterIds).forEach(([key, id]) => { const value = document.getElementById(id).value; if (value && value !== "all") context.set(key, value); });
    return context;
  }
  function queueHref(item) {
    const query = new URLSearchParams({ id: item.id, return: queueContext().toString() });
    return `workbench.html?${query}`;
  }
  function filtersMatch(item) {
    const q = $("#queue-search").value.trim().toLowerCase();
    const priority = $("#priority-filter").value;
    const status = $("#status-filter").value;
    const minutes = $("#time-filter").value;
    const owner = $("#owner-filter").value;
    const domain = $("#domain-filter").value;
    const corpus = [item.id, item.title, item.reason, ko(item.reason), item.host, item.user, item.ip, item.rule, item.owner, ko(item.owner || "Unassigned"), item.domain, ko(item.domain)].join(" ").toLowerCase();
    return (!q || corpus.includes(q)) && (priority === "all" || priority === item.priority) && (status === "all" || status === item.status) && (minutes === "all" || item.age <= Number(minutes)) && (owner === "all" || (owner === "unassigned" ? !item.owner : item.owner === owner)) && (domain === "all" || domain === item.domain);
  }
  function renderConfidence() {
    const normal = demoState === "normal";
    $("#confidence").innerHTML = `<div class="confidence-main"><div><h2>데이터 신뢰도</h2><small>데모 상태 · 실제 측정 아님</small></div><span class="health-badge ${normal ? "" : "unknown"}">${normal ? "정상" : "확인 불가"}</span></div>${[["로그 소스", normal ? "3 / 3" : "미측정"], ["마지막 수집", normal ? "2분 전 (데모)" : "확인 불가"], ["처리 파이프라인", normal ? "정상 (데모)" : "확인 불가"], ["탐지 엔진", normal ? "정상 (데모)" : "확인 불가"]].map(([label, value]) => `<div class="confidence-stat"><span>${label}</span><strong>${value}</strong></div>`).join("")}`;
  }
  function renderKpis() {
    const incidents = demo.items.filter((item) => item.kind === "Incident" && filtersMatch(item));
    const open = incidents.filter((item) => item.status !== "Closed");
    const counts = [open.length, open.filter((item) => ["Critical", "High"].includes(item.priority)).length, open.filter((item) => item.status === "New").length, open.filter((item) => item.status === "Investigating").length, open.filter((item) => !item.owner).length];
    const titles = ["미종결", "긴급 / 높음", "신규", "조사 중", "미배정"];
    $("#kpis").innerHTML = titles.map((label, index) => `<button class="kpi" data-kpi="${index}" aria-label="${label} 데모 사건"><span class="kpi-label">${label}<small>데모</small></span><strong class="kpi-value">${demoState === "normal" ? counts[index] : demoState === "empty" ? "0" : "미확인"}</strong></button>`).join("");
    $$('[data-kpi]').forEach((button) => button.addEventListener("click", () => {
      clearFilters();
      queueTab = "incidents";
      const key = Number(button.dataset.kpi);
      if (key === 1) $("#priority-filter").value = "High";
      if (key === 2) $("#status-filter").value = "New";
      if (key === 3) $("#status-filter").value = "Investigating";
      if (key === 4) { $("#owner-filter").value = "unassigned"; $("#extra-filters").hidden = false; $("#more-filters").setAttribute("aria-expanded", "true"); }
      renderMission();
      notify("데모 사건 필터만 변경했습니다. 백엔드 조회는 없습니다.");
    }));
  }
  function renderCharts() {
    if (demoState !== "normal") {
      ["trend-chart", "rule-chart", "ip-chart"].forEach((id) => { document.getElementById(id).innerHTML = `<div class="chart-state">${escapeHtml(states[demoState][0])}<small>데모 상태 · 실시간 지표 아님</small></div>`; });
      return;
    }
    const colors = ["critical", "high", "medium", "low"];
    $("#trend-chart").innerHTML = `<div role="img" aria-label="최근 24시간의 시간별 데모 경보 차트. 운영 데이터가 아닙니다."><div class="trend-plot"><div class="y-axis"><span>40</span><span>20</span><span>0</span></div><div class="trend-bars">${demo.trend.map((value, hour) => `<div class="trend-bar" title="데모 ${hour}시 / 경보 ${value}건">${[.04, .09, .23, .64].map((part, index) => `<span class="trend-${colors[index]}" style="height:${value / 40 * part * 100}%"></span>`).join("")}</div>`).join("")}</div></div><div class="x-axis"><span>00</span><span>04</span><span>08</span><span>12</span><span>16</span><span>20</span><span>23</span></div></div><div class="chart-axis-label"><span>경보 수</span><span>시간 / 한국 표준시 · 데모 기준</span></div><div class="legend">${colors.map((color) => `<span><i class="trend-${color}"></i>${ko(color[0].toUpperCase() + color.slice(1))}</span>`).join("")}</div>`;
    const bars = (rows) => `<div class="ranked-bars">${rows.map(([label, value]) => `<div class="rank-row"><span class="mono">${escapeHtml(label)}</span><div class="bar-track"><div class="bar-fill" style="width:${value / 12 * 100}%"></div></div><span class="rank-count">${value}</span></div>`).join("")}</div>`;
    $("#rule-chart").innerHTML = bars(demo.rules);
    $("#ip-chart").innerHTML = bars(demo.ips);
  }
  function renderMission() {
    renderConfidence(); renderKpis(); renderCharts();
    selectTabs("[data-queue-tab]", "queueTab", queueTab);
    $("#queue-panel").setAttribute("aria-labelledby", `tab-${queueTab}`);
    $("#queue-search").placeholder = queueTab === "incidents" ? "사건 검색..." : "경보 검색...";
    $("#queue-title-column").textContent = queueTab === "incidents" ? "사건" : "경보";
    $("#incidents-count").textContent = "(5)";
    $("#alerts-count").textContent = "(3)";
    const kind = queueTab === "incidents" ? "Incident" : "Alert";
    const ranks = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    const rows = demo.items.filter((item) => item.kind === kind && filtersMatch(item)).sort((a, b) => ranks[a.priority] - ranks[b.priority] || b.age - a.age || a.id.localeCompare(b.id));
    const noData = demoState !== "normal" || rows.length === 0;
    $("#queue-table-wrap").hidden = noData;
    $("#queue-state").hidden = !noData;
    if (noData) {
      $("#queue-state").innerHTML = stateCard(demoState === "normal" ? "empty" : demoState);
      bindStateReset($("#queue-state"));
      if (demoState === "normal") $("[data-reset-state]", $("#queue-state")).addEventListener("click", () => { clearFilters(); renderMission(); });
    }
    $("#queue-rows").innerHTML = rows.map((item) => `<tr data-demo-item="${item.id}"><td>${badge(item.priority, "severity")}</td><td><a class="incident-link" href="${escapeHtml(queueHref(item))}" title="${escapeHtml(item.title)}">${escapeHtml(item.title)}</a><span class="row-id">${item.id}</span></td><td class="row-reason" title="${escapeHtml(ko(item.reason))}">${escapeHtml(ko(item.reason))}</td><td>${badge(item.status)}</td><td><span class="entity-summary">${escapeHtml([item.user, item.host].join(", "))}<br>${escapeHtml(item.ip)}</span></td><td><span class="${item.owner ? "owner" : "unassigned"}">${ko(item.owner || "Unassigned")}</span></td><td>${item.age < 60 ? `${item.age}분` : `${item.age / 60}시간`}</td><td>${icon("chevron")}</td></tr>`).join("");
    $("#queue-result").textContent = demoState === "normal" ? `데모 ${ko(kind)} ${kind === "Incident" ? 5 : 3}건 중 ${rows.length}건 · 지표는 사건만 집계` : `${states[demoState][0]} · 데모 화면 상태`;
    $("#queue-rows").onclick = (event) => {
      if (event.target.closest("a")) return;
      const row = event.target.closest("[data-demo-item]");
      if (row) location.href = queueHref(demo.items.find((item) => item.id === row.dataset.demoItem));
    };
    try { history.replaceState(null, "", `index.html?${queueContext()}`); } catch { /* file:// history restrictions do not prevent navigation. */ }
  }
  function clearFilters() { Object.entries(filterIds).forEach(([key, id]) => { document.getElementById(id).value = key === "q" ? "" : "all"; }); }
  function initMission() {
    Object.entries(filterIds).forEach(([key, id]) => {
      const element = document.getElementById(id);
      const value = params.get(key);
      if (value && (key === "q" || Array.from(element.options).some((option) => option.value === value))) element.value = value;
      element.addEventListener(key === "q" ? "input" : "change", renderMission);
    });
    if ($("#owner-filter").value !== "all" || $("#domain-filter").value !== "all") { $("#extra-filters").hidden = false; $("#more-filters").setAttribute("aria-expanded", "true"); }
    $$('[data-queue-tab]').forEach((button) => button.addEventListener("click", () => { queueTab = button.dataset.queueTab; renderMission(); }));
    $("#more-filters").addEventListener("click", () => { const open = $("#extra-filters").hidden; $("#extra-filters").hidden = !open; $("#more-filters").setAttribute("aria-expanded", String(open)); });
    $("#clear-filters").addEventListener("click", () => { clearFilters(); renderMission(); });
    $("#refresh-demo").addEventListener("click", () => { renderMission(); notify("데모 화면을 새로 표시했습니다. 백엔드 요청은 없습니다."); });
    renderMission();
  }

  function statusOptions() {
    return ["New", "Investigating", "Triage", "Escalated", "Closed"].map((value) => `<option value="${value}" ${draft.status === value ? "selected" : ""}>${ko(value)}</option>`).join("");
  }
  function ownerOptions() { return [["", "Unassigned"], ["analyst01", "analyst01"], ["analyst02", "analyst02"]].map(([value, label]) => `<option value="${value}" ${draft.owner === value ? "selected" : ""}>${ko(label)}</option>`).join(""); }
  function reasonRows() {
    const evidence = currentItem.evidence;
    return [["탐지 규칙", `${currentItem.rule} ${ko(currentItem.ruleName)}`], ["탐지 유형", ko(currentItem.type)], ["탐지 조건", currentItem.condition], ["임계치", ko(currentItem.threshold)], ["평가 구간", ko(currentItem.window)], ["관측 결과", `일치 이벤트 ${evidence.length}건`], ["첫 근거 시각", evidence[0].time], ["마지막 근거 시각", evidence.at(-1).time]];
  }
  function fieldTable(rows) { return `<table class="reason-table"><tbody>${rows.map(([key, value]) => `<tr><th scope="row">${escapeHtml(key)}</th><td>${escapeHtml(Array.isArray(value) ? value.join(", ") : value)}</td></tr>`).join("")}</tbody></table>`; }
  function relatedEntities() {
    return currentItem.entities.filter((entity) => entity.type !== "Cloud Account").map((entity) => `<button class="entity-button" data-entity="${escapeHtml(ko(entity.type) + ": " + ko(entity.value))}">${icon(entity.icon)}<small>${ko(entity.type)}</small><strong>${escapeHtml(ko(entity.value))}</strong></button>`).join("");
  }
  function verdicts() {
    return `<div class="verdict-group" role="group" aria-label="데모 판단 결과">${["Malicious", "Benign", "False Positive", "Inconclusive"].map((value) => `<button data-verdict="${value}" aria-pressed="${draft.verdict === value}">${ko(value)}</button>`).join("")}</div>`;
  }
  function saveRow() { return '<div class="save-row"><span class="save-warning">현재 화면 입력만 유지 · 저장되지 않음</span><button class="save-button" data-save>저장 (미구현)</button></div>'; }
  function notesField() { return `<label class="input-label" for="analyst-notes">분석 메모</label><textarea class="notes-input" id="analyst-notes" data-draft="notes" placeholder="조사 내용과 판단 근거를 입력하세요." maxlength="10000">${escapeHtml(draft.notes)}</textarea><small class="draft-note">프로토타입 입력 · 새로고침 또는 페이지 이동 시 사라집니다.</small>`; }
  function overview() {
    return `<div class="overview-grid"><div class="column-stack"><article class="light-card"><div class="card-label-row"><h2>탐지 이유</h2><span class="micro-label">데모 규칙 스냅샷</span></div>${fieldTable(reasonRows())}</article><article class="light-card"><h2>관련 대상</h2><div class="entity-grid">${relatedEntities()}</div></article></div><div class="column-stack"><article class="light-card"><h2>사건 요약</h2><p>${escapeHtml(currentItem.summary)}</p></article><article class="light-card"><h2>주요 확인 사항</h2><ul class="question-list"><li>이 계정의 다른 활동이 있는가?</li><li>이 IP가 다른 서버에도 접근했는가?</li><li>이후 클라우드 API 호출이 있었는가?</li><li>정상 관리 작업으로 설명 가능한가?</li></ul></article><article class="light-card">${notesField()}</article><article class="light-card"><h2>판단 결과</h2>${verdicts()}${saveRow()}</article></div></div>`;
  }
  function timeline() {
    const first = currentItem.evidence[0].time;
    const last = currentItem.evidence.at(-1).time;
    const eventRow = (time, title, kind, note = "") => `<div class="timeline-event"><time class="timeline-time mono">${time}</time><span class="event-label">${escapeHtml(ko(title))}</span><span class="badge ${kind.toLowerCase()}-badge">${ko(kind)}</span>${note ? `<small>${escapeHtml(note)}</small>` : ""}</div>`;
    return `<article class="light-card"><div class="tab-intro"><div><h2>이벤트 시간 흐름</h2><p>2026-08-31 · UTC+9 / 서울 · ${currentItem.id} 합성 타임라인</p></div><span class="badge evidence-badge">탐지 근거 ${currentItem.evidence.length}건</span></div><div class="timeline"><section class="timeline-group"><h3>탐지 이전 / 관련 활동</h3>${eventRow(relativeTime(first, -10), currentItem.related, "RELATED", "전후 맥락 예시. 탐지 일치 근거가 아닙니다.")}</section><section class="timeline-group detection"><h3>탐지 평가 구간 / ${escapeHtml(ko(currentItem.window))}</h3>${currentItem.evidence.map((event) => eventRow(event.time, event.action === "ssh_login" ? "로그인 실패" : event.action, "EVIDENCE", `${ko(event.host)} / ${event.user}`)).join("")}${eventRow(last, `${currentItem.rule} / 데모 탐지 스냅샷`, "TRIGGER", "실제 엔진 실행 결과가 아닙니다.")}</section><section class="timeline-group"><h3>탐지 이후 / 관련 활동</h3>${eventRow(relativeTime(last, 2), currentItem.related, "RELATED")}${eventRow(relativeTime(last, 5), currentItem.domain === "Authentication" ? "sudo 명령 (합성 맥락)" : "후속 활동 (합성 맥락)", "RELATED", "시간적 연관만으로 인과 또는 침해를 확정하지 않습니다.")}</section></div></article>`;
  }
  function evidenceView() {
    return `<article class="light-card"><div class="tab-intro"><div><h2>탐지 근거</h2><p>합성 근거 ${currentItem.evidence.length}건 · 행을 선택하여 상세와 원문을 확인하세요.</p></div><span class="badge evidence-badge">데모 근거</span></div><div class="table-scroll"><table class="evidence-table"><thead><tr>${["시각", "로그 소스", "호스트", "사용자", "행위", "결과", "근거 유형", "품질"].map((title) => `<th>${title}</th>`).join("")}</tr></thead><tbody>${currentItem.evidence.map((event) => `<tr data-evidence="${event.id}" class="${expandedEvidence === event.id ? "selected" : ""}"><td><button class="evidence-row-button" data-evidence="${event.id}" aria-expanded="${expandedEvidence === event.id}" aria-controls="evidence-detail">${event.time}</button></td><td>${escapeHtml(ko(event.source))}</td><td>${escapeHtml(ko(event.host))}</td><td>${escapeHtml(event.user)}</td><td>${escapeHtml(ko(event.action))}</td><td>${ko(event.outcome)}</td><td><span class="badge evidence-badge">탐지 근거</span></td><td>합성 데이터</td></tr>`).join("")}</tbody></table></div><section id="evidence-detail" class="light-card evidence-detail" ${expandedEvidence ? "" : "hidden"}></section></article>`;
  }
  function updateEvidenceDetail() {
    const detail = $("#evidence-detail");
    if (!detail || !expandedEvidence) return;
    const evidence = currentItem.evidence.find((event) => event.id === expandedEvidence);
    detail.innerHTML = `<div class="detail-heading"><div><h2>근거 상세</h2><p class="mono">${evidence.id}</p></div><button data-collapse-evidence aria-label="근거 상세 접기">${icon("close")}</button></div>${fieldTable([["로그 소스", ko(evidence.source)], ["관측 시각", `${evidence.time} / 한국 표준시`], ["행위 / 결과", `${ko(evidence.action)} / ${ko(evidence.outcome)}`], ["품질", "화면용 합성 기록이며 검증된 근거가 아닙니다"]])}<div class="detail-actions"><button data-open-raw>원문 이벤트 열기</button><button data-open-normalized>정규화 필드 보기</button></div>`;
  }
  function rawView() {
    const evidence = selectedEvidence || currentItem.evidence[0];
    let body;
    if (rawTab === "normalized") body = fieldTable(Object.entries(evidence.normalized));
    else if (rawTab === "raw") body = `<pre class="raw-block">${escapeHtml(evidence.raw)}</pre><p class="raw-caption">합성 예시입니다. 실제 수집 로그, 계정 정보 또는 Elasticsearch 문서가 아닙니다.</p>`;
    else body = fieldTable([["로그 소스", ko(evidence.source)], ["파서", ko(evidence.parser)], ["스키마", "ECS 호환 필드 예시 (미검증)"], ["원문 참조", evidence.id], ["근거 상태", "프로토타입 / 합성 데이터"], ["무결성 / 보존", "미검증 / 미연결"], ["저장 위치", "화면 메모리의 샘플 데이터. Elasticsearch _index/_id 없음"]]);
    return `<article class="light-card"><div class="tab-intro"><div><h2>원본 이벤트 탐색</h2><p class="mono">${evidence.id} · ${evidence.time} / 한국 표준시</p></div><span class="badge related-badge">데모 데이터</span></div><div class="tab-list raw-subtabs" role="tablist" aria-label="이벤트 표시 방식">${[["normalized", "정규화 필드"], ["raw", "원문 로그"], ["provenance", "출처 정보"]].map(([value, label]) => `<button id="raw-tab-${value}" role="tab" aria-selected="${rawTab === value}" aria-controls="raw-content" tabindex="${rawTab === value ? 0 : -1}" data-raw-tab="${value}">${label}</button>`).join("")}</div><section id="raw-content" role="tabpanel" aria-labelledby="raw-tab-${rawTab}" tabindex="0">${body}</section></article>`;
  }
  function entitiesView() {
    return `<div class="tab-intro"><div><h2>관련 대상</h2><p>데모 범위의 관측 대상입니다. IP와 계정 이름은 사람을 식별하지 않습니다.</p></div></div><div class="entity-full-grid">${currentItem.entities.map((entity) => `<article class="light-card entity-card">${icon(entity.icon)}<h3>${ko(entity.type)}</h3><strong>${escapeHtml(ko(entity.value))}</strong><p>범위: tenant-demo-01<br>식별 신뢰도: 데모 예시</p><button data-entity="${escapeHtml(ko(entity.type) + ": " + ko(entity.value))}">대상 조사 열기</button></article>`).join("")}</div>`;
  }
  function workView() {
    return `<div class="work-grid"><article class="light-card"><div class="tab-intro"><div><h2>분석 기록</h2><p>입력 연습용 화면입니다. 업무 변경이나 감사 이력은 저장하지 않습니다.</p></div></div><div class="work-fields"><label>상태<select data-draft="status">${statusOptions()}</select></label><label>담당자<select data-draft="owner">${ownerOptions()}</select></label></div><h3 class="input-label">판단 결과</h3>${verdicts()}<div style="height:16px"></div><label class="input-label" for="rationale">판단 근거</label><textarea id="rationale" class="rationale-input" data-draft="rationale" placeholder="판단 근거와 남은 불확실성을 기록하세요." maxlength="10000">${escapeHtml(draft.rationale)}</textarea>${notesField()}${saveRow()}</article><article class="light-card"><div class="card-label-row"><h2>활동 이력</h2><span class="micro-label">데모 활동</span></div><ul class="history-list"><li><span class="badge">데모</span><time>${timeLabel(currentItem.created)}</time><span>조사 시작 (예시)</span></li><li><span class="badge">데모</span><time>${relativeTime(timeLabel(currentItem.created), 1)}</time><span>담당자 선택 (예시)</span></li></ul><p style="margin-top:14px">실제 감사 이력이 아닙니다. 현재 입력으로 서버 기록이 생성되거나 이 목록에 저장되지 않습니다.</p></article></div>`;
  }
  function renderWorkbench() {
    const panel = $("#workbench-panel");
    selectTabs("[data-workbench-tab]", "workbenchTab", activeWorkbenchTab);
    panel.setAttribute("aria-labelledby", `tab-${activeWorkbenchTab}`);
    if (!currentItem) {
      panel.innerHTML = `<div class="state-card"><span class="state-tag">데모 항목 없음</span><h3>알 수 없는 데모 ID입니다</h3><p>요청한 데모 항목이 없습니다. 다른 사건의 근거를 대신 표시하지 않습니다.</p><a href="index.html">관제 현황으로 이동</a></div>`;
      return;
    }
    if (demoState !== "normal") { panel.innerHTML = stateCard(demoState, true); bindStateReset(panel); return; }
    const views = { overview, timeline, evidence: evidenceView, raw: rawView, entities: entitiesView, work: workView };
    panel.innerHTML = `<div class="surface-demo-label"><span>데모 데이터 · 실제 보안 이벤트 아님</span><span>데모 기준일: 2026-08-31 / 한국 표준시</span></div>${views[activeWorkbenchTab]()}`;
    updateEvidenceDetail();
  }
  function syncDraft() {
    $$('[data-draft]').forEach((element) => { if (element.value !== draft[element.dataset.draft]) element.value = draft[element.dataset.draft]; });
    $$('[data-verdict]').forEach((button) => button.setAttribute("aria-pressed", String(button.dataset.verdict === draft.verdict)));
  }
  function initWorkbench() {
    const id = params.get("id") || "INC-DEMO-001";
    currentItem = demo.items.find((item) => item.id === id) || null;
    // Only queue filter keys are accepted; an arbitrary return URL is never followed.
    const returnParams = new URLSearchParams(params.get("return") || "");
    const safeReturn = new URLSearchParams();
    ["tab", "state", ...Object.keys(filterIds)].forEach((key) => { if (returnParams.has(key)) safeReturn.set(key, returnParams.get(key)); });
    $("#back-link").href = `index.html${safeReturn.size ? `?${safeReturn}` : ""}`;
    if (currentItem) {
      draft = { ...draft, status: currentItem.status, owner: currentItem.owner };
      selectedEvidence = currentItem.evidence[0];
      $("#incident-heading").innerHTML = `<p class="incident-type">${ko(currentItem.kind)} 조사 / ${currentItem.id} / 데모</p><div class="incident-top"><div class="incident-title"><h1>${escapeHtml(currentItem.title)}</h1>${badge(currentItem.priority, "severity")}</div><div class="header-fields"><label>상태 <small>(미저장)</small><select data-draft="status">${statusOptions()}</select></label><label>담당자 <small>(미저장)</small><select data-draft="owner">${ownerOptions()}</select></label></div></div><div class="incident-meta"><span>환경<strong>운영 (데모)</strong></span><span>범위<strong>tenant-demo-01</strong></span><span>${ko(currentItem.kind)} ID<strong>${currentItem.id}</strong></span><span>생성 시각<strong>${timeLabel(currentItem.created)} KST</strong></span><span>마지막 활동<strong>${relativeTime(currentItem.evidence.at(-1).time, 5)} KST</strong></span></div>`;
      document.title = `${currentItem.title} | Cloud SOC 프로토타입`;
    } else $("#incident-heading").innerHTML = '<h1>조사 화면을 열 수 없습니다</h1>';
    $$('[data-workbench-tab]').forEach((button) => button.addEventListener("click", () => { activeWorkbenchTab = button.dataset.workbenchTab; renderWorkbench(); }));
    document.addEventListener("input", (event) => {
      const key = event.target.dataset.draft;
      if (key && Object.hasOwn(draft, key)) { draft[key] = event.target.value; syncDraft(); }
    });
    document.addEventListener("change", (event) => {
      const key = event.target.dataset.draft;
      if (key && Object.hasOwn(draft, key)) { draft[key] = event.target.value; syncDraft(); }
    });
    $("#workbench-panel").addEventListener("click", (event) => {
      if (!currentItem) return;
      const target = event.target;
      if (target.closest("[data-save]")) showDialog("프로토타입 전용", "업무 저장용 백엔드가 연결되지 않았습니다.\n아무 내용도 저장되지 않았습니다.\n\n입력한 판단과 메모는 현재 페이지에만 있습니다.");
      const verdict = target.closest("[data-verdict]");
      if (verdict) { draft.verdict = verdict.dataset.verdict; syncDraft(); }
      const entity = target.closest("[data-entity]");
      if (entity) showDialog("관련 대상 조사", `${entity.dataset.entity}\n후속 단계에서 제공할 예정입니다.\nA단계에서는 구현하지 않습니다.`);
      const evidence = target.closest("[data-evidence]");
      if (evidence) {
        const evidenceId = evidence.dataset.evidence;
        expandedEvidence = expandedEvidence === evidenceId ? null : evidenceId;
        if (expandedEvidence) selectedEvidence = currentItem.evidence.find((record) => record.id === expandedEvidence);
        renderWorkbench();
        // Re-rendering replaces the clicked button; keep keyboard navigation in context.
        $(`button[data-evidence="${evidenceId}"]`).focus({ preventScroll: true });
        if (expandedEvidence) $("#evidence-detail").scrollIntoView({ block: "nearest" });
      }
      if (target.closest("[data-collapse-evidence]")) {
        const evidenceId = expandedEvidence;
        expandedEvidence = null;
        renderWorkbench();
        $(`button[data-evidence="${evidenceId}"]`)?.focus();
      }
      if (target.closest("[data-open-raw], [data-open-normalized]")) { rawTab = target.closest("[data-open-raw]") ? "raw" : "normalized"; activeWorkbenchTab = "raw"; renderWorkbench(); }
      const subtab = target.closest("[data-raw-tab]");
      if (subtab) { rawTab = subtab.dataset.rawTab; renderWorkbench(); $(`#raw-tab-${rawTab}`).focus(); }
    });
    renderWorkbench();
  }

  shell();
  if (page === "mission") initMission();
  else if (page === "logs") {
    window.CloudSocLogView.init({ escapeHtml, stateCard, bindStateReset });
    window.CloudSocLogView.render(demoState);
  } else initWorkbench();
})();
