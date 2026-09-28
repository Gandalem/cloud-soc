/* Shared chrome for the static portal pages; no API or credentials required. */
(() => {
  "use strict";
  const groups = [
    { title: "보안 관제", items: [
      ["index.html", "관제 현황"], ["logs.html", "통합 로그"],
      ["cases.html", "사건 조사"], ["collection-health.html", "수집 품질"]
    ] },
    { title: "에이전트", items: [
      ["agents.html", "에이전트 설치 파일"], ["agents.html#keys", "발급 키 관리"],
      ["agent-status.html", "에이전트 접속 현황"]
    ] }
  ];
  function current(pathname, hash) {
    const page = pathname.split("/").pop() || "index.html";
    if (page === "workbench.html") return "cases.html";
    return page === "agents.html" && hash === "#keys" ? "agents.html#keys" : page;
  }
  function markup(pathname, hash) {
    const active = current(pathname, hash);
    const title = groups.flatMap(group => group.items).find(([href]) => href === active)?.[1] || "Cloud SOC";
    const nav = groups.map(group => `<section class="shell-group" aria-label="${group.title}"><h2 class="nav-group">${group.title}</h2>${group.items.map(([href, label]) => `<a class="nav-item${href === active ? " active" : ""}" href="${href}"${href === active ? ' aria-current="page"' : ""}>${label}</a>`).join("")}</section>`).join("");
    return `<header class="app-header"><a class="brand" href="index.html"><img src="assets/mark.svg" alt="">Cloud SOC</a><span class="workspace-label">${title}</span><span class="header-context">관리자 전용 · 중앙 관리</span><button type="button" class="shell-toggle" aria-expanded="false" aria-controls="portal-sidebar">메뉴</button></header><aside id="portal-sidebar" class="sidebar" aria-label="공통 업무 메뉴"><nav aria-label="전체 메뉴">${nav}</nav><div class="sidebar-footer"><strong>Cloud SOC Mini SIEM</strong>수집 · 관제 · 사건 조사</div></aside>`;
  }
  if (typeof module !== "undefined" && module.exports) module.exports = { groups, current, markup };
  if (typeof document === "undefined") return;
  const root = document.getElementById("app-shell");
  if (!root) return;
  function render() {
    root.innerHTML = markup(window.location.pathname, window.location.hash);
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
  window.addEventListener("hashchange", refresh);
})();
