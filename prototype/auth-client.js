/* Shared authentication transport: server remains authoritative for permissions. */
(() => {
  "use strict";
  const original = window.fetch.bind(window);
  const identity = original("/api/auth/me", {credentials:"same-origin"}).then(async response => {
    if (!response.ok) return null;
    return response.json();
  }).catch(() => null);
  window.portalIdentity = identity;
  window.fetch = async (input, options = {}) => {
    const url = new URL(typeof input === "string" ? input : input.url, window.location.href);
    if (url.origin !== window.location.origin) return original(input, options);
    const method = String(options.method || (input instanceof Request ? input.method : "GET")).toUpperCase();
    const user = await identity;
    if (!["GET","HEAD","OPTIONS"].includes(method) && user?.mode === "session") {
      const headers = new Headers(options.headers || (input instanceof Request ? input.headers : undefined));
      headers.set("X-CSRF-Token", user.csrf);
      options = {...options, headers};
    }
    const response = await original(input, options);
    if (response.status === 401 && user?.mode === "session") window.location.assign("/login");
    return response;
  };
  document.addEventListener("DOMContentLoaded", async () => {
    const user = await identity;
    if (!user) return;
    document.body.dataset.socRole = user.role;
    const context = document.querySelector(".header-context");
    const roles = {admin: "관리자", analyst: "분석가", viewer: "조회 전용", investigator: "조사 담당"};
    if (context) context.textContent = `${user.user} · ${roles[user.role] || "권한 미확인"}`;
    if (user.role !== "admin") {
      for (const link of document.querySelectorAll('a[href^="agents.html"]')) link.hidden = true;
    }
    if (Array.isArray(user.navigation)) {
      const known = new Set(['index.html', 'dashboard.html', 'operations.html', 'logs.html', 'cases.html', 'workbench.html', 'agents.html',
        'agent-status.html', 'collection-health.html', 'detection-history.html', 'reprocessing-history.html']);
      const diagnostics = new Set(['collection-health.html', 'detection-history.html', 'reprocessing-history.html']);
      for (const link of document.querySelectorAll('a[href]')) {
        const href = link.getAttribute('href'), page = href.split(/[?#]/)[0].split('/').pop();
        const directAccess = (page === 'operations.html' && (user.role === 'admin' || user.mode === 'session')) ||
          (diagnostics.has(page) && user.role === 'admin');
        if (known.has(page) && !directAccess && !user.navigation.includes(page === 'workbench.html' ? 'cases.html' : page)) link.hidden = true;
      }
    }
    if (user.role === "viewer") {
      for (const id of ["case-create-panel", "case-work-panel", "case-link-form"]) {
        const panel = document.getElementById(id);
        for (const control of panel?.querySelectorAll("input,select,textarea,button") || []) control.disabled = true;
      }
    }
    if (user.mode === "session") {
      const button = document.createElement("button");
      button.type = "button"; button.textContent = "로그아웃";
      button.addEventListener("click", async () => {
        const response = await window.fetch("/api/auth/logout", {method:"POST",headers:{"Content-Type":"application/json","X-Cloud-SOC":"portal"},body:"{}"});
        if (response.ok) window.location.assign("/login");
      });
      context?.after(button);
    }
  });
})();
