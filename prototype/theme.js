/* Only a validated display preference is stored; no account or telemetry data. */
(() => {
  'use strict';
  const key = 'cloud-soc.theme', valid = value => value === 'light' || value === 'dark';
  let stored;
  try { stored = localStorage.getItem(key); } catch { /* Storage may be unavailable. */ }
  let theme = valid(stored) ? stored : 'light', chosen = valid(stored);
  function apply() {
    document.documentElement.dataset.theme = theme;
    if (document.body) document.body.dataset.theme = theme;
  }
  function set(value) {
    if (!valid(value)) return false;
    theme = value; chosen = true;
    try { localStorage.setItem(key, theme); } catch { /* Current page still switches. */ }
    apply();
    window.dispatchEvent(new CustomEvent('cloud-soc-themechange', {detail: {theme}}));
    return true;
  }
  window.CloudSOCTheme = {get: () => theme, set, adopt: value => !chosen && valid(value) ? set(value) : false};
  apply();
  document.addEventListener('DOMContentLoaded', apply, {once: true});
  window.addEventListener('storage', event => {
    if (event.key !== key) return;
    theme = valid(event.newValue) ? event.newValue : 'light'; chosen = valid(event.newValue); apply();
    window.dispatchEvent(new CustomEvent('cloud-soc-themechange', {detail: {theme}}));
  });
})();
