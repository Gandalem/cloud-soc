window.CloudSocLogView = (() => {
  "use strict";
  const data = window.CloudSocLogData;
  const $ = (selector) => document.querySelector(selector);
  const filterIds = { q: "log-search", environment: "log-environment", os: "log-os", platform: "log-platform", source: "log-source", parse: "log-parse", outcome: "log-outcome", minutes: "log-period" };
  const columns = [["id", "로그 ID"], ["ingestedAt", "수집 시각 (KST)"], ["environment", "환경"], ["os", "운영체제"], ["platform", "플랫폼"], ["source", "로그 소스"], ["parse", "파싱 상태"], ["origin", "채널 / 파일 / 저널"], ["target", "호스트 / 자원"], ["user", "사용자"], ["ip", "출발지 IP"], ["action", "행위"], ["outcome", "결과"], ["message", "메시지"]];
  let helpers, state = "normal", page = 1, pageSize = 25, sort = "ingestedAt", order = "desc", selected = null, detailTab = "fields";
  const options = () => ({ ...Object.fromEntries(Object.entries(filterIds).map(([key, id]) => [key, document.getElementById(id).value])), sort, order });
  const esc = (value) => helpers.escapeHtml(value ?? "미관측");
  const formatTime = (value) => value ? new Intl.DateTimeFormat("ko-KR", { timeZone: "Asia/Seoul", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" }).format(new Date(value)) : "미관측";
  const parseBadge = (value) => `<span class="badge parse-${value}">${data.parseLabels[value]}</span>`;
  const parseNote = (record) => record.parse === "parsed" ? "파싱된 필드의 데모 예시입니다. 소스에 없는 IP·사용자·결과는 미관측/미확인입니다. 파싱 완료는 정상 활동이나 안전함을 의미하지 않습니다." : record.parse === "partial" ? "@timestamp와 event.outcome이 누락된 데모입니다. 수집 시각으로 이벤트 시각을 임의 보충하지 않습니다." : "로그 형식을 해석하지 못한 예시입니다. 파싱 필드는 없지만 원문과 수집 정보는 유지합니다.";

  function fieldTable(rows) {
    return `<table class="reason-table"><tbody>${rows.map(([key, value]) => `<tr><th scope="row">${esc(key)}</th><td>${esc(Array.isArray(value) ? value.join(", ") : value)}</td></tr>`).join("")}</tbody></table>`;
  }
  function renderDetail() {
    if (!selected) return;
    $("#log-detail-title").textContent = selected.id;
    $("#log-detail-context").textContent = `${data.environments[selected.environment]} / ${data.operatingSystems[selected.os]} / ${data.platforms[selected.platform]} / ${data.sources[selected.source]}`;
    $("#log-detail-status").innerHTML = `${parseBadge(selected.parse)}<p>${esc(parseNote(selected))}</p>`;
    document.querySelectorAll("[data-log-tab]").forEach((button) => {
      const active = button.dataset.logTab === detailTab;
      button.setAttribute("aria-selected", String(active));
      button.tabIndex = active ? 0 : -1;
    });
    const content = $("#log-detail-content");
    content.setAttribute("aria-labelledby", `log-tab-${detailTab}`);
    if (detailTab === "fields") content.innerHTML = Object.keys(selected.fields).length ? fieldTable(Object.entries(selected.fields)) : '<div class="log-detail-empty"><h3>파싱 필드가 없습니다</h3><p>원문 로그 탭에서 해석되지 않은 데이터를 확인하세요.</p></div>';
    else if (detailTab === "raw") content.innerHTML = `<pre class="raw-block">${esc(selected.raw)}</pre>`;
    else content.innerHTML = fieldTable([["데모 로그 ID", selected.id], ["환경", data.environments[selected.environment]], ["운영체제", data.operatingSystems[selected.os]], ["플랫폼", `${data.platforms[selected.platform]} (데모)`], ["로그 소스", data.sources[selected.source]], ["채널 / 파일 / 저널", selected.origin], ["수집 대상", selected.target], ["수집 시각", selected.ingestedAt], ["이벤트 시각", selected.eventAt], ["파서 예시", selected.parser], ["수집기 연결", "미연결"], ["실제 파서 실행", "미연결 / 고정 결과 예시"], ["범위·대상 정보", "수집 설정을 가정한 데모 메타데이터"], ["보존·무결성", "미검증 / 실제 저장소 없음"]]);
  }
  function openDetail(id) {
    selected = data.records.find((record) => record.id === id);
    if (!selected) return;
    detailTab = "fields";
    renderDetail();
    $("#log-detail-dialog").showModal();
  }
  function render(nextState = state) {
    state = nextState;
    const rows = state === "normal" ? data.query(options()) : [];
    const visible = state === "normal";
    const count = (kind) => visible ? rows.filter((record) => record.parse === kind).length : state === "empty" ? 0 : "미확인";
    $("#log-metrics").innerHTML = [["조회 로그", visible ? rows.length : state === "empty" ? 0 : "미확인"], ["파싱 완료", count("parsed")], ["일부 필드 누락", count("partial")], ["파싱 실패", count("failed")]].map(([label, total]) => `<span>${label}<strong>${total}${typeof total === "number" ? "건" : ""}</strong></span>`).join("") + '<small>현재 필터 범위 · 모두 데모</small>';
    $("#log-sheet-scroll").hidden = !visible || !rows.length;
    $("#log-state").hidden = visible && rows.length > 0;
    if (state !== "normal") {
      $("#log-state").innerHTML = helpers.stateCard(state);
      helpers.bindStateReset($("#log-state"));
    } else if (!rows.length) {
      $("#log-state").innerHTML = '<div class="state-card"><h3>일치하는 로그가 없습니다</h3><p>데모 검색 범위에 일치하는 결과가 없습니다. 실제 환경의 로그가 없다는 의미는 아닙니다.</p><button id="log-empty-reset" class="quiet-button">필터 초기화</button></div>';
      $("#log-empty-reset").addEventListener("click", clearFilters);
    }
    const pages = Math.max(1, Math.ceil(rows.length / pageSize));
    page = Math.min(page, pages);
    const start = (page - 1) * pageSize;
    $("#log-columns").innerHTML = `<tr><th class="log-row-number" scope="col">행</th>${columns.map(([key, label]) => `<th scope="col" class="log-col-${key}" aria-sort="${sort === key ? order === "asc" ? "ascending" : "descending" : "none"}"><button type="button" data-log-sort="${key}">${label}<span aria-hidden="true">${sort === key ? order === "asc" ? " ↑" : " ↓" : " ↕"}</span></button></th>`).join("")}</tr>`;
    $("#log-rows").innerHTML = rows.slice(start, start + pageSize).map((record, index) => `<tr data-log-id="${record.id}"><td class="log-row-number">${start + index + 1}</td><td class="log-col-id"><button class="log-row-open" type="button" data-log-open="${record.id}" aria-label="${record.id} 로그 상세 열기">${record.id}</button></td><td class="mono">${formatTime(record.ingestedAt)}</td><td><span class="log-env">${data.environments[record.environment]}</span></td><td>${data.operatingSystems[record.os]}</td><td>${data.platforms[record.platform]}</td><td>${data.sources[record.source]}</td><td>${parseBadge(record.parse)}</td><td class="mono" title="${esc(record.origin)}">${esc(record.origin)}</td><td class="mono" title="${esc(record.target)}">${esc(record.target)}</td><td class="mono">${esc(record.user)}</td><td class="mono">${esc(record.ip)}</td><td title="${esc(record.action)}">${esc(record.actionLabel)}</td><td><span class="log-outcome-${record.outcome}">${data.outcomeLabels[record.outcome]}</span></td><td title="${esc(record.message)}">${esc(record.message)}</td></tr>`).join("");
    $("#log-result").textContent = visible ? `데모 ${data.records.length}건 중 ${rows.length}건 일치 · ${rows.length ? start + 1 : 0}~${Math.min(start + pageSize, rows.length)}행 표시` : "데모 상태 예시 · 실제 조회 요청 없음";
    $("#log-page-label").textContent = `${page} / ${pages}`;
    $("#log-prev").disabled = !visible || page <= 1;
    $("#log-next").disabled = !visible || page >= pages;
    $("#log-page-size").disabled = !visible;
  }
  function clearFilters() {
    Object.entries(filterIds).forEach(([key, id]) => { document.getElementById(id).value = key === "q" ? "" : "all"; });
    page = 1;
    render();
  }
  function init(shared) {
    helpers = shared;
    [["log-environment", data.environments], ["log-os", data.operatingSystems], ["log-platform", data.platforms], ["log-source", data.sources]].forEach(([id, labels]) => {
      document.getElementById(id).insertAdjacentHTML("beforeend", Object.entries(labels).map(([value, label]) => `<option value="${value}">${label}</option>`).join(""));
    });
    $("#log-filters").addEventListener("submit", (event) => event.preventDefault());
    Object.entries(filterIds).forEach(([key, id]) => document.getElementById(id).addEventListener(key === "q" ? "input" : "change", () => { page = 1; render(); }));
    $("#log-reset").addEventListener("click", clearFilters);
    $("#log-page-size").addEventListener("change", (event) => { pageSize = Number(event.target.value); page = 1; render(); });
    $("#log-prev").addEventListener("click", () => { page -= 1; render(); });
    $("#log-next").addEventListener("click", () => { page += 1; render(); });
    $("#log-columns").addEventListener("click", (event) => {
      const button = event.target.closest("[data-log-sort]");
      if (!button) return;
      const key = button.dataset.logSort;
      order = key === sort && order === "asc" ? "desc" : "asc";
      sort = key; page = 1; render();
      $(`[data-log-sort="${key}"]`).focus({ preventScroll: true });
    });
    $("#log-rows").addEventListener("click", (event) => {
      const row = event.target.closest("[data-log-id]");
      if (row) { $("#log-rows").querySelector(`[data-log-open="${row.dataset.logId}"]`).focus({ preventScroll: true }); openDetail(row.dataset.logId); }
    });
    $("#log-detail-close").addEventListener("click", () => $("#log-detail-dialog").close());
    document.querySelectorAll("[data-log-tab]").forEach((button) => button.addEventListener("click", () => { detailTab = button.dataset.logTab; renderDetail(); }));
  }
  return Object.freeze({ init, render });
})();
