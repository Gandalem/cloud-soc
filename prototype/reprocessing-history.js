(() => {
  "use strict";
  const state = {rows: [], page: 0, query: "", status: ""};
  const $ = id => document.getElementById(id);
  const names = {recognized: "지원 형식 일치", partial: "부분 정규화"};
  function date(value) {
    if (!value || Number.isNaN(Date.parse(value))) return "미확인";
    return new Intl.DateTimeFormat("ko-KR", {timeZone: "Asia/Seoul", dateStyle: "short", timeStyle: "medium"}).format(new Date(value));
  }
  function detail(row) {
    $("detail").replaceChildren();
    for (const [name, value] of [
      ["정규화 문서 ID", row.id], ["파서", row.adapter], ["해석 상태", names[row.parse_status]],
      ["이벤트 시각 (KST)", date(row.timestamp)], ["수신 시각 (KST)", date(row.ingested)],
      ["시각 근거", row.time_basis], ["관측 결과", row.outcome],
      ["시간대 보완", row.timezone_corrected ? "+09:00 / 원본 변경 없음" : "없음"],
      ["원본 인덱스", row.raw.index], ["원본 문서 ID", row.raw.id]
    ]) {
      const dt = document.createElement("dt"), dd = document.createElement("dd");
      dt.textContent = name; dd.textContent = value || "미확인";
      $("detail").append(dt, dd);
    }
    if (!$("detail-panel").open) $("detail-panel").showModal();
  }
  function render() {
    const query = $("search").value.trim().toLocaleLowerCase();
    state.query = query; state.status = $("status").value;
    const rows = state.rows.filter(row => (!$("status").value || row.parse_status === $("status").value)
      && `${row.host || ""} ${row.action || ""}`.toLocaleLowerCase().includes(query));
    const pages = Math.max(1, Math.ceil(rows.length / 50));
    state.page = Math.max(0, Math.min(state.page, pages - 1));
    $("rows").replaceChildren();
    for (const [offset, row] of rows.slice(state.page * 50, (state.page + 1) * 50).entries()) {
      const tr = document.createElement("tr");
      for (const value of [state.page * 50 + offset + 1, date(row.timestamp), row.host, row.action, names[row.parse_status], row.timezone_corrected ? "+09:00" : "없음"]) {
        const td = document.createElement("td"); td.textContent = value || "미확인"; tr.append(td);
      }
      const td = document.createElement("td"), button = document.createElement("button");
      button.type = "button"; button.textContent = "상세"; button.addEventListener("click", () => detail(row));
      td.append(button); tr.append(td); $("rows").append(tr);
    }
    $("page-state").textContent = `${rows.length}건 · ${state.page + 1} / ${pages}페이지 · ${rows.length ? state.page * 50 + 1 : 0}~${Math.min((state.page + 1) * 50, rows.length)}번째 기록`;
    $("previous").disabled = state.page === 0; $("next").disabled = state.page + 1 >= pages;
  }
  async function load() {
    $("refresh").disabled = true; $("error").hidden = true; $("summary").textContent = "조회 중";
    if ($("detail-panel").open) $("detail-panel").close();
    state.rows = []; state.page = 0; render();
    try {
      const response = await fetch("/api/reprocessing/history", {credentials: "same-origin"});
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "이력 조회 실패");
      if (!Array.isArray(result.rows)) throw new Error("이력 목록 응답 형식이 올바르지 않습니다. 포털 업데이트를 확인하세요.");
      state.rows = result.rows;
      $("summary").textContent = `전체 ${result.total}건 · 지원 형식 일치 ${result.recognized}건 · 부분 정규화 ${result.partial}건 · 시간대 보완 ${result.timezone_corrected}건`;
      render();
    } catch (error) {
      $("summary").textContent = "조회 실패"; $("error").textContent = error.message; $("error").hidden = false;
    } finally { $("refresh").disabled = false; }
  }
  $("detail-close").addEventListener("click", () => $("detail-panel").close());
  $("refresh").addEventListener("click", load);
  function filter() {
    if (state.query === $("search").value.trim().toLocaleLowerCase() && state.status === $("status").value) return;
    state.page = 0; render();
  }
  $("status").addEventListener("change", filter);
  $("status").addEventListener("input", filter);
  for (const event of ["input", "search", "change", "compositionend"]) $("search").addEventListener(event, filter);
  function move(delta) {
    const button = $(delta < 0 ? "previous" : "next");
    if (button.disabled) return;
    state.page += delta;
    render();
    $("page-state").scrollIntoView({block: "center", behavior: "auto"});
  }
  $("previous").addEventListener("click", () => move(-1));
  $("next").addEventListener("click", () => move(1));
  load();
})();
