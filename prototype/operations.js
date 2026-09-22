(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const labels = {ok: "조회 성공", no_index: "인덱스 없음", unavailable: "조회 실패", not_started: "실행 기록 없음", stale: "상태 갱신 지연 / 중단 여부 확인 필요", success: "최근 정규화 성공", running: "정규화 실행 중", failed: "정규화 실패", waiting: "다음 수신 구간 대기"};
  const evidenceLabels = {exact_reference: "정확한 문서 참조 확인 (내용 해시 재검증은 아님)", normalized_missing_or_expired: "정규화 근거 없음 / 만료", raw_missing_or_expired: "원본 근거 없음 / 만료", provenance_mismatch: "근거 참조 불일치", unsupported_or_invalid_reference: "지원하지 않거나 잘못된 근거 참조", invalid_reference: "잘못된 근거 참조"};
  const fmt = (value) => value ? new Date(value).toLocaleString("ko-KR", {timeZone: "Asia/Seoul", hour12: false}) : "미확인";
  let generation = 0, detailGeneration = 0;
  function node(tag, value, className) {
    const element = document.createElement(tag);
    if (value !== undefined) element.textContent = value;
    if (className) element.className = className;
    return element;
  }
  async function request(path) {
    const response = await fetch(path, {cache: "no-store", credentials: "same-origin"});
    if (!response.ok) throw new Error("서버 연결·권한·조회 조건을 확인하세요. (" + response.status + ")");
    return response.json();
  }
  function chart(target, section) {
    target.replaceChildren();
    if (!section || section.state !== "ok") { target.append(node("p", labels[section?.state] || "미확인")); return; }
    if (!section.count) { target.append(node("p", "조회 구간의 기록이 없습니다.")); return; }
    const buckets = section.buckets, max = Math.max(1, ...buckets.map((item) => item.count));
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 600 140"); svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", "기간별 문서 수. 총 " + section.count + "건");
    buckets.forEach((item, i) => {
      const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      const height = item.count / max * 130;
      for (const [key, value] of Object.entries({x: i * 600 / buckets.length, y: 140 - height, width: Math.max(0.5, 600 / buckets.length - 1), height})) rect.setAttribute(key, String(value));
      const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
      title.textContent = fmt(item.time) + " · " + item.count + "건"; rect.append(title); svg.append(rect);
    });
    const box = node("div", undefined, "ops-bars"); box.append(svg); target.append(box, node("p", fmt(buckets[0]?.time) + " ~ " + fmt(buckets.at(-1)?.time)));
  }
  function render(data) {
    if (!data || !data.sections || !Number.isFinite(Date.parse(data.start)) || !Number.isFinite(Date.parse(data.end))) throw new Error("관제 응답 형식을 확인하세요.");
    const sections = data.sections;
    for (const key of ["intake", "processing", "alerts", "quality"]) {
      const s = sections[key];
      if (!s || !["ok", "no_index", "unavailable"].includes(s.state) || (s.state === "ok" &&
          (!Number.isSafeInteger(s.count) || s.count < 0 || !Array.isArray(s.rows) || s.rows.length > 50 || !Array.isArray(s.statuses) ||
           !Array.isArray(s.buckets) || s.buckets.length > 1000 || s.buckets.some(b => !Number.isFinite(Date.parse(b.time)) || !Number.isSafeInteger(b.count) || b.count < 0)))) throw new Error("관제 응답 형식을 확인하세요.");
    }
    if (!sections.pipeline || !Object.hasOwn(labels, sections.pipeline.state)) throw new Error("처리기 응답 형식을 확인하세요.");
    $("ops-range").textContent = fmt(data.start) + " ~ " + fmt(data.end) + " (KST)";
    const metrics = $("ops-metrics"); metrics.replaceChildren();
    for (const [key, title] of [["intake", "수신 로그"], ["processing", "처리 결과 기록"], ["alerts", "저장된 경보"], ["quality", "수집 품질 보고"]]) {
      const section = sections[key], card = node("article", undefined, "panel");
      card.append(node("h2", title), node("strong", section.state === "ok" ? section.count.toLocaleString("ko-KR") : "미확인", "ops-value"), node("p", labels[section.state] || "미확인"));
      if (key === "processing" && section.state === "ok") card.append(node("p", section.statuses.map((s) => ({normalized: "정규화", unsupported: "미지원", invalid: "검증 실패"}[s.key] || "기타") + " " + s.doc_count).join(" · ") || "처리 기록 없음"));
      metrics.append(card);
    }
    const pipeline = sections.pipeline;
    $("ops-pipeline").textContent = "정규화 처리기: " + (labels[pipeline.state] || "미확인") + " · 마지막 성공: " + fmt(pipeline.last_success) + " · 수신 시각 체크포인트: " + fmt(pipeline.checkpoint);
    chart($("ops-intake-chart"), sections.intake); chart($("ops-alert-chart"), sections.alerts);
    const alerts = sections.alerts; $("ops-alert-rows").replaceChildren();
    $("ops-alert-state").textContent = alerts.state === "ok" ? "총 " + alerts.count + "건 · 최신 최대 50건 표시 (페이지 탐색 미지원)" : labels[alerts.state];
    for (const row of alerts.rows || []) {
      const tr = node("tr");
      const severity = {critical: "긴급", high: "높음", medium: "중간", low: "낮음"}[row.severity] || row.severity || "미확인";
      for (const value of [fmt(row.timestamp), severity, row.rule, row.title, row.organization]) tr.append(node("td", value || "미관측"));
      const td = node("td"), button = node("button", "상세 / 근거");
      button.type = "button"; button.addEventListener("click", () => detail(row.id)); td.append(button); tr.append(td); $("ops-alert-rows").append(tr);
    }
  }
  async function detail(id) {
    const version = ++detailGeneration;
    $("ops-detail-content").replaceChildren(); $("ops-detail-state").textContent = "조회 중";
    if (!$("ops-detail").open) $("ops-detail").showModal();
    try {
      const data = await request("/api/alerts/detail?" + new URLSearchParams({id}));
      if (version !== detailGeneration) return;
      $("ops-detail-state").textContent = data.evidence_count ? "저장된 근거 " + data.evidence_count + "건 · 최대 100건 개별 확인" : "과거 경보에 정확한 근거 참조가 없습니다. 주변 로그로 대체하지 않습니다.";
      const condition = data.condition;
      $("ops-detail-content").append(node("p", (data.alert.title || data.alert.rule || "경보") + " · 규칙 버전 " + (data.rule_version || "미기록")), node("p", "관측 수 " + (condition.event_count ?? "미기록") + " / 임계값 " + (condition.threshold ?? "미기록") + " / 시간 창 " + (condition.time_window_seconds ?? "미기록") + "초"));
      for (let i = 0; i < data.evidence_limit; i++) {
        const box = node("section", undefined, "ops-evidence"), button = node("button", "근거 " + (i + 1) + " 확인"), result = node("div");
        button.type = "button";
        button.addEventListener("click", async () => {
          button.disabled = true; result.textContent = "조회 중";
          try {
            const reply = await request("/api/alerts/detail?" + new URLSearchParams({id, evidence: String(i)}));
            if (version !== detailGeneration) return;
            const item = reply.evidence;
            result.replaceChildren(node("p", evidenceLabels[item.state] || "미확인"));
            if (item.raw) result.append(node("p", "원본: " + item.raw.index + " / " + item.raw.id));
            if (item.metadata) result.append(node("pre", JSON.stringify(item.metadata, null, 2)));
          } catch (error) { result.textContent = error.message; } finally { button.disabled = false; }
        });
        box.append(button, result); $("ops-detail-content").append(box);
      }
    } catch (error) { if (version === detailGeneration) $("ops-detail-state").textContent = error.message; }
  }
  async function refresh() {
    const version = ++generation;
    $("ops-error").hidden = true; $("ops-range").textContent = "조회 중";
    // Clear stale counts while loading a different interval or after failure.
    for (const id of ["ops-metrics", "ops-intake-chart", "ops-alert-chart", "ops-alert-rows"]) $(id).replaceChildren();
    $("ops-pipeline").textContent = "처리기 상태 조회 중"; $("ops-alert-state").textContent = "조회 중";
    const end = new Date(), start = new Date(end.getTime() - Number($("ops-period").value) * 60000);
    try {
      const data = await request("/api/operations?" + new URLSearchParams({start: start.toISOString(), end: end.toISOString()}));
      if (version === generation) render(data);
    } catch (error) {
      if (version !== generation) return;
      for (const id of ["ops-metrics", "ops-intake-chart", "ops-alert-chart", "ops-alert-rows"]) $(id).replaceChildren();
      $("ops-error").hidden = false; $("ops-error").textContent = error.message;
      $("ops-range").textContent = "조회 실패"; $("ops-pipeline").textContent = "처리기 상태 미확인"; $("ops-alert-state").textContent = "조회 실패";
    }
  }
  $("ops-filter").addEventListener("submit", (event) => {event.preventDefault(); refresh();});
  $("ops-detail-close").addEventListener("click", () => $("ops-detail").close());
  $("ops-detail").addEventListener("close", () => {detailGeneration++; $("ops-detail-content").replaceChildren();});
  window.addEventListener("pagehide", () => {generation++; detailGeneration++; $("ops-detail-content").replaceChildren();});
  refresh();
})();
