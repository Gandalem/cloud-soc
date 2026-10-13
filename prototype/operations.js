(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const labels = {ok: "조회 성공", no_index: "인덱스 없음", unavailable: "조회 실패", not_started: "실행 기록 없음", stale: "상태 갱신 지연 / 중단 여부 확인 필요", success: "최근 정규화 성공", running: "정규화 실행 중", failed: "정규화 실패", waiting: "다음 수신 구간 대기"};
  const evidenceLabels = {exact_reference: "정확한 문서 참조 확인", normalized_hash_mismatch: "정규화 근거 내용 변경 감지", invalid_evidence_hash: "저장된 근거 해시 형식 오류", normalized_missing_or_expired: "정규화 근거 없음 / 만료", raw_missing_or_expired: "원본 근거 없음 / 만료", provenance_mismatch: "근거 참조 불일치", unsupported_or_invalid_reference: "지원하지 않거나 잘못된 근거 참조", invalid_reference: "잘못된 근거 참조"};
  const fmt = (value) => typeof value === 'string' && Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString("ko-KR", {timeZone: "Asia/Seoul", hour12: false}) : "미확인";
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
    const pipeline = sections.pipeline, detector = pipeline.detector || {state: 'not_started'};
    const limited = pipeline.coverage ? pipeline.coverage.state !== 'observed' :
      [pipeline, detector].some(stage => !['success', 'running', 'waiting'].includes(stage.state) || ['failed', 'stale', 'delayed', 'warning'].includes(stage.health));
    $("ops-range").textContent = fmt(data.start) + " ~ " + fmt(data.end) + " (KST)";
    const metrics = $("ops-metrics"); metrics.replaceChildren();
    for (const [key, title] of [["alerts", "저장된 경보"], ["intake", "수신 로그"], ["processing", "로그 해석 결과"], ["quality", "수집 상태 보고"]]) {
      const section = sections[key], card = node("article", undefined, "panel");
      card.append(node("h2", title), node("strong", section.state === "ok" ? section.count.toLocaleString("ko-KR") : "미확인", "ops-value"), node("p", labels[section.state] || "미확인"));
      if (key === 'alerts' && limited) card.append(node('p', '분석 미완료·확인 필요 구간이 있습니다. 이 숫자로 위험 없음을 판단할 수 없습니다.', 'ops-warning'));
      if (key === 'quality') card.append(node('p', '보고 건수이며 정상 호스트 수를 뜻하지 않습니다.'));
      if (key === "processing" && section.state === "ok") card.append(node("p", section.statuses.map((s) => ({normalized: "위험 평가용", unsupported: "지원 범위 밖", invalid: "필수 정보 누락"}[s.key] || "기타") + " " + s.doc_count).join(" · ") || "해석 결과 없음"));
      metrics.append(card);
    }
    $("ops-pipeline").textContent = "정규화 처리기: " + (labels[pipeline.state] || "미확인");
    const detectorLabels = { ...labels, success: "최근 탐지 성공", running: "탐지 실행 중", failed: "탐지 실패" };
    const detectorName = detector.detection?.includes("ATTACK-") ? "공격 행위 탐지기 (시험 프로필)" : detector.detection && detector.detection.includes(",") ? "SSH·클라우드 탐지기" : "SSH 탐지기";
    $("ops-pipeline").textContent += " · " + detectorName + ": " + (detectorLabels[detector.state] || "미확인");
    if ($("ops-pipeline-times")) $("ops-pipeline-times").textContent = "정규화 마지막 성공: " + fmt(pipeline.last_success) + " · 처리 위치: " + fmt(pipeline.checkpoint) + " · 탐지 마지막 성공: " + fmt(detector.last_success);
    const healthLabels = { failed: "탐지 장애: 처리 실패", stale: "탐지 장애: 상태 갱신 중단", delayed: "탐지 지연: 처리 위치 확인 필요", warning: "탐지 경고: 평가 범위·초기 통지 확인 필요" };
    if (healthLabels[detector.health]) $("ops-pipeline").textContent += " · " + healthLabels[detector.health];
    const earlyLabels = {failed:'초기 통지 처리 실패',reconcile_required:'초기 통지·최종 근거 재확인 필요',pending:'초기 통지 처리·전달 대기',unknown:'초기 통지 상태 미확인'};
    if(Object.hasOwn(earlyLabels,detector.early?.state)) $("ops-pipeline").textContent += ' · '+earlyLabels[detector.early.state];
    if (Number.isSafeInteger(detector.lag_seconds)) $("ops-pipeline").textContent += " · 처리 지연 " + detector.lag_seconds + "초";
    if (detector.late_total > 0) $("ops-pipeline").textContent += " · 지연 제외 누적 " + detector.late_total + "건";
    if (detector.legacy_excluded > 0) $("ops-pipeline").textContent += " · 과거 형식 제외 " + detector.legacy_excluded + "건";
    if (detector.history_pending > 0) $("ops-pipeline").textContent += " · 실행 이력 전송 대기 " + detector.history_pending + "건";
    if (detector.excluded_total > 0) $("ops-pipeline").textContent += " · 규칙 평가 제외 누적 " + detector.excluded_total + "건";
    if (pipeline.state === 'failed') $("ops-pipeline").textContent += ' · 새 로그 분석 중단: 탐지기의 실행 완료는 전체 분석 완료를 뜻하지 않습니다.';
    if (pipeline.progress?.state === 'catching_up') $("ops-pipeline").textContent += ' · 현재 구간 ' + pipeline.progress.processed.toLocaleString('ko-KR') + '건 처리 중 · 구간 완료 전';
    $("ops-pipeline").setAttribute("role", "status");
    $("ops-pipeline").setAttribute("aria-live", "polite");
    chart($("ops-intake-chart"), sections.intake); chart($("ops-alert-chart"), sections.alerts);
    const alerts = sections.alerts; $("ops-alert-rows").replaceChildren();
    $("ops-alert-state").textContent = alerts.state === "ok" ? (alerts.count ? "총 " + alerts.count + "건 · 최신 50건까지 표시" :
      limited ? '저장된 경보가 없습니다. 분석 상태가 불완전해 위험 없음으로 해석할 수 없습니다.' : '조회 기간에 저장된 경보가 없습니다. 지원 규칙과 수집 범위를 함께 확인하세요.') : labels[alerts.state];
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
      $("ops-detail-state").textContent = data.evidence_count ? "근거 로그 " + data.evidence_count + "건" : "근거 로그가 없습니다. 주변 로그로 대체하지 않습니다.";
      const condition = data.condition;
      const investigate = node("a", "사건 조사 / 등록");
      investigate.href = "workbench.html?" + new URLSearchParams({alert: id, return: (window.location?.search || "").slice(1), return_page: "operations.html"});
      $("ops-detail-content").append(investigate);
      $("ops-detail-content").append(node("p", data.alert.title || data.alert.rule || "경보"), node("p", "관측 로그 " + (condition.event_count ?? "미기록") + "건"));
      if (data.assessment && typeof data.assessment === "object") {
        const box = node("section", undefined, "ops-evidence"), assessment = data.assessment;
        box.append(node("h3", "탐지 이유"));
        box.append(node("p", assessment.type === "attack_correlation" ? "여러 행위의 연계 의심 · 공격 성공 미확정" : "공격 징후 의심 · 공격 성공 미확정"));
        if (assessment.reason === "call_count_and_api_diversity" && Number.isSafeInteger(assessment.observed_count) && Number.isSafeInteger(assessment.distinct_count)) {
          box.append(node("p", "API 호출 " + assessment.observed_count + "건 · API " + assessment.distinct_count + "종 (중복 제외)"));
        }
        const stageNames = {ssh_failures: "SSH 인증 실패", ssh_success: "SSH 인증 성공", sudo_root_metadata: "root 대상 PAM sudo 세션 기록", high_privilege_policy_attachment: "고권한 정책 연결", trail_stop_or_delete: "Trail 중지·삭제"};
        if (Array.isArray(assessment.stages)) for (const stage of assessment.stages.slice(0, 3)) {
          if (stage && Number.isSafeInteger(stage.count)) box.append(node("p", (stageNames[stage.name] || "관측 단계") + " " + stage.count + "건"));
        }
        const limits = {
          host_user_time_context_only_not_same_session: "동일 SSH 세션인지는 확인되지 않았습니다.",
          sudo_record_not_command_execution_or_privilege_success: "명령 실행·권한 상승 성공은 확인되지 않았습니다.",
          no_user_agent_or_normal_activity_baseline: "사용자 에이전트·평소 활동과의 차이는 평가하지 않았습니다.",
          api_result_not_effective_privilege_or_all_audit_logs_removed: "실제 권한 적용·전체 감사 중단 여부는 확인되지 않았습니다.",
          candidate_threshold_not_live_validated: "시험 규칙 · 운영 기준 미확정"
        };
        if (Array.isArray(assessment.limitations)) for (const code of assessment.limitations.slice(0, 12)) {
          if (typeof code === "string" && Object.hasOwn(limits, code)) box.append(node("p", limits[code]));
        }
        // Existing evidence pagination positions stay unchanged for old alerts.
        $("ops-detail-content").append(box);
      }
      const evidenceContainer = node('div'), navigation = node('div');
      if (data.assessment && typeof data.assessment === "object") {
        const evidenceDetails = node('details', undefined, 'ops-evidence');
        evidenceDetails.append(node('summary', '근거 로그 보기 (' + (data.evidence_count || 0) + '건)'), evidenceContainer, navigation);
        $("ops-detail-content").append(evidenceDetails);
      } else $("ops-detail-content").append(evidenceContainer, navigation);
      const ruleDetails = node('details', undefined, 'ops-evidence');
      ruleDetails.append(node('summary', '규칙 정보'),
        node('p', '규칙 버전: ' + (data.rule_version || '미기록')),
        node('p', '임계값 ' + (condition.threshold ?? '미기록') + ' / 시간 범위 ' + (condition.time_window_seconds ?? '미기록') + '초'));
      $("ops-detail-content").append(ruleDetails);
      function evidencePage(pageData) {
      const page = pageData.evidence_page || {positions: Array.from({length: pageData.evidence_limit}, (_, i) => i), next_offset: null};
      for (const i of page.positions) {
        const box = node("section", undefined, "ops-evidence"), button = node("button", "근거 " + (i + 1) + " 확인"), result = node("div");
        button.type = "button";
        button.addEventListener("click", async () => {
          button.disabled = true; result.textContent = "조회 중";
          try {
            const reply = await request("/api/alerts/detail?" + new URLSearchParams({id, evidence: String(i)}));
            if (version !== detailGeneration) return;
            const item = reply.evidence;
            result.replaceChildren(node("p", evidenceLabels[item.state] || "미확인"));
            if (item.integrity) result.append(node('p', item.integrity === 'normalized_hash_verified' ? '정규화 내용 해시 일치 · 원본 내용 해시는 미검증' : '과거 근거의 내용 해시는 미기록'));
            if (item.raw) result.append(node("p", "원본: " + item.raw.index + " / " + item.raw.id));
            if (item.metadata) result.append(node("pre", JSON.stringify(item.metadata, null, 2)));
          } catch (error) { result.textContent = error.message; } finally { button.disabled = false; }
        });
        box.append(button, result); evidenceContainer.append(box);
      }
      navigation.replaceChildren();
      if (page.next_offset !== null) {
        const more = node('button', '다음 근거 페이지'); more.type = 'button'; navigation.append(more);
        more.addEventListener('click', async () => {
          more.disabled = true;
          try {
            const next = await request('/api/alerts/detail?' + new URLSearchParams({id, offset: String(page.next_offset)}));
            if (version === detailGeneration) evidencePage(next);
          } catch (error) { more.textContent = error.message; } finally { more.disabled = false; }
        });
      }
      }
      evidencePage(data);
    } catch (error) { if (version === detailGeneration) $("ops-detail-state").textContent = error.message; }
  }
  async function refresh() {
    const version = ++generation;
    $("ops-error").hidden = true; $("ops-range").textContent = "조회 중";
    if ($("ops-pipeline-times")) $("ops-pipeline-times").textContent = "";
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
