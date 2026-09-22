/* Read-only live intake metadata. No fixture fallback or browser persistence. */
(() => {
  "use strict";
  const sources = { windows_event: "Windows 이벤트", windows_file: "Windows 파일", linux_file: "Linux 파일", linux_journald: "Linux 저널", network_packetbeat: "네트워크", aws_cloudtrail: "AWS 관리 이벤트", oci_audit: "OCI 감사 이벤트", unknown: "미분류" };
  const osNames = { windows: "Windows", linux: "Linux", cloud: "클라우드 API", unknown: "미확인" };
  const outcomes = { success: "성공", failure: "실패", unknown: "미확인" };
  const label = (map, value, fallback = "미확인") => Object.hasOwn(map, value) ? map[value] : fallback;
  const escape = value => String(value ?? "미관측").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const time = value => value && Number.isFinite(Date.parse(value)) ? new Intl.DateTimeFormat("ko-KR", { timeZone: "Asia/Seoul", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" }).format(new Date(value)) : "미관측";
  function rowMarkup(row, index) {
    const cloudName = row.cloud_provider === "oci" ? "OCI" : row.source_kind === "aws_cloudtrail" ? "AWS" : "클라우드";
    const origin = row.stream === "cloud" ? `${cloudName} ${row.cloud_account || "계정 미관측"} / ${row.cloud_region || "리전 미관측"}` : row.host_name;
    const values = [time(row.received_at), time(row.event_at), origin, label(osNames, row.os), row.collector,
      label(sources, row.source_kind, "미분류"), row.channel || row.file_path || row.dataset,
      row.source_ip, row.destination_ip, row.user || row.actor_id, `${row.action || "미관측"} / ${label(outcomes, row.outcome)}`, "미평가"];
    return `<tr><td><button type="button" class="log-row-open" data-row="${index}" title="${escape(row.reference.id)}">${escape(row.reference.id)}</button></td>${values.map(value => `<td title="${escape(value)}">${escape(value)}</td>`).join("")}</tr>`;
  }
  function query(values, now = Date.now()) {
    let start, end;
    if (values.period === "custom") {
      const pattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/;
      if (!pattern.test(values.start) || !pattern.test(values.end)) throw new Error("시작과 종료 시각을 KST로 입력하세요.");
      start = new Date(values.start + "+09:00"); end = new Date(values.end + "+09:00");
    } else {
      if (!["60", "1440", "10080", "43200"].includes(values.period)) throw new Error("조회 기간을 확인하세요.");
      end = new Date(now); start = new Date(now - Number(values.period) * 60000);
    }
    if (!Number.isFinite(+start) || !Number.isFinite(+end) || +end <= +start || +end - +start > 30 * 86400000) throw new Error("조회 기간은 0일 초과, 최대 30일입니다.");
    const params = new URLSearchParams({ start: start.toISOString(), end: end.toISOString(), time_basis: values.timeBasis, page_size: values.pageSize });
    for (const name of ["host", "ip", "os", "collector"]) if (values[name].trim()) params.set(name, values[name].trim());
    return "/api/logs?" + params;
  }
  function validPage(data) {
    return data?.contract_version === 1 && Array.isArray(data.rows) && data.rows.length <= 50 && data.filters
      && ["ingested", "event"].includes(data.filters.time_basis) && Number.isFinite(Date.parse(data.filters.start)) && Number.isFinite(Date.parse(data.filters.end))
      && (data.next_cursor === null || (typeof data.next_cursor === "string" && data.next_cursor.length <= 8192))
      && data.raw_access === "restricted" && data.rows.every(row => row && typeof row.reference?.id === "string" && typeof row.reference?.index === "string");
  }
  const securityLabels = {
    category: "보안 분류", action: "보안 행위", outcome: "보안 결과", actor: "행위/요청 주체", execution_user: "새 프로세스 실행 계정",
    target_user: "대상 계정", target_domain: "대상 도메인", group: "대상 그룹", member_sid: "구성원 SID", logon_type: "Windows 로그온 유형", privileges: "할당된 권한",
    process_path: "실행 경로", process_pid: "프로세스 PID", parent_path: "부모 실행 경로", parent_pid: "부모 PID", process_guid: "프로세스 GUID", parent_guid: "부모 GUID", sha256: "실행 파일 SHA-256",
    object_type: "객체 유형", object_path: "접근 대상 경로", access_mask: "접근 권한 마스크", access_rights: "사용된 접근 권한", task_name: "예약 작업", service_name: "서비스",
    source_ip: "출발지 IP", source_port: "출발지 포트", destination_ip: "목적지 IP", destination_port: "목적지 포트", bytes: "통신량 (바이트)", packets: "패킷 수",
    dns_name: "DNS 질의 이름", dns_type: "DNS 질의 유형", tls_server: "TLS 서버 이름", tls_version: "TLS 버전", flow_id: "흐름 ID", flow_final: "흐름 종료 보고", protocol: "프로토콜", transport: "전송 방식",
    start: "활동 시작 시각", end: "활동 종료 시각", identity_organization: "GUID 범위 조직", identity_host: "GUID 범위 호스트",
    api: "클라우드 API", event_id: "클라우드 이벤트 ID", provider: "클라우드 서비스", cloud_account: "수집 계정 / 테넌시", cloud_region: "수집 리전",
    compartment_id: "OCI 구획 OCID", compartment_name: "OCI 구획 이름", resource_id: "대상 자원 ID", resource_name: "대상 자원 이름",
    identity_tenancy: "주체 테넌시", principal_id: "행위 주체 OCID", auth_type: "OCI 인증 유형", caller_id: "대리 호출자 OCID", caller_name: "대리 호출자 이름",
    request_id: "요청 ID", http_method: "HTTP 메서드", http_status: "HTTP 응답 코드", event_type: "OCI 이벤트 유형", grouping_id: "OCI 이벤트 그룹 ID",
    identity_type: "AWS 주체 유형", identity_arn: "행위 주체 ARN", identity_account: "행위 주체 계정", session_issuer_arn: "세션 발급 역할 ARN",
    identity_invoked_by: "호출 AWS 서비스", target_policy_arn: "대상 정책 ARN",
    source_address: "출발지 주소 / 서비스", target_role: "대상 역할", target_group_id: "대상 보안그룹", resource_arns: "관측된 자원 ARN", error_code: "AWS 오류 코드", outcome_basis: "결과 판정 근거"
  };
  const securityTerms = {
    cloud: "클라우드 관리", management_api_call: "관리 API 호출",
    authentication: "인증", privilege: "권한", process: "프로세스", account: "계정", group: "그룹", file: "파일", object: "객체", configuration: "설정 변경", network: "네트워크",
    login: "로그인", special_privileges_assigned: "특수 권한 할당", process_created: "프로세스 생성", account_created: "계정 생성", account_deleted: "계정 삭제", local_group_member_added: "로컬 그룹 구성원 추가", local_group_member_removed: "로컬 그룹 구성원 제거", access_right_used: "객체 접근 권한 사용", object_permissions_changed: "객체 권한 변경", service_installed: "서비스 설치", scheduled_task_created: "예약 작업 생성", scheduled_task_updated: "예약 작업 변경", audit_policy_changed: "감사 정책 변경", connection_observed: "연결 관측", file_created_or_overwritten: "파일 생성 또는 덮어쓰기", file_delete_detected: "파일 삭제 관측", traffic_observed: "통신 관측",
    read_data_or_list_directory: "데이터 읽기 / 디렉터리 열람", write_data_or_add_file: "데이터 쓰기 / 파일 추가", append_data_or_add_subdirectory: "데이터 추가 / 하위 디렉터리 추가", delete_right: "삭제 권한", write_dacl: "DACL 변경", write_owner: "소유자 변경"
  };
  const securityLimits = { not_a_detection: "이 해석은 공격 판정이나 탐지 경보가 아닙니다.", conflicting_event_code: "이벤트 코드가 서로 달라 해석하지 않았습니다.", privilege_assignment_not_use: "권한 할당은 실제 권한 사용을 의미하지 않습니다.", pid_not_stable_identity: "PID만으로 다른 시점의 프로세스를 연결하지 않습니다.", access_right_not_exfiltration_or_completed_delete: "접근 권한 사용만으로 유출이나 삭제 완료를 단정하지 않습니다.", not_file_read_audit: "이 이벤트는 파일 읽기 감사가 아닙니다.", no_process_or_file_attribution: "Packetbeat만으로 실행 프로세스나 유출 파일을 알 수 없습니다.", flow_counters_cumulative_do_not_sum_reports: "흐름 카운터는 누적값입니다. 중간 보고들을 합산하지 마세요." };
  function securityEntries(value) {
    if (!value || value.version !== 1) return [["보안 이벤트 해석", "미제공 · 서버 버전 확인 필요"]];
    const entries = [["보안 이벤트 해석", label({ recognized: "지원 형식 확인", partial: "부분 해석 · 필드 누락", unsupported: "미지원 형식 또는 근거 부족" }, value.status)],
      ["감사 설정 상태", value.adapter === "aws_cloudtrail_metadata_v1" ? "관리 이벤트만 수집 · 데이터 이벤트는 미수집" : value.adapter === "oci_audit_metadata_v1" ? "OCI Audit 범위 · 객체 접근/Identity Domains 감사는 별도" : "미확인 · 로그 부재를 감사 비활성으로 단정할 수 없음"], ["해석기", value.adapter || "없음"],
      ["프로세스 연관 근거", value.process_link === "guid_in_same_host_event" ? "같은 호스트 이벤트 내 GUID · 이벤트 간 자동 연결 아님" : "연결하지 않음"]];
    const fields = value.fields || {};
    for (const [key, title] of Object.entries(securityLabels)) {
      if (!Object.hasOwn(fields, key)) continue;
      let item = fields[key];
      if (["category", "action"].includes(key)) item = label(securityTerms, item);
      else if (key === "outcome") item = label(outcomes, item);
      else if (key === "outcome_basis") item = label({ error_code: "오류 코드 관측", console_response: "콘솔 로그인 응답", no_error_reported: "오류 코드 없음 (최종 자원 상태 보장 아님)", http_status: "HTTP 응답 코드 (최종 자원 상태 보장 아님)", status_not_observed: "HTTP 결과 미관측" }, item);
      else if (key === "logon_type" && item != null) item = `${item} · ${label({ 2: "대화형", 3: "네트워크", 4: "배치", 5: "서비스", 7: "잠금 해제", 8: "네트워크 평문 유형", 9: "새 자격 증명", 10: "원격 대화형", 11: "캐시 대화형" }, item, "기타 유형")}`;
      else if (key === "access_rights") item = Array.isArray(item) ? item.slice(0, 6).map(v => label(securityTerms, v)) : null;
      else if (["start", "end"].includes(key)) item = time(item);
      else if (key === "flow_final") item = item === true ? "예" : item === false ? "아니요" : null;
      entries.push([title, item]);
    }
    entries.push(["미관측 / 보호된 필수 필드", Array.isArray(value.missing) ? value.missing.slice(0, 16).map(v => label(securityLabels, v)) : []]);
    entries.push(["해석 제한", Array.isArray(value.limitations) ? value.limitations.slice(0, 8).map(v => label({ ...securityLimits, management_events_not_object_access: "관리 이벤트만 조회하며 S3 객체 접근 등 데이터 이벤트는 포함하지 않습니다.", api_result_not_resource_effect: "API 결과는 이후 자원 상태나 공격 여부의 확정 판정이 아닙니다.", resource_list_truncated: "자원 목록은 최대 20개로 제한되었습니다.", oci_audit_not_object_or_identity_domain_access: "OCI 객체 접근과 Identity Domains 로그인 감사는 별도 수집이 필요합니다.", region_from_collection_scope: "리전은 자원의 위치를 추측한 값이 아니라 Audit 조회 리전입니다." }, v, "추가 제한 사항 있음")) : []]);
    return entries;
  }
  if (typeof module !== "undefined") module.exports = { rowMarkup, query, validPage, time, securityEntries };
  if (typeof document === "undefined") return;
  const $ = selector => document.querySelector(selector);
  let pages = [], page = -1, offset = 0, generation = 0, detailGeneration = 0, pending = null, detailPending = null, busy = false;
  function values() {
    return Object.fromEntries(Object.entries({ period: "log-period", start: "log-start", end: "log-end", timeBasis: "log-time-basis", pageSize: "log-page-size", host: "log-host", ip: "log-ip", os: "log-os", collector: "log-collector" }).map(([key, id]) => [key, $("#" + id).value]));
  }
  function controls() {
    $("#log-panel").setAttribute("aria-busy", String(busy));
    $("#log-prev").disabled = busy || page <= 0;
    $("#log-next").disabled = busy || page < 0 || (!pages[page]?.next_cursor && page >= pages.length - 1);
  }
  function clearDetail() {
    detailGeneration++; detailPending?.abort(); detailPending = null;
    $("#log-detail-fields").replaceChildren();
    $("#log-detail-state").textContent = "";
    if ($("#log-detail-dialog").open) $("#log-detail-dialog").close();
  }
  function clearRows() {
    $("#log-rows").innerHTML = ""; $("#log-empty").hidden = true;
    $("#log-result").textContent = "-"; $("#log-query-range").textContent = "조회 결과 없음";
    clearDetail();
  }
  function fail(error) {
    pages = []; page = -1; offset = 0; clearRows();
    $("#log-error").textContent = error.message; $("#log-error").hidden = false;
    $("#log-state-label").textContent = "조회 실패"; $("#log-page-label").textContent = "페이지 없음";
  }
  async function fetchJson(url, controller) {
    const timer = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch(url, { credentials: "same-origin", cache: "no-store", signal: controller.signal, headers: { Accept: "application/json" } });
      if (!response.ok) {
        const messages = { 400: "조회 조건이 올바르지 않습니다.", 401: "관리자 로그인이 필요합니다. 페이지를 다시 여세요.", 403: "조회 권한이 없습니다.", 404: "조회 API 또는 문서를 찾을 수 없습니다. 서버 배포와 문서 보존 상태를 확인하세요.", 410: "조회 스냅샷이 만료되었습니다. 새로고침하세요.", 413: "표시 한도를 초과했습니다. 페이지 크기나 기간을 줄이세요.", 503: "로그 조회를 사용할 수 없습니다. 서버 연결·조회 계정·매핑을 확인하세요." };
        throw new Error(messages[response.status] || "서버의 로그 조회 요청이 실패했습니다.");
      }
      try { return await response.json(); }
      catch { throw new Error("서버 응답을 읽을 수 없습니다. 중앙 서버 배포 상태를 확인하세요."); }
    } finally { clearTimeout(timer); }
  }
  function render() {
    const current = pages[page];
    $("#log-error").hidden = true;
    $("#log-rows").innerHTML = current.rows.map(rowMarkup).join("");
    $("#log-empty").hidden = current.rows.length !== 0;
    $("#log-result").textContent = `현재 페이지 ${current.rows.length}건 · 전체 건수 미집계`;
    $("#log-page-label").textContent = `${offset + page + 1} 페이지`;
    $("#log-state-label").textContent = "조회 완료 · 스냅샷";
    $("#log-query-range").textContent = `${current.filters.time_basis === "ingested" ? "서버 수신 시각" : "로그 기준 시각"}: ${time(current.filters.start)} ~ ${time(current.filters.end)} (종료 미포함, KST)`;
    controls();
  }
  async function load(url, reset) {
    const ticket = ++generation;
    pending?.abort(); pending = new AbortController(); const controller = pending;
    if (reset) { pages = []; page = -1; offset = 0; }
    busy = true; clearRows(); controls();
    $("#log-error").hidden = true; $("#log-state-label").textContent = "조회 중";
    try {
      const data = await fetchJson(url, controller);
      if (ticket !== generation) return;
      if (!validPage(data)) throw new Error("조회 응답 형식이 올바르지 않습니다. 중앙 서버 버전을 확인하세요.");
      pages.push(data); page = pages.length - 1;
      if (pages.length > 20) { pages.shift(); page--; offset++; }
      render();
    } catch (error) {
      if (ticket === generation) fail(new Error(error instanceof TypeError || error.name === "AbortError" ? "중앙 서버 연결에 실패했거나 응답 시간이 초과되었습니다. 새로고침하세요." : error.message));
    } finally {
      if (ticket === generation) { busy = false; pending = null; controls(); }
    }
  }
  function refresh() {
    try { return load(query(values()), true); }
    catch (error) { generation++; pending?.abort(); busy = false; fail(error); controls(); }
  }
  const detailLabels = { received_at: "서버 수신 시각", event_at: "로그 기준 시각", organization: "조직", agent_id: "수집기 ID", collector: "수집기", host_name: "수집 호스트", host_ips: "호스트 IP", os: "OS 분류", os_basis: "OS 분류 근거", os_name: "OS 이름", source_label: "소스 태그", channel: "채널", file_path: "파일 경로", dataset: "데이터셋", event_code: "이벤트 코드", action: "행위", user: "사용자", source_ip: "출발지 IP", destination_ip: "목적지 IP", transport: "전송 방식", protocol: "프로토콜", flow_final: "흐름 종료 보고" };
  async function detail(row) {
    const ticket = ++detailGeneration; detailPending?.abort(); detailPending = new AbortController();
    const controller = detailPending;
    $("#log-detail-fields").replaceChildren(); $("#log-detail-title").textContent = row.reference.id;
    $("#log-detail-state").textContent = "상세 조회 중";
    if (!$("#log-detail-dialog").open) $("#log-detail-dialog").showModal();
    try {
      const data = await fetchJson("/api/logs/detail?" + new URLSearchParams(row.reference), controller);
      if (ticket !== detailGeneration) return;
      if (data.contract_version !== 1 || data.raw_access !== "restricted" || data.row?.reference?.id !== row.reference.id || data.row?.reference?.index !== row.reference.index) throw new Error("상세 응답의 문서 참조가 일치하지 않습니다.");
      const entries = [["인덱스", data.row.reference.index], ["문서 ID", data.row.reference.id], ...securityEntries(data.security), ...Object.entries(detailLabels).map(([key, name]) => [name, key.endsWith("_at") ? time(data.row[key]) : data.row[key]]), ["원본 표준 필드 결과", label(outcomes, data.row.outcome)], ["목록 메타데이터 평가", "미평가"], ["형식 오류 필드", data.row.quality?.invalid_fields], ["표시 제한 필드", data.row.quality?.truncated_fields]];
      for (const [name, value] of entries) {
        const dt = document.createElement("dt"), dd = document.createElement("dd"); dt.textContent = name;
        dd.textContent = Array.isArray(value) ? value.join(", ") || "없음" : value == null ? "미관측" : String(value);
        $("#log-detail-fields").append(dt, dd);
      }
      $("#log-detail-state").textContent = "제한된 메타데이터 · 전체 원문 접근 제한";
    } catch (error) {
      if (ticket === detailGeneration) $("#log-detail-state").textContent = error.name === "AbortError" || error instanceof TypeError ? "상세 조회 연결에 실패했습니다. 다시 열어 주세요." : error.message;
    }
  }
  $("#log-filters").addEventListener("submit", event => { event.preventDefault(); refresh(); });
  $("#log-refresh").addEventListener("click", refresh);
  $("#log-reset").addEventListener("click", () => { $("#log-filters").reset(); updatePeriod(); refresh(); });
  function updatePeriod() { for (const id of ["#log-start-label", "#log-end-label"]) $(id).hidden = $("#log-period").value !== "custom"; }
  $("#log-period").addEventListener("change", updatePeriod);
  $("#log-next").addEventListener("click", () => {
    if (busy || page < 0) return;
    clearDetail();
    if (page < pages.length - 1) { page++; render(); }
    else if (pages[page].next_cursor) load("/api/logs?" + new URLSearchParams({ cursor: pages[page].next_cursor }), false);
  });
  $("#log-prev").addEventListener("click", () => { if (!busy && page > 0) { clearDetail(); page--; render(); } });
  $("#log-rows").addEventListener("click", event => {
    const button = event.target.closest("[data-row]");
    if (!busy && button && page >= 0) { const row = pages[page].rows[Number(button.dataset.row)]; if (row) detail(row); }
  });
  $("#log-detail-close").addEventListener("click", clearDetail);
  $("#log-detail-dialog").addEventListener("cancel", () => { detailGeneration++; detailPending?.abort(); });
  window.addEventListener("pagehide", () => { generation++; pending?.abort(); clearDetail(); pages = []; page = -1; clearRows(); });
  window.addEventListener("pageshow", event => { if (event.persisted) refresh(); });
  refresh();
})();
