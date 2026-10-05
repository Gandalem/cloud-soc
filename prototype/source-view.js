/* Explicit POST, text-only JSON and volatile memory. Never fetch unfiltered ES. */
(() => {
  "use strict";
  if (typeof document === "undefined") return;
  const $ = id => document.getElementById(id);
  let ref = null, controller = null, generation = 0;
  function close() {
    generation++; controller?.abort(); controller = null; ref = null;
    $("source-panel").hidden = true; $("source-json").hidden = true;
    $("source-json").textContent = ""; $("source-state").textContent = "";
    $("source-read").disabled = false; $("source-purpose").value = "investigation";
  }
  async function open(reference) {
    close(); const ticket = generation; controller = new AbortController();
    const pending = controller, timer = setTimeout(() => pending.abort(), 15000);
    try {
      const response = await fetch("/api/logs/access", {cache:"no-store", credentials:"same-origin", signal:controller.signal});
      if (!response.ok) return;
      const capabilities = await response.json();
      if (ticket !== generation || !$("log-detail-dialog").open || capabilities.policy_version !== "protected-fields-v1" || capabilities.protected_source !== true) return;
      ref = {index:reference.index, id:reference.id}; $("source-panel").hidden = false;
    } catch (_) { /* Metadata stays usable if capabilities cannot be read. */ }
    finally { clearTimeout(timer); }
  }
  async function read() {
    if (!ref || $("source-read").disabled) return;
    const ticket = ++generation; controller?.abort(); controller = new AbortController();
    $("source-read").disabled = true; $("source-json").hidden = true; $("source-json").textContent = "";
    $("source-state").textContent = "권한·조회 사유·감사 기록 확인 중";
    const pending = controller, timer = setTimeout(() => pending.abort(), 15000);
    try {
      const response = await fetch("/api/logs/source", {method:"POST", cache:"no-store", credentials:"same-origin", signal:controller.signal,
        headers:{"Content-Type":"application/json","X-Cloud-SOC":"portal"}, body:JSON.stringify({...ref,purpose:$("source-purpose").value})});
      if (!response.ok) {
        const messages = {400:"문서 참조와 조회 사유를 확인하세요.",401:"로그인이 필요합니다.",403:"원문 조회 권한이 없습니다.",404:"문서를 찾을 수 없습니다.",413:"원문 필드가 표시 한도를 초과했습니다.",503:"권한·수신 서버·감사 저장소를 확인하세요. 조회를 허용하지 않았습니다."};
        throw Error(messages[response.status] || "보호된 원문 필드를 조회하지 못했습니다.");
      }
      let data;
      try { data = await response.json(); }
      catch (_) { throw Error("보호된 원문 응답을 읽지 못했습니다."); }
      if (ticket !== generation) return;
      if (data.contract_version !== 1 || data.policy_version !== "protected-fields-v1" || data.raw_access !== "protected_fields" || data.complete_source !== false
          || typeof data.audit_id !== "string" || !/^[1-9][0-9]*$/.test(data.audit_id)
          || data.reference?.id !== ref.id || data.reference?.index !== ref.index || !data.source || typeof data.source !== "object" || Array.isArray(data.source)) throw Error("보호된 원문 응답을 확인하지 못했습니다.");
      $("source-json").textContent = JSON.stringify(data.source,null,2); $("source-json").hidden = false;
      $("source-state").textContent = `접근 감사 ${data.audit_id} · 마스킹된 허용 필드 · 전체 원본 아님`;
    } catch (error) {
      if (ticket === generation) $("source-state").textContent = error.name === "AbortError" || error instanceof TypeError ? "원문 조회 연결이 종료되었습니다. 다시 조회하세요." : error.message;
    } finally { clearTimeout(timer); if (ticket === generation) $("source-read").disabled = false; }
  }
  $("source-read").addEventListener("click",read);
  $("log-detail-dialog").addEventListener("close",close);
  window.addEventListener("pagehide",close);
  window.cloudSocSource = {open,close};
  close();
})();
