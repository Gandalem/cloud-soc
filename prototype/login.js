(() => {
  "use strict";
  const form = document.getElementById("login-form"), error = document.getElementById("login-error");
  const query = new URLSearchParams(window.location.search || ""), alert = query.get("alert") || "";
  // Only this fixed same-origin route may survive login; never accept a caller-supplied return URL.
  const destination = query.getAll("alert").length === 1 && /^[0-9a-f]{64}$/.test(alert)
    ? "/workbench.html?alert=" + alert : "/";
  let mode = null;
  async function configure() {
    try {
      const response = await fetch('/api/auth/config', {cache: 'no-store', credentials: 'same-origin'});
      if (!response.ok) throw new Error('unavailable');
      mode = (await response.json()).mode;
      if (!['session', 'basic'].includes(mode)) throw new Error('invalid');
      form.hidden = mode !== 'session'; document.getElementById('login-basic').hidden = mode !== 'basic';
      document.getElementById('login-mode').textContent = mode === 'session' ? '계정으로 보안 관제에 접속합니다.' : '브라우저 인증';
    } catch {
      mode = null; form.hidden = true;
      document.getElementById('login-mode').textContent = '로그인 방식을 확인하지 못했습니다. 페이지를 새로고침하세요.';
    }
  }
  form.addEventListener("submit", async event => {
    event.preventDefault(); error.textContent = "";
    if (mode !== 'session') {error.textContent = '서버의 로그인 방식을 먼저 확인해 주세요.'; return;}
    const button = form.querySelector("button"); button.disabled = true;
    try {
      const response = await fetch("/api/auth/login", {method:"POST",headers:{"Content-Type":"application/json","X-Cloud-SOC":"portal"},body:JSON.stringify({username:form.elements.username.value,password:form.elements.password.value})});
      form.elements.password.value = "";
      if (response.ok) window.location.replace(destination);
      else error.textContent = (await response.json()).error || "로그인에 실패했습니다.";
    } catch { error.textContent = "서버 연결을 확인하세요."; }
    finally { form.elements.password.value = ""; button.disabled = false; }
  });
  configure();
})();
