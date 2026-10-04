(() => {
  "use strict";
  const form = document.getElementById("login-form"), error = document.getElementById("login-error");
  form.addEventListener("submit", async event => {
    event.preventDefault(); error.textContent = "";
    const button = form.querySelector("button"); button.disabled = true;
    try {
      const response = await fetch("/api/auth/login", {method:"POST",headers:{"Content-Type":"application/json","X-Cloud-SOC":"portal"},body:JSON.stringify({username:form.elements.username.value,password:form.elements.password.value})});
      form.elements.password.value = "";
      if (response.ok) window.location.replace("/");
      else error.textContent = (await response.json()).error || "로그인에 실패했습니다.";
    } catch { error.textContent = "서버 연결을 확인하세요."; }
    finally { form.elements.password.value = ""; button.disabled = false; }
  });
})();
