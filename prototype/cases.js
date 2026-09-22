(() => {
  "use strict";
  const $ = id => document.getElementById(id), form = $("case-filters");
  const states = {new:"신규",triage:"초기 분류",investigating:"조사 중",escalated:"상위 이관",closed:"종결"};
  const priorities = {critical:"긴급",high:"높음",medium:"중간",low:"낮음"};
  let page = 1, generation = 0;
  const saved = new URLSearchParams(window.location.search);
  for (const field of form.querySelectorAll("select")) if (saved.has("case_" + field.name) && Array.from(field.options).some(o => o.value === saved.get("case_" + field.name))) field.value = saved.get("case_" + field.name);
  if (/^[1-9][0-9]{0,4}$/.test(saved.get("case_page") || "")) page = Number(saved.get("case_page"));
  function node(tag, text) {const n=document.createElement(tag);n.textContent=text;return n;}
  async function load() {
    const version=++generation;
    $("case-rows").replaceChildren(); $("case-counts").textContent="업무 조회 중"; $("case-error").hidden=true;
    $("case-prev").disabled=true; $("case-next").disabled=true;
    const params = new URLSearchParams();
    for (const [key,value] of new FormData(form)) if (value) params.set(key,value);
    params.set("page",String(page));
    const back = new URLSearchParams();
    for (const [key,value] of params) back.set("case_"+key,value);
    window.history.replaceState(null,"","index.html?"+back+"#case-queue");
    try {
      const response=await fetch("/api/cases?"+params,{credentials:"same-origin",cache:"no-store"});
      if(!response.ok) throw new Error("사건 업무 조회 실패 ("+response.status+")");
      const data=await response.json(); if(version!==generation)return;
      if(!Array.isArray(data.rows)||data.rows.length>25||!data.counts||!Number.isSafeInteger(data.counts.total))throw new Error("잘못된 업무 응답입니다.");
      const c=data.counts;
      $("case-counts").textContent="현재 필터: 전체 "+c.total+" · 미종결 "+c.open+" · 조사 중 "+c.investigating+" · 미배정 "+c.unassigned;
      for(const row of data.rows){
        const tr=node("tr",""),td=node("td",""),link=node("a",row.title);
        link.href="workbench.html?"+new URLSearchParams({case:row.id,return:back.toString()});td.append(link);tr.append(td);
        for(const value of [row.organization,priorities[row.priority],states[row.status],row.owner||"미배정",new Date(row.created_at).toLocaleString("ko-KR",{timeZone:"Asia/Seoul"})])tr.append(node("td",value));
        $("case-rows").append(tr);
      }
      if(!data.rows.length)$("case-counts").textContent+=" · 해당 사건 없음";
      $("case-page").textContent=page+" 페이지";$("case-prev").disabled=page<=1;$("case-next").disabled=!data.has_next;
    }catch(error){if(version===generation){$("case-rows").replaceChildren();$("case-counts").textContent="업무 조회 실패";$("case-error").hidden=false;$("case-error").textContent=error.message;}}
  }
  form.addEventListener("submit",event=>{event.preventDefault();page=1;load();});
  $("case-prev").addEventListener("click",()=>{if(page>1){page--;load();}});
  $("case-next").addEventListener("click",()=>{page++;load();});
  window.addEventListener("pagehide",()=>{generation++;$("case-rows").replaceChildren();});
  load();
})();
