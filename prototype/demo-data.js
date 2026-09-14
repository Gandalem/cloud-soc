/* Synthetic UI fixtures only. These are not collected logs or detector output. */
window.CloudSocDemo = (() => {
  "use strict";
  const snapshot = "2026-08-31T13:17:00+09:00";
  const clockTime = (second) => `13:${String(Math.floor(second / 60)).padStart(2, "0")}:${String(second % 60).padStart(2, "0")}`;

  function authEvidence(key, host, user, ip, count = 12) {
    return Array.from({ length: count }, (_, index) => {
      const time = clockTime(72 + Math.round(index * 205 / Math.max(count - 1, 1)));
      const id = `DEMO-RAW-${key}-${String(index + 1).padStart(3, "0")}`;
      return {
        id, time, source: "Linux Authentication", host, user, ip,
        action: "ssh_login", outcome: "failure", kind: "EVIDENCE", quality: "Synthetic",
        raw: `Aug 31 ${time} ${host} sshd[1234]: Failed password for ${user} from ${ip} port 54321 ssh2`,
        normalized: { "event.category": ["authentication"], "event.action": "ssh_login", "event.outcome": "failure", "source.ip": ip, "user.name": user, "host.name": host, "@timestamp": `2026-08-31T${time}+09:00` },
        parser: "linux_auth (demo label)",
      };
    });
  }

  function singleEvidence(key, domain, host, user, ip) {
    const cloud = domain === "Cloud";
    const action = cloud ? "demo_policy_change" : "demo_privileged_execution";
    const source = cloud ? "Cloud Audit (synthetic)" : "Host Activity (synthetic)";
    return [{
      id: `DEMO-RAW-${key}-001`, time: "13:04:37", source, host: cloud ? "Not observed" : host, user, ip,
      action, outcome: "success", kind: "EVIDENCE", quality: "Synthetic",
      raw: JSON.stringify({ prototype: true, operation: action, actor: user, target: host, result: "success", source_ip: ip, note: "Invented UI record. Not an OCI API payload or a collected host log." }, null, 2),
      normalized: { "event.category": [cloud ? "configuration" : "process"], "event.action": action, "event.outcome": "success", "source.ip": ip, "user.name": user, "demo.resource": host, "@timestamp": "2026-08-31T13:04:37+09:00" },
      parser: "Not implemented / demo representation",
    }];
  }

  const definitions = [
    { id: "INC-DEMO-001", kind: "Incident", title: "계정 침해 의심", heading: "Possible Account Compromise", priority: "High", status: "New", owner: "", age: 12, domain: "Authentication", reason: "로그인 이상 + 후속 활동 검토", host: "vm01", user: "ubuntu", ip: "192.0.2.10", resource: "instance-demo-01", rule: "AUTH-001", ruleName: "SSH Brute Force", related: "Successful Login", summary: "동일한 IP에서 짧은 시간 동안 반복된 SSH 인증 실패가 관측된 상황을 표현한 데모입니다. 이후 로그인과 권한 활동의 관련성 및 정상 관리 작업 여부를 조사해야 합니다." },
    { id: "INC-DEMO-002", kind: "Incident", title: "비정상 클라우드 API 검토", heading: "Cloud API Activity Review", priority: "High", status: "Investigating", owner: "analyst01", age: 60, domain: "Cloud", reason: "IAM 정책 변경 맥락 확인", host: "policy-demo-02", user: "cloud-user-demo", ip: "198.51.100.20", resource: "policy-demo-02", rule: "CLOUD-001", ruleName: "Cloud Policy Change", related: "Related API Activity", summary: "클라우드 정책 변경을 조사하는 가상의 사례입니다. 변경 주체와 대상, 승인된 관리 작업 여부를 확인해야 하며 API 응답 성공만으로 악성 또는 변경 완료를 단정하지 않습니다." },
    { id: "INC-DEMO-003", kind: "Incident", title: "반복 로그인 실패", heading: "Repeated Authentication Failures", priority: "Medium", status: "New", owner: "", age: 120, domain: "Authentication", reason: "SSH Brute Force", host: "vm02", user: "service-demo", ip: "203.0.113.10", resource: "instance-demo-02", rule: "AUTH-002", ruleName: "Authentication Failure Review", related: "Successful Login", summary: "반복된 인증 실패를 검토하는 합성 데이터입니다. 정상 계정의 설정 오류, 자동화 작업, 의심 접근 등 대안 가설을 확인하며 계정 침해를 확정하지 않습니다." },
    { id: "INC-DEMO-004", kind: "Incident", title: "권한 상승 의심 활동", heading: "Privileged Activity Review", priority: "Medium", status: "Triage", owner: "", age: 180, domain: "Host", reason: "sudo 실행 맥락 확인", host: "vm01", user: "ubuntu", ip: "192.0.2.10", resource: "instance-demo-01", rule: "SYSTEM-001", ruleName: "Privileged Execution Review", related: "Related Host Activity", summary: "특권 명령 실행의 승인 여부를 검토하는 가상의 Host 활동입니다. 명령 실행만으로 악용을 확정하지 않으며 요청자와 업무 맥락을 확인해야 합니다." },
    { id: "INC-DEMO-005", kind: "Incident", title: "클라우드 정책 변경", heading: "Cloud Configuration Change", priority: "Low", status: "Investigating", owner: "analyst02", age: 300, domain: "Cloud", reason: "정책 설정 변경 검토", host: "policy-demo-05", user: "operator-demo", ip: "198.51.100.50", resource: "policy-demo-05", rule: "CLOUD-002", ruleName: "Configuration Change Review", related: "Related API Activity", summary: "정책 설정 변경을 검토하는 데모 업무입니다. 변경 요청과 권한 범위가 일치하는지 확인하고 승인된 작업이라면 근거를 남기는 흐름을 보여줍니다." },
    { id: "ALT-DEMO-001", kind: "Alert", title: "SSH 인증 실패 경보", heading: "SSH Authentication Alert", priority: "High", status: "New", owner: "", age: 8, domain: "Authentication", reason: "300초 내 반복 실패", host: "vm03", user: "ubuntu", ip: "203.0.113.30", resource: "instance-demo-03", rule: "AUTH-001", ruleName: "SSH Brute Force", related: "Successful Login", summary: "Incident에 연결되지 않은 인증 경보의 데모입니다. 실제 탐지 결과가 아니며 근거 검토 후 사건으로 묶을지 판단하는 화면 흐름만 제공합니다." },
    { id: "ALT-DEMO-002", kind: "Alert", title: "클라우드 권한 변경 경보", heading: "Cloud Permission Alert", priority: "Medium", status: "New", owner: "", age: 30, domain: "Cloud", reason: "권한 변경 검토 필요", host: "policy-demo-03", user: "iam-user-demo", ip: "192.0.2.30", resource: "policy-demo-03", rule: "CLOUD-001", ruleName: "Cloud Policy Change", related: "Related API Activity", summary: "미분류 클라우드 경보를 표현한 합성 데이터입니다. 현재 프로젝트에서 이 규칙이 배포되었거나 실제 API가 수집되었다는 의미가 아닙니다." },
    { id: "ALT-DEMO-003", kind: "Alert", title: "특권 실행 검토 경보", heading: "Privileged Execution Alert", priority: "Low", status: "New", owner: "", age: 90, domain: "Host", reason: "명령 및 실행자 확인", host: "vm02", user: "service-demo", ip: "203.0.113.10", resource: "instance-demo-02", rule: "SYSTEM-001", ruleName: "Privileged Execution Review", related: "Related Host Activity", summary: "특권 실행 경보의 화면 배치 예시입니다. 탐지 엔진 또는 Endpoint 수집 기능과 연결되어 있지 않습니다." },
  ];

  const items = definitions.map((item) => {
    const auth = item.domain === "Authentication";
    const evidence = auth ? authEvidence(item.id, item.host, item.user, item.ip) : singleEvidence(item.id, item.domain, item.host, item.user, item.ip);
    return Object.freeze({
      ...item, evidence,
      created: new Date(Date.parse(snapshot) - item.age * 60000).toISOString(),
      // Each case has its own day-relative fixture interval, before its queue creation.
      type: auth ? "Grouped Threshold" : "Single Event (demo only)",
      condition: auth ? `source.ip = ${item.ip}; outcome = failure` : `${evidence[0].action}; 승인 맥락 확인`,
      threshold: auth ? "10 matching events" : "1 matching event",
      window: auth ? "300 seconds" : "Single event / N/A",
      entities: [
        { type: "Host", value: item.domain === "Cloud" ? "Not observed in this demo" : item.host, icon: "host" },
        { type: "User", value: item.user, icon: "user" },
        { type: "Source IP", value: item.ip, icon: "network" },
        { type: "Cloud Account", value: "tenant-demo-01", icon: "account" },
        { type: "Cloud Resource", value: item.resource, icon: "cloud" },
      ],
    });
  });

  // Align all fixture events to the case creation without connecting to a clock or backend.
  items.forEach((item) => {
    const offset = item.age - 12;
    item.evidence.forEach((event) => {
      const originalTime = event.time;
      const date = new Date(`2026-08-31T${originalTime}+09:00`);
      date.setTime(date.getTime() - offset * 60000);
      const time = new Intl.DateTimeFormat("en-GB", { timeZone: "Asia/Seoul", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(date);
      event.time = time;
      event.normalized["@timestamp"] = `2026-08-31T${time}+09:00`;
      event.raw = event.raw.replace(originalTime, time);
      Object.freeze(event.normalized);
      Object.freeze(event);
    });
    Object.freeze(item.evidence);
  });

  return Object.freeze({
    snapshot,
    items: Object.freeze(items),
    rules: Object.freeze([["AUTH-001", 12], ["AUTH-002", 8], ["AUTH-003", 5], ["CLOUD-001", 3], ["SYSTEM-001", 2]]),
    ips: Object.freeze([["192.0.2.10", 12], ["198.51.100.20", 8], ["203.0.113.10", 5], ["192.0.2.30", 3], ["198.51.100.50", 2]]),
    trend: Object.freeze([5, 7, 10, 13, 17, 16, 22, 28, 25, 30, 33, 27, 35, 29, 24, 21, 17, 16, 11, 8, 6, 5, 4, 3]),
  });
})();
