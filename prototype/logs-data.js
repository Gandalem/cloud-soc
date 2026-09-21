/* Independent UI fixtures, not collected logs or actual parser output. */
window.CloudSocLogData = (() => {
  "use strict";
  const snapshot = "2026-09-21T12:00:00+09:00";
  const environments = Object.freeze({ production: "운영", staging: "테스트", development: "개발" });
  const platforms = Object.freeze({ onprem: "온프레미스", oci: "OCI", aws: "AWS", other: "기타" });
  const operatingSystems = Object.freeze({ windows: "Windows", linux: "Linux", notApplicable: "해당 없음 (클라우드 API)", unknown: "미확인" });
  const sources = Object.freeze({ auth: "리눅스 인증", host: "호스트 활동", cloud: "클라우드 감사", web: "웹 접근", app: "애플리케이션", winevent: "Windows 이벤트", powershell: "PowerShell", defender: "Defender", sysmon: "Sysmon", syslog: "시스템 로그", journal: "시스템 저널", kernel: "커널", audit: "리눅스 감사", cron: "예약 작업", firewall: "방화벽", unknown: "미분류 소스" });
  const parseLabels = Object.freeze({ parsed: "파싱 완료", partial: "일부 필드 누락", failed: "파싱 실패" });
  const outcomeLabels = Object.freeze({ success: "성공", failure: "실패", unknown: "미확인" });
  const templates = [
    { source: "auth", platform: "onprem", action: "ssh_login", actionLabel: "SSH 로그인", outcome: "failure", user: "ubuntu", category: "authentication", message: "SSH 비밀번호 인증 실패", parser: "linux_auth / 예시", parse: "parsed" },
    { source: "auth", platform: "onprem", action: "ssh_login", actionLabel: "SSH 로그인", outcome: "success", user: "operator-demo", category: "authentication", message: "SSH 공개키 인증 성공", parser: "linux_auth / 예시", parse: "parsed" },
    { source: "host", platform: "oci", action: "privileged_execution", actionLabel: "특권 명령 실행", outcome: "success", user: "operator-demo", category: "process", message: "관리 명령 실행 기록", parser: "host_activity / 예시", parse: "parsed" },
    { source: "cloud", platform: "oci", action: "demo_policy_read", actionLabel: "정책 조회", outcome: "success", user: "cloud-user-demo", category: "configuration", message: "클라우드 정책 조회 기록", parser: "cloud_audit / 예시", parse: "parsed" },
    { source: "web", platform: "aws", action: "http_request", actionLabel: "HTTP 요청", outcome: "success", user: null, category: "web", message: "GET /health 200", parser: "web_access / 예시", parse: "parsed" },
    { source: "app", platform: "aws", action: "application_error", actionLabel: "애플리케이션 오류", outcome: "failure", user: "service-demo", category: "application", message: "데모 작업 처리 중 오류 발생", parser: "app_json / 예시", parse: "parsed" },
    { source: "app", platform: "aws", action: "task_update", actionLabel: "작업 상태 변경", outcome: "unknown", user: null, category: "application", message: "이벤트 시각과 결과 필드가 없는 예시", parser: "app_json / 예시", parse: "partial" },
    { source: "unknown", platform: "other", action: null, actionLabel: "미확인", outcome: "unknown", user: null, category: null, message: "인식할 수 없는 로그 형식", parser: "미지정", parse: "failed" },
  ];
  const baseOrigins = { auth: "/var/log/auth.log", host: "/var/log/auth.log", cloud: "OCI Audit API / 예시", web: "/var/log/nginx/access.log", app: "/var/log/demo-app/app.log", unknown: "미확인" };
  const osTemplates = [
    { os: "windows", source: "winevent", channel: "Security", category: "authentication", message: "보안 감사 이벤트 예시" },
    { os: "windows", source: "winevent", channel: "System", category: "host", message: "시스템 서비스 이벤트 예시" },
    { os: "windows", source: "winevent", channel: "Application", category: "host", message: "응용 프로그램 이벤트 예시" },
    { os: "windows", source: "powershell", channel: "Microsoft-Windows-PowerShell/Operational", category: "process", message: "PowerShell 실행 기록 예시" },
    { os: "windows", source: "defender", channel: "Microsoft-Windows-Windows Defender/Operational", category: "malware", message: "보안 제품 활동 기록 예시" },
    { os: "windows", source: "sysmon", channel: "Microsoft-Windows-Sysmon/Operational", category: "process", message: "프로세스 관측 이벤트 예시" },
    { os: "windows", source: "web", filePath: "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\demo.log", category: "web", message: "IIS 접근 로그 예시" },
    { os: "windows", source: "app", filePath: "C:\\ProgramData\\DemoApp\\logs\\app.log", category: "host", message: "사용자 지정 응용 프로그램 파일 로그 예시" },
    { os: "linux", source: "syslog", filePath: "/var/log/syslog", category: "host", message: "시스템 서비스 기록 예시" },
    { os: "linux", source: "journal", origin: "journald / demo.service", category: "host", message: "systemd 서비스 저널 예시" },
    { os: "linux", source: "kernel", filePath: "/var/log/kern.log", category: "host", message: "커널 메시지 예시" },
    { os: "linux", source: "audit", filePath: "/var/log/audit/audit.log", category: "process", message: "감사 이벤트 예시" },
    { os: "linux", source: "cron", filePath: "/var/log/cron", category: "process", message: "예약 작업 실행 기록 예시" },
    { os: "linux", source: "firewall", filePath: "/var/log/ufw.log", category: "network", message: "방화벽 기록 예시" },
  ];
  const recordTemplates = [
    ...Array.from({ length: 48 }, (_, index) => {
      const template = templates[index % templates.length];
      const os = template.source === "cloud" ? "notApplicable" : template.source === "unknown" ? "unknown" : "linux";
      const origin = baseOrigins[template.source];
      return { ...template, os, origin, ...(os === "linux" ? { filePath: origin } : {}), hasIp: template.parse === "parsed" };
    }),
    ...Array.from({ length: 3 }, () => osTemplates).flat().map((template) => ({
      platform: "onprem", user: null, action: "demo_activity", actionLabel: "활동 기록", outcome: "unknown", parser: "os_log / 예시", parse: "parsed", hasIp: false,
      ...template, origin: template.channel || template.filePath || template.origin,
    })),
  ];
  const records = Object.freeze(recordTemplates.map((template, index) => {
    const environment = Object.keys(environments)[index % 3];
    const id = `LOG-DEMO-${String(index + 1).padStart(3, "0")}`;
    const ingestedAt = new Date(Date.parse(snapshot) - index * 7 * 60000).toISOString();
    const eventAt = template.parse === "parsed" ? new Date(Date.parse(ingestedAt) - 2000).toISOString() : null;
    const target = template.source === "cloud" ? `policy-demo-${environment}` : `${template.os}-${template.source}-demo-${environment}`;
    const ip = template.hasIp ? `${["192.0.2", "198.51.100", "203.0.113"][index % 3]}.${10 + index}` : null;
    const fields = template.parse === "failed" ? {} : {
      ...(eventAt ? { "@timestamp": eventAt } : {}),
      "event.category": [template.category], "event.action": template.action,
      ...(template.outcome === "unknown" ? {} : { "event.outcome": template.outcome }),
      ...(template.user ? { "user.name": template.user } : {}),
      ...(ip ? { "source.ip": ip } : {}),
      ...(["windows", "linux"].includes(template.os) ? { "host.os.type": template.os } : {}),
      ...(template.channel ? { "winlog.channel": template.channel } : {}),
      ...(template.filePath ? { "log.file.path": template.filePath } : {}),
      ...(template.source === "cloud" ? { "cloud.resource.id": target } : { "host.name": target }),
      message: template.message,
    };
    let raw;
    if (template.source === "auth") raw = `${eventAt} ${target} sshd[1234]: ${template.outcome === "success" ? "Accepted publickey" : "Failed password"} for ${template.user} from ${ip} port 54321 ssh2`;
    else if (template.parse === "failed") raw = "DEMO unknown-format | ts=??? | payload=<unparsed> | parser-not-available";
    else raw = JSON.stringify({ prototype: true, ...(eventAt ? { timestamp: eventAt } : {}), target, os: template.os, origin: template.origin, ...(template.channel ? { channel: template.channel } : {}), ...(template.user ? { actor: template.user } : {}), ...(ip ? { source_ip: ip } : {}), action: template.action, ...(template.outcome === "unknown" ? {} : { result: template.outcome }), message: template.message }, null, 2);
    return Object.freeze({ ...template, id, environment, target, ip, ingestedAt, eventAt, fields: Object.freeze(fields), raw });
  }));

  // Keep searching and sorting independent of the DOM for deterministic tests.
  function query(options = {}) {
    const q = String(options.q || "").trim().toLocaleLowerCase("ko-KR");
    const minutes = Number(options.minutes);
    const result = records.filter((record) => {
      const matches = ["environment", "platform", "os", "source", "parse", "outcome"].every((key) => !options[key] || options[key] === "all" || options[key] === record[key]);
      const corpus = [record.id, record.target, record.user, record.ip, record.origin, record.action, record.actionLabel, record.message, record.raw, environments[record.environment], platforms[record.platform], operatingSystems[record.os], sources[record.source], parseLabels[record.parse], outcomeLabels[record.outcome], JSON.stringify(record.fields)].join(" ").toLocaleLowerCase("ko-KR");
      const age = (Date.parse(snapshot) - Date.parse(record.ingestedAt)) / 60000;
      return matches && (!q || corpus.includes(q)) && (!(minutes > 0) || age <= minutes);
    });
    const sortKeys = ["id", "ingestedAt", "environment", "platform", "os", "source", "origin", "target", "user", "ip", "action", "outcome", "parse", "message"];
    const sort = sortKeys.includes(options.sort) ? options.sort : "ingestedAt";
    const direction = options.order === "asc" ? 1 : -1;
    const maps = { environment: environments, platform: platforms, os: operatingSystems, source: sources, parse: parseLabels, outcome: outcomeLabels };
    const value = (record) => maps[sort]?.[record[sort]] ?? (sort === "action" ? record.actionLabel : record[sort]);
    return result.sort((a, b) => {
      const left = value(a), right = value(b);
      if (left == null && right != null) return 1;
      if (right == null && left != null) return -1;
      return String(left ?? "").localeCompare(String(right ?? ""), "ko", { numeric: true }) * direction || a.id.localeCompare(b.id);
    });
  }
  return Object.freeze({ snapshot, records, environments, platforms, operatingSystems, sources, parseLabels, outcomeLabels, query });
})();
