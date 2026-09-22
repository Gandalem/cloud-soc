const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const context = vm.createContext({ window: {} });
vm.runInContext(fs.readFileSync(path.join(root, "logs-data.js"), "utf8"), context);
const data = context.window.CloudSocLogData;
const ids = (rows) => Array.from(rows, (row) => row.id);

test("fixtures include ordinary, partial, and failed logs across environments", () => {
  assert.equal(data.records.length, 90);
  assert.equal(new Set(ids(data.records)).size, 90);
  for (const environment of Object.keys(data.environments)) {
    assert.equal(data.query({ environment }).length, 30);
  }
  assert.equal(data.query({ parse: "parsed" }).length, 78);
  assert.equal(data.query({ parse: "partial" }).length, 6);
  assert.equal(data.query({ parse: "failed" }).length, 6);
  assert.equal(data.query({ outcome: "success" }).length, 24);
  assert.equal(data.query({ outcome: "failure" }).length, 12);
  assert.equal(data.query({ outcome: "unknown" }).length, 54);
  assert.equal(new Set(data.records.map((row) => row.source)).size, 16);
});

test("missing event fields stay missing without dropping the raw log", () => {
  for (const row of data.records) {
    assert.ok(row.raw.length > 0);
    assert.ok(Number.isFinite(Date.parse(row.ingestedAt)));
    if (row.parse === "parsed") {
      assert.equal(row.fields["@timestamp"], row.eventAt);
      assert.equal(Date.parse(row.ingestedAt) - Date.parse(row.eventAt), 2000);
      assert.ok(row.raw.includes(row.eventAt));
      if (row.ip) assert.ok(row.raw.includes(row.ip));
      else assert.equal(row.fields["source.ip"], undefined);
    } else {
      assert.equal(row.eventAt, null);
      assert.equal(row.fields["@timestamp"], undefined);
      assert.equal(row.fields["event.outcome"], undefined);
      assert.equal(row.ip, null);
      if (row.parse === "failed") {
        assert.equal(Object.keys(row.fields).length, 0);
        assert.ok(row.raw.includes("<unparsed>"));
      }
    }
  }
});

test("exact filters combine with AND semantics", () => {
  assert.deepEqual(ids(data.query({ environment: "production", platform: "oci", source: "cloud" })), ["LOG-DEMO-004", "LOG-DEMO-028"]);
  assert.equal(data.query({ source: "auth", outcome: "success", parse: "parsed" }).length, 6);
  assert.equal(data.query({ source: "auth", parse: "failed" }).length, 0);
  assert.equal(data.query({ environment: "not-a-demo-environment" }).length, 0);
  assert.equal(data.query({ environment: "all", platform: "all", os: "all", source: "all", parse: "all", outcome: "all" }).length, 90);
});

test("search supports labels, raw text, fields, and case folding", () => {
  assert.equal(data.query({ q: "  ACCEPTED PUBLICKEY  " }).length, 6);
  assert.equal(data.query({ q: "클라우드 감사" }).length, 6);
  assert.equal(data.query({ q: "event.category" }).length, 84);
  assert.equal(data.query({ q: "<unparsed>" }).length, 6);
  assert.deepEqual(ids(data.query({ q: "192.0.2.10" })), ["LOG-DEMO-001"]);
  assert.equal(data.query({ q: "not-found-fixture" }).length, 0);
  assert.equal(data.query({ q: "   " }).length, 90);
});

test("time windows use ingestion time and the fixed snapshot", () => {
  assert.equal(data.query({ minutes: 60 }).length, 9);
  assert.equal(data.query({ minutes: 180 }).length, 26);
  assert.equal(data.query({ minutes: 7 }).length, 2);
  assert.equal(data.query({ minutes: "all" }).length, 90);
  assert.equal(data.query({ minutes: 60, parse: "failed" }).length, 1);
  assert.equal(data.query({ minutes: 60, parse: "partial" }).length, 1);
});

test("sort directions and fallback are deterministic without mutating fixtures", () => {
  const original = JSON.stringify(data.records);
  const asc = data.query({ sort: "id", order: "asc" });
  const desc = data.query({ sort: "id", order: "desc" });
  assert.equal(asc[0].id, "LOG-DEMO-001");
  assert.equal(desc[0].id, "LOG-DEMO-090");
  assert.deepEqual(ids(asc), ids(desc).reverse());
  assert.equal(data.query()[0].id, "LOG-DEMO-001");
  assert.equal(data.query({ sort: "__proto__" })[0].id, "LOG-DEMO-001");
  for (const order of ["asc", "desc"]) {
    const rows = data.query({ sort: "user", order });
    const missing = rows.findIndex((row) => row.user === null);
    assert.ok(missing > 0);
    assert.ok(rows.slice(missing).every((row) => row.user === null));
    assert.deepEqual(ids(rows.slice(missing)), ids(rows.slice(missing)).sort());
  }
  assert.equal(JSON.stringify(data.records), original);
});

test("OS filters distinguish Windows, Linux, cloud API, and unknown", () => {
  assert.equal(data.query({ os: "windows" }).length, 24);
  assert.equal(data.query({ os: "linux" }).length, 54);
  assert.equal(data.query({ os: "notApplicable" }).length, 6);
  assert.equal(data.query({ os: "unknown" }).length, 6);
  assert.equal(data.query({ os: "windows", source: "winevent" }).length, 9);
  assert.equal(data.query({ os: "windows", source: "auth" }).length, 0);
  assert.equal(data.query({ os: "linux", source: "journal", environment: "production" }).length, 1);
  assert.equal(data.query({ os: "windows", q: "Microsoft-Windows-Sysmon/Operational" }).length, 3);
  assert.equal(data.query({ q: "C:\\inetpub\\logs\\LogFiles" }).length, 3);
  assert.equal(data.query({ os: "linux", q: "/var/log/audit/audit.log" }).length, 3);
  for (const row of data.records) {
    assert.ok(row.origin);
    if (["windows", "linux"].includes(row.os)) assert.equal(row.fields["host.os.type"], row.os);
    else assert.equal(row.fields["host.os.type"], undefined);
    if (row.channel) {
      assert.equal(row.os, "windows");
      assert.equal(row.fields["winlog.channel"], row.channel);
      assert.equal(JSON.parse(row.raw).channel, row.channel);
    }
    if (row.filePath) assert.equal(row.fields["log.file.path"], row.filePath);
  }
});

test("OS and origin columns sort their displayed values", () => {
  for (const sort of ["os", "origin"]) {
    const rows = data.query({ sort, order: "asc" });
    const value = (row) => sort === "os" ? data.operatingSystems[row.os] : row.origin;
    for (let index = 1; index < rows.length; index += 1) {
      assert.ok(value(rows[index - 1]).localeCompare(value(rows[index]), "ko", { numeric: true }) <= 0);
    }
  }
});

test("live page uses local assets and no longer loads demo fixtures", () => {
  const html = fs.readFileSync(path.join(root, "logs.html"), "utf8");
  assert.ok(html.includes('lang="ko"'));
  assert.ok(html.includes("connect-src 'self'"));
  assert.ok(!html.includes('src="logs-data.js"'));
  assert.ok(!html.includes('src="app.js"'));
  assert.ok(html.includes("form-action 'none'"));
  const assets = Array.from(html.matchAll(/(?:src|href)="([^"#]+)"/g), (match) => match[1]);
  assert.ok(assets.length > 0);
  for (const asset of assets) {
    assert.ok(!/^(?:\w+:|\/\/)/.test(asset), `External asset: ${asset}`);
    assert.ok(fs.existsSync(path.join(root, asset)), `Missing asset: ${asset}`);
  }
  for (const file of ["logs-data.js"]) {
    const source = fs.readFileSync(path.join(root, file), "utf8");
    assert.doesNotMatch(source, /\b(?:fetch|XMLHttpRequest|WebSocket|localStorage|sessionStorage|indexedDB)\b/);
  }
  assert.doesNotMatch(fs.readFileSync(path.join(root, "logs.js"), "utf8"), /CloudSocLogData|localStorage|sessionStorage/);
});
