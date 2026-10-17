// Filebeat 9.5 ECMAScript 5.1: consume ONLY private projected JSONL, never AKZ/TSV.
var scope;
var paths = ['/', '/login', '/logout', '/signup', '/cart', '/cart/add', '/item/:id',
    '/order/checkout', '/order/complete/:id', '/board', '/board/:id', '/board/mutation',
    '/board/mutation/:id', '/admin', '/admin/item/mutation', '/admin/resource/mutation/:id', '/static', '/_unclassified'];
function fail() { throw new Error('edge_intake_invalid'); }
function keys(value, names) {
    if (!value || typeof value !== 'object' || Array.isArray(value) ||
        Object.keys(value).sort().join('|') !== names.slice().sort().join('|')) { fail(); }
}
function register(params) {
    if (!params || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(params.organization_id) ||
        !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(params.host_id)) { fail(); }
    scope = params;
}
// JSON.parse validates grammar; this walk separately rejects duplicate decoded keys.
function uniqueKeys(raw) {
    var i = 0;
    function ws() { while (i < raw.length && /\s/.test(raw.charAt(i))) { i++; } }
    function string() {
        var start = i++;
        while (i < raw.length) {
            if (raw.charAt(i) === '\\') { i += 2; }
            else if (raw.charAt(i++) === '"') { return JSON.parse(raw.slice(start, i)); }
        }
        fail();
    }
    function value(depth) {
        if (depth > 12) { fail(); }
        ws(); var ch = raw.charAt(i), seen = {}, name;
        if (ch === '{') {
            i++; ws();
            if (raw.charAt(i) === '}') { i++; return; }
            while (i < raw.length) {
                if (raw.charAt(i) !== '"') { fail(); }
                name = string();
                if (Object.prototype.hasOwnProperty.call(seen, name)) { fail(); }
                seen[name] = true; ws();
                if (raw.charAt(i++) !== ':') { fail(); }
                value(depth + 1); ws();
                ch = raw.charAt(i++); if (ch === '}') { return; }
                if (ch !== ',') { fail(); } ws();
            }
        } else if (ch === '[') {
            i++; ws(); if (raw.charAt(i) === ']') { i++; return; }
            while (i < raw.length) {
                value(depth + 1); ws(); ch = raw.charAt(i++);
                if (ch === ']') { return; } if (ch !== ',') { fail(); }
            }
        } else if (ch === '"') { string(); return; }
        else { while (i < raw.length && !/[,\]}\s]/.test(raw.charAt(i))) { i++; } return; }
        fail();
    }
    value(0); ws(); if (i !== raw.length) { fail(); }
}
function validTime(s) {
    if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/.test(s)) { fail(); }
    var date = new Date(s.slice(0, 19) + 'Z');
    if (!isFinite(date.getTime()) || date.toISOString().slice(0, 19) !== s.slice(0, 19)) { fail(); }
}
function validate(raw) {
    if (typeof raw !== 'string' || raw.length > 131072) { fail(); }
    var d = JSON.parse(raw), p, fields, i, r, ids = {};
    uniqueKeys(raw);
    keys(d, ['@timestamp', 'organization', 'host', 'labels', 'event', 'security_mall_edge']);
    keys(d.organization, ['id']); keys(d.host, ['id']); keys(d.labels, ['log_source']); keys(d.event, ['id']);
    if (d.organization.id !== scope.organization_id || d.host.id !== scope.host_id ||
        d.labels.log_source !== 'security_mall_edge' || typeof d.event.id !== 'string' ||
        !/^[0-9a-f]{64}$/.test(d.event.id)) { fail(); }
    p = d.security_mall_edge;
    fields = ['schema_version', 'stream', 'timestamp', 'request_id', 'service_name', 'source_ip'];
    if (p.stream === 'access') { fields = fields.concat(['method', 'path', 'status_code', 'duration_us']); }
    else if (p.stream === 'waf') { fields = fields.concat(['rules', 'engine_mode', 'blocked']); }
    else { fail(); }
    keys(p, fields); validTime(p.timestamp);
    if (p.schema_version !== 1 || p.service_name !== 'security-mall' ||
        typeof p.request_id !== 'string' || !/^[A-Za-z0-9_-]{27}$/.test(p.request_id) || typeof p.source_ip !== 'string' ||
        !/^[0-9a-fA-F:.]{2,45}$/.test(p.source_ip) || d['@timestamp'] !== p.timestamp) { fail(); }
    if (p.stream === 'access') {
        if (['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','OTHER'].indexOf(p.method) < 0 ||
            paths.indexOf(p.path) < 0 || typeof p.status_code !== 'number' || p.status_code % 1 ||
            p.status_code < 100 || p.status_code > 599 || typeof p.duration_us !== 'number' ||
            p.duration_us % 1 || p.duration_us < 0 || p.duration_us > 9000000000000000) { fail(); }
    } else {
        if (p.engine_mode !== 'DetectionOnly' || p.blocked !== false || !Array.isArray(p.rules) ||
            p.rules.length < 1 || p.rules.length > 1024) { fail(); }
        for (i = 0; i < p.rules.length; i++) {
            r = p.rules[i]; fields = ['id', 'action', 'diagnostic'];
            if (Object.prototype.hasOwnProperty.call(r, 'severity')) { fields.push('severity'); }
            keys(r, fields);
            if (typeof r.id !== 'string' || !/^[0-9]{1,9}$/.test(r.id) || ids[r.id] ||
                ['pass','block','deny','drop','allow'].indexOf(r.action) < 0 ||
                r.diagnostic !== (r.id === '10002') || (r.severity !== undefined &&
                ['emergency','alert','critical','error','warning','notice','info','debug'].indexOf(r.severity) < 0)) { fail(); }
            ids[r.id] = true;
        }
    }
    return d;
}
function process(event) {
    try {
        var doc = validate(event.Get('message'));
        event.Put('organization', {id: scope.organization_id});
        event.Put('host', {id: scope.host_id});
        event.Put('labels', {log_source: 'security_mall_edge'});
        event.Put('security_mall_edge', doc.security_mall_edge);
        event.Put('event', {id: doc.event.id});
        event.Delete('message'); event.Delete('type');
        event.Put('@metadata._id', doc.event.id);
        event.Put('@metadata.op_type', 'create');
        event.Put('@metadata.edge_validated', true);
    } catch (ignored) { event.Cancel(); }
}
