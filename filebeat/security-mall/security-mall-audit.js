// Filebeat ECMAScript 5.1 processor. No external modules or raw-value diagnostics.
var scope = null;
var common = ['schema_version', '@timestamp', 'event_id', 'service_name', 'event_action',
    'event_outcome', 'source_ip', 'account_id', 'account_key_id'];
var resources = {admin_view: 'admin', item_create_form: 'item', item_create: 'item',
    item_edit_form: 'item', item_update: 'item', item_delete: 'item', user_delete: 'user'};

function own(object, key) { return Object.prototype.hasOwnProperty.call(object, key); }
function fail() { throw new Error('security_mall_intake_invalid'); }
function token(value, maximum) {
    return typeof value === 'string' && value.length <= maximum &&
        /^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(value) &&
        !/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/i.test(value);
}
function register(params) {
    if (!token(params.organization_id, 128) || !token(params.host_id, 128)) { fail(); }
    scope = {organization: params.organization_id, host: params.host_id};
}

// JSON.parse verifies grammar. This separate flat-object walk rejects repeated
// decoded keys (including escaped spellings), which JSON.parse would overwrite.
function uniqueKeys(raw) {
    var i = 0, seen = {}, start, key, valueStart;
    function whitespace() { while (/\s/.test(raw.charAt(i)) && i < raw.length) { i++; } }
    function quoted() {
        if (raw.charAt(i) !== '"') { fail(); }
        i++;
        while (i < raw.length) {
            if (raw.charAt(i) === '\\') { i += 2; }
            else if (raw.charAt(i++) === '"') { return; }
        }
        fail();
    }
    whitespace();
    if (raw.charAt(i++) !== '{') { fail(); }
    whitespace();
    while (raw.charAt(i) !== '}') {
        start = i; quoted(); key = JSON.parse(raw.slice(start, i));
        if (own(seen, key)) { fail(); }
        seen[key] = true;
        whitespace();
        if (raw.charAt(i++) !== ':') { fail(); }
        whitespace();
        valueStart = i;
        if (raw.charAt(i) === '"') { quoted(); }
        else {
            while (i < raw.length && raw.charAt(i) !== ',' && raw.charAt(i) !== '}') { i++; }
        }
        // JS numbers erase the distinction between integer 1 and float 1.0/1e0.
        if (key === 'schema_version' && raw.slice(valueStart, i).trim() !== '1') { fail(); }
        whitespace();
        if (raw.charAt(i) === ',') { i++; whitespace(); }
        else if (raw.charAt(i) !== '}') { fail(); }
    }
}

function validTime(value) {
    if (typeof value !== 'string') { return false; }
    var m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);
    if (!m || Number(m[1]) < 1) { return false; }
    var base = value.slice(0, 19) + 'Z', date = new Date(base);
    return isFinite(date.getTime()) && date.getUTCFullYear() === Number(m[1]) &&
        date.getUTCMonth() + 1 === Number(m[2]) && date.getUTCDate() === Number(m[3]) &&
        date.getUTCHours() === Number(m[4]) && date.getUTCMinutes() === Number(m[5]) &&
        date.getUTCSeconds() === Number(m[6]);
}
function ipv4(value) {
    var parts = value.split('.'), i;
    if (parts.length !== 4) { return false; }
    for (i = 0; i < parts.length; i++) {
        if (!/^(0|[1-9][0-9]{0,2})$/.test(parts[i]) || Number(parts[i]) > 255) { return false; }
    }
    return true;
}
function validIP(value) {
    if (typeof value !== 'string' || value.length > 45 || /[^0-9a-fA-F:.]/.test(value)) { return false; }
    if (value.indexOf(':') < 0) { return ipv4(value); }
    var groups = value.split(':'), count = 0, compressed = value.indexOf('::') >= 0, i;
    if (value.indexOf(':::') >= 0 || value.indexOf('::') !== value.lastIndexOf('::')) { return false; }
    if ((value.charAt(0) === ':' && value.slice(0, 2) !== '::') ||
        (value.slice(-1) === ':' && value.slice(-2) !== '::')) { return false; }
    for (i = 0; i < groups.length; i++) {
        if (groups[i] === '') { continue; }
        if (groups[i].indexOf('.') >= 0) {
            if (i !== groups.length - 1 || !ipv4(groups[i])) { return false; }
            count += 2;
        } else {
            if (!/^[0-9a-fA-F]{1,4}$/.test(groups[i])) { return false; }
            count++;
        }
    }
    return compressed ? count < 8 : count === 8;
}

function validate(raw) {
    if (typeof raw !== 'string' || raw.length > 8192 || /[^\x00-\x7f]/.test(raw)) { fail(); }
    var a = JSON.parse(raw), keys, i, action, auth, expected, reason, valid;
    if (!a || Object.prototype.toString.call(a) !== '[object Object]') { fail(); }
    keys = Object.keys(a);
    for (i = 0; i < keys.length; i++) {
        if (common.indexOf(keys[i]) < 0 && keys[i] !== 'resource_type' &&
            keys[i] !== 'authorization_reason' && keys[i] !== 'request_id') { fail(); }
        if (a[keys[i]] !== null && typeof a[keys[i]] === 'object') { fail(); }
    }
    uniqueKeys(raw);
    for (i = 0; i < common.length; i++) { if (!own(a, common[i])) { fail(); } }
    if (a.schema_version !== 1 || !validTime(a['@timestamp']) || !validIP(a.source_ip) ||
        !token(a.service_name, 64) || !token(a.account_key_id, 64) ||
        typeof a.event_id !== 'string' || !/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(a.event_id) ||
        a.event_id === '00000000-0000-0000-0000-000000000000' ||
        (a.account_id !== null && (typeof a.account_id !== 'string' || !/^[0-9a-f]{64}$/.test(a.account_id))) ||
        (a.event_outcome !== 'success' && a.event_outcome !== 'failure')) { fail(); }
    var optional = own(a, 'request_id') ? 1 : 0;
    if (optional && a.request_id !== null && (typeof a.request_id !== 'string' ||
        !/^[A-Za-z0-9_-]{27}$/.test(a.request_id) || a.request_id.length !== 27)) { fail(); }
    action = a.event_action;
    auth = action !== 'login';
    if (!auth) {
        if (a.account_id === null || keys.length !== common.length + optional) { fail(); }
        return a;
    }
    expected = action === 'order_view' ? 'order' : own(resources, action) ? resources[action] : null;
    if (!expected || a.resource_type !== expected || keys.length !== common.length + 2 + optional) { fail(); }
    reason = a.authorization_reason;
    if (reason === 'unauthenticated') { valid = a.event_outcome === 'failure' && a.account_id === null; }
    else if (a.account_id === null) { valid = false; }
    else if (action === 'order_view') {
        valid = (a.event_outcome === 'success' && reason === 'owner') ||
            (a.event_outcome === 'failure' && (reason === 'not_owner' || reason === 'not_found'));
    } else {
        valid = (a.event_outcome === 'success' && reason === 'admin') ||
            (a.event_outcome === 'failure' && reason === 'admin_required');
    }
    if (!valid) { fail(); }
    return a;
}

function process(event) {
    try {
        var audit = validate(event.Get('message'));
        // Only fixed schema fields and operator-configured identity reach the queue.
        event.Put('security_mall', {audit: audit});
        event.Put('organization', {id: scope.organization});
        event.Put('host', {id: scope.host});
        event.Put('labels', {log_source: 'security_mall_audit'});
        event.Delete('message');
        event.Delete('event');
        event.Delete('type');
        // Include-fields below also removes default Filebeat metadata from _source.
        event.Put('@metadata.mall_validated', true);
    } catch (ignored) {
        event.Cancel();
    }
}
