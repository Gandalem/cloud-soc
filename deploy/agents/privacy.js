// Beats ECMAScript 5.1. Run before publishing/queueing; never log field values.
var secretText = /-----BEGIN [^-]*(PRIVATE KEY|CERTIFICATE)-----|(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie)\s*["']?\s*[:=]|(--?|\/)(password|passwd|pwd|secret|token|api[_-]?key)\b(\s+|=|:)|\b(Bearer|Basic)\s+\S+|\b[a-z][a-z0-9+.-]*:\/\/[^\s/]+@|\b[a-z][a-z0-9+.-]*:\/\/[^\s]*[?#]|[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2060-\u206f]|\b(AKIA|ASIA)[A-Z0-9]{16}\b|\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/i;
var secretKey = /password|passwd|pwd|secret|token|authorization|cookie|private[_-]?key|command[_-]?line|task[_-]?content|script[_-]?(block[_-]?text|contents?)|(^|[._-])(api[_-]?key|args|original|xml|body|content)($|[._-])/i;
var accessLine = /^\S+\s+\S+\s+\S+\s+\[[^\]\r\n]+\]\s+"[A-Z]+\s+[^"\r\n]+\s+HTTP\/[0-9.]+"\s+[0-9]{3}\s+/;

function auditProjection(tag, raw) {
    if (typeof raw !== 'string' || !raw.length || raw.length > 262144) { return null; }
    if (tag === 'eks_audit') {
        var value;
        try { value = JSON.parse(raw); } catch (_) { return null; }
        if (!value || value.apiVersion !== 'audit.k8s.io/v1' || value.kind !== 'Event' ||
            typeof value.auditID !== 'string' || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(value.auditID) ||
            typeof value.stage !== 'string' || !/^(RequestReceived|ResponseStarted|ResponseComplete|Panic)$/.test(value.stage) ||
            typeof value.verb !== 'string' || !/^(get|list|watch|create|update|patch|delete|deletecollection|connect|proxy)$/.test(value.verb) ||
            typeof value.stageTimestamp !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value.stageTimestamp)) { return null; }
        var result = {schema: 1, id: value.auditID, stage: value.stage, verb: value.verb, stage_at: value.stageTimestamp};
        var code = value.responseStatus && value.responseStatus.code;
        if (typeof code === 'number' && Math.floor(code) === code && code >= 100 && code <= 599) { result.status = code; }
        var decision = value.annotations && value.annotations['authorization.k8s.io/decision'];
        if (decision === 'allow' || decision === 'forbid') { result.decision = decision; }
        var resource = value.objectRef && value.objectRef.resource;
        if (typeof resource === 'string' && /^[a-z0-9][a-z0-9.-]{0,127}$/.test(resource)) { result.resource = resource; }
        return result;
    }
    var record = /^(?:node=[A-Za-z0-9_.-]{1,253} )?type=([A-Z_]{2,32}) +msg=audit\((\d{1,12}\.\d{1,9}:\d{1,12})\):([^\r\n]*)$/.exec(raw);
    if (!record || /^(EXECVE|PROCTITLE|USER_CMD)$/.test(record[1])) { return null; }
    var result = {schema: 1, type: record[1], id: record[2]};
    if (record[1] === 'SYSCALL') {
        // Native SYSCALL fields preceding arguments have a fixed order.
        var syscall = /^\s*arch=([0-9a-f]{8}) syscall=(\d{1,5}) success=(yes|no)(?: |$)/.exec(record[3]);
        if (syscall) { result.arch = syscall[1]; result.syscall = Number(syscall[2]); result.success = syscall[3]; }
    }
    return result;
}

function process(event) {
    try {
        var source = event.Get();
        var tag = source.labels && source.labels.log_source;
        if (tag === 'eks_audit' || tag === 'linux_auditd') {
            var projected = auditProjection(tag, source.message);
            var target = tag === 'eks_audit' ? 'eks_audit' : 'linux_audit_record';
            if (source[target] !== undefined && event.Delete(target) === false) { throw new Error('privacy removal failed'); }
            if (projected) { event.Put(target, projected); }
            if (source.message !== undefined && event.Delete('message') === false) { throw new Error('privacy removal failed'); }
            source = event.Get();
        }
        // Web selection must not be bypassed through generic file discovery or
        // a journald/stdout duplicate. Dedicated web inputs remove message first.
        if (source.labels && /^(linux_file|linux_journald|windows_file)$/.test(source.labels.log_source || '') && typeof source.message === 'string') {
            // Dedicated WAF inputs must project audit JSON before the queue.
            // A generic file/journal mirror cannot bypass that privacy boundary.
            var filePath=source.log&&source.log.file&&source.log.file.path;
            if (typeof filePath==='string' && /[\\/](modsecurity|modsec)[\\/]|modsec[^\\/]*audit/i.test(filePath)) { event.Cancel(); return event; }
            var rawAccess = source.message;
            if (rawAccess.length <= 8192 && /^\s*\{/.test(rawAccess)) {
                try { var wrapper=JSON.parse(rawAccess);
                    if (wrapper && wrapper.transaction && wrapper.transaction.producer && typeof wrapper.transaction.producer.modsecurity==='string' && wrapper.transaction.request) { event.Cancel(); return event; }
                    if (wrapper && typeof wrapper.log==='string') { rawAccess=wrapper.log; }
                } catch (_) {}
            }
            if (/^\s*\{/.test(rawAccess)) {
                try { var audit=JSON.parse(rawAccess); if (audit && audit.transaction && audit.transaction.producer && typeof audit.transaction.producer.modsecurity==='string' && audit.transaction.request) { event.Cancel(); return event; } } catch (_) {}
            }
            if (accessLine.test(rawAccess)) { event.Cancel(); return event; }
        }
        // Native audit argument records can carry hex-encoded secrets. They are
        // not required for the selected SYSCALL/PATH metadata and are withheld.
        if (source.labels && /^linux_/.test(source.labels.log_source || '') &&
            typeof source.message === 'string' && /^type=(EXECVE|PROCTITLE|USER_CMD)\s/.test(source.message)) {
            event.Cancel(); return event;
        }
        // Rendered Windows messages duplicate CommandLine, TaskContent and
        // ScriptBlockText under an unstructured name. Keep structured metadata.
        if (source.winlog && typeof source.winlog === 'object' && source.message !== undefined) {
            if (event.Delete('message') === false) { throw new Error('privacy removal failed'); }
        }
        var budget = {count: 0};
        function unsafeArray(value, depth) {
            budget.count++;
            if (depth > 12 || budget.count > 4096) { throw new Error('privacy limit'); }
            if (typeof value === 'string') { return value.length > 8192 || secretText.test(value); }
            if (value === null || typeof value !== 'object') { return false; }
            return Object.keys(value).some(function (key) {
                return secretKey.test(key) || secretText.test(key) || unsafeArray(value[key], depth + 1);
            });
        }
        function walk(value, path, depth) {
            budget.count++;
            if (depth > 12 || budget.count > 4096) { throw new Error('privacy limit'); }
            if (typeof value === 'string') {
                if (value.length > 8192 || secretText.test(value)) { event.Put(path, '[REDACTED]'); }
            } else if (value !== null && typeof value === 'object') {
                if (Object.prototype.toString.call(value) === '[object Array]') {
                    if (unsafeArray(value, depth)) { event.Put(path, ['[REDACTED]']); }
                } else {
                    Object.keys(value).forEach(function (key) {
                        if (!path && (key === '@timestamp' || key === '@metadata')) { return; }
                        var child = path ? path + '.' + key : key;
                        if (secretKey.test(key) || secretText.test(key)) {
                            if (event.Delete(child) === false) { throw new Error('privacy removal failed'); }
                        } else { walk(value[key], child, depth + 1); }
                    });
                }
            }
        }
        // Mutate only sensitive leaves. Replacing parent maps coerces native Beat
        // timestamps/IP types and can make disk-queue serialization fail.
        walk(source, '', 0);
        event.Put('labels.privacy_policy', 'v3');
    } catch (_) {
        event.Cancel();
    }
    return event;
}

function test() {
    if (!secretText.test('password=CANARY') || !secretKey.test('clientSecret')) {
        throw new Error('privacy self-test failed');
    }
}
