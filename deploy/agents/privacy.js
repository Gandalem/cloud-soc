// Beats ECMAScript 5.1. Run before publishing/queueing; never log field values.
var secretText = /-----BEGIN [^-]*(PRIVATE KEY|CERTIFICATE)-----|(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie)\s*["']?\s*[:=]|(--?|\/)(password|passwd|pwd|secret|token|api[_-]?key)\b(\s+|=|:)|\b(Bearer|Basic)\s+\S+|\b[a-z][a-z0-9+.-]*:\/\/[^\s/]+@|\b[a-z][a-z0-9+.-]*:\/\/[^\s]*[?#]|[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2060-\u206f]|\b(AKIA|ASIA)[A-Z0-9]{16}\b|\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/i;
var secretKey = /password|passwd|pwd|secret|token|authorization|cookie|private[_-]?key|command[_-]?line|task[_-]?content|script[_-]?(block[_-]?text|contents?)|(^|[._-])(api[_-]?key|args|original|xml|body|content)($|[._-])/i;
var accessLine = /^\S+\s+\S+\s+\S+\s+\[[^\]\r\n]+\]\s+"[A-Z]+\s+[^"\r\n]+\s+HTTP\/[0-9.]+"\s+[0-9]{3}\s+/;

function process(event) {
    try {
        var source = event.Get();
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
        // Native sudo command lines contain PWD= (working directory), which
        // intentionally trips the general secret detector. Retain only the
        // actor/target/time from a complete known-file record before that scan;
        // never publish its directory, terminal, executable or arguments.
        var sudoPath = source.log && source.log.file && source.log.file.path;
        if (source.labels && source.labels.log_source === 'linux_file' &&
            (sudoPath === '/var/log/auth.log' || sudoPath === '/var/log/syslog') &&
            typeof source.message === 'string' && source.message.length <= 8192) {
            // Otto uses RE2, whose counted repetitions stop at 1000. The
            // enclosing 8192-byte limit bounds the two discarded values.
            var sudoLine = /^((?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2}))\s+\S+\s+sudo(?:\[\d{1,10}\])?:\s*)([A-Za-z0-9_.@-]{1,128})\s*:\s*TTY=[^;\r\n]{1,128}\s*;\s*PWD=[^;\r\n]+\s*;\s*USER=([A-Za-z0-9_.@-]{1,128})\s*;\s*(?:GROUP=[^;\r\n]{1,128}\s*;\s*)?(?:TSID=[^;\r\n]{1,128}\s*;\s*)?COMMAND=[^\r\n]+$/.exec(source.message);
            if (sudoLine) {
                event.Put('message', sudoLine[1] + sudoLine[2] + ' : TTY=[REDACTED] ; CWD=[REDACTED] ; USER=' + sudoLine[3] + ' ; COMMAND=[REDACTED]');
                event.Put('labels.sudo_privacy', 'selected-metadata-v1');
                source = event.Get();
            }
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
