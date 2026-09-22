// Beats ECMAScript 5.1. Run before publishing/queueing; never log field values.
var secretText = /-----BEGIN [^-]*(PRIVATE KEY|CERTIFICATE)-----|(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie)\s*["']?\s*[:=]|\b(Bearer|Basic)\s+\S+|https?:\/\/[^\s/]+@|https?:\/\/[^\s]*[?#]|\b(AKIA|ASIA)[A-Z0-9]{16}\b|\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/i;
var secretKey = /password|passwd|pwd|secret|token|authorization|cookie|private[_-]?key|command[_-]?line|task[_-]?content|script[_-]?(block[_-]?text|contents?)|(^|[._-])(api[_-]?key|args|original|xml|body|content)($|[._-])/i;

function process(event) {
    try {
        var source = event.Get();
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
        event.Put('labels.privacy_policy', 'v2');
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
