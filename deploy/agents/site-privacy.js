// Separate per-input script. Only selected access metadata crosses the queue.
var settings;
var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
function register(params) {
    settings = params;
    if (!settings || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(settings.id) ||
        ['apache','nginx','docker'].indexOf(settings.server_type) < 0 || isNaN(Date.parse(settings.start_at))) {
        throw new Error('invalid site configuration');
    }
}
function occurred(text) {
    var m = /^(\d{2})\/([A-Z][a-z]{2})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/.exec(text);
    if (!m) { throw new Error('invalid access time'); }
    var month=months.indexOf(m[2]), day=+m[1], year=+m[3], hour=+m[4], minute=+m[5], second=+m[6];
    var zone=(+m[8]*60 + +m[9])*(m[7]==='+'?1:-1);
    var date=new Date(Date.UTC(year,month,day,hour,minute,second));
    if (month<0 || year<2000 || year>2100 || hour>23 || minute>59 || second>59 || +m[8]>14 || +m[9]>59 || Math.abs(zone)>840 || date.getUTCDate()!==day || date.getUTCMonth()!==month) { throw new Error('invalid access time'); }
    return new Date(date.getTime()-zone*60000);
}
function process(event) {
    try {
        var line=event.Get('message');
        if (typeof line!=='string' || line.length>8192) { throw new Error('invalid access line'); }
        if (settings.server_type==='docker') {
            var wrapper=JSON.parse(line);
            if (!wrapper || typeof wrapper.log!=='string') { throw new Error('invalid Docker JSON access line'); }
            line=wrapper.log;
        }
        line=line.replace(/[\r\n]+$/, '');
        var m=/^(\S+) \S+ \S+ \[([^\]]+)\] "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) [^"\r\n]+ HTTP\/[0-9.]+" ([0-9]{3}) ([0-9]+|-)(?: "[^"\r\n]*" "[^"\r\n]*")?$/.exec(line);
        if (!m || +m[4]<100 || +m[4]>599) { throw new Error('unsupported access format'); }
        var time=occurred(m[2]);
        if (time.getTime()<Date.parse(settings.start_at)) { event.Cancel(); return event; }
        // Raw request, authenticated name, referrer, headers and unknown Docker
        // fields are discarded, never recursively copied or sent to a queue.
        ['message','url','user','http','event','source','destination','related','error','container','docker'].forEach(function(k){
            var value=event.Get(k);
            if (value!==null && value!==undefined && event.Delete(k)===false) { throw new Error('privacy removal failed'); }
        });
        event.Put('service.id',settings.id); event.Put('service.name',settings.name);
        event.Put('web.schema','web-access-agent-v1'); event.Put('web.server_type',settings.server_type);
        event.Put('web.occurred_at',time.toISOString()); event.Put('web.ip_basis','observed_peer');
        event.Put('event.category',['web']); event.Put('event.action','http_access');
        event.Put('event.dataset','cloud_soc.web_access');
        event.Put('event.outcome',+m[4]>=400?'failure':'success');
        event.Put('http.request.method',m[3]); event.Put('http.response.status_code',+m[4]);
        if (m[5]!=='-') {
            var bytes=+m[5]; if (bytes>9007199254740991) { throw new Error('invalid response size'); }
            event.Put('http.response.body.bytes',bytes);
        }
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(m[1]) && m[1].split('.').every(function(v){return +v<=255;})) { event.Put('source.ip',m[1]); }
        else if (/^[0-9a-fA-F:]{3,45}$/.test(m[1]) && m[1].indexOf(':')>=0) { event.Put('source.ip',m[1]); }
        event.Put('labels.privacy_policy','web-access-agent-v1');
    } catch (_) { event.Cancel(); }
    return event;
}
function test() {
    if (occurred('14/Oct/2026:09:00:00 +0900').toISOString()!=='2026-10-14T00:00:00.000Z') { throw new Error('access timestamp self-test failed'); }
}
