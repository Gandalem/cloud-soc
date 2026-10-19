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
        if (settings.stream==='modsecurity') { return processWaf(event); }
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
function processWaf(event) {
    try {
        var raw=event.Get('message');
        if (typeof raw!=='string' || raw.length>131072) { throw new Error('invalid audit size'); }
        var envelope=JSON.parse(raw), tx=envelope.transaction;
        if (!tx || !tx.request || !tx.response || !tx.producer || !Array.isArray(tx.messages) || !tx.messages.length || tx.messages.length>64) { throw new Error('invalid audit transaction'); }
        var requestId=tx.unique_id, peer=tx.client_ip, method=tx.request.method, status=tx.response.http_code;
        if (typeof requestId!=='string' || !/^[A-Za-z0-9_.:@-]{1,128}$/.test(requestId) || typeof peer!=='string' ||
            !(/^(\d{1,3}\.){3}\d{1,3}$/.test(peer) || /^[0-9a-fA-F:]{3,45}$/.test(peer)) ||
            ['GET','HEAD','POST','PUT','DELETE','OPTIONS','PATCH'].indexOf(method)<0 || typeof status!=='number' || status%1!==0 || status<100 || status>599) { throw new Error('invalid audit identity'); }
        // ModSecurity v3 emits local asctime without a zone. The collector must
        // supply its configured offset; never assume UTC from the host locale.
        var match=/^[A-Z][a-z]{2} ([A-Z][a-z]{2}) +([0-9]{1,2}) ([0-9:]{8}) ([0-9]{4})$/.exec(tx.time_stamp);
        if (!match || !/^[+-](?:0[0-9]|1[0-4]):[0-5][0-9]$/.test(settings.timezone)) { throw new Error('audit timezone required'); }
        var time=occurred(('0'+match[2]).slice(-2)+'/'+match[1]+'/'+match[4]+':'+match[3]+' '+settings.timezone.replace(':',''));
        if (time.getTime()<Date.parse(settings.start_at)) { event.Cancel(); return event; }
        var mode=tx.producer.secrules_engine;
        mode=mode==='Enabled'?'On':mode==='Disabled'?'Off':mode;
        if (['On','Off','DetectionOnly'].indexOf(mode)<0) { throw new Error('unknown WAF engine mode'); }
        var interruption=typeof tx.is_interrupted==='boolean'?(tx.is_interrupted?'observed':'not_observed'):'unknown';
        if (mode!=='On' && interruption==='observed') { throw new Error('contradictory WAF intervention'); }
        var rules=[], seen={};
        tx.messages.forEach(function(message){
            var details=message.details, id=details&&details.ruleId;
            if (typeof id!=='string' || !/^[1-9][0-9]{0,7}$/.test(id)) { throw new Error('invalid WAF rule ID'); }
            var version=typeof details.ver==='string'?/^(?:OWASP_CRS|CRS)\/([34]\.[0-9]{1,3}\.[0-9]{1,3})$/.exec(details.ver):null;
            if (seen[id]) { if (seen[id]!==String(version&&version[1])) { throw new Error('conflicting WAF rule versions'); } return; }
            seen[id]=String(version&&version[1]); rules.push({id:id,crs_version:version?version[1]:null});
        });
        ['message','url','user','http','event','source','destination','related','error','container','docker','transaction','waf'].forEach(function(k){
            var value=event.Get(k); if (value!==null && value!==undefined && event.Delete(k)===false) { throw new Error('privacy removal failed'); }
        });
        event.Put('service.id',settings.id); event.Put('service.name',settings.name);
        event.Put('event.category',['web']); event.Put('event.action','waf_rule_match');
        event.Put('event.dataset','cloud_soc.modsecurity'); event.Put('event.outcome','unknown');
        event.Put('http.request.id',requestId); event.Put('http.request.method',method); event.Put('http.response.status_code',status);
        event.Put('source.ip',peer); event.Put('web.occurred_at',time.toISOString());
        event.Put('waf.schema','modsecurity-metadata-v1'); event.Put('waf.engine_mode',mode);
        event.Put('waf.interruption',interruption); event.Put('waf.rules',rules);
        event.Put('labels.privacy_policy','modsecurity-metadata-v1');
    } catch (_) { event.Cancel(); }
    return event;
}
function test() {
    if (occurred('14/Oct/2026:09:00:00 +0900').toISOString()!=='2026-10-14T00:00:00.000Z') { throw new Error('access timestamp self-test failed'); }
}
