const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const scope={window:{},document:{getElementById:()=>null}};
vm.runInNewContext(fs.readFileSync(require('node:path').join(__dirname,'../dashboard.js'),'utf8'),scope);
const {validLayout,count,defaults}=scope.window.CloudSOCDashboard;
test('unknown and unavailable counts never become zero',()=>{
 for(const section of [null,{state:'unavailable',count:0},{state:'no_index',count:0},{state:'ok',count:-1},{state:'ok',count:NaN}])assert.equal(count(section),'미확인');
 assert.equal(count({state:'ok',count:0}),'0');
});
test('layout rejects duplicated widgets arbitrary sources and malformed choices',()=>{
 assert.ok(validLayout(defaults()));
 for(const extra of [{widgets:[]},{widgets:[{id:'alerts',size:'wide'},{id:'alerts',size:'normal'}]},{widgets:[{id:'http://evil.test',size:'normal'}]},{theme:'remote'},{period:15}])assert.equal(!!validLayout({...defaults(),...extra}),false);
});
test('layout has no telemetry source or credentials',()=>{
 const html=fs.readFileSync(require('node:path').join(__dirname,'../dashboard.html'),'utf8');
 assert.match(html,/dashboard-widget-options/);assert.match(html,/구성 저장/);
 const js=fs.readFileSync(require('node:path').join(__dirname,'../dashboard.js'),'utf8');
 assert.doesNotMatch(js,/innerHTML|localStorage|eval\(/);assert.match(js,/최신 표시된|최근 표시된/);
});

test('legacy technical widgets remain readable but are absent from customer defaults',()=>{
 const legacy={...defaults(),widgets:[{id:'pipeline',size:'wide'},{id:'processing',size:'normal'}]};
 assert.ok(validLayout(legacy));
 assert.equal(defaults().widgets.length,6);
 assert.ok(defaults().widgets.every(w=>!['pipeline','processing'].includes(w.id)));
});
