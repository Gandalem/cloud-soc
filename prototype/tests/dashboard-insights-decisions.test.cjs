const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
function widgets(){const context={window:{},URLSearchParams,AbortController,console};vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../dashboard-widgets.js'),'utf8'),context);return context.window.CloudSOCWidgets;}
test('an optional failed source retains only its own snapshot while fresh sources advance',()=>{
 const W=widgets(),old={geo:{body:{located:7}},'operations:60':{body:{count:2}}};
 const fresh={geo:{error:'unavailable'},'operations:60':{body:{count:3}},fleet:{error:'forbidden'}};
 const merged=W.mergeResults(old,fresh);
 assert.equal(merged.values.geo.body.located,7);assert.equal(merged.values.geo.stale,true);
 assert.equal(merged.values['operations:60'].body.count,3);assert.equal(merged.values.fleet.body,undefined);
 assert.equal(old.geo.stale,undefined);assert.equal(old['operations:60'].body.count,2);
 const recovered=W.mergeResults(merged.values,{geo:{body:{located:9}}});
 assert.equal(recovered.values.geo.stale,undefined);assert.equal(recovered.values.geo.body.located,9);
});
test('new insight widgets share data by source and period without mixing periods',()=>{
 const W=widgets(),catalog=[{type:'cloud-events',source:'cloud',enabled:true},{type:'cloud-iam',source:'cloud',enabled:true},{type:'world-map',source:'geo',enabled:true}];
 const layout={period:1440,widgets:[{type:'cloud-events',config:{period:0}},{type:'cloud-iam',config:{period:0}},{type:'world-map',config:{period:60}}]};
 assert.deepEqual(Array.from(W.plan(layout,catalog)),['status','cloud:1440','geo:60']);
});
