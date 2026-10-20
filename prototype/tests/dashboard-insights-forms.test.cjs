/* Targeted DOM/transport contracts; native browser layout and TLS are separate. */
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {parseHTML}=require('linkedom');
const {randomUUID}=require('node:crypto');
function ui(responses=[]){
 const {document,window}=parseHTML('<html><body></body></html>');
 const create=document.createElement.bind(document),calls=[];
 document.createElement=tag=>{
  const e=create(tag);e.listeners={};const add=e.addEventListener.bind(e);
  e.addEventListener=(name,fn,...rest)=>{e.listeners[name]=fn;add(name,fn,...rest);};
  if(tag==='details')Object.defineProperty(e,'open',{get(){return this.hasAttribute('open');},set(v){this.toggleAttribute('open',v);}});
  if(tag==='select')Object.defineProperty(e,'value',{get(){return (this.querySelector('option[selected]')||this.querySelector('option'))?.value||'';},set(value){for(const o of this.querySelectorAll('option'))o.toggleAttribute('selected',o.value===value);}});
  return e;
 };
 const storage={setItem(){throw new Error('Credentials must not enter browser storage');}};
 const context={document,Node:window.Node,window:{addEventListener(){},localStorage:storage,sessionStorage:storage},
  localStorage:storage,sessionStorage:storage,crypto:{randomUUID},URLSearchParams,AbortController,Date,console,
  setTimeout,clearTimeout,confirm:()=>true,
  fetch:async(url,options)=>{calls.push({url,options});const next=responses.shift();return typeof next==='function'?next():next||{ok:true,json:async()=>({})};}};
 for(const file of ['dashboard-insight-metrics.js','dashboard-insights.js'])vm.runInNewContext(fs.readFileSync(path.join(__dirname,'..',file),'utf8'),context);
 const box=create('section');box.matches=()=>false;document.body.append(box);
 function render(kind,body){context.window.CloudSOCInsights.render(box,{id:'widget-'+kind,type:kind,config:{limit:10}},{source:kind},{body});}
 // linkedom has no constraint validation. Model the browser submit gate, not a server validator.
 function valid(form){return [...form.querySelectorAll('input,select')].every(e=>{
  if(e.required&&(e.type==='checkbox'?!e.checked:!e.value))return false;
  if(e.type==='number'&&e.value!==''&&(!Number.isFinite(Number(e.value))||(e.min!==undefined&&e.min!==''&&Number(e.value)<Number(e.min))||(e.max!==undefined&&e.max!==''&&Number(e.value)>Number(e.max))))return false;
  return true;
 });}
 const submit=form=>valid(form)?form.listeners.submit({preventDefault(){}}):Promise.resolve();
 const emit=form=>form.listeners.submit({preventDefault(){}});
 return {box,calls,render,submit,emit};
}
const bodies={fleet:{total:0,counts:{},rows:[]},accounts:{total:0,accounts:[],can_manage:true,policies:[]},evaluation:{run_total:0,groups:[],runs:[],can_manage:true}};
function prepared(kind,responses){
 const view=ui(responses);view.render(kind,bodies[kind]);
 const form=view.box.querySelector('form');
 for(const field of form.querySelectorAll('input')){
  if(field.type==='checkbox')field.checked=true;
  else if(field.type==='number')field.value='30';
  else if(field.type==='datetime-local')field.value='2020-01-01T09:00';
  else field.value=field.name==='input_digest'?'a'.repeat(64):'synthetic';
 }
 const interval=form.querySelector('[name=interval]');if(interval)interval.value='30';
 const weight=form.querySelector('[name=weight]');if(weight)weight.value='3';
 return {view,form};
}
for(const kind of ['fleet','accounts','evaluation']){
 test(kind+': required fields prevent submission and a valid form sends its exact contract',async()=>{
  const {view,form}=prepared(kind);const field=form.querySelector('[name=organization]');
  assert.equal(field.required,true);field.value='';await view.submit(form);assert.equal(view.calls.length,0);
  field.value='org-a';await view.submit(form);assert.equal(view.calls.length,1);
  const call=view.calls[0],body=JSON.parse(call.options.body);
  assert.equal(call.url,kind==='fleet'?'/api/dashboard-devices':kind==='accounts'?'/api/dashboard-records/policy':'/api/dashboard-records/evaluation');
  assert.equal(call.options.method,'POST');assert.equal(call.options.headers['X-Cloud-SOC'],'portal');assert.equal(body.organization,'org-a');
  if(kind==='fleet'){assert.equal(body.interval,30);assert.equal(body.days,30);assert.ok(body.request_id);}
  if(kind==='accounts'){assert.equal(body.approved,true);assert.equal(body.items[0].weight,3);}
  if(kind==='evaluation'){assert.equal(body.started_at,'2020-01-01T00:00:00.000Z');assert.equal(body.cases[0].expected,true);assert.equal(body.cases[0].verdict,'inconclusive');}
 });
 test(kind+': repeated submit during save sends one request and preserves the request identity after failure',async()=>{
  let finish;
  const {view,form}=prepared(kind,[()=>new Promise(resolve=>{finish=resolve;})]);
  const first=view.emit(form),second=view.emit(form);
  assert.equal(view.calls.length,1);
  finish({ok:false,json:async()=>({error:'synthetic save failure'})});await Promise.all([first,second]);
  assert.match(form.textContent,/synthetic save failure/);
  assert.equal(form.querySelector('[name=organization]').value,'synthetic');
  const body=JSON.parse(view.calls[0].options.body);await view.submit(form);
  assert.equal(view.calls.length,2);assert.deepEqual(JSON.parse(view.calls[1].options.body),body);
 });
 test(kind+': background refresh preserves the open form node and draft',()=>{
  const {view,form}=prepared(kind),details=form.closest('details');details.open=true;
  form.querySelector('[name=organization]').value='unsaved-org';
  view.render(kind,{...bodies[kind],total:99,run_total:99});
  assert.equal(view.box.querySelector('form'),form);assert.equal(form.querySelector('[name=organization]').value,'unsaved-org');assert.equal(details.open,true);
 });
}
test('device one-time credential survives refresh and close removes the visible secret',async()=>{
 const credential='synthetic-display-only-credential';
 const {view,form}=prepared('fleet',[{ok:true,json:async()=>({id:'new-device',generation:'new-generation',credential})}]);
 await view.submit(form);const output=view.box.querySelector('output.insight-credential');assert.equal(output.textContent,credential);
 view.render('fleet',{total:1,counts:{},rows:[]});assert.equal(view.box.querySelector('output'),output);
 const close=[...form.querySelectorAll('button')].find(b=>b.textContent==='표시 닫기');close.listeners.click();
 assert.equal(output.textContent,'');assert.equal(view.box.querySelector('output'),null);assert.ok(!view.box.textContent.includes(credential));
});
test('approved policy checkbox is required and unapproved form does not submit',async()=>{
 const {view,form}=prepared('accounts');const check=form.querySelector('input[type=checkbox]');
 assert.equal(check.required,true);check.checked=false;await view.submit(form);assert.equal(view.calls.length,0);
});
test('device interval bounds are present and prevent invalid browser submission',async()=>{
 const {view,form}=prepared('fleet'),interval=form.querySelector('[name=interval]');
 assert.equal(interval.min,'15');assert.equal(interval.max,'300');
 interval.value='14';await view.submit(form);assert.equal(view.calls.length,0);
 interval.value='301';await view.submit(form);assert.equal(view.calls.length,0);
});

test('account assessment preserves the selected policy, KST instant, expiry and evidence',async()=>{
 const view=ui(),policy={id:'approved-policy',organization:'org-a',version:'v1',items:[{id:'control-one',title:'One',weight:3,criterion:'Defined control',rationale:'Approved importance'}]};
 view.render('accounts',{total:0,accounts:[],can_manage:true,policies:[policy]});
 const form=view.box.querySelectorAll('form')[1];
 form.querySelector('[name=account]').value='123456789012';form.querySelector('[name=observed]').value='2020-01-01T09:00';
 form.querySelector('[name=expires]').value='2';form.querySelector('[name=control-one]').value='fail';
 form.querySelector('[name=evidence]').value='synthetic-evidence-reference';
 await view.submit(form);assert.equal(view.calls.length,1);assert.equal(view.calls[0].url,'/api/dashboard-records/assessment');
 const body=JSON.parse(view.calls[0].options.body);
 assert.equal(body.organization,'org-a');assert.equal(body.policy_id,'approved-policy');assert.equal(body.source,'operator_evidence_review');
 assert.equal(body.observed_at,'2020-01-01T00:00:00.000Z');assert.equal(body.expires_at,'2020-01-03T00:00:00.000Z');
 assert.deepEqual(body.items,[{id:'control-one',state:'fail',evidence:'synthetic-evidence-reference'}]);
});
