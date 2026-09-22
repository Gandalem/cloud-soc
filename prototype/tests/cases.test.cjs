const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {randomUUID}=require('node:crypto');
const settle=()=>new Promise(resolve=>setImmediate(resolve));
const id='a'.repeat(32),row={id,title:'<img src=x>',organization:'school',priority:'high',status:'new',owner:null,verdict:'unreviewed',version:1,created_at:'2026-09-22T01:00:00Z'};
const detail={case:row,alerts:[],history:[],history_next:null,actor:'admin'};
const ok=data=>()=>({ok:true,json:async()=>data});
function browser(script,responses,search='?case='+id){
  const elements=new Map(),calls=[],locations=[];
  function element(){return {value:'',textContent:'',children:[],listeners:{},hidden:false,disabled:false,
    append(...nodes){this.children.push(...nodes);},replaceChildren(...nodes){this.children=nodes;},addEventListener(n,f){this.listeners[n]=f;},querySelectorAll(){return[];}};}
  const get=name=>{if(!elements.has(name))elements.set(name,element());return elements.get(name);};
  const context={document:{getElementById:get,createElement:element},window:{location:{search},history:{replaceState(_a,_b,url){locations.push(url);}},addEventListener(){}},URLSearchParams,Date,crypto:{randomUUID},FormData:class{*[Symbol.iterator](){yield['status','open'];yield['sort','priority'];}},fetch:async(url,options)=>{calls.push({url,options});return responses.shift()();}};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../'+script),'utf8'),context);
  return {get,calls,locations};
}
test('workbench has no demo script or save-disabled placeholder',()=>{
  const html=fs.readFileSync(path.join(__dirname,'../workbench.html'),'utf8');assert.ok(html.includes('investigation.js'));assert.ok(!html.includes('demo-data.js'));
});
test('conflict preserves memo and sends server version, not actor',async()=>{
  const ui=browser('investigation.js',[ok(detail),()=>({ok:false,status:409,json:async()=>({code:'case_version_conflict',error:'PRIVATE_CANARY'})})]);await settle();
  ui.get('work-note').value='Analyst draft';ui.get('case-work-form').listeners.submit({preventDefault(){}});await settle();
  const sent=JSON.parse(ui.calls[1].options.body);assert.equal(sent.version,1);assert.ok(!('actor'in sent));assert.equal(ui.get('work-note').value,'Analyst draft');assert.match(ui.get('investigation-error').textContent,/다른 수정/);assert.ok(!ui.get('investigation-error').textContent.includes('PRIVATE_CANARY'));
});
test('uncertain save retries with same key and clears note only on success',async()=>{
  const ui=browser('investigation.js',[ok(detail),()=>{throw new TypeError('Network error');},ok({...row,version:2}),ok({...detail,case:{...row,version:2}})]);await settle();
  ui.get('work-note').value='Save me';ui.get('case-work-form').listeners.submit({preventDefault(){}});await settle();
  ui.get('case-work-form').listeners.submit({preventDefault(){}});await settle();
  assert.equal(ui.calls[1].options.headers['Idempotency-Key'],ui.calls[2].options.headers['Idempotency-Key']);assert.equal(ui.get('work-note').value,'');
});
test('linking an alert does not discard unsaved memo',async()=>{
  const ui=browser('investigation.js',[ok(detail),ok({...row,version:2}),ok({...detail,case:{...row,version:2}})]);await settle();
  ui.get('work-note').value='Still a draft';ui.get('case-link-id').value='another-alert';ui.get('case-link-form').listeners.submit({preventDefault(){}});await settle();
  assert.equal(ui.get('work-note').value,'Still a draft');assert.equal(JSON.parse(ui.calls[1].options.body).alert_id,'another-alert');
});
test('existing alert resolves saved case and creates nothing automatically',async()=>{
  const ui=browser('investigation.js',[ok({case_id:id}),ok(detail)],'?alert=fixture');await settle();
  assert.equal(ui.calls.length,2);assert.ok(ui.calls.every(c=>!c.options.method));assert.equal(ui.get('case-title').textContent,row.title);
});
test('queue preserves filters, text nodes and clears stale rows on errors',async()=>{
  const ui=browser('cases.js',[ok({rows:[row],counts:{total:1,open:1,unassigned:1,investigating:0},has_next:false}),()=>({ok:false,status:503})],'');await settle();
  const link=ui.get('case-rows').children[0].children[0].children[0];assert.equal(link.textContent,row.title);assert.ok(link.href.includes('return='));
  ui.get('case-filters').listeners.submit({preventDefault(){}});await settle();assert.equal(ui.get('case-rows').children.length,0);assert.equal(ui.get('case-error').hidden,false);
});
test('return URL cannot escape local case queue',async()=>{
  const ui=browser('investigation.js',[ok(detail)],'?case='+id+'&return='+encodeURIComponent('https://evil.example/?x=1&case_status=closed'));await settle();
  assert.equal(ui.get('case-back').href,'index.html?case_status=closed#case-queue');
});
