const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {randomUUID}=require('node:crypto');
const settle=()=>new Promise(resolve=>setImmediate(resolve));
const id='a'.repeat(32),row={id,title:'<img src=x>',organization:'school',priority:'high',status:'new',owner:null,verdict:'unreviewed',version:1,created_at:'2026-09-22T01:00:00Z'};
const detail={case:row,alerts:[],history:[],history_next:null,actor:'admin'};
const ok=data=>()=>({ok:true,json:async()=>data});
function browser(script,responses,search='?case='+id,options={}){
  const elements=new Map(),calls=[],locations=[];
  function element(){return {value:'',textContent:'',children:[],listeners:{},hidden:false,disabled:false,
    append(...nodes){this.children.push(...nodes);},replaceChildren(...nodes){this.children=nodes;},addEventListener(n,f){this.listeners[n]=f;},querySelectorAll(){return[];}};}
  const get=name=>{
    if(!elements.has(name)){
      const node=element();
      if(name==='work-owner'){
        let selected='';
        Object.defineProperty(node,'value',{get(){return selected;},set(value){selected=node.children.some(option=>option.value===value)?value:'';}});
      }
      elements.set(name,node);
    }
    return elements.get(name);
  };
  const context={document:{body:{dataset:{caseListPage:options.page}},getElementById:get,createElement:element},window:{location:{search,hash:options.hash},history:{replaceState(_a,_b,url){locations.push(url);}},addEventListener(){}},URLSearchParams,Date,crypto:{randomUUID},FormData:class{*[Symbol.iterator](){yield['status',options.status??'open'];yield['sort','priority'];}},fetch:async(url,options)=>{calls.push({url,options});return responses.shift()();}};
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
test('note-only save preserves a different or retired current owner',async()=>{
  for(const assigned of ['analyst-a','retired-user']){
    const owned={...row,owner:assigned};
    const ui=browser('investigation.js',[ok({...detail,case:owned}),ok({...owned,version:2}),ok({...detail,case:{...owned,version:2}})]);await settle();
    assert.ok(ui.get('work-owner').children.some(option=>option.value===assigned));
    assert.equal(ui.get('work-owner').value,assigned);
    ui.get('work-note').value='Note only';ui.get('case-work-form').listeners.submit({preventDefault(){}});await settle();
    const sent=JSON.parse(ui.calls[1].options.body);assert.equal(sent.note,'Note only');assert.ok(!Object.hasOwn(sent,'owner'));
    assert.equal(ui.get('work-owner').value,assigned);
  }
});
test('explicit owner reassignment and unassignment are sent',async()=>{
  for(const selected of ['admin','']){
    const owned={...row,owner:'analyst-a'},updated={...owned,owner:selected||null,version:2};
    const ui=browser('investigation.js',[ok({...detail,case:owned}),ok(updated),ok({...detail,case:updated})]);await settle();
    ui.get('work-owner').value=selected;ui.get('case-work-form').listeners.submit({preventDefault(){}});await settle();
    assert.equal(JSON.parse(ui.calls[1].options.body).owner,selected||null);
  }
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
  assert.equal(ui.get('case-back').href,'cases.html?case_status=closed#case-queue');
});

test('all live investigation menus point to independent case list',()=>{
  const {markup}=require('../shell.js');
  for(const file of ['index.html','logs.html','agents.html','agent-status.html','collection-health.html','workbench.html','cases.html']){
    const html=fs.readFileSync(path.join(__dirname,'../'+file),'utf8');
    assert.match(html,/src="shell.js"/);
    const menus=[...markup('/'+file,'').matchAll(/<a\b([^>]+)>사건 조사<\/a>/g)];
    assert.ok(menus.length>0,file);
    for(const [,attributes] of menus)assert.match(attributes,/href="cases\.html"/,file);
  }
  const html=fs.readFileSync(path.join(__dirname,'../cases.html'),'utf8');
  assert.match(html,/<h1>사건 조사<\/h1>/);
  assert.match(markup('/cases.html',''),/href="cases.html" aria-current="page"/);
  assert.ok(html.includes('cases.js'));
  assert.ok(!html.includes('operations.js')&&!html.includes('demo-data.js'));
});

test('independent list stays on cases route and returns exact all filter plus page',async()=>{
  const ui=browser('cases.js',[ok({rows:[row],counts:{total:1,open:1,unassigned:1,investigating:0},has_next:false})],'?case_page=2',{page:'cases.html',status:''});await settle();
  assert.match(ui.locations[0],/^cases\.html\?/);
  const href=ui.get('case-rows').children[0].children[0].children[0].href;
  const query=new URLSearchParams(href.split('?')[1]);
  assert.equal(query.get('return_page'),'cases.html');
  assert.equal(new URLSearchParams(query.get('return')).get('case_status'),'');
  const detailUI=browser('investigation.js',[ok(detail)],'?'+query);await settle();
  assert.equal(detailUI.get('case-back').href,'cases.html?case_status=&case_sort=priority&case_page=2#case-queue');
});

test('overview queue keeps its source and does not steal alert anchor',async()=>{
  const ui=browser('cases.js',[ok({rows:[row],counts:{total:1,open:1,unassigned:1,investigating:0},has_next:false})],'',{hash:'#ops-alerts'});await settle();
  assert.match(ui.locations[0],/^index\.html\?.*#ops-alerts$/);
  const href=ui.get('case-rows').children[0].children[0].children[0].href;
  const query=new URLSearchParams(href.split('?')[1]);assert.equal(query.get('return_page'),'index.html');
  const detailUI=browser('investigation.js',[ok(detail)],'?'+query);await settle();
  assert.match(detailUI.get('case-back').href,/^index\.html\?.*#case-queue$/);
});

test('empty list, direct detail and untrusted return page never redirect to overview',async()=>{
  const ui=browser('cases.js',[ok({rows:[],counts:{total:0,open:0,unassigned:0,investigating:0},has_next:false})],'',{page:'cases.html'});await settle();
  assert.match(ui.get('case-counts').textContent,/해당 사건 없음/);
  assert.match(ui.locations[0],/^cases\.html\?/);
  const direct=browser('investigation.js',[],'');await settle();
  assert.equal(direct.calls.length,0);assert.match(direct.get('investigation-status').textContent,/선택한 사건이 없습니다/);
  assert.match(direct.get('case-back').href,/^cases\.html/);
  const hostile=browser('investigation.js',[ok(detail)],'?case='+id+'&return_page=https://evil.example');await settle();
  assert.equal(hostile.get('case-back').href,'cases.html?#case-queue');
});
