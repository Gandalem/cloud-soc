const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname,'../auth-client.js'),'utf8');
function harness() {
  const calls = [], redirects = [];
  const window = {
    location:{href:'https://soc.invalid/cases.html',origin:'https://soc.invalid',assign:url=>redirects.push(url)},
    fetch: async (input,options) => {
      calls.push({input,options});
      return input==='/api/auth/me'
        ? {ok:true,status:200,json:async()=>({user:'analyst',role:'analyst',mode:'session',csrf:'synthetic-csrf'})}
        : {ok:true,status:200};
    }
  };
  vm.runInNewContext(source,{window,document:{addEventListener(){}},Headers,Request,URL});
  return {window,calls,redirects};
}
test('same-origin mutations receive server-issued CSRF without changing caller headers',async()=>{
  const {window,calls}=harness(),headers={'X-Cloud-SOC':'portal'};
  await window.fetch('/api/cases',{method:'POST',headers,body:'{}'});
  assert.equal(calls.at(-1).options.headers.get('X-CSRF-Token'),'synthetic-csrf');
  assert.equal(headers['X-CSRF-Token'],undefined);
});
test('external requests never receive portal CSRF',async()=>{
  const {window,calls}=harness();
  await window.fetch('https://other.invalid/',{method:'POST'});
  assert.equal(calls.at(-1).options.headers,undefined);
});
test('read-only evidence requests do not attach mutation CSRF',async()=>{
  const {window,calls}=harness();
  await window.fetch('/api/alerts/detail?id=fixture');
  assert.equal(calls.at(-1).options.headers,undefined);
});

function headerHarness(mode='session', readyState='loading') {
  const events={}, nodes=new Map(), calls=[], redirects=[];
  let context=null;
  function element() {return {textContent:'',handlers:{},addEventListener(type,fn){this.handlers[type]=fn;},after(node){if(node.id)nodes.set(node.id,node);}};}
  const document={readyState,body:{dataset:{}},
    addEventListener(type,fn){events[type]=fn;},
    querySelector(selector){return selector==='.header-context'?context:null;},
    querySelectorAll(){return [];},getElementById(id){return nodes.get(id)||null;},createElement:element};
  const window={location:{href:'https://soc.invalid/index.html',origin:'https://soc.invalid',assign:url=>redirects.push(url)},
    fetch:async(input,options)=>{calls.push({input,options});return input==='/api/auth/me'
      ?{ok:true,status:200,json:async()=>({user:'admin',role:'admin',mode,csrf:'test-token'})}
      :{ok:true,status:200};}};
  vm.runInNewContext(source,{window,document,Headers,Request,URL});
  return {window,document,calls,redirects,nodes,events,
    renderShell(){nodes.clear();context=element();},
    async fire(name){await events[name]?.();}};
}
test('session logout appears when header arrives after DOM ready and returns after rerender',async()=>{
  const h=headerHarness();
  await h.fire('DOMContentLoaded');
  assert.equal(h.nodes.size,0);
  h.renderShell();await h.fire('cloud-soc-shell-rendered');
  const first=h.nodes.get('portal-logout');assert.equal(first.textContent,'로그아웃');
  h.renderShell();await h.fire('cloud-soc-shell-rendered');
  assert.ok(h.nodes.get('portal-logout'));assert.notEqual(h.nodes.get('portal-logout'),first);
});
test('repeated and concurrent identity rendering never duplicates logout controls',async()=>{
  const h=headerHarness();h.renderShell();
  await Promise.all([h.fire('DOMContentLoaded'),h.fire('cloud-soc-shell-rendered')]);
  assert.equal(h.nodes.size,1);
  const button=h.nodes.get('portal-logout');await h.fire('cloud-soc-shell-rendered');
  assert.equal(h.nodes.get('portal-logout'),button);
});
test('basic auth does not claim session logout is available',async()=>{
  const h=headerHarness('basic');h.renderShell();await h.fire('DOMContentLoaded');
  assert.equal(h.nodes.has('portal-logout'),false);
});
test('restored button still uses original server logout and CSRF transport',async()=>{
  const h=headerHarness();h.renderShell();await h.fire('cloud-soc-shell-rendered');
  await h.nodes.get('portal-logout').handlers.click();
  assert.equal(h.calls.at(-1).input,'/api/auth/logout');
  assert.equal(h.calls.at(-1).options.headers.get('X-CSRF-Token'),'test-token');
  assert.equal(h.redirects.at(-1),'/login');
});
