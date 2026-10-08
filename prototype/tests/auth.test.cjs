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
