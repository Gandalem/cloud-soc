const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const script=fs.readFileSync(path.join(__dirname,'../login.js'),'utf8'),settle=()=>new Promise(r=>setImmediate(r));
function browser(mode,success=true){
 const els=new Map(),calls=[],redirect=[];
 const get=id=>{if(!els.has(id))els.set(id,{hidden:true,textContent:'',listeners:{},addEventListener(n,f){this.listeners[n]=f}});return els.get(id)};
 const button={disabled:false};get('login-form').querySelector=()=>button;
 get('login-form').elements={username:{value:'synthetic'},password:{value:'synthetic-password'}};
 vm.runInNewContext(script,{document:{getElementById:get},fetch:async(url,options)=>{calls.push({url,options});return {ok:success,json:async()=>({mode})}},
  window:{location:{replace:p=>redirect.push(p)}}});return {get,calls,redirect};
}
test('basic deployment exposes working browser-login entry and never submits a disabled session form',async()=>{
 const ui=browser('basic');await settle();assert.equal(ui.get('login-form').hidden,true);assert.equal(ui.get('login-basic').hidden,false);
 await ui.get('login-form').listeners.submit({preventDefault(){}});assert.equal(ui.calls.length,1);assert.match(ui.get('login-error').textContent,/로그인 방식/);
});
test('configured session form is usable and clears password after authentication',async()=>{
 const ui=browser('session');await settle();assert.equal(ui.get('login-form').hidden,false);assert.equal(ui.get('login-basic').hidden,true);
 await ui.get('login-form').listeners.submit({preventDefault(){}});assert.equal(ui.calls.at(-1).url,'/api/auth/login');
 assert.equal(ui.get('login-form').elements.password.value,'');assert.deepEqual(ui.redirect,['/']);
});
test('unavailable or malformed login configuration cannot expose a misleading usable form',async()=>{
 for(const [mode,success] of [['unknown',true],['session',false]]){
  const ui=browser(mode,success);await settle();assert.equal(ui.get('login-form').hidden,true);assert.equal(ui.get('login-basic').hidden,true);
  assert.match(ui.get('login-mode').textContent,/확인하지 못했습니다/);
 }
});
