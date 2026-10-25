const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {parseHTML} = require('linkedom');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname,'../devices.html'),'utf8');
const script = fs.readFileSync(path.join(__dirname,'../devices.js'),'utf8');
const pause = ms => new Promise(resolve=>setTimeout(resolve,ms));
async function until(check){for(let i=0;i<100;i++){if(check())return;await pause(5);}assert.fail('UI did not reach the expected state');}
function fixture(){
  const {window:domWindow,document}=parseHTML(html),calls=[],timers=[];
  const storage=new Map();
  const window={document,crypto:{},Event:domWindow.Event,sessionStorage:{getItem:k=>storage.get(k)||null,setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)}};
  for(const select of document.querySelectorAll('select'))Object.defineProperty(select,'value',{configurable:true,get(){return(this.querySelector('option[selected]')||this.querySelector('option'))?.value||'';},set(v){for(const option of this.querySelectorAll('option'))option.toggleAttribute('selected',option.value===v);}});
  for(const input of document.querySelectorAll('input[type=checkbox]'))Object.defineProperty(input,'checked',{configurable:true,get(){return this.hasAttribute('checked');},set(v){this.toggleAttribute('checked',v);}});
  // LinkeDOM omits browser constraint validation, just as it omits reset/showModal.
  // Retain the message and validity so a missing/ineffective scope guard still fails.
  for(const input of document.querySelectorAll('input')){
    let message='';input.setCustomValidity=value=>{message=String(value);};
    Object.defineProperty(input,'validationMessage',{get(){return message;}});
    input.checkValidity=()=>message==='';
  }
  for(const dialog of document.querySelectorAll('dialog')){Object.defineProperty(dialog,'open',{get(){return this.hasAttribute('open');}});dialog.showModal=()=>dialog.setAttribute('open','');dialog.close=()=>dialog.removeAttribute('open');}
  for(const form of document.querySelectorAll('form')){
    const elements={};for(const field of form.querySelectorAll('[name]'))elements[field.name]=field;
    Object.defineProperty(form,'elements',{value:elements});
    const defaults=Object.fromEntries(Object.entries(elements).map(([k,v])=>[k,{value:v.value,checked:v.checked}]));
    form.reset=()=>{for(const [k,v]of Object.entries(defaults)){elements[k].value=v.value??'';if(elements[k].type==='checkbox')elements[k].checked=v.checked;}};
  }
  let serial=0,device=null,hold=null;
  Object.defineProperty(window.crypto,'randomUUID',{value:()=>String(++serial).padStart(32,'0')});
  window.fetch=async(url,options={})=>{
    const body=options.body?JSON.parse(options.body):null;
    calls.push({url,options,body});
    let result={};
    if(url.startsWith('/api/key-history'))result={keys:[],total:0};
    else if(url==='/api/managed-devices'&&options.method==='POST'){
      if(hold)await hold;
      device={id:'a'.repeat(32),label:body.label,organization:body.organization,os:body.os,purpose:body.purpose,state:'requested',keys:[],registration:null};result={device};
    }else if(url.endsWith('/prepare')){device={...device,registration:{state:'unused',expires:Math.floor(Date.now()/1000)+900}};result={device};}
    else if(url.endsWith('/end')){device={...device,state:'ended'};result={device};}
    else if(url.startsWith('/api/managed-devices?'))result={devices:device&&device.state!=='ended'?[device]:[],total:device&&device.state!=='ended'?1:0,enrollment_enabled:true};
    else result={device};
    return {ok:true,status:200,json:async()=>JSON.parse(JSON.stringify(result))};
  };
  const context={window,document,crypto:window.crypto,sessionStorage:window.sessionStorage,fetch:window.fetch,URLSearchParams,
    setTimeout:(fn,ms)=>{const timer=setTimeout(fn,ms);timers.push(timer);return timer;},clearTimeout,Date,console};
  vm.runInNewContext(script,context);
  return {window,calls,close:()=>timers.forEach(clearTimeout),hold:promise=>hold=promise};
}
test('device creation automatically prepares a download without manual publisher-key requests',async()=>{
  const f=fixture();try{
    await until(()=>!f.window.document.querySelector('#add-device').disabled);
    f.window.document.querySelector('#add-device').click();
    const form=f.window.document.querySelector('#device-form');form.elements.label.value='쇼핑몰 웹 서버';form.elements.organization.value='synthetic';
    form.dispatchEvent(new f.window.Event('submit',{bubbles:true,cancelable:true}));
    await until(()=>!f.window.document.querySelector('#device-download').hidden);
    assert.equal(f.calls.filter(c=>c.url==='/api/managed-devices'&&c.options.method==='POST').length,1);
    assert.equal(f.calls.filter(c=>c.url.endsWith('/prepare')).length,1);
    assert.ok(f.calls.every(c=>!c.url.endsWith('/keys')));
    assert.match(f.window.document.querySelector('#device-download').getAttribute('href'),/managed-devices\/a+\/download/);
  }finally{f.close();}
});
test('duplicate submit while pending sends a single create and preserves the form request identity',async()=>{
  const f=fixture();let release;try{
    await pause(10);f.window.document.querySelector('#add-device').click();
    const form=f.window.document.querySelector('#device-form');form.elements.label.value='synthetic';form.elements.organization.value='synthetic';
    f.hold(new Promise(resolve=>release=resolve));
    form.dispatchEvent(new f.window.Event('submit',{bubbles:true,cancelable:true}));
    form.dispatchEvent(new f.window.Event('submit',{bubbles:true,cancelable:true}));
    assert.equal(f.calls.filter(c=>c.url==='/api/managed-devices'&&c.options.method==='POST').length,1);
    assert.match(JSON.parse(f.window.sessionStorage.getItem('soc-device-add')).id,/^[a-f0-9]{32}$/);
    release();await until(()=>!f.window.document.querySelector('#device-download').hidden);
  }finally{if(release)release();f.close();}
});
test('Windows capture scope is rejected before requests and OS changes restore validity without altering selection',async()=>{
  const f=fixture();try{
    await until(()=>!f.window.document.querySelector('#add-device').disabled);
    f.window.document.querySelector('#add-device').click();
    const form=f.window.document.querySelector('#device-form'),fields=form.elements;
    fields.label.value='synthetic';fields.organization.value='synthetic';fields.os.value='windows';fields.network.checked=true;
    form.dispatchEvent(new f.window.Event('change',{bubbles:true}));
    assert.equal(fields.network.checkValidity(),false);
    assert.match(fields.network.validationMessage,/네트워크 패킷 수집/);
    form.dispatchEvent(new f.window.Event('submit',{bubbles:true,cancelable:true}));
    assert.equal(f.calls.filter(c=>c.options.method==='POST').length,0);
    assert.equal(fields.network.checked,true);
    assert.match(f.window.document.querySelector('#device-form-error').textContent,/네트워크 패킷 수집/);
    fields.os.value='ubuntu';form.dispatchEvent(new f.window.Event('change',{bubbles:true}));
    assert.equal(fields.network.validationMessage,'');assert.equal(fields.network.checkValidity(),true);
    assert.equal(fields.network.checked,true);
    form.dispatchEvent(new f.window.Event('submit',{bubbles:true,cancelable:true}));
    await until(()=>!f.window.document.querySelector('#device-download').hidden);
    const creates=f.calls.filter(c=>c.url==='/api/managed-devices'&&c.options.method==='POST');
    assert.equal(creates.length,1);assert.equal(creates[0].body.os,'ubuntu');assert.equal(creates[0].body.network,true);
  }finally{f.close();}
});
test('key history defaults to active and names are escaped',async()=>{
  const f=fixture();try{
    await pause(10);
    assert.ok(f.calls.some(c=>c.url.startsWith('/api/key-history?view=active')));
    const common=require('../devices.js');
    const rendered=common.keyMarkup({target_label:'<img src=x onerror=alert(1)>',organization:'test',scope:'host',status:'revoked',id:'public-id'});
    assert.ok(!rendered.includes('<img'));
    assert.match(rendered,/폐기 완료/);
  }finally{f.close();}
});
