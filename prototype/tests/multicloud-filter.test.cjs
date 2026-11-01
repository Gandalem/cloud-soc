const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const {parseHTML}=require('linkedom');
test('all cloud choices remain present and AWS reaches API filter',async()=>{
 const {window}=parseHTML(fs.readFileSync(require('node:path').join(__dirname,'../multicloud.html'),'utf8'));
 const select=window.document.getElementById('provider');
 assert.deepEqual([...select.querySelectorAll('option')].map(o=>[o.getAttribute('value'),o.textContent]),[['','전체 클라우드'],['aws','AWS'],['azure','Microsoft Azure'],['naver','Naver Cloud']]);
 const urls=[];
 const context=vm.createContext({document:window.document,window,URLSearchParams,Date,console,setInterval:()=>0,
 fetch:async url=>{urls.push(url);return {ok:true,status:200,json:async()=>({metrics:{providers:{buckets:[]},timeline:{buckets:[]},actions:{buckets:[]}},events:[],total:0})}}});
 vm.runInContext(fs.readFileSync(require('node:path').join(__dirname,'../multicloud.js'),'utf8'),context);
 await new Promise(r=>setImmediate(r));
 assert.ok(!new URL(urls[0],'https://fixture').searchParams.has('provider'));
 for(const option of select.querySelectorAll('option'))option.removeAttribute('selected');
 select.querySelector('option[value=aws]').setAttribute('selected','');
 await vm.runInContext('load()',context);
 assert.equal(new URL(urls.at(-1),'https://fixture').searchParams.get('provider'),'aws');
});
