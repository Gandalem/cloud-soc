/* Native DOM fixture for shared polling. Install dev-only linkedom@0.18.12. */
const {parseHTML}=require('linkedom');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
function dom(){
 const {document}=parseHTML('<html><body></body></html>');let tick=()=>{};
 function element(tag='div',value=''){
  if(typeof tag!=='string'||!(/^[a-z][a-z0-9-]*$/i.test(tag)))tag='div';
  const node=document.createElement(tag);node.value=value;node.listeners={};node.open=false;
  const add=node.addEventListener.bind(node);node.addEventListener=(name,fn,...rest)=>{node.listeners[name]=fn;add(name,fn,...rest);};
  node.showModal=function(){this.open=true;};node.close=function(){this.open=false;this.listeners.close?.();};node.reset=()=>{};
  document.body.append(node);return node;
 }
 function install(context){
  context.AbortController??=AbortController;
  context.window??={addEventListener(){}};
  context.document.createElement??=element;context.document.createElementNS??=(_ns,tag)=>element(tag);
  context.document.addEventListener??=()=>{};context.document.removeEventListener??=()=>{};
  context.document.createDocumentFragment=()=>document.createDocumentFragment();
  context.document.createTextNode=value=>document.createTextNode(value);
  const timeout=context.setTimeout||context.window.setTimeout||(()=>1);
  context.setTimeout=(fn,ms)=>{if(ms===10000){tick=fn;return -1;}return timeout(fn,ms);};
  context.clearTimeout??=context.window.clearTimeout||(()=>{});
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../live-refresh.js'),'utf8'),context);
 }
 return {element,install,tick:()=>tick()};
}
module.exports={dom};
