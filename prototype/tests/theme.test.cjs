const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const script=fs.readFileSync(require('node:path').join(__dirname,'../theme.js'),'utf8');
function runtime(storage,blocked=false){
 const listeners={},root={dataset:{}},body={dataset:{}},writes=[];
 const window={addEventListener:(name,handler)=>listeners[name]=handler,dispatchEvent:event=>listeners[event.type]?.(event)};
 const document={documentElement:root,body,addEventListener:(name,handler)=>listeners[name]=handler};
 const localStorage={getItem:key=>{if(blocked)throw Error('blocked');return storage.get(key);},setItem:(key,value)=>{if(blocked)throw Error('blocked');storage.set(key,value);writes.push([key,value]);}};
 vm.runInNewContext(script,{window,document,localStorage,CustomEvent:function(type,options){this.type=type;this.detail=options.detail;}});
 return{theme:window.CloudSOCTheme,root,body,writes,listeners};
}
test('theme persists between pages and accepts only fixed display values',()=>{
 const storage=new Map(),home=runtime(storage);assert.equal(home.theme.get(),'light');home.theme.set('dark');assert.equal(home.root.dataset.theme,'dark');
 const logs=runtime(storage);assert.equal(logs.body.dataset.theme,'dark');assert.equal(logs.theme.set('https://evil.example'),false);assert.equal(logs.theme.get(),'dark');
 assert.deepEqual([...storage],[['cloud-soc.theme','dark']]);
});
test('saved dashboard theme cannot override an explicit global choice',()=>{
 const storage=new Map([['cloud-soc.theme','dark']]),personal=runtime(storage);assert.equal(personal.theme.adopt('light'),false);assert.equal(personal.theme.get(),'dark');
 const fresh=runtime(new Map());assert.equal(fresh.theme.adopt('dark'),true);assert.equal(fresh.theme.get(),'dark');
});
test('storage failure does not prevent a switch and cross-tab choice updates both roots',()=>{
 const blocked=runtime(new Map(),true);assert.equal(blocked.theme.set('dark'),true);assert.equal(blocked.body.dataset.theme,'dark');
 const other=runtime(new Map());other.listeners.storage({key:'cloud-soc.theme',newValue:'dark'});assert.equal(other.root.dataset.theme,'dark');other.listeners.storage({key:'cloud-soc.theme',newValue:null});assert.equal(other.theme.get(),'light');
});
