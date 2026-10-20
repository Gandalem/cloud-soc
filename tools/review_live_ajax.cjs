/* Final browser checks for the shared poller, using no service credentials. */
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {chromium}=require('playwright');
(async()=>{
 const browser=await chromium.launch({channel:'msedge',headless:true});
 try{
  const page=await browser.newPage();await page.setContent('<main><div id="host"></div><div id="rows"><section data-live-key="a"><input id="draft" value=""><details open><summary>details</summary><p>old</p></details></section></div></main>');
  await page.addScriptTag({content:fs.readFileSync(path.join(__dirname,'../prototype/live-refresh.js'),'utf8')});
  await page.locator('#draft').fill('unsaved');await page.locator('#draft').focus();
  const stable=await page.evaluate(()=>{
   const old=document.querySelector('section'),fresh=document.createElement('section');fresh.dataset.liveKey='a';fresh.innerHTML='<input id="draft" value=""><details><summary>details</summary><p>new</p></details>';
   CloudSOCLive.children(document.querySelector('#rows'),[fresh]);
   return old===document.querySelector('section')&&document.activeElement.id==='draft'&&document.querySelector('#draft').value==='unsaved'&&document.querySelector('details').open;
  });assert.equal(stable,true);
  await page.evaluate(()=>{window.requests=[];window.applied=[];window.poll=CloudSOCLive.create({host:document.querySelector('#host'),interval:60000,load:signal=>new Promise((resolve,reject)=>requests.push({signal,resolve,reject})),apply:v=>applied.push(v)});poll.start();poll.refresh(true);});
  await page.evaluate(()=>{requests[1].resolve('new');requests[0].resolve('old');});
  await page.waitForFunction(()=>applied.length===1);assert.deepEqual(await page.evaluate(()=>applied),['new']);
  await page.locator('.live-controls button').first().click();
  await page.evaluate(()=>poll.refresh(false));assert.equal(await page.evaluate(()=>requests.length),2);
  await page.evaluate(()=>{poll.refresh(true);requests[2].reject(new Error('simulated connection failure'));});
  await page.waitForFunction(()=>document.querySelector('.live-controls span').textContent.includes('갱신 실패'));
  assert.deepEqual(await page.evaluate(()=>applied),['new']);
  await page.evaluate(()=>poll.dispose());
  console.log(JSON.stringify({passed:true,checks:['stable nodes/focus/input/details','obsolete response cancelled','pause blocks automatic reads','manual read while paused','failure retains prior data']}));
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
