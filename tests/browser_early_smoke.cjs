async(page)=>{
 const errors=[];page.on('pageerror',e=>errors.push(e.message));await page.reload();await page.locator('.notice-card[data-state="verifying"]').waitFor();
 const result=await page.evaluate(()=>({cards:document.querySelectorAll('.notice-card').length,state:document.querySelector('.notice-card').dataset.state,viewport:innerWidth,overflow:document.documentElement.scrollWidth>innerWidth}));
 if(result.cards!==1||result.overflow||errors.length)throw new Error(JSON.stringify({result,errors}));return {...result,errors};
}
