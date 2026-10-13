async(page)=>{
 const base='http://127.0.0.1:8773',runs=[];
 await page.goto(base+'/');
 for(let i=0;i<3;i++){
  await page.request.get(base+'/__fixture/notices?action=nine');
  await page.locator('#dashboard-refresh').click();await page.locator('#early-alert-panel').filter({hasText:'0건'}).waitFor();
  const measured=await (await page.request.get(base+'/__fixture/notices?action=ten')).json();
  await page.locator('.notice-card[data-state="verifying"]').waitFor({timeout:20000});
  runs.push({searchable_at:measured.tenth_searchable_at,initial_at:measured.initial_at,
   searchable_to_initial_seconds:(Date.parse(measured.initial_at)-Date.parse(measured.tenth_searchable_at))/1000,
   searchable_to_visible_seconds:(Date.now()-Date.parse(measured.tenth_searchable_at))/1000});
 }
 const report={synthetic:true,real_elasticsearch:false,runs};await page.evaluate(value=>{window.__earlyLatencyQA=value;},report);return report;
}
