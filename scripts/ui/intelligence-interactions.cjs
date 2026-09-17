/* Real isolated collector integration; no API mocking. */
const fs=require('node:fs'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const base=process.env.CFC_REVIEW_URL||'http://127.0.0.1:28082';
(async()=>{
 if(new URL(base).hostname!=='127.0.0.1')throw Error('Requires isolated localhost collector');
 const password=fs.readFileSync(process.env.CFC_REVIEW_CREDENTIAL_FILE,'utf8').match(/^password: (.+)$/m)[1];
 const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true});
 const page=await browser.newPage({viewport:{width:1920,height:1080}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base);await page.locator('#username').fill('admin');await page.locator('#password').fill(password);await page.locator('#loginForm button.primary').click();await page.locator('#app').waitFor({state:'visible'});
 const cases=[['changes','changes','application'],['distribution','distribution','bytes'],['distribution','concentration','src_network'],['distribution','diversity','src_ip'],['relationships','relationships','src_network'],['bandwidth','temporal','application'],['quality','quality','exporter'],['relationships','persistence','src_ip']];
 for(const [route,kind,dimension]of cases){
  await page.goto(`${base}/?page=${route}&kind=${kind}&dimension=${dimension}&range=24h`);
  await page.locator('#intelExport:not([disabled])').waitFor();
  assert.equal(await page.locator('.error-state').count(),0);
  if(kind==='temporal')assert.ok(await page.evaluate(()=>[...chartData.values()].some(c=>c.data.some(p=>p.value>0))),'rate chart must contain observed values');
  await page.locator('.intelligence-method summary').click();
  assert.match(await page.locator('#intelligenceOut').innerText(),/Observed record counters/);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 }
 await page.goto(`${base}/?page=distribution&range=24h`);await page.locator('#intelExport:not([disabled])').waitFor();
 await page.locator('#intelKind').selectOption('concentration');await page.locator('#intelExport:not([disabled])').waitFor();assert.match(page.url(),/kind=concentration/);
 await page.locator('#intelDimension').selectOption('src_network');await page.locator('#intelExport:not([disabled])').waitFor();
 const jsonDownload=page.waitForEvent('download');await page.locator('#intelExport').click();const downloaded=await jsonDownload;const result=JSON.parse(fs.readFileSync(await downloaded.path(),'utf8'));assert.equal(result.spec.kind,'concentration');assert.equal(result.spec.dimension,'src_network');assert.ok(result.generated_at&&result.method&&result.filters);
 const csvDownload=page.waitForEvent('download');await page.locator('#intelCSV').click();const csv=await csvDownload;assert.match(fs.readFileSync(await csv.path(),'utf8'),/field,value/);
 await page.locator('#intelSave').click();const name='Advanced browser regression '+Date.now();await page.locator('#intelSaveName').fill(name);await page.locator('#intelSaveForm button').click();await page.locator('#modal').waitFor({state:'hidden'});await page.waitForFunction(n=>[...document.querySelectorAll('#intelSavedSelect option')].some(o=>o.textContent===n),name);
 const savedID=await page.locator('#intelSavedSelect option').evaluateAll((options,n)=>options.find(o=>o.textContent===n).value,name);
 await page.locator('#intelDimension').selectOption('exporter');await page.locator('#intelExport:not([disabled])').waitFor();await page.locator('#intelSavedSelect').selectOption(savedID);await page.locator('#intelExport:not([disabled])').waitFor();assert.equal(await page.locator('#intelDimension').inputValue(),'src_network');assert.match(page.url(),/range=custom/);
 const first=page.locator('[data-intelligence-row]').first();if(await first.count()){await first.click();await page.locator('#flowOut table').waitFor();assert.match(page.url(),/src_cidr=/)}
 await page.evaluate(async id=>{await api('/api/v1/searches/'+id,{method:'DELETE'})},savedID);
 assert.deepEqual(errors,[]);console.log(JSON.stringify({modes:8,exports:2,saved_restore:true,drill:true,errors}));await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
