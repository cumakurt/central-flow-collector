/* Read-only smoke test against an isolated collector; no intercepted responses. */
const fs=require('node:fs');
const assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const base=process.env.CFC_REVIEW_URL||'http://127.0.0.1:28085';
(async()=>{
 assert.equal(new URL(base).hostname,'127.0.0.1');
 const password=fs.readFileSync(process.env.CFC_REVIEW_CREDENTIAL_FILE,'utf8').match(/^password: (.+)$/m)?.[1];
 const browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true});
 try {
  const page=await browser.newPage({viewport:{width:1366,height:768}}),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.goto(base);await page.locator('#username').fill('admin');await page.locator('#password').fill(password);await page.locator('#loginForm button.primary').click();await page.locator('#app').waitFor({state:'visible'});
  await page.goto(`${base}/?page=anomalies&range=24h`);
  await page.locator('#anomalyHistory').waitFor();
  assert.match(await page.locator('#pageTitle').innerText(),/Traffic Anomalies/);
  const response=page.waitForResponse(r=>r.url().includes('/analytics/query?')&&r.status()===200);
  await page.locator('#anomalyHistory').click();
  const payload=await (await response).json();
  assert.equal(payload.spec.kind,'anomalies');assert.equal(payload.spec.bucket_seconds,3600);
  assert.equal(new URL(page.url()).searchParams.get('range'),'30d');
  assert.equal(payload.anomalies.minimum_history,3);
  await page.locator('#intelCSV:not([disabled])').waitFor();
  const download=page.waitForEvent('download');await page.locator('#intelCSV').click();
  const file=await (await download).path();const csv=fs.readFileSync(file,'utf8');
  assert.match(csv,/anomalies.method/);assert.match(csv,/anomalies.status/);
  const filtered=page.waitForResponse(r=>r.url().includes('event_state=ACTIVE')&&r.status()===200);
  await page.locator('#intelEventState').selectOption('ACTIVE');
  assert.equal((await (await filtered).json()).spec.event_state,'ACTIVE');
  await page.locator('#anomalyRules').click();
  await page.locator('tr').filter({hasText:'Seasonal Traffic Deviation'}).getByRole('button',{name:'Use template'}).click();
  assert.equal(await page.locator('#nrKind').inputValue(),'seasonal');
  assert.equal(await page.locator('#nrWindow').inputValue(),'3600');
  assert.equal(await page.locator('#nrThreshold').inputValue(),'4');
  await page.locator('#nrValidate').click();
  await page.waitForFunction(()=>document.getElementById('nrSummary').textContent.includes('median/MAD'));
  assert.equal(errors.length,0,errors.join('\n'));
  console.log(JSON.stringify({passed:true,realAPI:true,historyAction:true,csvMetadata:true,stateFilter:true,seasonalRuleValidation:true,browserErrors:errors.length}));
 } finally {await browser.close()}
})().catch(e=>{console.error(e.message);process.exitCode=1});
