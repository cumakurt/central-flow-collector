/* Desktop visual audit against a real, isolated collector. No response interception. */
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const base = process.env.CFC_REVIEW_URL || 'http://127.0.0.1:18080';
const output = process.env.CFC_REVIEW_OUTPUT || '/tmp/cfc-ui-review/screens/before';
const credentialFile = process.env.CFC_REVIEW_CREDENTIAL_FILE;
const sizes = [[2560,1440],[1920,1080],[1440,900],[1366,768]];
const routes = process.env.CFC_REVIEW_ROUTES ? process.env.CFC_REVIEW_ROUTES.split(',') : ['overview','executive','analytics','flows','traffic','map','exporters','reports','system','admin','policy','live'];
(async () => {
  if (!credentialFile) throw Error('CFC_REVIEW_CREDENTIAL_FILE is required');
  const credential = fs.readFileSync(credentialFile,'utf8').match(/^password: (.+)$/m)?.[1];
  if (!credential) throw Error('Bootstrap credential file is invalid');
  fs.mkdirSync(output,{recursive:true});
  const browser = await chromium.launch({executablePath:process.env.CHROMIUM_PATH || '/usr/bin/chromium',headless:true});
  const context = await browser.newContext({viewport:{width:1920,height:1080},reducedMotion:'reduce'});
  const page = await context.newPage();
  const errors=[], requests=[], geometry=[];let authenticated=false;
  page.on('pageerror',e=>errors.push({route:page.url(),message:e.message}));
  page.on('console',e=>{if(authenticated&&e.type()==='error')errors.push({route:page.url(),message:e.text()})});
  page.on('response',r=>{if(r.url().includes('/api/'))requests.push({url:r.url(),status:r.status()})});
  await page.goto(base);
  await page.locator('#username').fill('admin');
  await page.locator('#password').fill(credential);
  await page.locator('#loginForm button.primary').click();
  await page.locator('#app').waitFor({state:'visible'});
  await page.waitForTimeout(500);authenticated=true;
  for (const theme of ['dark','light']) {
    await page.evaluate(t=>{localStorage.setItem('cfc-theme',t);document.documentElement.dataset.theme=t},theme);
    for (const [width,height] of sizes) {
      await page.setViewportSize({width,height});
      for (const route of routes) {
        await page.goto(`${base}/?page=${route}&range=24h`);
        if(process.env.CFC_BASELINE_BOOT === '1') await page.evaluate(async()=>{await boot();if(me)showApp()});
        await page.locator('#app').waitFor({state:'visible'});
        await page.waitForFunction(()=>!document.querySelector('#content .loading-state'),{},{timeout:10000}).catch(e=>{if(process.env.CFC_BASELINE_BOOT!=='1')throw e});
        await page.waitForTimeout(route==='live'?600:120);
        const file=`${route}-${theme}-${width}x${height}.png`;
        await page.screenshot({path:path.join(output,file),fullPage:true});
        geometry.push({file,...await page.evaluate(()=>({bodyWidth:document.body.scrollWidth,viewport:innerWidth,contentHeight:document.getElementById('content').scrollHeight,empty:!!document.querySelector('#content .empty'),error:!!document.querySelector('#content .error-state')}))});
      }
      if (process.env.CFC_REVIEW_ROUTES) continue;
      await page.goto(`${base}/?page=flows&range=24h`);
      if(process.env.CFC_BASELINE_BOOT === '1') await page.evaluate(async()=>{await boot();if(me)showApp()});
      await page.waitForFunction(()=>!document.querySelector('#content .loading-state'),{},{timeout:10000}).catch(e=>{if(process.env.CFC_BASELINE_BOOT!=='1')throw e});
      await page.evaluate(()=>ipDetail('10.10.0.1'));
      await page.waitForTimeout(300);
      await page.screenshot({path:path.join(output,`ip-detail-${theme}-${width}x${height}.png`),fullPage:true});
    }
  }
  fs.writeFileSync(path.join(output,'audit.json'),JSON.stringify({base,errors,requests,geometry},null,2));
  console.log(JSON.stringify({screens:routes.length*sizes.length*2+(process.env.CFC_REVIEW_ROUTES?0:8),errors:errors.length,overflow:geometry.filter(x=>x.bodyWidth>x.viewport),output}));
  await browser.close();
})().catch(e=>{console.error(e.message);process.exit(1)});
