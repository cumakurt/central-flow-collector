/* Compare identical viewport crops. Dynamic telemetry changes require human review. */
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const [before,after,output] = process.argv.slice(2);

(async()=>{
  if (!before || !after || !output) throw Error('Usage: node compare-screens.cjs BEFORE AFTER OUTPUT');
  fs.mkdirSync(output,{recursive:true});
  const browser = await chromium.launch({executablePath:process.env.CHROMIUM_PATH || '/usr/bin/chromium',headless:true});
  try {
    const page = await browser.newPage(), results=[];
    for (const file of fs.readdirSync(before).filter(name=>/\d+x\d+\.png$/.test(name)).sort()) {
      if (!fs.existsSync(path.join(after,file))) continue;
      const size=file.match(/-(\d+)x(\d+)\.png$/);
      const result=await page.evaluate(async({oldImage,newImage,width,height})=>{
        const decode=source=>new Promise((resolve,reject)=>{const img=new Image();img.onload=()=>resolve(img);img.onerror=reject;img.src=source});
        const [old,next]=await Promise.all([decode(oldImage),decode(newImage)]);
        const pixels=img=>{const canvas=document.createElement('canvas');canvas.width=width;canvas.height=height;const ctx=canvas.getContext('2d');ctx.drawImage(img,0,0);return ctx.getImageData(0,0,width,height)};
        const a=pixels(old),b=pixels(next),diff=new ImageData(width,height);let changed=0;
        for(let i=0;i<a.data.length;i+=4){
          const different=Math.max(Math.abs(a.data[i]-b.data[i]),Math.abs(a.data[i+1]-b.data[i+1]),Math.abs(a.data[i+2]-b.data[i+2]))>24;
          if(different)changed++;
          diff.data[i]=different?230:Math.round(b.data[i]*.25);diff.data[i+1]=different?100:Math.round(b.data[i+1]*.25);diff.data[i+2]=different?170:Math.round(b.data[i+2]*.25);diff.data[i+3]=255;
        }
        const canvas=document.createElement('canvas');canvas.width=width;canvas.height=height;canvas.getContext('2d').putImageData(diff,0,0);
        return {changedPixels:changed,changedPercent:100*changed/(width*height),beforeHeight:old.height,afterHeight:next.height,diff:canvas.toDataURL('image/png')};
      },{oldImage:'data:image/png;base64,'+fs.readFileSync(path.join(before,file)).toString('base64'),newImage:'data:image/png;base64,'+fs.readFileSync(path.join(after,file)).toString('base64'),width:Number(size[1]),height:Number(size[2])});
      fs.writeFileSync(path.join(output,file),Buffer.from(result.diff.split(',')[1],'base64'));
      delete result.diff;results.push({file,...result});
    }
    fs.writeFileSync(path.join(output,'comparison.json'),JSON.stringify({before,after,tolerance:24,scope:'Viewport crop; pixel differences include live timestamps and changed time windows. Review alongside geometry and browser errors.',results},null,2));
    console.log(JSON.stringify({compared:results.length,heightChanges:results.filter(row=>row.beforeHeight!==row.afterHeight).length,largestDifferences:[...results].sort((a,b)=>b.changedPercent-a.changedPercent).slice(0,5),output}));
  } finally {await browser.close()}
})().catch(error=>{console.error(error.message);process.exitCode=1});
