/* Test-only input: NetFlow v5 UDP datagrams decoded by isolated collectors. */
const fs=require('node:fs');
const dgram=require('node:dgram');
const configurations=JSON.parse(process.env.CFC_LAB_TARGETS||'[]');
(async()=>{
  if(!configurations.length)throw Error('CFC_LAB_TARGETS must identify isolated localhost collectors');
  for(const target of configurations){
    const url=new URL(target.url);
    if(url.hostname!=='127.0.0.1'||!target.credentialFile.startsWith('/tmp/'))throw Error('Lab input is restricted to localhost and temporary credentials');
    const password=fs.readFileSync(target.credentialFile,'utf8').match(/^password: (.+)$/m)[1];
    const login=await fetch(target.url+'/api/v1/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'admin',password})});
    if(!login.ok)throw Error('Lab authentication failed');
    const body=await login.json(),cookie=login.headers.get('set-cookie').split(';')[0];
    const headers={'Content-Type':'application/json',Cookie:cookie,'X-CSRF-Token':body.csrf};
    const response=await fetch(target.url+'/api/v1/policies',{headers});
    const policies=(await response.json())||[];
    if(!policies.some(p=>p.source==='127.0.0.1'&&p.action==='allow')){
      const added=await fetch(target.url+'/api/v1/policies',{method:'POST',headers,body:JSON.stringify({source:'127.0.0.1',action:'allow',priority:100,enabled:true,comment:'Isolated UI regression traffic'})});
      if(!added.ok)throw Error('Could not admit localhost lab exporter');
    }
  }
  const socket=dgram.createSocket('udp4'),count=Number(process.env.CFC_LAB_PACKETS||240);
  for(let n=0;n<count;n++){
    const records=20,packet=Buffer.alloc(24+records*48);packet.writeUInt16BE(5,0);packet.writeUInt16BE(records,2);packet.writeUInt32BE(600000,4);packet.writeUInt32BE(Math.floor(Date.now()/1000),8);packet.writeUInt32BE(n*records,16);
    for(let i=0;i<records;i++){
      const offset=24+i*48,source=(n+i)%8,dest=(n*3+i)%6;
      Buffer.from([10,10,source,1+i]).copy(packet,offset);Buffer.from([172,16,dest,10+i]).copy(packet,offset+4);
      packet.writeUInt16BE(source+1,offset+12);packet.writeUInt16BE(dest+10,offset+14);
      packet.writeUInt32BE(10+(n+i)%900,offset+16);packet.writeUInt32BE(10000+((n+1)*(i+3)*7919)%8000000,offset+20);
      packet.writeUInt32BE(590000,offset+24);packet.writeUInt32BE(599000,offset+28);
      packet.writeUInt16BE(1024+(n*records+i)%50000,offset+32);packet.writeUInt16BE([443,53,80,22,123][i%5],offset+34);
      packet[offset+37]=0x12;packet[offset+38]=i%3===0?17:6;packet.writeUInt16BE(64512+source,offset+40);packet.writeUInt16BE(64540+dest,offset+42);packet[offset+44]=24;packet[offset+45]=24;
    }
    await Promise.all(configurations.map(target=>new Promise((resolve,reject)=>socket.send(packet,target.port,'127.0.0.1',e=>e?reject(e):resolve()))));
    await new Promise(resolve=>setTimeout(resolve,Number(process.env.CFC_LAB_INTERVAL||100)));
  }
  socket.close();console.log(`Sent ${count*20} NetFlow v5 test records to each of ${configurations.length} isolated collectors.`);
})().catch(e=>{console.error(e.message);process.exit(1)});
