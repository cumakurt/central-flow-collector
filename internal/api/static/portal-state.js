/* Shared URL/query vocabulary; no DOM or network dependencies. */
'use strict';
const PortalState = (() => {
  const ranges = {'5m':300,'15m':900,'30m':1800,'1h':3600,'6h':21600,'12h':43200,'24h':86400,'7d':604800,'30d':2592000};
  const fields = [
    ['src_country','Source country','text','='],['dst_country','Destination country','text','='],
    ['src_site','Source network group','text','='],['dst_site','Destination network group','text','='],
    ['src_ip','Source IP','text','='],['dst_ip','Destination IP','text','='],
    ['src_cidr','Source subnet','text','in'],['dst_cidr','Destination subnet','text','in'],['cidr','Either subnet','text','in'],
    ['host','Either IP','text','='],['service','Standard service','text','='],['port','Either port','number','='],['src_port','Source port','number','='],['dst_port','Destination port','number','='],
    ['ip_protocol','Protocol','text','='],['app','Application','text','='],['exporter','Exporter','text','='],
    ['ingress_if','Ingress interface','number','='],['egress_if','Egress interface','number','='],
    ['asn','Either ASN','number','='],['src_as','Source ASN','number','='],['dst_as','Destination ASN','number','='],
    ['country','Country','text','='],['site','Site','text','='],['tcp_flags','TCP flags (hex)','text','contains'],
    ['min_bytes','Bytes','number','≥'],['max_bytes','Bytes','number','≤'],
    ['min_packets','Packets','number','≥'],['max_packets','Packets','number','≤'],
    ['min_duration_ms','Duration (ms)','number','≥'],['max_duration_ms','Duration (ms)','number','≤']
  ];
  const dimensions = {src_ip:'Source IP',dst_ip:'Destination IP',application:'Application',protocol:'Protocol',country:'Country',asn:'ASN',exporter:'Exporter',interface:'Interface',direction:'Direction',src_port:'Source port',dst_port:'Destination port'};
  function filters(params) {
    const p = params instanceof URLSearchParams ? params : new URLSearchParams(params);
    return Object.fromEntries(fields.filter(([k])=>p.get(k)?.trim()).map(([k])=>[k,p.get(k).trim()]));
  }
  function time(params, now = new Date()) {
    const p = params instanceof URLSearchParams ? params : new URLSearchParams(params);
    const key = p.get('range') || '24h';
    if (key === 'custom') {
      const from=new Date(p.get('from')),to=new Date(p.get('to'));
      if(Number.isFinite(+from)&&Number.isFinite(+to)&&to>from)return {key,from,to};
    }
    const valid = key === 'live' || ranges[key] ? key : '24h';
    return {key:valid,from:new Date(+now-1000*(valid==='live'?300:ranges[valid])),to:new Date(now)};
  }
  function setFilters(url, values) {
    const u=new URL(url);
    for(const [k] of fields)u.searchParams.delete(k);
    for(const [k] of fields)if(String(values[k]??'').trim())u.searchParams.set(k,String(values[k]).trim());
    return u;
  }
  function lens(dim,value) {
    if(!value || dim==='direction')return null;
    if(dim==='interface'){
      const match=String(value).match(/^(Ingress|Egress) (\d+)$/i);
      if(match)return {[match[1].toLowerCase()==='egress'?'egress_if':'ingress_if']:match[2]};
      if(!/^\d+$/.test(value))return null;
    }
    if(dim==='asn'){
      const match=String(value).match(/^(?:AS)?(\d+)(?:\s|$)/i);
      if(!match)return null;
      value=match[1];
    }
    if(dim==='country'&&!/^[a-z]{2}$/i.test(value))return null;
    const keys={application:'app',protocol:'ip_protocol',interface:'ingress_if'};
    const key=keys[dim]||dim;
    return fields.some(([k])=>k===key)?{[key]:String(value)}:null;
  }
  function comparison(change) {
    if(!change)return 'Comparison unavailable';
    if(!Number(change.previous))return Number(change.current)?'New activity · no prior baseline':'No change · no prior traffic';
    const n=Number(change.change_percent)||0;
    return `${n>0?'+':''}${n.toFixed(1)}% vs previous period`;
  }
  function bandwidth(n) {
    let value=Number(n)||0;
    for(const unit of ['bit/s','kbit/s','Mbit/s','Gbit/s','Tbit/s']) {
      if(Math.abs(value)<1000 || unit==='Tbit/s')return `${Intl.NumberFormat('en',{maximumFractionDigits:1}).format(value)} ${unit}`;
      value/=1000;
    }
  }
  return {ranges,fields,dimensions,filters,time,setFilters,lens,comparison,bandwidth};
})();
if(typeof module!=='undefined')module.exports=PortalState;
