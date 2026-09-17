'use strict';
const serviceChartData=new Map();
let serviceChartSequence=0;
const serviceSeriesKeys=['series_service','series_port','series_protocol','series_app'];
const serviceProtocolOptions=[['tcp','TCP'],['udp','UDP'],['sctp','SCTP'],['any','Any IP protocol']];
const serviceProtocolSeries=[['6','TCP'],['17','UDP'],['1','ICMP'],['58','ICMPv6'],['47','GRE'],['50','ESP'],['89','OSPF'],['132','SCTP']];

function serviceSelections(){
  const p=new URLSearchParams(location.search),out={services:p.getAll('series_service'),ports:p.getAll('series_port'),protocols:p.getAll('series_protocol'),apps:p.getAll('series_app')};
  if(!out.services.length&&!out.ports.length&&!out.protocols.length&&!out.apps.length)out.services=['smtp','dns','https','ssh'];
  out.metric=['bps','bytes','packets','flows'].includes(p.get('series_metric'))?p.get('series_metric'):'bps';
  out.scale=['auto','linear','log'].includes(p.get('series_scale'))?p.get('series_scale'):'auto';
  return out;
}
function serviceSelectionCount(s){return s.services.length+s.ports.length+s.protocols.length+s.apps.length}
function setServiceSelections(s){
  const u=new URL(location.href);for(const k of serviceSeriesKeys)u.searchParams.delete(k);
  for(const v of s.services)u.searchParams.append('series_service',v);for(const v of s.ports)u.searchParams.append('series_port',v);for(const v of s.protocols)u.searchParams.append('series_protocol',v);for(const v of s.apps)u.searchParams.append('series_app',v);
  u.searchParams.set('series_metric',s.metric||'bps');u.searchParams.set('series_scale',s.scale||'auto');u.searchParams.set('dimension','services');setURL(timeURL(u));return render();
}
function serviceQueryParams(s){const p=qs();for(const v of s.services)p.append('series_service',v);for(const v of s.ports)p.append('series_port',v);for(const v of s.protocols)p.append('series_protocol',v);for(const v of s.apps)p.append('series_app',v);return p}
function serviceTabs(){const tabs=[['services','Service Timeline'],['application','Applications'],['protocol','Protocols'],['country','Countries'],['asn','ASNs'],['interface','Interfaces'],['direction','Direction']];return `<div class="tabs">${tabs.map(([k,n])=>k==='services'?`<button data-route="services" class="active">${n}</button>`:`<button data-traffic="${k}">${n}</button>`).join('')}<button data-route="map">Traffic Matrix ↗</button></div>`}
function protocolText(list){if(!Array.isArray(list))return 'Protocol data unavailable';return !list.length?'Any':list.map(p=>({1:'ICMP',6:'TCP',17:'UDP',47:'GRE',50:'ESP',58:'ICMPv6',89:'OSPF',132:'SCTP'})[p]||p).join('/')}
function serviceRuleText(service){return service.rules.map(r=>`${protocolText(r.protocols)} ${r.port}`).join(' · ')}
function serviceSeriesDescription(selector,catalog){
  if(selector.kind==='service'){const s=catalog.find(x=>x.id===selector.service);return s?serviceRuleText(s):selector.service}
  if(selector.kind==='port')return `${protocolText(selector.protocols)} · either source or destination port`;
  if(selector.kind==='protocol')return 'IP protocol across all ports';
  return 'Exporter-provided application name or ID';
}
function serviceControls(catalog,s){
  const chosen=new Set(s.services),available=catalog.filter(x=>!chosen.has(x.id));
  return `<section class="service-controls card"><div class="service-control-head"><div><span class="eyebrow">SERVICE TRAFFIC EXPLORER</span><h3>Compare services, ports and protocols</h3><small>Up to 8 simultaneous series · selected period ${esc(rangeLabel())}</small></div><div class="service-chart-options"><label class="compact-label">Metric<select id="serviceMetric">${[['bps','Bandwidth'],['bytes','Bytes'],['packets','Packets'],['flows','Flows']].map(([k,n])=>`<option value="${k}" ${s.metric===k?'selected':''}>${n}</option>`).join('')}</select></label><label class="compact-label">Y-axis<select id="serviceScale">${[['auto','Auto visibility'],['linear','Linear'],['log','Logarithmic']].map(([k,n])=>`<option value="${k}" ${s.scale===k?'selected':''}>${n}</option>`).join('')}</select></label></div></div><div class="service-add-grid"><label>Standard service<select id="servicePreset"><option value="">Select a service…</option>${available.map(x=>`<option value="${esc(x.id)}">${esc(x.label)} · ${esc(serviceRuleText(x))}</option>`).join('')}</select></label><button id="serviceAddPreset" class="small" ${available.length?'':'disabled'}>＋ Add service</button><label>Custom port<div class="service-inline"><select id="servicePortProtocol">${serviceProtocolOptions.map(([k,n])=>`<option value="${k}">${n}</option>`).join('')}</select><input id="servicePort" inputmode="numeric" placeholder="8443" maxlength="5"></div></label><button id="serviceAddPort" class="small">＋ Add port</button><label>IP protocol<select id="serviceProtocol"><option value="">Select protocol…</option>${serviceProtocolSeries.map(([k,n])=>`<option value="${k}">${n}</option>`).join('')}</select></label><button id="serviceAddProtocol" class="small">＋ Add protocol</button><label>Application<input id="serviceApp" placeholder="Exporter application name / ID" maxlength="128"></label><button id="serviceAddApp" class="small">＋ Add application</button></div><p class="service-note">Every selected service is drawn as its own color on the same chart. Auto visibility uses a logarithmic Y-axis only when traffic levels differ by orders of magnitude, so low-volume services remain visible without changing their actual values.</p></section>`;
}
function completeServiceTimeline(series,bucket){
  const step=Math.max(1,bucketSeconds(bucket))*1000,r=range(),start=Math.floor(+r.from/step)*step,by=new Map((series.timeline||[]).map(p=>[+new Date(p.timestamp),p])),out=[];
  for(let ts=start;ts<+r.to&&out.length<10000;ts+=step){if(ts<+r.from-step)continue;const p=by.get(ts)||{timestamp:new Date(ts).toISOString(),bytes:0,packets:0,flows:0};out.push(p)}
  return out;
}
function serviceMetricValue(p,metric,bucket){if(metric==='bps')return chartValue(p.bytes)*8/Math.max(1,bucketSeconds(bucket));return chartValue(p[metric])}
function serviceMetricFormat(metric){return metric==='bps'?bandwidth:metric==='bytes'?bytes:fmt}
function serviceScaleMode(peaks,requested='auto'){const positive=(peaks||[]).map(Number).filter(v=>Number.isFinite(v)&&v>0),hi=positive.length?Math.max(...positive):0,lo=positive.length?Math.min(...positive):0;if(requested==='log')return 'log';if(requested==='linear')return 'linear';return positive.length>1&&hi/Math.max(lo,Number.EPSILON)>=100?'log':'linear'}
function serviceSeriesChart(result,metric,catalog,scaleMode='auto'){
  const series=(result.series||[]).map((s,i)=>({...s,index:i,points:completeServiceTimeline(s,result.bucket)}));if(!series.length)return empty('Select at least one service, port, protocol or application.',false);
  const id='service-chart-'+(++serviceChartSequence),w=1000,h=330,l=82,r=22,t=30,b=280,plot=w-l-r,format=serviceMetricFormat(metric),start=+range().from,end=+range().to;
  const enriched=series.map(s=>({...s,values:s.points.map(p=>({...p,value:serviceMetricValue(p,metric,result.bucket)}))}));
  const positivePeaks=enriched.map(s=>Math.max(0,...s.values.map(p=>p.value))).filter(v=>v>0),peak=Math.max(0,...positivePeaks);
  const effectiveScale=serviceScaleMode(positivePeaks,scaleMode);
  const transform=v=>effectiveScale==='log'?Math.log10(1+Math.max(0,v)):Math.max(0,v),inverse=v=>effectiveScale==='log'?Math.pow(10,v)-1:v,maxT=Math.max(1e-12,transform(Math.max(1,peak)*1.08));
  const coord=p=>[l+plot*Math.max(0,Math.min(1,(new Date(p.timestamp)-start)/Math.max(1,end-start))),b-(b-t)*transform(p.value)/maxT];
  const paths=enriched.map(s=>`<path class="service-series-line service-series-${s.index%8}" style="stroke:var(--series-${s.index%8+1})" d="${s.values.map((p,i)=>`${i?'L':'M'}${coord(p).map(n=>n.toFixed(2)).join(',')}`).join(' ')}"/>`).join('');
  const ticks=Array.from({length:7},(_,i)=>{const stamp=start+(end-start)*i/6;return `<text class="plot-label" x="${l+plot*i/6}" y="310" text-anchor="${i===0?'start':i===6?'end':'middle'}">${esc(new Date(stamp).toLocaleDateString('en-GB',{month:'short',day:'numeric'})+' '+new Date(stamp).toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'}))}</text>`}).join('');
  serviceChartData.set(id,{series:enriched,metric,bucket:result.bucket,max:peak,maxT,transform,inverse,format,plotLeft:l,plotWidth:plot,top:t,bottom:b,catalog});
  const scaleLabel=effectiveScale==='log'?'Log Y-axis · actual values':'Linear Y-axis';
  return `<div class="service-plot" data-service-chart="${id}"><div class="plot-summary service-legend"><span>${enriched.map(s=>`<span class="service-legend-item"><i class="service-swatch service-series-${s.index%8}" style="background:var(--series-${s.index%8+1})"></i><b>${esc(s.selector.label)}</b><small>${esc(format(Math.max(0,...s.values.map(p=>p.value))))} peak</small></span>`).join('')}</span><b>${esc(scaleLabel)}</b></div><svg class="line-chart service-line-chart" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="Selected service traffic timeline">${Array.from({length:5},(_,i)=>{const tv=maxT*(1-i/4);return `<line class="plot-grid" x1="${l}" x2="${w-r}" y1="${t+(b-t)*i/4}" y2="${t+(b-t)*i/4}"/><text class="plot-label" x="${l-12}" y="${t+(b-t)*i/4+4}" text-anchor="end">${esc(format(inverse(tv)))}</text>`}).join('')}${paths}<line class="plot-crosshair hidden" x1="0" x2="0" y1="${t}" y2="${b}"/>${ticks}</svg><div class="service-plot-interaction" tabindex="0" role="application" aria-label="Inspect service timeline. Use left and right arrows; press Enter to open the nearest matching series in Flow Explorer."></div><output class="chart-tooltip service-tooltip hidden"></output></div>`;
}

function serviceSelectorFilter(selector){
  if(selector.kind==='service')return {service:selector.service};
  if(selector.kind==='port'){const f={port:String(selector.port)};if(selector.protocols?.length===1)f.ip_protocol=String(selector.protocols[0]);return f}
  if(selector.kind==='protocol')return {ip_protocol:String(selector.protocols?.[0]||'')};
  if(selector.kind==='application')return {app:selector.app};return {};
}
function serviceBucketRange(point,bucket){const start=new Date(Math.max(+range().from,+new Date(point.timestamp))),end=new Date(Math.min(+range().to,+new Date(point.timestamp)+bucketSeconds(bucket)*1000));return {from:start,to:end}}
function openServiceFlows(selector,from,to){
  const base={...urlFlowFilters()},specific=serviceSelectorFilter(selector);
  for(const key of ['service','app','ip_protocol','port'])if(base[key]&&specific[key]&&String(base[key]).toLowerCase()!==String(specific[key]).toLowerCase())return toast('This series is outside the active lens. Remove the conflicting filter to drill down.','bad');
  const filters={...base,...specific},u=PortalState.setFilters(location.href,filters);u.searchParams.set('page','flows');u.searchParams.delete('dimension');u.searchParams.delete('series_metric');for(const k of serviceSeriesKeys)u.searchParams.delete(k);u.searchParams.set('range','custom');u.searchParams.set('from',from.toISOString());u.searchParams.set('to',to.toISOString());setURL(u);render();
}
function bindServiceChart(){
  $$('.service-plot').forEach(el=>{const chart=serviceChartData.get(el.dataset.serviceChart);if(!chart)return;const target=el.querySelector('.service-plot-interaction'),tip=el.querySelector('output'),line=el.querySelector('.plot-crosshair');let index=0,lastSeries=0;
    const show=i=>{const count=chart.series[0]?.values.length||0;if(!count)return;index=Math.max(0,Math.min(count-1,i));const stamp=new Date(chart.series[0].values[index].timestamp),ratio=Math.max(0,Math.min(1,(stamp-range().from)/(range().to-range().from)));line.setAttribute('x1',chart.plotLeft+chart.plotWidth*ratio);line.setAttribute('x2',chart.plotLeft+chart.plotWidth*ratio);line.classList.remove('hidden');tip.innerHTML=`<b>${esc(dateTime(stamp))}</b>${chart.series.map(s=>`<span><i class="service-swatch service-series-${s.index%8}"></i>${esc(s.selector.label)} <strong>${esc(chart.format(s.values[index]?.value||0))}</strong></span>`).join('')}<small>Click near a line to open flows for this interval.</small>`;tip.classList.remove('hidden');tip.style.left=`${Math.min(70,Math.max(2,ratio*84))}%`;target.setAttribute('aria-label',`${dateTime(stamp)}. ${chart.series.map(s=>`${s.selector.label} ${chart.format(s.values[index]?.value||0)}`).join('; ')}`)};
    const nearestIndex=e=>{const rect=target.getBoundingClientRect(),ratio=Math.max(0,Math.min(1,(e.clientX-rect.left)/rect.width)),stamp=+range().from+ratio*(range().to-range().from),points=chart.series[0]?.values||[];let closest=0;points.forEach((p,i)=>{if(Math.abs(new Date(p.timestamp)-stamp)<Math.abs(new Date(points[closest].timestamp)-stamp))closest=i});return closest};
    target.onpointermove=e=>{show(nearestIndex(e));const rect=target.getBoundingClientRect(),desired=chart.maxT*(1-Math.max(0,Math.min(1,(e.clientY-rect.top)/rect.height)));lastSeries=chart.series.reduce((best,s,i)=>Math.abs(chart.transform(s.values[index]?.value||0)-desired)<Math.abs(chart.transform(chart.series[best].values[index]?.value||0)-desired)?i:best,0)};
    target.onclick=e=>{show(nearestIndex(e));const s=chart.series[lastSeries],p=s?.values[index];if(!s||!p||p.value<=0)return toast('No matching traffic in this interval.','bad');const window=serviceBucketRange(p,chart.bucket);openServiceFlows(s.selector,window.from,window.to)};
    target.onpointerleave=()=>{if(document.activeElement!==target){tip.classList.add('hidden');line.classList.add('hidden')}};target.onfocus=()=>show(index);target.onblur=()=>{tip.classList.add('hidden');line.classList.add('hidden')};target.onkeydown=e=>{if(['ArrowLeft','ArrowRight','Home','End'].includes(e.key)){e.preventDefault();show(e.key==='Home'?0:e.key==='End'?(chart.series[0]?.values.length||1)-1:index+(e.key==='ArrowRight'?1:-1))}if(e.key==='Enter'){const s=chart.series[lastSeries]||chart.series[0],p=s?.values[index];if(p?.value>0){const window=serviceBucketRange(p,chart.bucket);openServiceFlows(s.selector,window.from,window.to)}}};
  })
}
function serviceSeriesCards(result,catalog){
  return `<div class="service-series-grid">${(result.series||[]).map((s,i)=>`<article class="service-series-card"><div><i class="service-swatch service-series-${i%8}"></i><div><b>${esc(s.selector.label)}</b><small>${esc(serviceSeriesDescription(s.selector,catalog))}</small></div></div><dl><div><dt>Traffic</dt><dd>${bytes(s.totals.bytes)}</dd></div><div><dt>Flows</dt><dd>${fmt(s.totals.flows)}</dd></div><div><dt>Packets</dt><dd>${fmt(s.totals.packets)}</dd></div></dl><div class="actions"><button class="ghost small" data-service-open="${i}">Open flows ↗</button><button class="ghost small" data-service-remove="${i}" aria-label="Remove ${esc(s.selector.label)}">Remove</button></div></article>`).join('')}</div>`;
}
async function serviceTrafficPage(){
  title('Traffic','Compare services, ports, protocols and applications over time');const s=serviceSelections();const catalogResponse=await cachedAPI('/api/v1/analytics/service-catalog'),catalog=catalogResponse.services||[];
  $('content').innerHTML=rangeToolbar()+lensBar()+(currentPage==='services'?'':serviceTabs())+serviceControls(catalog,s)+`<div id="serviceSeriesOut"><div class="loading-state" role="status">Building service timelines…</div></div>`;
  const addGuard=()=>{if(serviceSelectionCount(serviceSelections())>=Number(catalogResponse.max_series||8)){toast('A maximum of 8 simultaneous series keeps the chart readable and queries bounded.','bad');return false}return true};
  $('serviceMetric').onchange=e=>{const n=serviceSelections();n.metric=e.target.value;setServiceSelections(n)};$('serviceScale').onchange=e=>{const n=serviceSelections();n.scale=e.target.value;setServiceSelections(n)};
  $('serviceAddPreset').onclick=()=>{const id=$('servicePreset').value;if(!id||!addGuard())return;const n=serviceSelections();if(!n.services.includes(id))n.services.push(id);setServiceSelections(n)};
  $('serviceAddPort').onclick=()=>{const port=$('servicePort').value.trim(),proto=$('servicePortProtocol').value;if(!/^\d{1,5}$/.test(port)||Number(port)<1||Number(port)>65535)return toast('Enter a valid port from 1 to 65535.','bad');if(!addGuard())return;const n=serviceSelections(),v=`${proto}:${Number(port)}`;if(!n.ports.includes(v))n.ports.push(v);setServiceSelections(n)};
  $('serviceAddProtocol').onclick=()=>{const v=$('serviceProtocol').value;if(!v||!addGuard())return;const n=serviceSelections();if(!n.protocols.includes(v))n.protocols.push(v);setServiceSelections(n)};
  $('serviceAddApp').onclick=()=>{const v=$('serviceApp').value.trim();if(!v)return toast('Enter an application name or ID.','bad');if(!addGuard())return;const n=serviceSelections();if(!n.apps.some(x=>x.toLowerCase()===v.toLowerCase()))n.apps.push(v);setServiceSelections(n)};
  const result=await api('/api/v1/analytics/service-series?'+serviceQueryParams(s));if(!$('serviceSeriesOut'))return;
  const any=(result.series||[]).some(x=>Number(x.totals?.flows)>0);$('serviceSeriesOut').innerHTML=`<section class="panel service-chart-panel"><div class="panel-head"><div><h3>Selected traffic timeline</h3><span class="muted">${esc(result.bucket)} buckets · click a line interval to drill into Flow Explorer</span></div></div><div class="widget-body">${serviceSeriesChart(result,s.metric,catalog,s.scale)}${!any?'<p class="service-note warn-text">No selected series has traffic under the current time range and active lens.</p>':''}</div></section><div class="section-ruler"><span>SELECTED SERIES</span><span>Totals for the complete selected period</span></div>${serviceSeriesCards(result,catalog)}`;
  bindServiceChart();$$('[data-service-open]').forEach(b=>b.onclick=()=>{const x=result.series[Number(b.dataset.serviceOpen)];if(x)openServiceFlows(x.selector,range().from,range().to)});$$('[data-service-remove]').forEach(b=>b.onclick=()=>{const x=result.series[Number(b.dataset.serviceRemove)];if(!x)return;const n=serviceSelections(),sel=x.selector;if(sel.kind==='service')n.services=n.services.filter(v=>v!==sel.service);else if(sel.kind==='port'){const proto=!sel.protocols?.length?'any':Number(sel.protocols[0])===6?'tcp':Number(sel.protocols[0])===17?'udp':Number(sel.protocols[0])===132?'sctp':'any',target=`${proto}:${sel.port}`;n.ports=n.ports.filter(v=>v!==target&&v!==String(sel.port));}else if(sel.kind==='protocol')n.protocols=n.protocols.filter(v=>Number(v)!==Number(sel.protocols?.[0]));else if(sel.kind==='application')n.apps=n.apps.filter(v=>v.toLowerCase()!==String(sel.app).toLowerCase());if(!serviceSelectionCount(n))return toast('Keep at least one series selected.','bad');setServiceSelections(n)});
}
