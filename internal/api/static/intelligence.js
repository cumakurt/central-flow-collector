'use strict';

const intelligenceDimensions = [['src_site','Source network group'],['dst_site','Destination network group'],['application','Application'],['src_ip','Source IP'],['dst_ip','Destination IP'],['src_network','Source network (/24, /64)'],['dst_network','Destination network (/24, /64)'],['protocol','Protocol'],['src_as','Source ASN'],['dst_as','Destination ASN'],['src_country','Source country'],['dst_country','Destination country'],['exporter','Exporter'],['ingress_if','Ingress interface'],['egress_if','Egress interface'],['dst_port','Destination port']];
const distributionDimensions = [['bytes','Bytes per flow'],['packets','Packets per flow'],['duration_ms','Duration (ms)'],['bytes_per_packet','Bytes per packet']];
function intelligenceLens(dimension,key) {
  if (!key || key === 'unknown') return null;
  if (dimension === 'src_network') return {src_cidr:key};
  if (dimension === 'dst_network') return {dst_cidr:key};
  if (dimension === 'ingress_if' || dimension === 'egress_if') {const [exporter,number]=key.split(' / ');return Number(number)>0?{exporter,[dimension]:number}:null;}
  if (['src_as','dst_as','dst_port'].includes(dimension) && key==='0') return null;
  return PortalState.lens(dimension,key);
}
function intelligenceRowLabel(row,index,dimension) {
  return intelligenceLens(dimension,row.key)?`<button class="linklike mono" data-intelligence-row="${index}">${esc(row.key)}</button>`:esc(row.key||'Unspecified');
}
function intelligenceCurve(points,label,percent=false) {
  if (!points.length) return empty('No observations for this curve.',false);
  const maxX=Math.max(1,...points.map(p=>p.x)),minX=Math.min(0,...points.map(p=>p.x)),maxY=Math.max(1,...points.map(p=>p.y));
  const coords=points.map(p=>`${50+500*(p.x-minX)/(maxX-minX)},${240-210*p.y/maxY}`).join(' ');
  return `<svg class="intelligence-chart" viewBox="0 0 600 280" role="img" aria-label="${esc(label)}"><title>${esc(label)}</title><path class="intel-axis" d="M50 20V240H550"/>${percent?'<path class="intel-reference" d="M50 240L550 30"/>':''}<polyline class="intel-line" points="${coords}"/><text x="50" y="267">${percent?'0% of entities':'Lower values'}</text><text x="390" y="267">${percent?'100% of entities':'Higher values'}</text><text x="55" y="25">${esc(label)}</text></svg>`;
}
function intelligenceHistogram(histogram) {
  if (!histogram.length) return empty('No valid distribution samples.',false);
  const max=Math.max(1,...histogram.map(b=>b.count));
  return `<div class="distribution-columns intel-histogram" style="grid-template-columns:repeat(${histogram.length},minmax(0,1fr))">${histogram.map(b=>`<div class="distribution-column"><b>${fmt(b.count)}</b><i style="--height:${100*b.count/max}%" title="${esc(fmt(b.from))}–${esc(fmt(b.to))}: ${fmt(b.count)} records; cumulative ${fmt(b.cdf*100)}%"></i></div>`).join('')}</div><div class="distribution-axis"><span>${fmt(histogram[0].from)}</span><span>Flow records per value bucket</span><span>${fmt(histogram.at(-1).to)}</span></div>`;
}
function intelligenceScatter(rows) {
  const maxPeers=Math.max(1,...rows.map(r=>r.peers)),maxBytes=Math.max(1,...rows.map(r=>r.bytes)),maxFlows=Math.max(1,...rows.map(r=>r.flows));
  return `<svg class="intelligence-chart" viewBox="0 0 600 280" role="img" aria-label="Peer count versus observed traffic; circle area represents flow count"><path class="intel-axis" d="M50 20V240H550"/>${rows.map(r=>`<circle class="intel-dot" cx="${50+500*r.peers/maxPeers}" cy="${240-210*r.bytes/maxBytes}" r="${3+12*Math.sqrt(r.flows/maxFlows)}"><title>${esc(r.key)}: ${r.peers} peers, ${bytes(r.bytes)}, ${fmt(r.flows)} flows</title></circle>`).join('')}<text x="50" y="265">0 peers</text><text x="440" y="265">${fmt(maxPeers)} peers</text><text x="55" y="20">${bytes(maxBytes)} traffic</text></svg>`;
}
function intelligenceMatrix(rows,metric){
 const sources=[...new Set(rows.map(r=>r.key))].slice(0,10),destinations=[...new Set(rows.map(r=>r.peer))].slice(0,10),maximum=Math.max(1,...rows.map(r=>r.current));
 return `<div class="table-wrap intel-matrix"><table><thead><tr><th>Source / Destination</th>${destinations.map(d=>`<th scope="col">${esc(d||'Unspecified')}</th>`).join('')}</tr></thead><tbody>${sources.map(source=>`<tr><th scope="row">${esc(source||'Unspecified')}</th>${destinations.map(destination=>{const index=rows.findIndex(r=>r.key===source&&r.peer===destination);if(index<0)return '<td title="No pair in the displayed ranking">—</td>';const row=rows[index];return `<td style="background:color-mix(in srgb,var(--accent) ${Math.round(35*row.current/maximum)}%,var(--panel))"><button class="linklike" data-intelligence-row="${index}" title="${esc(source)} → ${esc(destination)}">${metric==='bytes'?bytes(row.current):fmt(row.current)}</button></td>`}).join('')}</tr>`).join('')}</tbody></table></div>`;
}
async function intelligencePage(defaultKind) {
  const choices=defaultKind==='distribution'?[['distribution','Flow distribution'],['concentration','Traffic concentration'],['diversity','Peer diversity']]:defaultKind==='relationships'?[['relationships','Communication pairs'],['persistence','Top-talker persistence']]:[[defaultKind,defaultKind]];
  const kind=insightParam('kind',choices.map(([k])=>k),defaultKind),numeric=kind==='distribution';
  const dimensions=numeric?distributionDimensions:intelligenceDimensions;
  const dimension=insightParam('dimension',dimensions.map(([k])=>k),numeric?'bytes':kind==='relationships'?'src_network':kind==='diversity'?'src_ip':kind==='quality'?'exporter':'application');
  const peer=insightParam('peer',intelligenceDimensions.map(([k])=>k),kind==='relationships'?'dst_network':'dst_ip');
  const metric=insightParam('metric',['bytes','packets','flows'],'bytes');
  const bucket=insightParam('bucket',['60','300','900','3600','86400'],'3600');
  const strategy=insightParam('strategy',['linear','logarithmic'],'logarithmic');
  const top=insightParam('top',['10','25','50','100'],'25');
  const threshold=insightParam('threshold',['90','95','99','99.9'],'99');
  const titles={anomalies:'Traffic Anomalies',changes:'Change Explorer',distribution:'Distribution Lab',concentration:'Traffic concentration',diversity:'Peer diversity',relationships:'Traffic relationships',temporal:'Capacity Lens',quality:'Telemetry Quality',persistence:'Top-talker persistence'};
  title(titles[kind],'Observed flow intelligence · transparent methods · bounded server aggregation');
  $('content').innerHTML=rangeToolbar()+lensBar(urlFlowFilters(),true)+`<div class="insight-controls intel-controls">${choices.length>1?insightSelect('intelKind','Analysis',choices,kind):''}${!['temporal','quality'].includes(kind)?insightSelect('intelDimension','Dimension',dimensions,dimension):''}${['diversity','relationships'].includes(kind)?insightSelect('intelPeer','Peer dimension',intelligenceDimensions,peer):''}${!numeric?insightSelect('intelMetric','Measure',[['bytes','Traffic'],['packets','Packets'],['flows','Flows']],metric):''}${numeric?insightSelect('intelStrategy','Histogram',[['logarithmic','Logarithmic'],['linear','Linear']],strategy)+insightSelect('intelThreshold','Largest flows above percentile',[['90','P90'],['95','P95'],['99','P99'],['99.9','P99.9']],threshold):''}${['temporal','quality','relationships','diversity','persistence','anomalies'].includes(kind)?insightSelect('intelBucket','UTC interval',[['60','1 minute'],['300','5 minutes'],['900','15 minutes'],['3600','1 hour'],['86400','1 day']],bucket):''}${insightSelect('intelTop','Shown rows',[['10','10'],['25','25'],['50','50'],['100','100']],top)}<button id="intelBookmark" class="ghost small">Copy analysis link</button><button id="intelExport" class="ghost small" disabled>Export JSON</button><button id="intelCSV" class="ghost small" disabled>Export CSV</button></div><div id="intelligenceOut"><div class="loading-state" role="status">Calculating complete aggregates…</div></div>`;
  const params={kind,dimension,peer,metric,bucket,strategy,top,threshold};
  if(kind==='anomalies'){params.event_state=insightParam('event_state',['','PENDING','ACTIVE','RECOVERED'],'');$('intelTop').closest('label').insertAdjacentHTML('afterend',insightSelect('intelEventState','Episode state',[['','All states'],['PENDING','Pending'],['ACTIVE','Active'],['RECOVERED','Recovered']],params.event_state));}
  if(kind==='anomalies')$('intelligenceOut').insertAdjacentHTML('beforebegin','<p class="insight-note">The selected range supplies baseline history. Last 24 hours are evaluated against the same UTC weekday and interval in earlier weeks. Select Last 30d for at least three comparable weeks. Missing or sampled intervals are withheld.</p>');
  if(kind==='temporal'&&metric==='bytes'){
    const capacity=new URLSearchParams(location.search).get('capacity_bps')||'0';
    params.capacity_bps=capacity;
    $('intelTop').closest('label').insertAdjacentHTML('afterend',`<label>Assumed capacity (bit/s)<input id="intelCapacity" type="number" min="0" max="1000000000000000" step="1000000" value="${esc(capacity)}"></label>`);
    $('intelCapacity').onchange=()=>{insightParams({...params,capacity_bps:$('intelCapacity').value});render()};
  }
  $('intelBookmark').insertAdjacentHTML('beforebegin','<span id="intelSaved"></span><button id="intelSave" class="ghost small">Save analysis</button>');
  $('intelSave').onclick=()=>saveIntelligenceView(params);

  const controls={intelEventState:'event_state',intelKind:'kind',intelDimension:'dimension',intelPeer:'peer',intelMetric:'metric',intelBucket:'bucket',intelStrategy:'strategy',intelTop:'top',intelThreshold:'threshold'};
  for(const [id,key] of Object.entries(controls)) if($(id)) $(id).onchange=()=>{insightParams({...params,[key]:$(id).value});render()};
  $('intelBookmark').onclick=async()=>{const u=new URL(location.href);for(const [k,v]of Object.entries(params))u.searchParams.set(k,v);const period=range();u.searchParams.set('range','custom');u.searchParams.set('from',period.from.toISOString());u.searchParams.set('to',period.to.toISOString());try{await navigator.clipboard.writeText(u.toString());toast('Analysis link copied with exact time window')}catch{toast('Clipboard unavailable; copy the address bar URL.','bad');setURL(u)}};
  const version=renderVersion,result=await api('/api/v1/analytics/query?'+qs(params));
  if(version!==renderVersion)return;
  intelligenceDraw(result);
  loadIntelligenceViews();
  for(const [id,format]of [['intelExport','json'],['intelCSV','csv']]){$(id).disabled=false;$(id).onclick=async()=>{try{const response=await fetch('/api/v1/analytics/query?'+qs({...params,format}),{signal:routeController.signal});if(!response.ok){const x=await response.json();throw Error(x.error||'Export failed')}const blob=await response.blob(),u=URL.createObjectURL(blob),a=document.createElement('a');a.href=u;a.download=`cfc-${kind}.${format}`;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000)}catch(e){if(e.name!=='AbortError')toast(e.message,'bad')}}}
}
function intelligenceDraw(result) {
  if(result.spec.kind==='anomalies'){anomalyDraw(result);return;}
  const {spec,summary:s,rows}=result,format=v=>spec.metric==='bytes'?bytes(v):fmt(v);
  let content='';
  if(!s.observed_flows&&!s.previous){$('intelligenceOut').innerHTML=empty('No flow records in the selected period.');return}
  if(spec.kind==='distribution'&&!s.valid_records){$('intelligenceOut').innerHTML=empty('No valid samples for this distribution. Check timestamp or packet metadata.',false);return}
  if(['changes','concentration'].includes(spec.kind)) {
    content=insightFacts(spec.kind==='changes'?[['Current',format(s.current),'Selected period'],['Previous',format(s.previous),'Equal preceding period'],['Net change',format(s.delta),'Includes positive and negative contributors'],['Mix distance',s.jensen_shannon_bits===undefined?'—':s.jensen_shannon_bits.toFixed(4),'Jensen–Shannon · 0 same, 1 disjoint']]:[['Entities',fmt(s.entities),'Positive traffic weight'],['Normalized entropy',fmt(s.normalized_entropy),'0 concentrated · 1 uniform'],['HHI',s.hhi.toFixed(4),'Sum of squared traffic shares'],['Top 1% share',fmt(s.top_1_percent_share)+'%','Ceiling of 1% entity count']]);
    if(spec.kind==='concentration')content+=panel('Traffic concentration curve',intelligenceCurve(result.curve,'Cumulative traffic share',true),'Ascending entity traffic · diagonal represents equal shares');
    const maxDelta=Math.max(1,...rows.map(r=>Math.abs(r.delta)));
    content+=table(['Entity','Previous','Current','Delta','Contribution','Share change','Rank now / prior','Magnitude'],rows.map((r,i)=>[intelligenceRowLabel(r,i,spec.dimension),format(r.previous),format(r.current),format(r.delta),r.contribution_percent===null?'—':fmt(r.contribution_percent)+'%',fmt(r.share_delta_pp)+' pp',`${r.rank||'—'} / ${r.previous_rank||'—'}`,`<span class="comparison-label">${r.delta>0?'+':r.delta<0?'−':'='} ${'▰'.repeat(Math.ceil(12*Math.abs(r.delta)/maxDelta))}</span>`]),true);
    if(spec.kind==='changes')content+=`<p class="insight-note">Other contributors: ${format(s.other_delta)}. Shown deltas + Other = ${format(s.delta)}. Contributions from different dimensions overlap; compare one dimension at a time. “New” means absent in the previous window, not first ever.</p>`;
  } else if(spec.kind==='distribution') {
    content=insightFacts([['P50',fmt(s.p50),spec.dimension],['P95',fmt(s.p95),spec.dimension],['P99',fmt(s.p99),spec.dimension],['Largest-flow traffic share',fmt(s.elephant_byte_share)+'%',`${fmt(s.elephant_flow_share)}% of valid flows; strictly above P${spec.threshold_percentile}`]])+`<div class="bandwidth-layout">${panel('Value distribution',intelligenceHistogram(result.histogram),`${spec.strategy} buckets · ${fmt(s.valid_records)} valid records`)}${panel('Cumulative distribution',intelligenceCurve(result.histogram.map(b=>({x:b.to,y:b.cdf})),'Cumulative flow fraction'),'Exact cumulative counts at histogram boundaries')}</div>`+table(['From','To','Flows','Cumulative share'],result.histogram.map(b=>[fmt(b.from),fmt(b.to),fmt(b.count),fmt(b.cdf*100)+'%']));
  } else if(spec.kind==='temporal') {
    const rate=v=>v===undefined?'—':spec.metric==='bytes'?bandwidth(v):fmt(v)+'/s';
    content=insightFacts([['Average',rate(s.average_rate),'Complete intervals only'],['P95',rate(s.p95),'Nearest rank'],['Peak / average',fmt(s.peak_to_average)+'×','Interval-average peaks'],['Variation',fmt(s.coefficient_of_variation),'Population standard deviation / mean']])+panel('Observed rate',lineChart(result.curve.map(p=>({timestamp:new Date(p.x).toISOString(),bytes:p.y/8,flows:p.y})), spec.metric==='bytes'?'bps':'flows'),'No records = zero observed traffic; not proof of available telemetry')+table(['Percentile','Rate'],['50','75','90','95','99','99.9'].map(p=>['P'+p,rate(s['p'+p])]))+table(['Busiest interval UTC','Rate','Explore'],[...result.curve].sort((a,b)=>b.y-a.y).slice(0,10).map(p=>[new Date(p.x).toISOString(),rate(p.y),`<button class="linklike" data-intelligence-peak="${p.x}">Inspect interval →</button>`]),true);
  } else if(spec.kind==='persistence'){
    content=table(['Entity','Top-10 presence','Top-50 presence','Average active rank','Rank deviation','Active intervals','Traffic','Flows'],rows.map((r,i)=>[intelligenceRowLabel(r,i,spec.dimension),fmt(r.top10_presence_percent||0)+'%',fmt(r.top50_presence_percent||0)+'%',fmt(r.average_rank),fmt(r.rank_standard_deviation||0),fmt(r.active_buckets),bytes(r.bytes),fmt(r.flows)]),true);
  } else {
    content=insightFacts([['Observed flows',fmt(s.observed_flows),'Record count'],['Sampled records',fmt(s.sampled_records),'Reported sampling rate > 1'],['Unknown sampling',fmt(s.sampling_unknown_records),'No valid rate supplied'],['Population',fmt(s.entities??s.observed_exporters),'Before display limit']]);
    if(spec.kind==='diversity')content+=panel('Connectivity and traffic',intelligenceScatter(rows),'X = unique peers · Y = bytes · bubble = flow count')+table(['Peer percentile','Unique peers'],['50','75','90','95','99'].map(p=>['P'+p,fmt(s['p'+p])]));
    if(spec.kind==='relationships')content+=panel('Observed communication matrix',intelligenceMatrix(rows,spec.metric),'Up to 10 × 10 axes from the displayed ranking · unlisted pairs are not inferred to be zero');
    content+=table(['Entity','Peer','Traffic','Flows','Unique peers','Active intervals','Activity coverage','First seen','Last seen'],rows.map((r,i)=>[intelligenceRowLabel(r,i,spec.dimension),esc(r.peer||'—'),bytes(r.bytes),fmt(r.flows),r.peers===undefined?'—':fmt(r.peers),r.active_buckets===undefined?'—':fmt(r.active_buckets),r.recurrence_percent===undefined?'—':fmt(r.recurrence_percent)+'%',r.first?dateTime(r.first):'—',r.last?dateTime(r.last):'—']),true);
  }
  if(spec.kind==='temporal'&&spec.metric==='bytes'){
    content+=panel('Capacity assumption and trend',table(['Measure','Value'],[
      ['Configured capacity',spec.capacity_bps?bandwidth(spec.capacity_bps):'Not configured'],
      ['P95 utilization',s.p95_utilization_percent===undefined?'—':fmt(s.p95_utilization_percent)+'%'],
      ['Headroom',s.headroom_percent===undefined?'—':fmt(s.headroom_percent)+'%'],
      ['30-day projected daily P95',s.projected_p95_30d_bps===undefined?'Insufficient history':bandwidth(s.projected_p95_30d_bps)],
      ['Fit R²',s.forecast_r_squared===undefined?'—':fmt(s.forecast_r_squared)],
      ['Estimated days to capacity',s.estimated_days_to_capacity===undefined?'Unavailable':fmt(s.estimated_days_to_capacity)]
    ]),'Forecast requires seven complete UTC days · capacity is specific to this saved view');
  }
  $('intelligenceOut').innerHTML=content+`<details class="intelligence-method"><summary>Method, sampling and query details</summary><p>${esc(result.method)}</p>${result.notes.map(n=>`<p>${esc(n)}</p>`).join('')}<p>Source: ${esc(result.source)} · ${fmt(result.groups)} groups · ${fmt(s.query_duration_ms)} ms · ${esc(result.from)} — ${esc(result.to)}</p></details>`;
  $('intelligenceOut').onclick=e=>{const peak=e.target.closest('[data-intelligence-peak]');if(peak){const from=new Date(Number(peak.dataset.intelligencePeak));return insightFlows({},{from,to:new Date(+from+spec.bucket_seconds*1000-1)})}const button=e.target.closest('[data-intelligence-row]');if(!button)return;const row=rows[Number(button.dataset.intelligenceRow)],lens=intelligenceLens(spec.dimension,row.key);if(!lens)return;const peer=row.peer?intelligenceLens(spec.peer,row.peer):null;if(row.peer&&!peer)return toast('Exact peer filter is unavailable for this dimension.','bad');insightFlows({...lens,...peer},{from:new Date(result.from),to:new Date(+new Date(result.to)-1)})};
}
function changesPage(){return intelligencePage('changes')}
function distributionPage(){return intelligencePage('distribution')}
function relationshipsPage(){return intelligencePage('relationships')}
function qualityPage(){return intelligencePage('quality')}
function bandwidthPage(){return intelligencePage('temporal')}

function anomalyChart(points,metric) {
 if(!points.length)return '<p class="insight-note">No eligible complete intervals. Extend history or check sampling metadata.</p>';
 const maximum=Math.max(1,...points.map(p=>Math.max(p.upper,p.observed))),first=points[0].time,last=Math.max(first+1,points.at(-1).time);
 const xy=(p,key)=>`${50+800*(p.time-first)/(last-first)},${230-200*p[key]/maximum}`;
 const band=points.map(p=>xy(p,'upper')).concat([...points].reverse().map(p=>xy(p,'lower'))).join(' ');
 return `<svg class="intelligence-chart" viewBox="0 0 900 280" role="img" aria-label="Expected versus observed ${esc(metric)} per complete interval"><title>Observed counters and sum of eligible entity baseline bounds</title><polygon points="${band}" fill="var(--accent)" fill-opacity=".12"/><polyline points="${points.map(p=>xy(p,'expected')).join(' ')}" fill="none" stroke="var(--muted)" stroke-dasharray="6 4" stroke-width="2"/><polyline points="${points.map(p=>xy(p,'observed')).join(' ')}" class="intel-line"/>${points.map(p=>`<circle cx="${xy(p,'observed').split(',')[0]}" cy="${xy(p,'observed').split(',')[1]}" r="3" fill="var(--accent)"><title>${new Date(p.time).toISOString()}: observed ${p.observed}; expected ${p.expected}; bounds ${p.lower}–${p.upper}; ${p.eligible_entities} eligible entities</title></circle>`).join('')}<text x="50" y="265">${esc(dateTime(first))}</text><text x="680" y="265">${esc(dateTime(last))}</text></svg>`;
}
function anomalyDraw(result) {
 const a=result.anomalies,metric=result.spec.metric,format=v=>metric==='bytes'?bytes(v):fmt(v);
 if(!a){$('intelligenceOut').innerHTML=empty('Anomaly analysis is unavailable.',false);return}
 let html=insightFacts([['Eligible intervals',fmt(a.evaluated),'Entity × complete interval'],['History unavailable',fmt(a.insufficient_history),'At least 3 comparable weeks'],['Sampling withheld',fmt(a.sampling_withheld),'Reported sampling or unknown'],['Deviation episodes',fmt(a.event_count),'Retrospective states; not live alerts']]);
 html+=`<p class="insight-note">${esc(a.reason)} Data coverage: unavailable. Historical exporter completeness is not measured by observed traffic counts.</p>`;
 html+=panel('Expected vs Observed',anomalyChart(a.timeline,metric),'Solid = observed · dashed = expected · band = summed entity bounds. Eligible population may change between intervals.');
 if(a.events.length)html+=table(['Entity','State','Change','Observed','Expected range','Deviation','History','Start / last interval'],a.events.map((e,i)=>[`<button class="linklike mono" data-anomaly-event="${i}">${esc(e.entity||'Unspecified')}</button>`,esc(e.state),esc(e.type),format(e.observed),`${format(e.lower)} – ${format(e.upper)}`,`${format(e.delta)} (${e.deviation_percent===null?'undefined':pct(e.deviation_percent)})`,`${e.history_depth} weeks · ${esc(e.confidence)}`,`${dateTime(e.start)} / ${dateTime(e.end)}`]),true);
 if(!a.events.length)html+=`<p class="insight-note">${a.status==='baseline_learning'?'Baseline learning: insufficient comparable unsampled history.':'No qualifying deviation episodes in eligible intervals.'}</p>`;
 html+='<button id="anomalyHistory" class="ghost small">Use 30-day history</button><button id="anomalyRules" class="ghost small">Configure scheduled rules</button>';
 if(a.event_count>a.events.length)html+=`<p class="muted">Showing ${a.events.length} of ${a.event_count} episodes. Increase the row limit or narrow the filters.</p>`;
 const c=a.comparison;
 if(c){
  html+=panel('What Changed? / Why Did It Change?',insightFacts([['Expected',format(c.summary.previous),'Sum of eligible entity medians'],['Observed',format(c.summary.current),'Last complete interval'],['Delta',format(c.summary.delta),'Shown contributions + Other'],['Distribution shift',c.summary.jensen_shannon_bits===undefined?'—':c.summary.jensen_shannon_bits.toFixed(4),'JSD: 0 same, 1 disjoint']]),'One dimension at a time; contribution describes arithmetic change, not causality.');
  html+=table(['Contributor','Expected','Observed','Delta','Share change'],c.rows.map((r,i)=>[`<button class="linklike mono" data-anomaly-contributor="${i}">${esc(r.key||'Unspecified')}</button>`,format(r.previous),format(r.current),format(r.delta),`${fmt(r.share_delta_pp)} pp`]),true);
  html+=`<p class="insight-note">Other: ${esc(format(c.summary.other_delta))}. Total change: ${esc(format(c.summary.delta))}. Baseline interval: ${esc(dateTime(c.from))} – ${esc(dateTime(c.to))}.</p>`;
 }
 html+=`<details class="panel"><summary>Detection method and limitations</summary><p>${esc(a.method)}</p><p>Absolute entry floors per interval: 1 MB, 1,000 packets or 100 flows. Recovery uses half the entry envelope. Missing intervals break continuity; zero MAD has no finite robust z-score. Confidence is limited by three or four comparable weeks and unknown exporter completeness.</p></details>`;
 $('intelligenceOut').innerHTML=html;
 $('anomalyRules').onclick=()=>notificationTab('templates');
 $('anomalyHistory').onclick=()=>{rangeKey='30d';rangeCustom=null;const u=timeURL(new URL(location.href));u.searchParams.set('bucket','3600');setURL(u);render()};
 $('intelligenceOut').onclick=e=>{
  const b=e.target.closest('[data-anomaly-event]');
  if(b){const event=a.events[Number(b.dataset.anomalyEvent)];openModal(`<div class="modal-heading"><h3>${esc(event.type)}</h3></div>${insightFacts([['Entity',event.entity,result.spec.dimension],['Observed',format(event.observed),'Per complete interval'],['Expected',format(event.expected),`Range ${format(event.lower)} – ${format(event.upper)}`],['Data confidence',event.confidence,`${event.history_depth} comparable weeks · coverage unknown`]])}<p>${esc(event.reason)}</p><p>${esc(a.method)}</p><button id="anomalyExplore">Open in Flow Explorer</button>`);$('anomalyExplore').onclick=()=>{closeModal();insightFlows(intelligenceLens(result.spec.dimension,event.entity)||{}, {from:new Date(event.start),to:new Date(event.end-1)})};return}
  const contributor=e.target.closest('[data-anomaly-contributor]');if(contributor&&c){const row=c.rows[Number(contributor.dataset.anomalyContributor)];insightFlows(intelligenceLens(result.spec.dimension,row.key)||{}, {from:new Date(c.from),to:new Date(+new Date(c.to)-1)})}
 };
}

async function loadIntelligenceViews(){
 const el=$('intelSaved');if(!el)return;
 try{const all=await api('/api/v1/searches');if(!el.isConnected)return;const views=all.filter(v=>v.visualization==='intelligence');
  el.innerHTML=`<label class="sr-only" for="intelSavedSelect">Saved analyses</label><select id="intelSavedSelect"><option value="">Saved analyses (${views.length})</option>${views.map(v=>`<option value="${esc(v.id)}">${esc(v.name)}</option>`).join('')}</select>`;
  $('intelSavedSelect').onchange=()=>{const v=views.find(x=>x.id===$('intelSavedSelect').value);if(!v)return;const u=new URL(location.href);u.search='';for(const [k,value]of Object.entries(v.query))u.searchParams.set(k,value);setURL(u);render()};
 }catch(e){if(e.name!=='AbortError'&&el.isConnected)el.textContent='Saved analyses unavailable'}
}
function saveIntelligenceView(params){
 openModal('<div class="modal-heading"><h3>Save analysis</h3></div><form id="intelSaveForm"><label>Name<input id="intelSaveName" required maxlength="100"></label><p class="muted">Preserves dimensions, metric, filters, bucket, threshold, capacity assumption and exact time window.</p><button>Save</button><p id="intelSaveError" role="alert"></p></form>');
 $('intelSaveForm').onsubmit=async e=>{e.preventDefault();const period=range();try{await api('/api/v1/searches',{method:'POST',body:JSON.stringify({name:$('intelSaveName').value.trim(),visualization:'intelligence',query:{...urlFlowFilters(),...params,page:currentPage,range:'custom',from:period.from.toISOString(),to:period.to.toISOString()}})});closeModal();toast('Analysis saved');loadIntelligenceViews()}catch(err){$('intelSaveError').textContent=err.message}};
}
