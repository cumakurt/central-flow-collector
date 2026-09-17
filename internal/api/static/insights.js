'use strict';

// Focused analytical views share the portal's time range, flow lens and router.
const insightFamilies = {
  analytics: [['analytics','Workspace'],['changes','What Changed?'],['anomalies','Traffic Anomalies'],['distribution','Distribution Lab'],['bandwidth','Capacity Lens'],['capacity','Retention & Sampling']],
  traffic: [['traffic','Breakdown'],['services','Service Timeline'],['servicemix','Service Mix'],['trends','Traffic Trends'],['heatmap','Heatmap'],['endpoints','Endpoints'],['conversations','Conversations'],['connections','Connection Signals'],['relationships','Relationships'],['routing','Routing'],['qos','QoS / DSCP'],['nat','NAT'],['coverage','Field Coverage']],
  exporters: [['exporters','Exporter health'],['quality','Telemetry Quality']]
};
function insightFamily(page) {
  return Object.keys(insightFamilies).find(key => insightFamilies[key].some(([id]) => id === page));
}
function insertInsightTabs() {
  const family = insightFamily(currentPage);
  if (!family) return;
  const tabs = document.createElement('nav');
  tabs.className = 'tabs insight-tabs';
  tabs.setAttribute('aria-label', family === 'analytics' ? 'Analysis views' : 'Traffic views');
  tabs.innerHTML = insightFamilies[family].map(([id,label]) => `<button data-route="${id}" class="${currentPage === id ? 'active' : ''}" ${currentPage === id ? 'aria-current="page"' : ''}>${label}</button>`).join('');
  $('content').prepend(tabs);
}
function insightSelect(id, label, choices, value) {
  return `<label>${esc(label)}<select id="${id}">${choices.map(([key,name]) => `<option value="${esc(key)}" ${value === key ? 'selected' : ''}>${esc(name)}</option>`).join('')}</select></label>`;
}
function insightParam(key, choices, fallback) {
  const value = new URLSearchParams(location.search).get(key);
  return choices.includes(value) ? value : fallback;
}
function insightParams(values, replace = false) {
  const u = timeURL(new URL(location.href));
  for (const [key,value] of Object.entries(values)) u.searchParams.set(key,value);
  setURL(u,replace);
}
function insightFacts(items) {
  return `<dl class="insight-facts">${items.map(([label,value,note]) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd><small>${esc(note)}</small></div>`).join('')}</dl>`;
}
function insightFormat(metric, value) { return value === null ? 'Outside top 50' : metric === 'bytes' ? bytes(value) : fmt(value); }
function insightFlows(filters, period) {
  const u = timeURL(PortalState.setFilters(location.href, {...urlFlowFilters(), ...filters}));
  u.searchParams.set('page','flows');
  if (period) {
    u.searchParams.set('range','custom');
    u.searchParams.set('from',period.from.toISOString());
    u.searchParams.set('to',period.to.toISOString());
  }
  setURL(u); return render();
}
function insightEntity(key, dimension) {
  const lens = PortalState.lens(dimension,key);
  return lens ? `<button class="linklike drill mono" data-dim="${esc(dimension)}" data-key="${esc(key)}">${esc(key)}</button>` : esc(key || 'Unspecified');
}
function endpointAddress(ip, port) {
  return `<button class="linklike mono" data-ip="${esc(ip)}">${esc(ip)}</button>${port === undefined ? '' : `<span class="endpoint-port">:${esc(port)}</span>`}`;
}
function insightProtocol(number) { return ({1:'ICMP',6:'TCP',17:'UDP',47:'GRE',50:'ESP',58:'ICMPv6',132:'SCTP'})[number] || `IP ${number}`; }
async function endpointAnalysisPage(conversations = false) {
  title(conversations ? 'Conversations' : 'Endpoints',conversations ? 'Two-way traffic between endpoint and port pairs' : 'Rank IPs by volume, activity or peer reach');
  const metrics = [['bytes','Traffic volume'],['packets','Packets'],['flows','Flows'],...(!conversations ? [['peers','Unique peers']] : [])];
  const metric = insightParam('metric',metrics.map(([key])=>key),'bytes');
  const limit = insightParam('limit',['25','50','100'],'50');
  $('content').innerHTML = rangeToolbar() + lensBar(urlFlowFilters(),true) + `<div class="insight-controls">${insightSelect('endpointMetric','Rank by',metrics,metric)}${insightSelect('endpointLimit','Result limit',[['25','Top 25'],['50','Top 50'],['100','Top 100']],limit)}<span class="muted">Ranked on the server · selected period and lens</span><button id="insightExport" class="ghost small" disabled>Export this ranking · CSV</button></div><div id="endpointOut"><div class="loading-state" role="status">Aggregating ${conversations ? 'conversations' : 'endpoints'}…</div></div>`;
  for (const id of ['endpointMetric','endpointLimit']) $(id).onchange = () => {
    insightParams({metric:$('endpointMetric').value,limit:$('endpointLimit').value}); render();
  };
  const version = renderVersion;
  const rows = await api(`/api/v1/${conversations ? 'conversations' : 'assets'}?` + qs({metric,limit}));
  if (version !== renderVersion) return;
  const records = rows || [];
  const caption = records.length === Number(limit) ? `Top ${limit} shown · more may match` : `${fmt(records.length)} matching ${conversations ? 'conversations' : 'endpoints'}`;
  const headers = conversations ? ['Endpoint A','Endpoint B','Protocol','A → B traffic','B → A traffic','Total traffic','Packets','Flows','Last seen','Explore direction'] : ['IP address','Country / ASN','Sent traffic','Received traffic','Total traffic','Packets','Flows','Peers','Last seen','Explore'];
  const values = records.map((row,index) => conversations ? [
    endpointAddress(row.a_ip,row.a_port),endpointAddress(row.b_ip,row.b_port),insightProtocol(row.protocol),
    bytes(row.bytes_a_to_b),bytes(row.bytes_b_to_a),bytes(row.bytes_a_to_b+row.bytes_b_to_a),fmt(row.packets_a_to_b+row.packets_b_to_a),fmt(row.flows),dateTime(row.last_seen),
    `<button class="linklike" data-conversation="${index}" data-reverse="0" ${!row.a_port||!row.b_port?'disabled':''}>A → B</button> <button class="linklike" data-conversation="${index}" data-reverse="1" ${!row.a_port||!row.b_port?'disabled':''}>B → A</button>`
  ] : [
    endpointAddress(row.ip),`${esc(row.country || '—')} <span class="muted">${row.asn ? 'AS'+String(row.asn) : ''}</span>`,bytes(row.bytes_out),bytes(row.bytes_in),bytes(row.bytes_in+row.bytes_out),fmt(row.packets_in+row.packets_out),fmt(row.flows),fmt(row.peers),dateTime(row.last_seen),`<button class="linklike" data-endpoint="${index}">Flows →</button>`
  ]);
  $('endpointOut').innerHTML = `${conversations?panel('Top conversations',conversationBarChart(records),'Bidirectional traffic volume · select a bar to inspect the conversation ledger row'):''}<div class="section-ruler"><span>${conversations ? 'CONVERSATION LEDGER' : 'ENDPOINT RANKING'} / ${esc(metrics.find(([key])=>key===metric)[1])}</span><span>${caption}</span></div><section class="insight-ledger">${table(headers,values,true)}</section><p class="insight-note">${conversations ? 'A and B are canonical address/port labels, not client and server roles. Directional filters apply before aggregation; a reverse direction may have no matching flows. Exact port drill-down is unavailable for port 0.' : 'Sent and received traffic is counted at each endpoint; summing endpoint totals double-counts traffic between listed IPs. Peer counts include only flows matching the current lens.'} Analysis ranges are limited to 31 days.</p>`;
  $('endpointOut').onclick = event => {
    const bar=event.target.closest('[data-conversation-bar]');if(bar){const target=$(`[data-conversation="${bar.dataset.conversationBar}"]`);target?.scrollIntoView({behavior:'smooth',block:'center'});target?.focus();return}
    const endpoint = event.target.closest('[data-endpoint]');
    if (endpoint) return insightFlows({host:records[Number(endpoint.dataset.endpoint)].ip});
    const button = event.target.closest('[data-conversation]');
    if (button && !button.disabled) return insightFlows(InsightState.directionalFilters(records[Number(button.dataset.conversation)],button.dataset.reverse==='1'));
  };
  $('insightExport').disabled = !records.length;
  $('insightExport').onclick = () => exportInsightRanking(records,conversations ? 'conversations' : 'endpoints');
}
function endpointsPage() { return endpointAnalysisPage(); }
function conversationsPage() { return endpointAnalysisPage(true); }
function exportInsightRanking(records,name) {
  const content = InsightState.rankingCSV(records);
  const url = URL.createObjectURL(new Blob([content],{type:'text/csv;charset=utf-8'})), link = document.createElement('a');
  link.href=url; link.download=`cfc-${name}-${new Date().toISOString().slice(0,10)}.csv`; link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
  toast(`Exported ${records.length} ranked records.`);
}
