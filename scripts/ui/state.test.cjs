const test=require('node:test');
const assert=require('node:assert/strict');
const state=require('../../internal/api/static/portal-state.js');

test('custom period round-trips with an analytical lens',()=>{
  const original='http://localhost/?page=analytics&range=custom&from=2026-09-01T00%3A00%3A00Z&to=2026-09-02T00%3A00%3A00Z&dimension=asn';
  const next=state.setFilters(original,{src_cidr:'2001:db8::/64',ip_protocol:'TCP'});
  assert.equal(next.searchParams.get('dimension'),'asn');
  assert.deepEqual(state.filters(next.search),{src_cidr:'2001:db8::/64',ip_protocol:'TCP'});
  const period=state.time(next.search);
  assert.equal(period.key,'custom');assert.equal(period.to-period.from,86400000);
});
test('invalid periods use a bounded default',()=>{
  const now=new Date('2026-09-15T12:00:00Z');
  for(const query of ['range=bogus','range=custom&from=bad&to=bad','range=custom&from=2026-09-16&to=2026-09-15']){
    const t=state.time(query,now);assert.equal(t.key,'24h');assert.equal(t.to-t.from,86400000);
  }
});
test('removing a lens clears previous fields and preserves selected time',()=>{
  const next=state.setFilters('http://localhost/?page=flows&range=1h&src_ip=10.1.1.1&dst_port=443',{country:'TR'});
  assert.deepEqual(state.filters(next.search),{country:'TR'});assert.equal(next.searchParams.get('range'),'1h');
});
test('unsupported predicates never become silently ignored query parameters',()=>{
  assert.equal(state.lens('direction','internal'),null);assert.equal(state.lens('not','TR'),null);
  assert.deepEqual(state.lens('interface','12'),{ingress_if:'12'});
  assert.deepEqual(state.lens('application','HTTPS'),{app:'HTTPS'});
  assert.deepEqual(state.filters('country=TR&tenant=123&or=udp'),{country:'TR'});
});
test('no-baseline comparisons do not claim percentage growth',()=>{
  assert.equal(state.comparison({previous:0,current:100,change_percent:100}),'New activity · no prior baseline');
  assert.equal(state.comparison({previous:100,current:150,change_percent:50}),'+50.0% vs previous period');
});
test('bandwidth uses decimal bit units and never labels bytes as bits',()=>{
  assert.equal(state.bandwidth(1000000000),'1 Gbit/s');assert.equal(state.bandwidth(0),'0 bit/s');
});
test('display labels resolve to the actual ASN and interface query fields',()=>{
  assert.deepEqual(state.lens('asn','AS64512 Example Network'),{asn:'64512'});
  assert.deepEqual(state.lens('interface','Ingress 4'),{ingress_if:'4'});
  assert.deepEqual(state.lens('interface','Egress 9'),{egress_if:'9'});
  assert.equal(state.lens('country','Unknown'),null);
});
test('service and either-port filters round-trip through Flow Explorer URLs',()=>{
  const next=state.setFilters('http://localhost/?page=flows&range=30d',{service:'smtp',port:'587'});
  assert.deepEqual(state.filters(next.search),{service:'smtp',port:'587'});
  assert.equal(next.searchParams.get('range'),'30d');
});
