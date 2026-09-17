const test = require('node:test');
const assert = require('node:assert/strict');
const state = require('../../internal/api/static/insight-state.js');

const start = Date.parse('2026-09-15T00:00:00Z');
const stamp = minute => new Date(start+minute*60000).toISOString();
const analysis = (from,to,points) => ({from:stamp(from),to:stamp(to),bucket:'1m',timeline:points.map(([minute,bytes])=>({timestamp:stamp(minute),bytes,packets:bytes/10,flows:1})),totals:{bytes:points.reduce((sum,[,bytes])=>sum+bytes,0)}});
test('P95 includes idle buckets and uses rates, not total byte counts',()=>{
  const result=state.rateSummary(analysis(0,20,[[1,600],[19,6000]]));
  assert.equal(result.samples,20);assert.equal(result.active,2);
  assert.equal(result.peak,800);assert.equal(result.p95,80);assert.equal(result.median,0);assert.equal(result.average,44);
  assert.equal(result.bins.reduce((sum,bin)=>sum+bin.count,0),20);
  assert.equal(result.peaks[0].timestamp,stamp(19));
});
test('partial boundary buckets do not suppress the observed complete-bucket rate',()=>{
  const result=state.rateSummary(analysis(.5,3.5,[[0,120000],[1,600],[2,1200],[3,60000]]));
  assert.equal(result.samples,2);assert.equal(result.peak,160);assert.equal(result.p95,160);
  assert.deepEqual(result.complete.map(point=>point.timestamp),[stamp(1),stamp(2)]);
  assert.equal(result.points.length,4);
});
test('empty series and too-short periods distinguish zero from unavailable',()=>{
  const idle=state.rateSummary(analysis(0,20,[]));assert.equal(idle.p95,0);assert.equal(idle.samples,20);assert.equal(idle.peaks.length,0);
  const short=state.rateSummary(analysis(.1,.2,[]));assert.equal(short.p95,null);assert.equal(short.samples,0);assert.equal(short.average,0);
});
test('daily buckets and malformed or oversized ranges are handled explicitly',()=>{
  assert.equal(state.bucketSeconds('1d'),86400);
  assert.throws(()=>state.bucketSeconds('1month'));
  assert.throws(()=>state.completeTimeline(analysis(2,1,[])));
  assert.throws(()=>state.completeTimeline(analysis(0,10001,[])));
});
test('comparison never invents zero for contributors outside a full ranking',()=>{
  const rows=state.comparisonRows([{key:'A',bytes:20},{key:'B',bytes:10}],[{key:'A',bytes:10},{key:'C',bytes:10}],'bytes',2);
  assert.equal(rows[0].key,'A');assert.equal(rows[0].percent,100);
  assert.equal(rows.find(row=>row.key==='B').previous,null);assert.equal(rows.find(row=>row.key==='B').status,'outside');
  assert.equal(rows.find(row=>row.key==='C').delta,null);
});
test('complete rankings distinguish new, inactive and unchanged contributors',()=>{
  const rows=state.comparisonRows([{key:'new',flows:2},{key:'same',flows:1}],[{key:'gone',flows:3},{key:'same',flows:1}],'flows');
  assert.deepEqual(rows.map(row=>row.status),['inactive','new','unchanged']);
  assert.equal(rows[1].previous,0);assert.equal(rows[1].percent,null);assert.equal(rows[0].percent,-100);
});
test('conversation drill-down reverses both addresses and ports',()=>{
  const row={a_ip:'2001:db8::1',a_port:443,b_ip:'2001:db8::2',b_port:40000,protocol:6};
  assert.deepEqual(state.directionalFilters(row),{src_ip:row.a_ip,dst_ip:row.b_ip,src_port:'443',dst_port:'40000',ip_protocol:'6'});
  assert.deepEqual(state.directionalFilters(row,true),{src_ip:row.b_ip,dst_ip:row.a_ip,src_port:'40000',dst_port:'443',ip_protocol:'6'});
});
test('ranking CSV escapes quotes and prevents spreadsheet formula evaluation',()=>{
  assert.equal(state.rankingCSV([]),'');
  const csv=state.rankingCSV([{ip:'2001:db8::1',as_name:'  =SUM(1,2)',site:'A "quoted" site',protocols:[6,17]}]);
  assert.match(csv,/"'  =SUM\(1,2\)"/);assert.match(csv,/"A ""quoted"" site"/);assert.match(csv,/"6 \| 17"/);
  assert.equal(csv.split('\r\n').length,2);
});
