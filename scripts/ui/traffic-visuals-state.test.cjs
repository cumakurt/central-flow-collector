const assert=require('node:assert/strict');
const V=require('../../internal/api/static/traffic-visuals-state.js');

assert.equal(V.value({bytes:125},'bps',5),200);
assert.equal(V.value({flows:7},'flows',60),7);
const ranked=V.topSeries([
 {selector:{label:'A'},totals:{bytes:10,flows:9}},
 {selector:{label:'B'},totals:{bytes:30,flows:1}},
 {selector:{label:'C'},totals:{bytes:20,flows:3}},
],'bytes',2);
assert.deepEqual(ranked.map(x=>x.selector.label),['B','C']);
const heat=V.heatmap([
 {timestamp:'2026-09-16T10:05:00Z',bytes:100,packets:1,flows:1},
 {timestamp:'2026-09-16T10:55:00Z',bytes:200,packets:2,flows:2},
 {timestamp:'2026-09-16T11:00:00Z',bytes:300,packets:3,flows:3}
],new Date('2026-09-16T10:00:00Z'),new Date('2026-09-16T12:00:00Z'));
assert.equal(heat.length,2);
assert.equal(heat[0].bytes,300);
assert.equal(heat[0].flows,3);
assert.equal(heat[1].bytes,300);
const win=V.bucketWindow('2026-09-16T10:00:00Z',3600,new Date('2026-09-16T10:15:00Z'),new Date('2026-09-16T10:45:00Z'));
assert.equal(win.from.toISOString(),'2026-09-16T10:15:00.000Z');
assert.equal(win.to.toISOString(),'2026-09-16T10:45:00.000Z');
console.log('traffic visual state tests: PASS');
