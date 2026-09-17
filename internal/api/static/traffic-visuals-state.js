'use strict';
(function(root){
  function value(point,metric,bucketSeconds){
    const n=Number(point?.[metric==='bps'?'bytes':metric]||0);
    return metric==='bps'?n*8/Math.max(1,Number(bucketSeconds)||1):n;
  }
  function topSeries(series,metric,limit=8){
    const field=metric==='bps'?'bytes':metric;
    return [...(series||[])].sort((a,b)=>Number(b?.totals?.[field]||0)-Number(a?.totals?.[field]||0)).slice(0,limit);
  }
  function heatmap(timeline,from,to){
    const start=+new Date(from),end=+new Date(to),hours=new Map();
    for(const p of timeline||[]){const ts=+new Date(p.timestamp);if(ts<start||ts>=end)continue;const d=new Date(ts),key=`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}T${String(d.getHours()).padStart(2,'0')}`;const x=hours.get(key)||{timestamp:new Date(d.getFullYear(),d.getMonth(),d.getDate(),d.getHours()).toISOString(),bytes:0,packets:0,flows:0};x.bytes+=Number(p.bytes||0);x.packets+=Number(p.packets||0);x.flows+=Number(p.flows||0);hours.set(key,x)}
    return [...hours.values()].sort((a,b)=>new Date(a.timestamp)-new Date(b.timestamp));
  }
  function bucketWindow(timestamp,seconds,from,to){const a=Math.max(+new Date(from),+new Date(timestamp)),b=Math.min(+new Date(to),+new Date(timestamp)+Math.max(1,seconds)*1000);return {from:new Date(a),to:new Date(b)}}
  const api={value,topSeries,heatmap,bucketWindow};
  if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.TrafficVisualState=api;
})(typeof window!=='undefined'?window:globalThis);
