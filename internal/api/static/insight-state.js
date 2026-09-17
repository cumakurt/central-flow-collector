'use strict';

// Pure analytical calculations; the input is always an aggregate API response.
const InsightState = (() => {
  function bucketSeconds(label) {
    const match = String(label).match(/^(\d+)(s|m|h|d)$/);
    if (!match || Number(match[1]) < 1) throw Error('Unsupported timeline interval.');
    return Number(match[1]) * {s:1,m:60,h:3600,d:86400}[match[2]];
  }

  function comparisonRows(current = [], previous = [], metric = 'bytes', limit = 50) {
    const now = new Map(current.map(row => [row.key, row]));
    const before = new Map(previous.map(row => [row.key, row]));
    return [...new Set([...now.keys(), ...before.keys()])].map(key => {
      // An absent Top-N row is only known to be zero when that list is complete.
      const a = now.has(key) ? Number(now.get(key)[metric] || 0) : current.length < limit ? 0 : null;
      const b = before.has(key) ? Number(before.get(key)[metric] || 0) : previous.length < limit ? 0 : null;
      const delta = a === null || b === null ? null : a - b;
      const status = delta === null ? 'outside' : b === 0 && a > 0 ? 'new' : a === 0 && b > 0 ? 'inactive' : delta > 0 ? 'increased' : delta < 0 ? 'decreased' : 'unchanged';
      return {key, current:a, previous:b, delta, percent:b > 0 && a !== null ? 100 * delta / b : null, status};
    }).sort((a,b) => (a.delta === null) - (b.delta === null) || Math.abs(b.delta || 0) - Math.abs(a.delta || 0) || a.key.localeCompare(b.key));
  }

  function completeTimeline(analysis) {
    const step = bucketSeconds(analysis.bucket) * 1000;
    const from = +new Date(analysis.from), to = +new Date(analysis.to);
    if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from || Math.ceil((to-from)/step) > 10000) throw Error('Choose a valid time range with at most 10,000 intervals.');
    const byTime = new Map((analysis.timeline || []).map(p => [+new Date(p.timestamp), p]));
    const points = [];
    for (let time = Math.floor(from/step)*step; time < to; time += step) {
      const point = byTime.get(time);
      points.push({timestamp:new Date(time).toISOString(), bytes:Number(point?.bytes || 0), packets:Number(point?.packets || 0), flows:Number(point?.flows || 0), complete:time >= from && time + step <= to});
    }
    return {points, seconds:step/1000, duration:(to-from)/1000};
  }

  function rateSummary(analysis, metric = 'bytes') {
    const series = completeTimeline(analysis), multiplier = metric === 'bytes' ? 8 : 1;
    const complete = series.points.filter(p => p.complete).map(p => ({...p, rate:p[metric]*multiplier/series.seconds}));
    const sorted = complete.map(p => p.rate).sort((a,b)=>a-b);
    const peak = sorted.length ? sorted.at(-1) : null;
    const percentile = p => sorted.length ? sorted[Math.max(0, Math.ceil(p*sorted.length)-1)] : null;
    const bins = Array.from({length:10},(_,index)=>({from:(peak||0)*index/10,to:(peak||0)*(index+1)/10,count:0}));
    for (const value of sorted) bins[peak ? Math.min(9, Math.floor(value/peak*10)) : 0].count++;
    return {...series, complete, peak, p95:percentile(.95), median:percentile(.5), average:Number(analysis.totals?.[metric]||0)*multiplier/series.duration, samples:sorted.length, active:complete.filter(p=>p.rate>0).length, bins, peaks:complete.filter(p=>p.rate>0).sort((a,b)=>b.rate-a.rate || a.timestamp.localeCompare(b.timestamp)).slice(0,10)};
  }

  function directionalFilters(row, reverse = false) {
    // Endpoint A/B order is canonical, not client/server or trust direction.
    return {src_ip:reverse?row.b_ip:row.a_ip, dst_ip:reverse?row.a_ip:row.b_ip, src_port:String(reverse?row.b_port:row.a_port), dst_port:String(reverse?row.a_port:row.b_port), ip_protocol:String(row.protocol)};
  }

  function rankingCSV(records) {
    if (!records.length) return '';
    const columns = Object.keys(records[0]);
    const cell = value => {
      let text = String(Array.isArray(value) ? value.join(' | ') : value ?? '');
      if (/^\s*[=+@-]|^[\t\r]/.test(text)) text = "'" + text;
      return '"' + text.replaceAll('"','""') + '"';
    };
    return [columns.map(cell).join(','),...records.map(record=>columns.map(key=>cell(record[key])).join(','))].join('\r\n');
  }

  return {bucketSeconds, comparisonRows, completeTimeline, rateSummary, directionalFilters, rankingCSV};
})();
if (typeof module !== 'undefined') module.exports = InsightState;
