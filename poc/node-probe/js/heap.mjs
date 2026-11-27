import v8 from "node:v8";
// V8 heap (not ArrayBuffers): grow to the target or until allocation fails.
const target = Number(process.argv[2] || 768);
const keep = [];
let mb = 0;
try {
  while (mb < target) { keep.push(new Array(1 << 20).fill(mb)); mb += 8; }
  let usage;
  try { usage = Math.round(process.memoryUsage().rss / 2 ** 20) + "MB"; } catch (e) { usage = e.code || String(e); }
  const heapMB = Math.round(v8.getHeapStatistics().used_heap_size / 2 ** 20);
  console.log(JSON.stringify({ ok: true, mb, heapMB, memoryUsage: usage }));
} catch (e) {
  console.log(JSON.stringify({ ok: false, mb, error: String(e) }));
}
