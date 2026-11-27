const out = {};
for (const mb of [512, 1536]) {
  try { const b = Buffer.alloc(mb * 2 ** 20); b[b.length - 1] = 1; out[mb] = "ok"; } catch (e) { out[mb] = e.name + ": " + e.message; }
}
console.log(JSON.stringify(out));
