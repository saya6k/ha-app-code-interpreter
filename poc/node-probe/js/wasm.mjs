// Undici's HTTP parser in fetch() is wasm, so wasm memory reservations matter under RLIMIT_AS.
const out = {};
const empty = new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]);
try { await WebAssembly.instantiate(empty); out.instantiate = "ok"; } catch (e) { out.instantiate = String(e); }
for (const [name, desc, grow] of [["bounded", { initial: 1, maximum: 16384 }, 1000], ["unbounded", { initial: 1 }, 1000]]) {
  try { const m = new WebAssembly.Memory(desc); m.grow(grow); out[name] = Math.round(m.buffer.byteLength / 2 ** 20) + "MB"; } catch (e) { out[name] = String(e); }
}
const many = [];
try { for (let i = 0; i < 8; i++) many.push(new WebAssembly.Memory({ initial: 1 })); out.eight = "ok"; } catch (e) { out.eight = many.length + ": " + e; }
console.log(JSON.stringify(out));
