import { Worker } from "node:worker_threads";
const n = Number(process.argv[2] || 1);
const results = await Promise.all(Array.from({ length: n }, (_, i) => new Promise((res) => {
  const w = new Worker("require('node:worker_threads').parentPort.postMessage(" + i + " * 2)", { eval: true });
  w.on("message", res); w.on("error", (e) => res(String(e)));
})));
console.log(JSON.stringify({ results }));
