import os from "node:os";
import fs from "node:fs";
let procStatus;
try { fs.readFileSync("/proc/self/status"); procStatus = "readable"; } catch (e) { procStatus = e.code; }
console.log(JSON.stringify({
  version: process.version, execPath: process.execPath, cpus: os.cpus().length,
  parallelism: os.availableParallelism(), totalmemMB: Math.round(os.totalmem() / 2 ** 20), procStatus,
}));
