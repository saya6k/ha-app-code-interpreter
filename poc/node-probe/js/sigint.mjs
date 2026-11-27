// The REPL's timeout path: a self-SIGINT must break a synchronous loop and leave the process alive.
import vm from "node:vm";
import { spawn } from "node:child_process";
spawn("/bin/sh", ["-c", `sleep 1; kill -INT ${process.pid}`], { stdio: "ignore" });
let outcome;
const t0 = Date.now();
try { vm.runInThisContext("while (true) {}", { breakOnSigint: true }); outcome = "not interrupted"; } catch (e) { outcome = e.code || String(e); }
console.log(JSON.stringify({ outcome, ms: Date.now() - t0, alive: true }));
