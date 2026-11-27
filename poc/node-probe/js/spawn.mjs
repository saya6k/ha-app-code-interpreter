import { execFileSync } from "node:child_process";
const out = {};
for (const [k, cmd, args] of [["sh", "/bin/sh", ["-c", "echo hi"]], ["python", "python3", ["-c", "print(6*7)"]]]) {
  try { out[k] = execFileSync(cmd, args, { encoding: "utf8" }).trim(); } catch (e) { out[k] = String(e); }
}
console.log(JSON.stringify(out));
