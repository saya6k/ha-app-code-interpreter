// Stateful JavaScript REPL server for the sandbox (Node built-ins + vendored acorn).
//
// Serves requests one at a time on an inherited socket (fd in $REPL_FD) and
// keeps its globals across requests. The app creates the socketpairs and
// passes one end through bubblewrap, so no socket file exists that sandbox
// code could replace. Framing matches proto.py: 4-byte big-endian length + JSON.
//
// Node runs JavaScript on one thread, so it cannot read the control channel
// while a cell spins in a loop. A small helper (ctl.py) owns $REPL_CTL_FD and
// answers "interrupt" by sending this process SIGINT: breakOnSigint stops a
// synchronous loop, and the SIGINT listener ends a cell waiting on a promise.
// A loop that runs after an await cannot be stopped; the app then restarts
// the REPL.
import { spawn } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import net from "node:net";
import path from "node:path";
import util from "node:util";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { install, installHa, installShare, killRunning } from "./globals.mjs";
import { transform } from "./transform.mjs";

const LOGS_LIMIT = 16000;
const RESULT_LIMIT = 16000;
const HERE = path.dirname(fileURLToPath(import.meta.url));
const realExit = process.exit.bind(process);

class Interrupted extends Error {
  name = "Interrupted";
}

class Capped {
  constructor(limit) {
    this.limit = limit;
    this.text = "";
    this.truncated = false;
  }
  write(s) {
    const room = this.limit - this.text.length;
    if (s.length > room) this.truncated = true;
    if (room > 0) this.text += s.slice(0, room);
  }
}

// Cells run as scripts in this (ES module) process: give them require for
// Node's built-ins and the libraries preinstalled under /opt/js.
globalThis.require = createRequire("/opt/js/");
install(globalThis);
installShare(globalThis, (...a) => rpc(...a));

let current = null; // the running cell or command: {interrupt()}
let late = []; // errors from abandoned async work, reported with the next cell

process.on("SIGINT", () => current?.interrupt()); // idle: ignored
process.on("uncaughtException", (e) => late.push(e));
process.on("unhandledRejection", (e) => late.push(e));
// Parity with the Python REPL: user code must not end the server.
process.exit = (code) => {
  throw Object.assign(new Error(`process.exit(${code ?? ""}) is disabled in the REPL`), { name: "SystemExit" });
};

function errorName(e) {
  if (e?.code === "ERR_SCRIPT_EXECUTION_INTERRUPTED") return "Interrupted";
  return e instanceof Error ? e.name : typeof e;
}

function formatError(e) {
  if (!(e instanceof Error)) return `Uncaught ${util.inspect(e)}`;
  const lines = String(e.stack ?? `${e.name}: ${e.message}`).split("\n");
  return lines.filter((l) => !(l.includes(HERE) || l.includes("node:internal"))).join("\n");
}

// Plain data as JSON (what the model will parse); anything JSON would
// misstate — a Map becomes {}, a function vanishes — as util.inspect.
function formatResult(value) {
  if (value === undefined) return null;
  if (typeof value === "string") return value;
  const proto = value !== null && typeof value === "object" ? Object.getPrototypeOf(value) : undefined;
  const plain = value === null || ["number", "boolean"].includes(typeof value) ||
    Array.isArray(value) || proto === Object.prototype || proto === null ||
    typeof value?.toJSON === "function"; // e.g. a $ result
  if (plain) {
    try {
      return JSON.stringify(value);
    } catch {
      // circular or BigInt inside: fall through
    }
  }
  return util.inspect(value, { depth: 4, breakLength: 120 });
}

// ({a: $`…`, b: fetch(…)}) returns once its promises have settled, so a cell
// can start work in parallel and hand back every result.
async function awaitMembers(value) {
  const proto = value !== null && typeof value === "object" ? Object.getPrototypeOf(value) : undefined;
  if (Array.isArray(value)) return Promise.all(value);
  if (proto !== Object.prototype && proto !== null) return value;
  const entries = await Promise.all(Object.entries(value).map(async ([k, v]) => [k, await v]));
  return Object.fromEntries(entries);
}

async function execute(code, cell, ctx = {}) {
  installHa(globalThis, (...a) => rpc(...a), Boolean(ctx.admin));
  // One log in the order things were written; stderr lines are marked.
  const logs = new Capped(LOGS_LIMIT);
  const out = logs;
  const err = { write: (s) => logs.write(s.replace(/^(?=.)/gm, "[stderr] ")) };
  for (const e of late.splice(0)) err.write(`[earlier cell] ${formatError(e)}\n`);
  const saved = [process.stdout.write, process.stderr.write];
  const sink = (cap) => (chunk, enc, cb) => {
    cap.write(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString());
    (typeof enc === "function" ? enc : cb)?.();
    return true;
  };
  process.stdout.write = sink(out);
  process.stderr.write = sink(err);
  const stopped = new Promise((_, reject) => {
    current = {
      interrupt: () => {
        killRunning(); // $ commands of this cell (and any still running from earlier ones)
        reject(new Interrupted("interrupted"));
      },
    };
  });
  stopped.catch(() => {});
  let result = null;
  let error = null;
  let message = null;
  let truncated = false;
  try {
    const script = new vm.Script(transform(code), {
      filename: `<cell-${cell}>`,
      importModuleDynamically: vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER,
    });
    let value = await Promise.race([script.runInThisContext({ breakOnSigint: true }), stopped]);
    if (value !== null && typeof value?.then === "function") value = await Promise.race([value, stopped]);
    value = await Promise.race([awaitMembers(value), stopped]);
    result = formatResult(value);
    if (result !== null && result.length > RESULT_LIMIT) {
      result = result.slice(0, RESULT_LIMIT);
      truncated = true;
    }
  } catch (e) {
    error = errorName(e);
    if (error !== "Interrupted") message = formatError(e);
  } finally {
    current = null;
    [process.stdout.write, process.stderr.write] = saved;
  }
  return { logs: logs.text, result, error, message, truncated: truncated || logs.truncated };
}

function channel(env) {
  return new net.Socket({ fd: Number(process.env[env]), readable: true, writable: true });
}

function send(sock, obj) {
  const data = Buffer.from(JSON.stringify(obj));
  const head = Buffer.alloc(4);
  head.writeUInt32BE(data.length);
  sock.write(Buffer.concat([head, data]));
}

function onFrames(sock, handle) {
  let buf = Buffer.alloc(0);
  sock.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) {
      const n = buf.readUInt32BE(0);
      let msg;
      try {
        msg = JSON.parse(buf.subarray(4, 4 + n).toString());
      } catch {
        realExit(1); // a broken channel ends the REPL; the app restarts it
      }
      buf = buf.subarray(4 + n);
      handle(msg);
    }
  });
}

// Calls to the app (share.*, ha.*) ride the REPL channel: the app answers
// them while it waits for the reply to the request that is running, and
// refuses calls tagged with any other request.
let conn = null;
let activeRequest = null;
let nextCall = 0;
const calls = new Map();

class RpcError extends Error {
  constructor({ name, message }) {
    super(message);
    this.name = name;
  }
}

function rpc(op, args = {}) {
  if (activeRequest === null) return Promise.reject(new Error(`${op}: only available while a cell runs`));
  const id = ++nextCall;
  return new Promise((resolve, reject) => {
    calls.set(id, { resolve, reject });
    send(conn, { rpc: { id, cell: activeRequest, op, args } });
  });
}

function settleCall(msg) {
  const call = calls.get(msg.rpc_reply);
  if (!call) return;
  calls.delete(msg.rpc_reply);
  if (msg.ok) call.resolve(msg.value);
  else call.reject(new RpcError(msg.error ?? { name: "RpcError", message: "call failed" }));
}

function startControlHelper() {
  const fd = Number(process.env.REPL_CTL_FD);
  const helper = spawn(process.env.CI_PYTHON || "python3", ["-I", "-S", path.join(HERE, "ctl.py")], {
    stdio: ["ignore", "ignore", "inherit", fd],
  });
  helper.on("error", () => {}); // no helper: timeouts end in a restart instead
  helper.unref();
  fs.closeSync(fd); // the helper holds it now
}

async function serve(req, cell) {
  if (req.op === "ping") return { pid: process.pid };
  activeRequest = req.id ?? null;
  try {
    return await execute(String(req.code ?? ""), cell, req.ctx ?? {});
  } finally {
    activeRequest = null;
  }
}

function main() {
  startControlHelper();
  conn = channel("REPL_FD");
  conn.on("error", () => realExit(0));
  conn.on("end", () => realExit(0)); // app side closed: the session is gone
  const queue = [];
  let busy = false;
  let cell = 0;
  const pump = async () => {
    if (busy) return;
    busy = true;
    while (queue.length) {
      const req = queue.shift();
      const resp = await serve(req, ++cell);
      resp.id = req.id ?? null; // after a cancelled request the app skips stale replies
      send(conn, resp);
    }
    busy = false;
  };
  onFrames(conn, (msg) => {
    if (msg === null || typeof msg !== "object") realExit(1); // not the app talking
    if ("rpc_reply" in msg) settleCall(msg);
    else {
      queue.push(msg);
      pump().catch(() => realExit(1));
    }
  });
}

main();
