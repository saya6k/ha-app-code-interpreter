// Globals for REPL cells: $ (shell), file, write, sleep, log (Node built-ins only).
//
// They run inside the sandbox, so they need no checks of their own: bubblewrap
// already limits what a cell can touch. Relative paths resolve against
// /sandbox, whatever the cell did with process.chdir.
import { spawn } from "node:child_process";
import fsp from "node:fs/promises";
import path from "node:path";
import util from "node:util";

const PIPE_GRACE_MS = 2000; // after exit: a detached grandchild may keep the pipes open
const STREAM_LIMIT = 16 << 20; // per stream: enough to parse a big file in the cell, bounded by RLIMIT_AS anyway
const running = new Set(); // child processes of $, killed when a cell is interrupted

export function sandboxDir() {
  return process.env.CI_SANDBOX_DIR || "/sandbox";
}

const resolve = (p) => path.resolve(sandboxDir(), String(p));

export function quote(value) {
  if (Array.isArray(value)) return value.map(quote).join(" ");
  if (value !== null && typeof value === "object" && "raw" in value) return String(value.raw);
  return "'" + String(value).replaceAll("'", "'\\''") + "'";
}

export class ShellError extends Error {
  name = "ShellError";
  constructor(out) {
    const why = out.timedOut ? "timed out" : out.signal ? `killed by ${out.signal}` : `exit code ${out.exitCode}`;
    super(`command failed (${why}): ${out.command}${out.stderr ? "\n" + out.stderr.slice(-2000) : ""}`);
    Object.assign(this, { stdout: out.stdout, stderr: out.stderr, exitCode: out.exitCode, signal: out.signal });
  }
}

export class ShellOutput {
  constructor(fields) {
    Object.assign(this, fields);
  }
  text() {
    return this.stdout;
  }
  lines() {
    return this.stdout.split("\n").filter((l, i, a) => l !== "" || i < a.length - 1);
  }
  json() {
    return JSON.parse(this.stdout);
  }
  // What a cell's result shows: the exit and a readable share of the output.
  toJSON() {
    const cut = (s) => (s.length > 4000 ? s.slice(0, 4000) + "…" : s);
    return { exitCode: this.exitCode, stdout: cut(this.stdout), stderr: cut(this.stderr), ...(this.truncated ? { truncated: true } : {}) };
  }
}

function capture(stream) {
  const chunks = [];
  let size = 0;
  let truncated = false;
  stream.on("data", (b) => {
    const room = STREAM_LIMIT - size;
    if (b.length > room) truncated = true;
    if (room > 0) chunks.push(b.subarray(0, room));
    size += Math.min(b.length, Math.max(room, 0));
  });
  return () => ({ text: Buffer.concat(chunks).toString(), truncated });
}

function run(command, timeoutMs) {
  return new Promise((resolveRun, rejectRun) => {
    let child;
    try {
      child = spawn("/bin/sh", ["-c", command], { cwd: sandboxDir(), stdio: ["ignore", "pipe", "pipe"], detached: true });
    } catch (e) {
      rejectRun(e);
      return;
    }
    running.add(child);
    const out = capture(child.stdout);
    const err = capture(child.stderr);
    let timedOut = false;
    const timer = timeoutMs ? setTimeout(() => ((timedOut = true), killGroup(child)), timeoutMs) : null;
    child.on("error", (e) => (running.delete(child), clearTimeout(timer), rejectRun(e)));
    let settled = false;
    const finish = (code, signal) => {
      if (settled) return;
      settled = true;
      running.delete(child);
      clearTimeout(timer);
      const o = out();
      const e = err();
      resolveRun(new ShellOutput({
        command, stdout: o.text, stderr: e.text, exitCode: code, signal: signal ?? null,
        timedOut, truncated: o.truncated || e.truncated,
      }));
    };
    child.on("close", finish);
    child.on("exit", (code, signal) => setTimeout(() => finish(code, signal), PIPE_GRACE_MS).unref());
  });
}

function killGroup(child) {
  try {
    process.kill(-child.pid, "SIGKILL");
  } catch {
    // already gone
  }
}

export function killRunning() {
  for (const child of running) killGroup(child);
}

class ShellPromise {
  #command;
  #timeoutMs = 0;
  #throws = true;
  #started = null;
  constructor(command) {
    this.#command = command;
  }
  nothrow() {
    this.#throws = false;
    return this;
  }
  timeout(ms) {
    this.#timeoutMs = Number(ms);
    return this;
  }
  #start() {
    // Lazy, so .nothrow() and .timeout() can follow $`…` before it runs.
    this.#started ??= run(this.#command, this.#timeoutMs).then((out) => {
      if (this.#throws && (out.exitCode !== 0 || out.timedOut)) throw new ShellError(out);
      return out;
    });
    return this.#started;
  }
  then(onFulfilled, onRejected) {
    return this.#start().then(onFulfilled, onRejected);
  }
  catch(onRejected) {
    return this.#start().catch(onRejected);
  }
  finally(onFinally) {
    return this.#start().finally(onFinally);
  }
  text() {
    return this.then((o) => o.text());
  }
  lines() {
    return this.then((o) => o.lines());
  }
  json() {
    return this.then((o) => o.json());
  }
}

function $(strings, ...values) {
  if (typeof strings === "string") return new ShellPromise(strings).timeout(values[0] ?? 0);
  let command = strings[0];
  values.forEach((v, i) => (command += quote(v) + strings[i + 1]));
  return new ShellPromise(command);
}
$.quote = quote;

function file(p) {
  const full = resolve(p);
  return {
    name: full,
    text: () => fsp.readFile(full, "utf8"),
    json: async () => JSON.parse(await fsp.readFile(full, "utf8")),
    lines: async () => (await fsp.readFile(full, "utf8")).split("\n"),
    exists: () => fsp.access(full).then(() => true, () => false),
  };
}

async function write(p, content) {
  if (typeof content !== "string" && !(content instanceof Uint8Array)) {
    throw new TypeError("write() takes a string or a Buffer; use JSON.stringify for other values");
  }
  const full = resolve(p);
  await fsp.mkdir(path.dirname(full), { recursive: true });
  await fsp.writeFile(full, content);
  return typeof content === "string" ? Buffer.byteLength(content) : content.length;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...args) => process.stdout.write(util.format(...args) + "\n");

// /share lives outside the sandbox: the app does these, and checks every path.
export function installShare(target, rpc) {
  target.share = {
    list: (dir = "") => rpc("share.list", { path: String(dir) }),
    import: (sharePath, dest) => rpc("share.import", { share_path: String(sharePath), ...(dest ? { dest: String(dest) } : {}) }),
    export: (p) => rpc("share.export", { path: String(p) }),
  };
}

// ha.<domain>.<tool>(args) calls Home Assistant's tool "<domain>__<tool>" (the
// names its MCP Server gives, e.g. intent__HassTurnOn); ha.call(name, args)
// takes a full name, ha.tools() lists them. The app decides what each call
// may reach; nothing here is a check.
function haNamespace(rpc, api) {
  const call = (name, args = {}) => rpc("ha.call", { api, name: String(name), args });
  const tools = () => rpc("ha.list", { api });
  const domains = new Map();
  const notThenable = (key) => typeof key !== "string" || key === "then" || key === "toJSON";
  return new Proxy({ call, tools }, {
    get(base, key) {
      if (key in base || notThenable(key)) return base[key];
      if (!domains.has(key)) {
        domains.set(key, new Proxy({}, {
          get: (_, tool) => (notThenable(tool) ? undefined : (args) => call(`${key}__${tool}`, args)),
        }));
      }
      return domains.get(key);
    },
  });
}

export function installHa(target, rpc, admin) {
  const ha = haNamespace(rpc, "assist");
  // Defined only in an administrator's cells: `ha.admin?.tools()` tells.
  const adminApi = admin ? haNamespace(rpc, "homeassistant") : undefined;
  target.ha = new Proxy(ha, { get: (base, key) => (key === "admin" ? adminApi : base[key]) });
}

export function install(target) {
  Object.assign(target, { $, file, write, sleep, log, ShellError });
}
