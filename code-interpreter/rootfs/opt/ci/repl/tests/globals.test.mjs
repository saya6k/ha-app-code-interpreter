// node --test code-interpreter/rootfs/opt/ci/repl/tests
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-"));
process.env.CI_SANDBOX_DIR = dir;
const g = {};
const { install, installPlugins, installSkills, quote, ShellError } = await import("../globals.mjs");
install(g);
const { $, file, write } = g;

test("interpolated values are single-quoted, one argument each", async () => {
  const evil = "x'; touch pwned; echo '";
  assert.equal(await $`printf %s ${evil}`.text(), evil);
  assert.equal(fs.existsSync(path.join(dir, "pwned")), false);
  assert.equal(await $`printf '[%s]' ${["a b", "c"]}`.text(), "[a b][c]");
  assert.equal(await $`echo ${{ raw: "$((1 + 2))" }}`.text(), "3\n");
  assert.equal(quote("it's"), "'it'\\''s'");
});

test("a failing command throws ShellError; nothrow hands it back", async () => {
  await assert.rejects($`echo bad >&2; exit 3`, (e) => e instanceof ShellError && e.exitCode === 3 && e.stderr === "bad\n");
  const out = await $`exit 4`.nothrow();
  assert.equal(out.exitCode, 4);
});

test("text, lines and json", async () => {
  assert.deepEqual(await $`printf 'a\\nb\\n'`.lines(), ["a", "b"]);
  assert.deepEqual(await $`echo '{"k": [1]}'`.json(), { k: [1] });
});

test("plain string form with a timeout kills the command", async () => {
  const t0 = Date.now();
  const out = await $("sleep 5", 200).nothrow();
  assert.ok(out.timedOut && Date.now() - t0 < 3000);
  await assert.rejects($("sleep 5", 200), ShellError);
});

test("a detached grandchild holding the pipes does not hold the command", async () => {
  const t0 = Date.now();
  const out = await $`(sleep 30 &) ; echo done`;
  assert.ok(out.stdout.startsWith("done") && Date.now() - t0 < 5000);
});

test("commands run in the sandbox directory", async () => {
  assert.equal(fs.realpathSync((await $`pwd`.text()).trim()), fs.realpathSync(dir));
});

test("a result shows exit code and output through toJSON", async () => {
  const out = await $`echo hi`;
  assert.deepEqual(JSON.parse(JSON.stringify(out)), { exitCode: 0, stdout: "hi\n", stderr: "" });
});

test("nothing runs until awaited", async () => {
  const p = $`touch ${path.join(dir, "lazy")}`;
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(fs.existsSync(path.join(dir, "lazy")), false);
  await p;
  assert.equal(fs.existsSync(path.join(dir, "lazy")), true);
});

test("write creates parents and file() reads relative to the sandbox", async () => {
  assert.equal(await write("d/e/f.json", '{"n": 1}'), 8);
  assert.deepEqual(await file("d/e/f.json").json(), { n: 1 });
  assert.equal(await file("d/e/f.json").exists(), true);
  assert.equal(await file("nope").exists(), false);
  assert.equal(file("x").name, path.join(dir, "x"));
  await assert.rejects(write("o", { a: 1 }), TypeError);
});

test("plugins map <server>.<tool> to the full tool name, and are undefined when off", async () => {
  const sent = [];
  const rpc = async (op, args) => (sent.push([op, args]), "ok");
  const target = {};
  installPlugins(target, rpc, true);
  await target.plugins.memory.search({ q: 1 });
  await target.plugins["multi-service-mcp"].find_places();
  await target.plugins.call("memory__save", { v: 2 });
  await target.plugins.tools();
  assert.deepEqual(sent, [
    ["plugins.call", { name: "memory__search", args: { q: 1 } }],
    ["plugins.call", { name: "multi-service-mcp__find_places", args: {} }],
    ["plugins.call", { name: "memory__save", args: { v: 2 } }],
    ["plugins.list", {}],
  ]);
  assert.equal(target.plugins.then, undefined); // awaiting the namespace does not call a tool
  installPlugins(target, rpc, false);
  assert.equal(target.plugins, undefined);
});

test("skills.request sends the text; it is not taken for a skill name", async () => {
  const sent = [];
  const target = {};
  installSkills(target, async (op, args) => (sent.push([op, args]), { requested: true }));
  assert.deepEqual(await target.skills.request("today's outfit"), { requested: true });
  assert.deepEqual(sent, [["skills.request", { request: "today's outfit" }]]);
});

test("skills.find sends the text; it is not taken for a skill name", async () => {
  const sent = [];
  const target = {};
  installSkills(target, async (op, args) => (sent.push([op, args]), []));
  assert.deepEqual(await target.skills.find("오늘 코디"), []);
  assert.deepEqual(sent, [["skills.find", { text: "오늘 코디" }]]);
});
