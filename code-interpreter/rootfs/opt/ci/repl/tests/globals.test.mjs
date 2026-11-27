// node --test code-interpreter/rootfs/opt/ci/repl/tests
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-"));
process.env.CI_SANDBOX_DIR = dir;
const g = {};
const { install, quote, ShellError } = await import("../globals.mjs");
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
