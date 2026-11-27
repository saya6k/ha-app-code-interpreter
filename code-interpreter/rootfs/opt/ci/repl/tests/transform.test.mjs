// node --test code-interpreter/rootfs/opt/ci/repl/tests
import assert from "node:assert/strict";
import test from "node:test";
import vm from "node:vm";
import { transform } from "../transform.mjs";

const opts = { importModuleDynamically: vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER };
const run = (code) => vm.runInThisContext(transform(code), opts);

test("const, let and var stay defined for the next cell", async () => {
  await run("const t1a = 1; let t1b = 2; var t1c; var t1d = 4");
  assert.deepEqual(await run("[t1a, t1b, t1c, t1d]"), [1, 2, undefined, 4]);
});

test("a name can be declared again, even const", async () => {
  await run("const t2 = 1");
  await run("const t2 = 2");
  assert.equal(await run("t2"), 2);
});

test("destructuring declarations", async () => {
  await run("const {t3a, t3b: [t3c]} = {t3a: 1, t3b: [2]}; let [t3d, ...t3e] = [3, 4, 5]");
  assert.deepEqual(await run("[t3a, t3c, t3d, t3e]"), [1, 2, 3, [4, 5]]);
});

test("functions are hoisted within the cell and persist", async () => {
  assert.equal(await run("const r = t4(2); function t4(x) { return x * 3 } r"), 6);
  assert.equal(await run("t4(5)"), 15);
});

test("classes persist", async () => {
  await run("class T5 { v() { return 7 } }");
  assert.equal(await run("new T5().v()"), 7);
});

test("top-level await and the last expression's value", async () => {
  assert.equal(await run("const t6 = await Promise.resolve(20); t6 + 1"), 21);
  assert.equal(await run("if (true) { 1 }"), undefined);
  assert.equal(await run("let t6b = 1"), undefined);
  assert.equal(await run("'just a string'"), "just a string");
});

test("return ends the cell with a value", async () => {
  assert.equal(await run("if (true) return 'early'; 'late'"), "early");
});

test("imports become dynamic imports bound to globals", async () => {
  await run('import t7fs, { join as t7join } from "node:path"; import * as t7os from "node:os"; import "node:util"');
  assert.equal(await run('t7join("a", "b")'), "a/b");
  assert.equal(typeof (await run("t7fs.basename")), "function");
  assert.equal(typeof (await run("t7os.platform")), "function");
});

test("block-scoped declarations stay local", async () => {
  await run("{ const t8 = 1 }");
  await assert.rejects(run("t8"), ReferenceError);
});

test("error line numbers match the cell", async () => {
  const err = await vm.runInThisContext(transform("const t9 = 1;\n\nnull.x"), { ...opts, filename: "<t9>" }).catch((e) => e);
  assert.ok(err instanceof TypeError);
  assert.match(err.stack, /<t9>:3:/);
});

test("syntax errors come from the parser with a position", () => {
  assert.throws(() => transform("const = 1"), (e) => e instanceof SyntaxError && /\(1:6\)/.test(e.message));
});
