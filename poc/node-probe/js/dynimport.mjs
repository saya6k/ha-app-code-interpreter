import vm from "node:vm";
const opts = { importModuleDynamically: vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER };
try {
  const p = await vm.runInThisContext('(async () => { const os = await import("node:os"); globalThis.kept = 41; return os.platform(); })()', opts);
  console.log(JSON.stringify({ platform: p, kept: vm.runInThisContext("kept + 1") }));
} catch (e) {
  console.log(JSON.stringify({ error: String(e) }));
}
