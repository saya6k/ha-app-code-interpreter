// Rewrites a cell so its top-level bindings outlive it (stdlib + vendored acorn).
//
// Each cell runs as the body of an async function, for top-level await. On
// their own, its const/let/class/function would vanish when that function
// returns, so they become assignments to globals instead: the next cell sees
// them, and declaring a name again is allowed (const can be reassigned, as in
// a REPL). A last expression statement becomes the return value. The wrapper
// starts on the cell's first line, so error line numbers match the cell.
import { parse } from "./vendor/acorn.mjs";

const OPTIONS = {
  ecmaVersion: "latest",
  sourceType: "script",
  allowAwaitOutsideFunction: true,
  allowReturnOutsideFunction: true,
  allowImportExportEverywhere: true,
};

function importAsAssignments(node, src) {
  const from = src(node.source);
  if (!node.specifiers.length) return `await import(${from});`;
  const parts = [];
  const named = [];
  for (const s of node.specifiers) {
    if (s.type === "ImportDefaultSpecifier") parts.push(`${s.local.name} = __ci_m.default;`);
    else if (s.type === "ImportNamespaceSpecifier") parts.push(`${s.local.name} = __ci_m;`);
    else named.push(`${src(s.imported)}: ${s.local.name}`);
  }
  if (named.length) parts.push(`({${named.join(", ")}} = __ci_m);`);
  return `{ const __ci_m = await import(${from}); ${parts.join(" ")} }`;
}

export function transform(code) {
  const ast = parse(code, OPTIONS);
  const src = (n) => code.slice(n.start, n.end);
  const edits = [];
  const hoisted = [];
  ast.body.forEach((node, i) => {
    switch (node.type) {
      case "VariableDeclaration": {
        const parts = node.declarations.map((d) => `(${src(d.id)} = ${d.init ? src(d.init) : "undefined"})`);
        edits.push([node.start, node.end, `void (${parts.join(", ")});`]);
        break;
      }
      case "FunctionDeclaration":
        // Left in place so it stays hoisted within the cell; published at the top.
        hoisted.push(node.id.name);
        break;
      case "ClassDeclaration":
        edits.push([node.start, node.end, `${node.id.name} = ${src(node)};`]);
        break;
      case "ImportDeclaration":
        edits.push([node.start, node.end, importAsAssignments(node, src)]);
        break;
      case "ExpressionStatement":
        // A lone string literal parses as a directive ("use strict" kind); as
        // the last statement it is still the value the cell asked for.
        if (i === ast.body.length - 1) {
          edits.push([node.start, node.end, `return (${src(node.expression)});`]);
        }
        break;
    }
  });
  let body = code;
  for (const [start, end, text] of edits.reverse()) body = body.slice(0, start) + text + body.slice(end);
  const publish = hoisted.map((n) => `globalThis.${n} = ${n};`).join(" ");
  return `(async () => {${publish} ${body}\n})()`;
}
