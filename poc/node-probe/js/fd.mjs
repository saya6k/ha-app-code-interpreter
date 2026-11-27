// The REPL channel: one end of an app-made socketpair, inherited by fd number.
import net from "node:net";
const s = new net.Socket({ fd: Number(process.argv[2]), readable: true, writable: true });
s.on("data", (d) => { console.log(JSON.stringify({ got: String(d) })); s.destroy(); });
s.on("error", (e) => { console.log(JSON.stringify({ error: String(e) })); process.exit(1); });
s.write("ping");
