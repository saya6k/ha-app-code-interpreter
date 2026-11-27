const url = process.argv[2];
try {
  const r = await fetch(url, { signal: AbortSignal.timeout(15000) });
  console.log(JSON.stringify({ status: r.status }));
} catch (e) {
  console.log(JSON.stringify({ error: String(e), cause: e.cause ? String(e.cause.code || e.cause) : null }));
}
