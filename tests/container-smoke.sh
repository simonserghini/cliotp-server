#!/usr/bin/env bash
# Live smoke test against the actual Docker image (not `node server.js`).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

TOKEN="container-test-token"
PORT=18082

echo "==> building image"
docker build -q -t cliotp-server:test . >/dev/null
echo "==> starting container"
CID=$(docker run -d --rm -e CLIOTP_TOKEN="$TOKEN" -p 127.0.0.1:$PORT:8080 cliotp-server:test)
cleanup() { docker stop "$CID" >/dev/null 2>&1 || true; }
trap cleanup EXIT

for i in $(seq 1 40); do curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 0.2; done

BASE="http://127.0.0.1:$PORT" TOKEN="$TOKEN" node --input-type=module - <<'NODE'
const base = process.env.BASE, T = process.env.TOKEN;
const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // RFC 4226 "12345678901234567890"
let fail = 0;
const check = (n, c) => { console.log((c ? 'ok   ' : 'FAIL ') + n); if (!c) fail++; };
async function api(m, p, b, t = T) {
  const h = {};
  if (t) h.Authorization = 'Bearer ' + t;
  if (b !== undefined) h['Content-Type'] = 'application/json';
  const r = await fetch(base + p, { method: m, headers: h, body: b === undefined ? undefined : JSON.stringify(b) });
  const txt = await r.text(); let j = null; try { j = txt ? JSON.parse(txt) : null; } catch {}
  return { s: r.status, j };
}

check('healthz ok', (await (await fetch(base + '/healthz')).json()).ok === true);
check('web UI served', (await (await fetch(base + '/')).text()).includes('<html'));
check('import QR UI present', (await (await fetch(base + '/')).text()).includes('Import QR'));
check('jsQR decoder served', (await fetch(base + '/vendor/jsQR.js')).status === 200);
check('unauth 401', (await api('GET', '/api/entries', undefined, null)).s === 401);
check('auth 200', (await api('GET', '/api/entries')).s === 200);

const add = await api('POST', '/api/entries', { name: 'ct', secret: SECRET, kind: 'hotp', algorithm: 'SHA1', counter: 0 });
check('POST entry 201', add.s === 201);

const code = await api('GET', `/api/entries/${add.j[0].id}/code`);
check('HOTP counter 0 == 755224 (RFC vector)', code.j.code === '755224');

const keys = await api('GET', '/api/keys');
check('keys list has default (admin)', keys.s === 200 && keys.j.some((k) => k.name === 'default'));

console.log(fail === 0 ? '\nCONTAINER OK' : `\nCONTAINER FAILED (${fail})`);
process.exit(fail === 0 ? 0 : 1);
NODE
