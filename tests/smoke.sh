#!/usr/bin/env bash
set -euo pipefail

export CLIOTP_DATA_DIR=$(mktemp -d)
export CLIOTP_TOKEN=smoke-root-token
PORT=18100 HOST=127.0.0.1 node server.js > /tmp/cliotp-smoke2.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -rf "$CLIOTP_DATA_DIR"' EXIT

for i in $(seq 1 40); do curl -sf http://127.0.0.1:18100/healthz >/dev/null 2>&1 && break; sleep 0.2; done

node --input-type=module <<'NODE'
const base = "http://127.0.0.1:18100";
const root = "smoke-root-token";
async function api(m, p, b, t = root) {
  const h = {};
  if (t) h.Authorization = "Bearer " + t;
  if (b !== undefined) h["Content-Type"] = "application/json";
  const r = await fetch(base + p, { method: m, headers: h, body: b === undefined ? undefined : JSON.stringify(b) });
  const text = await r.text();
  let j = null; try { j = text ? JSON.parse(text) : null; } catch {}
  return { s: r.status, j };
}

let fail = 0;
function check(name, cond) { console.log((cond ? "ok   " : "FAIL ") + name); if (!cond) fail++; }

const html = await fetch(base + "/");
check("GET / serves HTML", html.status === 200 && (await html.text()).includes("<html"));
const js = await fetch(base + "/app.js");
check("GET /app.js serves JS", js.status === 200);
const css = await fetch(base + "/style.css");
check("GET /style.css serves CSS", css.status === 200);

const keys1 = await api("GET", "/api/keys");
check("GET /api/keys lists default key", keys1.s === 200 && keys1.j.some(k => k.name === "default"));
check("keys list never exposes secret/hash", keys1.j[0].secret === undefined && keys1.j[0].keyHash === undefined);

const created = await api("POST", "/api/keys", { name: "laptop" });
check("POST /api/keys returns 64-hex key", created.s === 201 && /^[0-9a-f]{64}$/.test(created.j.key));

const withNew = await api("GET", "/api/entries", undefined, created.j.key);
check("new key authenticates", withNew.s === 200);

const rev = await api("DELETE", `/api/keys/${created.j.id}`);
check("DELETE key works", rev.s === 200);

const after = await api("GET", "/api/entries", undefined, created.j.key);
check("revoked key is rejected (401)", after.s === 401);

const add = await api("POST", "/api/entries", { name: "demo", secret: "JBSWY3DPEHPK3PXP", issuer: "Test" });
check("POST entry works", add.s === 201);

const codes = await api("GET", "/api/codes");
check("GET /api/codes returns a 6-digit code", codes.s === 200 && /^[0-9]{6}$/.test(codes.j[0].code));

const last = (await api("GET", "/api/keys")).j;
const lastRev = await api("DELETE", `/api/keys/${last[0].id}`);
check("cannot revoke last key (400)", lastRev.s === 400);

console.log(fail === 0 ? "\nSMOKE OK" : `\nSMOKE FAILED (${fail})`);
process.exit(fail === 0 ? 0 : 1);
NODE
