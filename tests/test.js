import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import * as s from '../server.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// ---------------------------------------------------------------------------
// RFC 4226 / 6238 test vectors (ground truth from the published RFCs)
// ---------------------------------------------------------------------------

const SECRET_ASCII_20 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // "12345678901234567890"
const SECRET_SHA256 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA';
const SECRET_SHA512 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA';

test('RFC 4226 HOTP SHA1 vectors', () => {
  const expected = [755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489];
  expected.forEach((code, counter) => {
    assert.equal(s.hotp(SECRET_ASCII_20, counter, 6, 'SHA1'), String(code), `counter ${counter}`);
  });
});

test('RFC 6238 TOTP SHA1 vectors (8 digits, period 30)', () => {
  const vectors = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ];
  for (const [t, expected] of vectors) {
    assert.equal(s.totp(SECRET_ASCII_20, t, 30, 8, 'SHA1'), expected, `t=${t}`);
  }
});

test('RFC 6238 TOTP SHA256/SHA512 vectors', () => {
  assert.equal(s.totp(SECRET_SHA256, 59, 30, 8, 'SHA256'), '46119246');
  assert.equal(s.totp(SECRET_SHA512, 59, 30, 8, 'SHA512'), '90693936');
});

test('Steam Guard code (cross-checked against the reference implementation)', () => {
  assert.equal(s.steam('JBSWY3DPEHPK3PXP', 1700000000), '2KM2P');
  const code = s.steam('JBSWY3DPEHPK3PXP', 1710000000);
  assert.equal(code.length, 5);
  assert.match(code, /^[23456789BCDFGHJKMNPQRTVWXY]{5}$/);
});

// ---------------------------------------------------------------------------
// base32
// ---------------------------------------------------------------------------

test('base32 encode/decode roundtrip', () => {
  for (const len of [1, 2, 5, 9, 16, 20, 32]) {
    const raw = new Uint8Array(len).map((_, i) => (i * 7 + 3) & 0xff);
    const enc = s.base32Encode(Buffer.from(raw));
    assert.deepEqual(s.base32Decode(enc), Buffer.from(raw), `len ${len}`);
  }
});

// ---------------------------------------------------------------------------
// otpauth / migration parsing
// ---------------------------------------------------------------------------

test('otpauth parse + encode roundtrip', () => {
  const uri = 'otpauth://totp/GitHub:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30';
  const e = s.parseOtpauth(uri);
  assert.equal(e.name, 'alice@example.com');
  assert.equal(e.issuer, 'GitHub');
  assert.equal(e.secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(e.digits, 6);
  assert.equal(e.period, 30);
  assert.equal(s.encodeOtpauth(e), uri);
});

test('Google Authenticator migration import', () => {
  const mig = 'otpauth-migration://offline?data=CjwKDEhlbGxvId6tvu%2B%2BchIRQWRhbSBzY2hvb2wgdGUucCAgASgBMAJCE2E2M2Q3NTE3ODY2MzYzNTU0MjYQAhgBIAA%3D';
  const entries = s.parseMigration(mig);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].name, 'Adam school te.p');
  assert.equal(entries[0].secret, 'JBSWY3DPEHPK3PXPXZZA');
  assert.equal(entries[0].algorithm, 'SHA1');
  assert.equal(entries[0].digits, 6);
  assert.equal(entries[0].kind, 'totp');
});

// ---------------------------------------------------------------------------
// Encryption at rest + store lifecycle
// ---------------------------------------------------------------------------

let tmpDataDir;

before(() => {
  tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cliotp-unit-'));
  process.env.CLIOTP_DATA_DIR = tmpDataDir;
});

after(() => {
  fs.rmSync(tmpDataDir, { recursive: true, force: true });
});

test('AES-256-GCM encryption roundtrip and tamper detection', () => {
  const plain = 'id\tname\tsecret\t6\t30\tSHA1\ttotp\t-';
  const enc = s.encrypt(plain);
  assert.ok(enc !== plain);
  assert.equal(s.decrypt(enc), plain);
  // flip a byte -> auth tag mismatch must throw
  const tampered = enc.slice(0, -1) + (enc.endsWith('A') ? 'B' : 'A');
  assert.throws(() => s.decrypt(tampered));
});

test('store saves encrypted at rest and reloads', () => {
  const entry = { id: 1, name: 'alice', issuer: 'GitHub', secret: 'JBSWY3DPEHPK3PXP', digits: 6, period: 30, algorithm: 'SHA1', kind: 'totp', counter: 0 };
  s.saveStore([entry]);

  const raw = fs.readFileSync(s.storeFile(), 'utf8');
  assert.match(raw, /^cliotp-server-encrypted-v1/);
  assert.ok(!raw.includes('JBSWY3DPEHPK3PXP'), 'secret must not appear in plaintext on disk');

  const loaded = s.loadStore();
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0].secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(loaded[0].name, 'alice');
});

// ---------------------------------------------------------------------------
// API integration (spawn a real server subprocess)
// ---------------------------------------------------------------------------

function startServer() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cliotp-api-'));
  const token = 'integration-test-token';
  const child = spawn(process.execPath, ['server.js'], {
    cwd: ROOT,
    env: { ...process.env, CLIOTP_DATA_DIR: dir, CLIOTP_TOKEN: token, PORT: '0', HOST: '127.0.0.1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return new Promise((resolve, reject) => {
    let out = '';
    let err = '';
    const timer = setTimeout(() => reject(new Error('server did not start\n' + out + err)), 5000);
    child.stdout.on('data', (d) => {
      out += d;
      const m = out.match(/listening on \S+:(\d+)/);
      if (m) {
        clearTimeout(timer);
        resolve({ child, port: Number(m[1]), token, dir, base: `http://127.0.0.1:${m[1]}` });
      }
    });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', reject);
  });
}

function stopServer(ctx) {
  return new Promise((resolve) => {
    ctx.child.on('exit', () => resolve());
    ctx.child.kill('SIGTERM');
    setTimeout(() => { try { ctx.child.kill('SIGKILL'); } catch {} resolve(); }, 2000);
  });
}

let server;

before(async () => {
  server = await startServer();
});

after(async () => {
  await stopServer(server);
  fs.rmSync(server.dir, { recursive: true, force: true });
});

async function req(method, p, body, token = server.token) {
  const headers = {};
  if (token) headers.Authorization = 'Bearer ' + token;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(server.base + p, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* ignore */ }
  return { status: res.status, body: json, raw: text };
}

test('health endpoint is unauthenticated', async () => {
  const res = await req('GET', '/healthz', undefined, null);
  assert.equal(res.status, 200);
  assert.equal(res.body.ok, true);
});

test('API requires a valid bearer token', async () => {
  const noAuth = await req('GET', '/api/entries', undefined, null);
  assert.equal(noAuth.status, 401);
  const badAuth = await req('GET', '/api/entries', undefined, 'wrong-token');
  assert.equal(badAuth.status, 401);
  const good = await req('GET', '/api/entries');
  assert.equal(good.status, 200);
});

test('full entry lifecycle over the API', async () => {
  // add a HOTP entry with the RFC secret -> deterministic codes
  const created = await req('POST', '/api/entries', {
    name: 'rfc', issuer: 'RFC', secret: SECRET_ASCII_20, kind: 'hotp', digits: 6, algorithm: 'SHA1', counter: 0,
  });
  assert.equal(created.status, 201);
  const id = created.body[0].id;

  // first code == RFC c=0, second == c=1 (counter advances server-side)
  const code0 = await req('GET', `/api/entries/${id}/code`);
  assert.equal(code0.status, 200);
  assert.equal(code0.body.code, '755224');
  const code1 = await req('GET', `/api/entries/${id}/code`);
  assert.equal(code1.body.code, '287082');

  // list shows it, no secret leaked
  const list = await req('GET', '/api/entries');
  assert.equal(list.body.length, 1);
  assert.equal(list.body[0].secret, undefined);

  // edit the name
  const edited = await req('PATCH', `/api/entries/${id}`, { name: 'renamed' });
  assert.equal(edited.status, 200);
  assert.equal(edited.body.name, 'renamed');

  // export returns an otpauth URI
  const exported = await req('GET', '/api/export');
  assert.equal(exported.status, 200);
  assert.match(exported.body.entries[0], /^otpauth:\/\/hotp\//);

  // delete
  const del = await req('DELETE', `/api/entries/${id}`);
  assert.equal(del.status, 200);
  const empty = await req('GET', '/api/entries');
  assert.equal(empty.body.length, 0);
});

test('add via otpauth URI and resolve by name substring', async () => {
  const created = await req('POST', '/api/entries', {
    uri: 'otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30',
  });
  assert.equal(created.status, 201);
  assert.equal(created.body[0].name, 'alice');
  assert.equal(created.body[0].issuer, 'GitHub');

  // resolve by substring
  const byName = await req('GET', '/api/entries/alice/code');
  assert.equal(byName.status, 200);
  assert.equal(byName.body.name, 'alice');
  assert.match(byName.body.code, /^\d{6}$/);
});

test('add via Google migration URI imports all accounts', async () => {
  const mig = 'otpauth-migration://offline?data=CjwKDEhlbGxvId6tvu%2B%2BchIRQWRhbSBzY2hvb2wgdGUucCAgASgBMAJCE2E2M2Q3NTE3ODY2MzYzNTU0MjYQAhgBIAA%3D';
  const created = await req('POST', '/api/entries', { uri: mig });
  assert.equal(created.status, 201);
  assert.equal(created.body[0].name, 'Adam school te.p');
});

test('web UI is served without auth', async () => {
  const html = await fetch(server.base + '/');
  assert.equal(html.status, 200);
  assert.match(html.headers.get('content-type'), /text\/html/);
  const body = await html.text();
  assert.match(body, /<html/);
  assert.match(body, /cliotp/);

  const js = await fetch(server.base + '/app.js');
  assert.equal(js.status, 200);
  assert.match(js.headers.get('content-type'), /javascript/);

  const css = await fetch(server.base + '/style.css');
  assert.equal(css.status, 200);
  assert.match(css.headers.get('content-type'), /text\/css/);

  // server source is never served as a static file (traversal neutralized)
  const traversal = await fetch(server.base + '/../server.js');
  assert.notEqual(traversal.status, 200);
  const src = await fetch(server.base + '/server.js');
  assert.notEqual(src.status, 200);
  const srcBody = await src.text();
  assert.ok(!srcBody.includes('createServer'), 'must not leak server source');
});

test('/api/codes peeks at every code without advancing HOTP counters', async () => {
  const created = await req('POST', '/api/entries', {
    name: 'peek', secret: SECRET_ASCII_20, kind: 'hotp', digits: 6, algorithm: 'SHA1', counter: 0,
  });
  const id = created.body[0].id;

  // two peeks must both show the c=0 code and NOT advance the counter
  const peek1 = await req('GET', '/api/codes');
  const e1 = peek1.body.find((e) => e.id === id);
  assert.equal(e1.code, '755224');
  assert.equal(e1.counter, 0);

  const peek2 = await req('GET', '/api/codes');
  const e2 = peek2.body.find((e) => e.id === id);
  assert.equal(e2.code, '755224');
  assert.equal(e2.counter, 0);

  // consuming advances it
  const consumed = await req('GET', `/api/entries/${id}/code`);
  assert.equal(consumed.body.code, '755224');

  const peek3 = await req('GET', '/api/codes');
  const e3 = peek3.body.find((e) => e.id === id);
  assert.equal(e3.code, '287082');
  assert.equal(e3.counter, 1);

  await req('DELETE', `/api/entries/${id}`);
});

test('API key management lifecycle', async () => {
  // list — the bootstrap key exists; no secret/hash is ever exposed
  const list1 = await req('GET', '/api/keys');
  assert.equal(list1.status, 200);
  assert.ok(list1.body.length >= 1);
  assert.equal(list1.body[0].secret, undefined);
  assert.equal(list1.body[0].keyHash, undefined);

  // create a key — secret returned exactly once
  const created = await req('POST', '/api/keys', { name: 'ci-key' });
  assert.equal(created.status, 201);
  assert.match(created.body.key, /^[0-9a-f]{64}$/);
  const newId = created.body.id;

  // the new key authenticates
  const withNew = await req('GET', '/api/entries', undefined, created.body.key);
  assert.equal(withNew.status, 200);

  // revoke it
  const revoked = await req('DELETE', `/api/keys/${newId}`);
  assert.equal(revoked.status, 200);

  // the revoked key no longer works
  const afterRevoke = await req('GET', '/api/entries', undefined, created.body.key);
  assert.equal(afterRevoke.status, 401);

  // the last remaining key cannot be revoked
  const remaining = (await req('GET', '/api/keys')).body;
  assert.equal(remaining.length, 1);
  const lastRevoke = await req('DELETE', `/api/keys/${remaining[0].id}`);
  assert.equal(lastRevoke.status, 400);
});
