#!/usr/bin/env node
// cliotp-server — self-hosted TOTP / HOTP / Steam Guard server.
// One file, zero runtime dependencies (Node >= 18). Implements RFC 4226/6238
// with the built-in crypto module, stores entries encrypted at rest
// (AES-256-GCM), and serves them over a bearer-token-authenticated REST API.
//
//   node server.js                    # run (reads config from env)
//   import * as s from './server.js'  # use as a library in tests

import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { pathToFileURL } from 'node:url';

export const VERSION = '0.1.0';

// ---------------------------------------------------------------------------
// Config / storage paths
// ---------------------------------------------------------------------------

export function dataDir() {
  if (process.env.CLIOTP_DATA_DIR) return process.env.CLIOTP_DATA_DIR;
  const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
  return path.join(base, 'cliotp-server');
}

export const storeFile = () => path.join(dataDir(), 'secrets.tsv');
export const keyFile = () => path.join(dataDir(), 'master.key');
export const tokenFile = () => path.join(dataDir(), 'api.token');

export const STORE_HEADER = 'cliotp-server-encrypted-v1';

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

export function normalizeSecret(s) {
  return String(s).replace(/[\s\-=]/g, '').toUpperCase();
}

export function normalizeAlgorithm(a) {
  const n = String(a || 'SHA1').replace(/-/g, '').toUpperCase();
  if (n === 'SHA1') return 'SHA1';
  if (n === 'SHA256') return 'SHA256';
  if (n === 'SHA512') return 'SHA512';
  throw new Error(`unknown algorithm "${a}" (use SHA1, SHA256, or SHA512)`);
}

const algoName = (a) => normalizeAlgorithm(a).toLowerCase(); // SHA256 -> sha256

// Percent-encode every byte except ASCII alphanumerics and : - _ . ~
export function pctEncode(s) {
  let out = '';
  for (const ch of String(s)) {
    const c = ch.codePointAt(0);
    if (
      (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) ||
      (c >= 0x61 && c <= 0x7a) || c === 0x3a || c === 0x2d ||
      c === 0x5f || c === 0x2e || c === 0x7e
    ) {
      out += ch;
    } else {
      for (const byte of Buffer.from(ch, 'utf8')) {
        out += '%' + byte.toString(16).toUpperCase().padStart(2, '0');
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// base32
// ---------------------------------------------------------------------------

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(s) {
  const cleaned = String(s).toUpperCase().replace(/[\s\-=]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const ch of cleaned) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error(`invalid base32 character "${ch}"`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

// ---------------------------------------------------------------------------
// OTP crypto (RFC 4226 / 6238)
// ---------------------------------------------------------------------------

function counterBytes(counter) {
  const b = Buffer.alloc(8);
  let v = BigInt(Math.trunc(counter));
  for (let i = 7; i >= 0; i--) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

function dynamicTruncate(hmac, digits) {
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  return (bin % (10 ** digits)).toString().padStart(digits, '0');
}

export function hotp(secret, counter, digits, algorithm = 'SHA1') {
  const key = base32Decode(secret);
  const hmac = crypto.createHmac(algoName(algorithm), key).update(counterBytes(counter)).digest();
  return dynamicTruncate(hmac, digits);
}

export function totp(secret, unix, period, digits, algorithm = 'SHA1') {
  return hotp(secret, Math.floor(unix / period), digits, algorithm);
}

const STEAM_ALPHABET = '23456789BCDFGHJKMNPQRTVWXY';

export function steam(secret, unix) {
  const key = base32Decode(secret);
  const hmac = crypto.createHmac('sha1', key).update(counterBytes(Math.floor(unix / 30))).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  let n =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  let out = '';
  for (let i = 0; i < 5; i++) {
    out += STEAM_ALPHABET[n % 26];
    n = Math.floor(n / 26);
  }
  return out;
}

export function secondsRemaining(period, now) {
  return period - (now % period);
}

// ---------------------------------------------------------------------------
// Entry model (TSV: id  name  issuer  secret  digits  period  algorithm  kind  counter)
// ---------------------------------------------------------------------------

export function parseLine(line) {
  const [id, name, issuer, secret, digits, period, algorithm, kind, counter] = String(line).split('\t');
  return {
    id: Number(id),
    name,
    issuer: issuer === '-' || issuer == null ? '' : issuer,
    secret: normalizeSecret(secret),
    digits: Number(digits),
    period: Number(period),
    algorithm: algorithm || 'SHA1',
    kind: kind || 'totp',
    counter: counter === '-' || counter == null || counter === '' ? 0 : Number(counter),
  };
}

export function serialize(entry) {
  const issuer = entry.issuer && entry.issuer !== '' ? entry.issuer : '-';
  const counter = entry.kind === 'hotp' ? (entry.counter ?? 0) : '-';
  return [
    entry.id, entry.name, issuer, normalizeSecret(entry.secret),
    entry.digits, entry.period, entry.algorithm, entry.kind, counter,
  ].join('\t');
}

export const label = (e) => (e.issuer ? `${e.issuer}: ${e.name}` : e.name);

export function nextId(entries) {
  return entries.reduce((m, e) => Math.max(m, e.id), 0) + 1;
}

// ---------------------------------------------------------------------------
// otpauth:// and otpauth-migration:// parsing
// ---------------------------------------------------------------------------

export function parseOtpauth(uri) {
  const m = String(uri).match(/^otpauth:\/\/(totp|hotp)\/([^?]+)\?(.*)$/i);
  if (!m) throw new Error('not a valid otpauth:// URI');
  const kind = m[1].toLowerCase();
  const labelPart = decodeURIComponent(m[2]);
  const qs = new URLSearchParams(m[3]);
  const secret = normalizeSecret(qs.get('secret') || '');
  if (!secret) throw new Error('otpauth URI is missing a secret');
  base32Decode(secret); // validate

  let name = labelPart;
  let issuer = qs.get('issuer') || '';
  const colon = labelPart.indexOf(':');
  if (colon > 0) {
    if (!issuer) issuer = labelPart.slice(0, colon);
    name = labelPart.slice(colon + 1);
  }

  const digits = Number(qs.get('digits') || 6);
  const period = Number(qs.get('period') || 30);
  const algorithm = normalizeAlgorithm(qs.get('algorithm') || 'SHA1');
  const counter = kind === 'hotp' ? Number(qs.get('counter') || 0) : 0;

  return { id: 0, name, issuer, secret, digits, period, algorithm, kind, counter };
}

export function encodeOtpauth(entry) {
  const type = entry.kind === 'hotp' ? 'hotp' : 'totp';
  const lbl = entry.issuer ? `${entry.issuer}:${entry.name}` : entry.name;
  let q = `secret=${pctEncode(normalizeSecret(entry.secret))}`;
  if (entry.issuer) q += `&issuer=${pctEncode(entry.issuer)}`;
  q += `&algorithm=${entry.algorithm}&digits=${entry.digits}&period=${entry.period}`;
  if (entry.kind === 'hotp') q += `&counter=${entry.counter ?? 0}`;
  return `otpauth://${type}/${pctEncode(lbl)}?${q}`;
}

// Minimal protobuf reader for Google Authenticator "transfer accounts" exports.
function readVarint(buf, pos) {
  let result = 0n, shift = 0n, b;
  do {
    b = buf[pos++];
    result |= BigInt(b & 0x7f) << shift;
    shift += 7n;
  } while (b & 0x80);
  return [result, pos];
}

function parseOtpParameters(buf) {
  let secret = Buffer.alloc(0), name = '', issuer = '';
  let algorithm = 1, digits = 1, type = 2, counter = 0;
  let pos = 0;
  while (pos < buf.length) {
    const [tag, p2] = readVarint(buf, pos);
    pos = p2;
    const field = Number(tag >> 3n);
    const wire = Number(tag & 7n);
    if (wire === 0) {
      const [v, p3] = readVarint(buf, pos);
      pos = p3;
      if (field === 4) algorithm = Number(v);
      else if (field === 5) digits = Number(v);
      else if (field === 6) type = Number(v);
      else if (field === 7) counter = Number(v);
    } else if (wire === 2) {
      const [len, p3] = readVarint(buf, pos);
      pos = p3;
      const n = Number(len);
      const slice = buf.subarray(pos, pos + n);
      pos += n;
      if (field === 1) secret = Buffer.from(slice);
      else if (field === 2) name = slice.toString('utf8');
      else if (field === 3) issuer = slice.toString('utf8');
    } else {
      throw new Error(`unsupported protobuf wire type ${wire}`);
    }
  }
  const algMap = { 1: 'SHA1', 2: 'SHA256', 3: 'SHA512' };
  const digitsMap = { 1: 6, 2: 8 };
  const kindMap = { 1: 'hotp', 2: 'totp' };
  const kind = kindMap[type] ?? 'totp';
  return {
    id: 0,
    name: name.replace(/\s+$/, ''), // sample vector has trailing space
    issuer,
    secret: base32Encode(secret),
    digits: digitsMap[digits] ?? 6,
    period: 30,
    algorithm: algMap[algorithm] ?? 'SHA1',
    kind,
    counter: kind === 'hotp' ? counter : 0,
  };
}

export function parseMigration(uri) {
  const m = String(uri).match(/^otpauth-migration:\/\/offline\?data=([^&]+)/i);
  if (!m) throw new Error('not a valid otpauth-migration:// URI');
  const decoded = decodeURIComponent(m[1]);
  const b64 = decoded.replace(/-/g, '+').replace(/_/g, '/');
  const buf = Buffer.from(b64, 'base64');
  const entries = [];
  let pos = 0;
  while (pos < buf.length) {
    const [tag, p2] = readVarint(buf, pos);
    pos = p2;
    const field = Number(tag >> 3n);
    const wire = Number(tag & 7n);
    if (wire === 2) {
      const [len, p3] = readVarint(buf, pos);
      pos = p3;
      const n = Number(len);
      const slice = buf.subarray(pos, pos + n);
      pos += n;
      if (field === 1) entries.push(parseOtpParameters(slice));
    } else if (wire === 0) {
      const [, p3] = readVarint(buf, pos);
      pos = p3;
    } else {
      throw new Error(`unsupported protobuf wire type ${wire}`);
    }
  }
  if (entries.length === 0) throw new Error('migration export contained no entries');
  return entries;
}

// ---------------------------------------------------------------------------
// Encryption at rest (AES-256-GCM, key from master.key)
// ---------------------------------------------------------------------------

function loadMasterKey() {
  const p = keyFile();
  if (!fs.existsSync(p)) {
    fs.mkdirSync(dataDir(), { recursive: true, mode: 0o700 });
    fs.writeFileSync(p, crypto.randomBytes(32), { mode: 0o600 });
  }
  const raw = fs.readFileSync(p);
  if (raw.length !== 32) throw new Error(`${p} must contain exactly 32 bytes`);
  return raw;
}

export function encrypt(plain, key = loadMasterKey()) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64');
}

export function decrypt(payload, key = loadMasterKey()) {
  const buf = Buffer.from(String(payload), 'base64');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const enc = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

// ---------------------------------------------------------------------------
// Store load/save (atomic, encrypted)
// ---------------------------------------------------------------------------

export function loadStore() {
  const p = storeFile();
  if (!fs.existsSync(p)) return [];
  const content = fs.readFileSync(p, 'utf8');
  const lines = content.split('\n');
  let body;
  if (lines[0] === STORE_HEADER) {
    body = decrypt(lines.slice(1).join('\n'));
  } else {
    body = content; // legacy plaintext, auto-migrates on next save
  }
  return body.split('\n').filter((l) => l.trim() !== '').map(parseLine);
}

export function saveStore(entries) {
  const p = storeFile();
  fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
  const body = entries.map(serialize).join('\n');
  const tmp = `${p}.tmp.${process.pid}.${crypto.randomBytes(4).toString('hex')}`;
  fs.writeFileSync(tmp, STORE_HEADER + '\n' + encrypt(body) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, p);
  fs.chmodSync(p, 0o600);
  try { fs.chmodSync(path.dirname(p), 0o700); } catch {}
}

// A simple async mutex so concurrent requests can't interleave load/modify/save.
let chain = Promise.resolve();
export function withLock(fn) {
  const run = chain.then(fn, fn);
  chain = run.catch(() => {});
  return run;
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export function loadToken() {
  if (process.env.CLIOTP_TOKEN) return process.env.CLIOTP_TOKEN;
  const p = tokenFile();
  if (fs.existsSync(p)) return fs.readFileSync(p, 'utf8').trim();
  fs.mkdirSync(dataDir(), { recursive: true, mode: 0o700 });
  const tok = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(p, tok + '\n', { mode: 0o600 });
  return tok;
}

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// ---------------------------------------------------------------------------
// Code generation for a stored entry
// ---------------------------------------------------------------------------

export function generateCode(entry, now = Math.floor(Date.now() / 1000)) {
  if (entry.kind === 'totp') {
    return {
      code: totp(entry.secret, now, entry.period, entry.digits, entry.algorithm),
      secondsRemaining: secondsRemaining(entry.period, now),
    };
  }
  if (entry.kind === 'steam') {
    return { code: steam(entry.secret, now), secondsRemaining: secondsRemaining(30, now) };
  }
  if (entry.kind === 'hotp') {
    return { code: hotp(entry.secret, entry.counter ?? 0, entry.digits, entry.algorithm), counter: entry.counter ?? 0 };
  }
  throw new Error(`unknown kind "${entry.kind}"`);
}

// ---------------------------------------------------------------------------
// Entry building / validation
// ---------------------------------------------------------------------------

function buildEntry(input) {
  const name = String(input.name || '').trim();
  if (!name) throw new Error('name is required');
  const secret = normalizeSecret(input.secret || '');
  if (!secret) throw new Error('secret is required');
  base32Decode(secret); // throws if invalid

  const kind = String(input.kind || 'totp').toLowerCase();
  if (!['totp', 'hotp', 'steam'].includes(kind)) {
    throw new Error('kind must be totp, hotp, or steam');
  }
  let digits = Number(input.digits ?? 6);
  let period = Number(input.period ?? 30);
  if (kind === 'steam') { digits = 5; period = 30; }
  if (kind !== 'steam' && digits !== 6 && digits !== 8) {
    throw new Error('digits must be 6 or 8');
  }
  const algorithm = normalizeAlgorithm(input.algorithm || 'SHA1');
  const counter = kind === 'hotp' ? Number(input.counter ?? 0) : 0;
  return { id: 0, name, issuer: String(input.issuer || '').trim(), secret, digits, period, algorithm, kind, counter };
}

function applyEdit(entry, patch) {
  const allowed = ['name', 'issuer', 'secret', 'digits', 'period', 'algorithm', 'kind', 'counter'];
  const merged = { ...entry };
  for (const k of allowed) {
    if (k in patch && patch[k] !== undefined) merged[k] = patch[k];
  }
  // rebuild through the validator, preserving identity fields
  const fresh = buildEntry({
    name: merged.name,
    secret: merged.secret,
    issuer: merged.issuer,
    digits: merged.digits,
    period: merged.period,
    algorithm: merged.algorithm,
    kind: merged.kind,
    counter: merged.counter,
  });
  fresh.id = entry.id;
  return fresh;
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

class HttpError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 1_000_000) { reject(new HttpError(413, 'payload too large')); req.destroy(); return; }
      data += c;
    });
    req.on('end', () => {
      if (data.trim() === '') return resolve({});
      try { resolve(JSON.parse(data)); }
      catch { reject(new HttpError(400, 'invalid JSON body')); }
    });
    req.on('error', reject);
  });
}

function publicEntry(e) {
  return { id: e.id, name: e.name, issuer: e.issuer, digits: e.digits, period: e.period, algorithm: e.algorithm, kind: e.kind, counter: e.kind === 'hotp' ? e.counter : undefined };
}

export function createServer(options = {}) {
  const token = options.token || loadToken();

  function resolveEntry(entries, ref) {
    if (/^\d+$/.test(ref)) {
      const n = Number(ref);
      const byId = entries.find((e) => e.id === n);
      if (byId) return byId;
      if (n >= 1 && n <= entries.length) return entries[n - 1];
      throw new HttpError(404, `no entry with id/index ${ref}`);
    }
    const needle = ref.toLowerCase();
    const matches = entries.filter((e) => label(e).toLowerCase().includes(needle));
    if (matches.length === 1) return matches[0];
    if (matches.length === 0) throw new HttpError(404, `no entry matches "${ref}"`);
    throw new HttpError(409, `"${ref}" is ambiguous: ${matches.map(label).join(', ')}`);
  }

  const handler = async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname.replace(/\/+$/, '') || '/';

    try {
      if (req.method === 'GET' && p === '/healthz') {
        return json(res, 200, { ok: true, version: VERSION });
      }

      // Everything under /api requires auth.
      const auth = req.headers.authorization || '';
      const bearer = auth.startsWith('Bearer ') ? auth.slice(7) : '';
      const provided = bearer || req.headers['x-api-token'] || '';
      if (!provided || !safeEqual(provided, token)) {
        res.setHeader('WWW-Authenticate', 'Bearer');
        return json(res, 401, { error: 'unauthorized' });
      }

      // GET /api/entries
      if (req.method === 'GET' && p === '/api/entries') {
        return json(res, 200, loadStore().map(publicEntry));
      }

      // POST /api/entries  { ...fields } | { uri }
      if (req.method === 'POST' && p === '/api/entries') {
        const body = await readJsonBody(req);
        return withLock(() => {
          const entries = loadStore();
          let added;
          if (body.uri) {
            const u = String(body.uri);
            if (/^otpauth-migration:\/\//i.test(u)) {
              const parsed = parseMigration(u);
              for (const e of parsed) { e.id = nextId(entries); entries.push(e); }
              added = parsed;
            } else {
              const e = parseOtpauth(u);
              e.id = nextId(entries);
              entries.push(e);
              added = [e];
            }
          } else {
            const e = buildEntry(body);
            e.id = nextId(entries);
            entries.push(e);
            added = [e];
          }
          saveStore(entries);
          return json(res, 201, added.map(publicEntry));
        });
      }

      // GET /api/export  (all otpauth URIs — sensitive)
      if (req.method === 'GET' && p === '/api/export') {
        return json(res, 200, { entries: loadStore().map(encodeOtpauth) });
      }

      // Entry-scoped routes: /api/entries/:id[...]
      const entryMatch = p.match(/^\/api\/entries\/([^/]+)(?:\/(code|uri))?$/);
      if (entryMatch) {
        const ref = decodeURIComponent(entryMatch[1]);
        const sub = entryMatch[2];

        if (sub === 'code') {
          if (req.method !== 'GET') throw new HttpError(405, 'method not allowed');
          return withLock(() => {
            const entries = loadStore();
            const entry = resolveEntry(entries, ref);
            const gen = generateCode(entry);
            if (entry.kind === 'hotp') {
              entry.counter = (entry.counter ?? 0) + 1;
              saveStore(entries);
            }
            return json(res, 200, { id: entry.id, name: entry.name, issuer: entry.issuer, kind: entry.kind, ...gen });
          });
        }

        if (sub === 'uri') {
          if (req.method !== 'GET') throw new HttpError(405, 'method not allowed');
          const entry = resolveEntry(loadStore(), ref);
          return json(res, 200, { uri: encodeOtpauth(entry) });
        }

        if (req.method === 'GET') {
          const entry = resolveEntry(loadStore(), ref);
          return json(res, 200, publicEntry(entry));
        }

        if (req.method === 'DELETE') {
          return withLock(() => {
            const entries = loadStore();
            const entry = resolveEntry(entries, ref);
            const remaining = entries.filter((e) => e.id !== entry.id);
            saveStore(remaining);
            return json(res, 200, { removed: publicEntry(entry) });
          });
        }

        if (req.method === 'PATCH') {
          const body = await readJsonBody(req);
          return withLock(() => {
            const entries = loadStore();
            const entry = resolveEntry(entries, ref);
            const updated = applyEdit(entry, body);
            const idx = entries.findIndex((e) => e.id === entry.id);
            entries[idx] = updated;
            saveStore(entries);
            return json(res, 200, publicEntry(updated));
          });
        }

        throw new HttpError(405, 'method not allowed');
      }

      throw new HttpError(404, 'not found');
    } catch (err) {
      if (err instanceof HttpError) return json(res, err.code, { error: err.message });
      console.error(err);
      return json(res, 500, { error: 'internal server error' });
    }
  };

  const hasTls = Boolean(options.tlsCert && options.tlsKey);
  if (hasTls) {
    return https.createServer({
      cert: fs.readFileSync(options.tlsCert),
      key: fs.readFileSync(options.tlsKey),
    }, handler);
  }
  return http.createServer(handler);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function main() {
  const port = Number(process.env.PORT || 8080);
  const host = process.env.HOST || '0.0.0.0';
  const tlsCert = process.env.CLIOTP_TLS_CERT;
  const tlsKey = process.env.CLIOTP_TLS_KEY;

  const token = loadToken();
  const isNew = process.env.CLIOTP_TOKEN ? false : !fs.existsSync(tokenFile());
  const server = createServer({ token, tlsCert, tlsKey });

  server.listen(port, host, () => {
    const scheme = tlsCert && tlsKey ? 'https' : 'http';
    const actualPort = server.address().port;
    // eslint-disable-next-line no-console
    console.log(`cliotp-server ${VERSION} listening on ${scheme}://${host}:${actualPort}`);
    // eslint-disable-next-line no-console
    console.log(`data dir: ${dataDir()}`);
    if (isNew) {
      // eslint-disable-next-line no-console
      console.log(`generated API token (save it!): ${token}`);
    }
  });
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) main();
