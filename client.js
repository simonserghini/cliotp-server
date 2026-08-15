#!/usr/bin/env node
// cliotpc — terminal client for cliotp-server.
// Zero dependencies. Talks to a self-hosted cliotp-server over HTTPS/HTTP.
//
//   export CLIOTP_SERVER=https://vps.example.com
//   export CLIOTP_TOKEN=...
//   cliotpc list
//   cliotpc code alice            # prints just the code (pipeable)
//   cliotpc add alice --secret JBSWY3DPEHPK3PXP --issuer GitHub

import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const VERSION = '0.1.0';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

function configPath() {
  return process.env.CLIOTP_CONFIG || path.join(os.homedir(), '.config', 'cliotp', 'client.conf');
}

function loadConfig() {
  const cfg = { server: process.env.CLIOTP_SERVER || '', token: process.env.CLIOTP_TOKEN || '' };
  const p = configPath();
  if (fs.existsSync(p)) {
    for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
      const m = line.match(/^([a-z_]+)\s*=\s*(.*)$/);
      if (m) {
        const key = m[1], val = m[2].trim();
        if (key === 'server' && !cfg.server) cfg.server = val;
        else if (key === 'token' && !cfg.token) cfg.token = val;
      }
    }
  }
  return cfg;
}

function die(msg) {
  console.error('error: ' + msg);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// HTTP request (uses node:http/https so --insecure can skip TLS verification)
// ---------------------------------------------------------------------------

function request(cfg, method, p, body, insecure) {
  if (!cfg.server) die('no server configured (set CLIOTP_SERVER, --server, or server= in ' + configPath() + ')');
  if (!cfg.token) die('no token configured (set CLIOTP_TOKEN, --token, or token= in ' + configPath() + ')');

  let u;
  try {
    u = new URL(p, cfg.server.replace(/\/?$/, '/'));
  } catch {
    die('invalid server URL: ' + cfg.server);
  }
  const mod = u.protocol === 'https:' ? https : http;
  const data = body === undefined ? null : JSON.stringify(body);
  const headers = {
    Accept: 'application/json',
    Authorization: 'Bearer ' + cfg.token,
  };
  if (data !== null) headers['Content-Type'] = 'application/json';
  if (data !== null) headers['Content-Length'] = Buffer.byteLength(data);

  const opts = { method, headers };
  if (u.protocol === 'https:' && insecure) opts.rejectUnauthorized = false;

  return new Promise((resolve, reject) => {
    const req = mod.request(u, opts, (res) => {
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', (c) => (buf += c));
      res.on('end', () => {
        let parsed = null;
        try { parsed = buf ? JSON.parse(buf) : null; } catch { /* keep raw */ }
        resolve({ status: res.statusCode || 0, body: parsed, raw: buf });
      });
    });
    req.on('error', reject);
    if (data !== null) req.write(data);
    req.end();
  });
}

async function api(cfg, method, p, body, insecure) {
  let res;
  try {
    res = await request(cfg, method, p, body, insecure);
  } catch (e) {
    die('request failed: ' + e.message);
  }
  if (res.status === 401) die('unauthorized — check your token');
  if (res.status >= 400) {
    die((res.body && res.body.error) || `HTTP ${res.status} ${res.raw}`);
  }
  return res.body;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function usage() {
  console.log(`cliotpc ${VERSION} — client for cliotp-server

Usage:
  cliotpc [GLOBAL FLAGS] <command> [args]

Commands:
  list                 List all entries
  code <id|name>       Print the current code (TOTP/HOTP/Steam)
  show <id|name>       Show entry details + live code
  add <name> --secret <S> [--issuer <I>] [--digits 6|8] [--period N] [--algorithm SHA1|SHA256|SHA512] [--kind totp|hotp|steam]
  add "otpauth://..."              Add from an otpauth:// URI
  add "otpauth-migration://..."    Import a Google Authenticator export
  edit <id|name> --issuer Work --name Alice   Change fields
  rm <id|name>         Remove an entry
  uri <id|name>        Print the otpauth:// URI
  export               Print all otpauth:// URIs (backup)

Global flags:
  --server <URL>       Server base URL (or CLIOTP_SERVER)
  --token <TOKEN>      Bearer token (or CLIOTP_TOKEN)
  --insecure           Skip TLS certificate verification (self-signed only)
  -c, --clip           Copy the code to the clipboard (wl-copy/xclip/xsel)
  -v, --verbose        Include label and seconds-remaining
  -h, --help           Print help
  -V, --version        Print version

Config file (optional): ${configPath()}
  server=https://vps.example.com
  token=YOUR_TOKEN
`);
}

function parseFlags(argv) {
  const cfg = loadConfig();
  let insecure = false;
  const global = [];
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--server') { cfg.server = argv[++i]; }
    else if (a.startsWith('--server=')) { cfg.server = a.slice('--server='.length); }
    else if (a === '--token') { cfg.token = argv[++i]; }
    else if (a.startsWith('--token=')) { cfg.token = a.slice('--token='.length); }
    else if (a === '--insecure') { insecure = true; }
    else if (a === '-h' || a === '--help') { global.push('help'); }
    else if (a === '-V' || a === '--version') { global.push('version'); }
    else { rest.push(a); }
  }
  return { cfg, insecure, global, rest };
}

function copyClipboard(text) {
  for (const cmd of ['wl-copy', 'xclip', 'xsel']) {
    const full = cmd === 'xclip' ? 'xclip -selection clipboard' : cmd === 'xsel' ? 'xsel --clipboard --input' : cmd;
    const bin = full.split(' ')[0];
    if (spawnSync(bin, full.split(' ').slice(1), { input: text, stdio: ['pipe', 'ignore', 'ignore'] }).status === 0) {
      return true;
    }
  }
  return false;
}

async function main() {
  const { cfg, insecure, global, rest } = parseFlags(process.argv.slice(2));
  if (global.includes('help') || rest.length === 0) return usage();
  if (global.includes('version')) { console.log('cliotpc ' + VERSION); return; }

  const cmd = rest[0];
  const args = rest.slice(1);

  // command-local flags (only -c/-v matter after the command)
  let clip = false, verbose = false;
  const positional = [];
  for (const a of args) {
    if (a === '-c' || a === '--clip') clip = true;
    else if (a === '-v' || a === '--verbose') verbose = true;
    else positional.push(a);
  }

  switch (cmd) {
    case 'list':
    case 'ls': {
      const entries = await api(cfg, 'GET', '/api/entries', undefined, insecure);
      if (entries.length === 0) { console.log('no entries yet — add one with "cliotpc add ..."'); return; }
      for (const e of entries) {
        console.log(`${String(e.id).padStart(3)}  [${e.kind}]  ${e.issuer ? e.issuer + ': ' : ''}${e.name}`);
      }
      return;
    }

    case 'code':
    case 'token':
    case 'get': {
      const target = positional[0];
      if (!target) die('code requires a target');
      const res = await api(cfg, 'GET', '/api/entries/' + encodeURIComponent(target) + '/code', undefined, insecure);
      if (clip && !copyClipboard(res.code)) die('clipboard copy failed (need wl-copy, xclip, or xsel)');
      if (verbose) {
        const lbl = (res.issuer ? res.issuer + ': ' : '') + res.name;
        if (res.kind === 'hotp') console.log(`${res.code}  ${lbl}  [hotp]  counter=${res.counter}`);
        else console.log(`${res.code}  ${lbl}  [${res.kind}]  ${res.secondsRemaining}s left`);
      } else {
        console.log(res.code);
      }
      return;
    }

    case 'show': {
      const target = positional[0];
      if (!target) die('show requires a target');
      const entry = await api(cfg, 'GET', '/api/entries/' + encodeURIComponent(target), undefined, insecure);
      const res = await api(cfg, 'GET', '/api/entries/' + encodeURIComponent(target) + '/code', undefined, insecure);
      console.log('name:      ' + entry.name);
      if (entry.issuer) console.log('issuer:    ' + entry.issuer);
      console.log('type:      ' + entry.kind);
      console.log('algorithm: ' + entry.algorithm);
      console.log('digits:    ' + entry.digits);
      if (entry.kind === 'hotp') console.log('counter:   ' + entry.counter);
      else console.log('period:    ' + entry.period + 's');
      const lbl = (entry.issuer ? entry.issuer + ': ' : '') + entry.name;
      if (entry.kind === 'hotp') console.log(`${res.code}  ${lbl}  [hotp]  counter=${res.counter}`);
      else console.log(`${res.code}  ${lbl}  [${entry.kind}]  ${res.secondsRemaining}s left`);
      return;
    }

    case 'add': {
      const target = positional[0];
      if (!target) die('add requires a name, an otpauth:// URI, or an otpauth-migration:// URI');
      if (/^otpauth(-migration)?:\/\//i.test(target)) {
        const added = await api(cfg, 'POST', '/api/entries', { uri: target }, insecure);
        for (const e of added) console.log(`added ${e.id}: ${e.issuer ? e.issuer + ': ' : ''}${e.name}`);
        return;
      }
      const body = { name: target };
      for (let i = 1; i < positional.length; i++) {
        const a = positional[i];
        const next = positional[i + 1];
        if (a === '--secret') { body.secret = next; i++; }
        else if (a.startsWith('--secret=')) body.secret = a.slice('--secret='.length);
        else if (a === '--issuer') { body.issuer = next; i++; }
        else if (a.startsWith('--issuer=')) body.issuer = a.slice('--issuer='.length);
        else if (a === '--digits') { body.digits = Number(next); i++; }
        else if (a === '--period') { body.period = Number(next); i++; }
        else if (a === '--algorithm') { body.algorithm = next; i++; }
        else if (a === '--kind') { body.kind = next; i++; }
        else if (a === '--counter') { body.counter = Number(next); i++; }
        else if (!a.startsWith('--')) { die('unexpected argument: ' + a); }
      }
      const added = await api(cfg, 'POST', '/api/entries', body, insecure);
      for (const e of added) console.log(`added ${e.id}: ${e.issuer ? e.issuer + ': ' : ''}${e.name}`);
      return;
    }

    case 'edit': {
      const target = positional[0];
      if (!target) die('edit requires a target');
      const patch = {};
      for (let i = 1; i < positional.length; i++) {
        const a = positional[i];
        const next = positional[i + 1];
        if (a === '--name') { patch.name = next; i++; }
        else if (a.startsWith('--name=')) patch.name = a.slice('--name='.length);
        else if (a === '--issuer') { patch.issuer = next; i++; }
        else if (a.startsWith('--issuer=')) patch.issuer = a.slice('--issuer='.length);
        else if (a === '--secret') { patch.secret = next; i++; }
        else if (a === '--digits') { patch.digits = Number(next); i++; }
        else if (a === '--period') { patch.period = Number(next); i++; }
        else if (a === '--algorithm') { patch.algorithm = next; i++; }
        else if (a === '--kind') { patch.kind = next; i++; }
        else if (a === '--counter') { patch.counter = Number(next); i++; }
        else if (!a.startsWith('--')) die('unexpected argument: ' + a);
      }
      if (Object.keys(patch).length === 0) die('edit requires at least one --field change');
      const e = await api(cfg, 'PATCH', '/api/entries/' + encodeURIComponent(target), patch, insecure);
      console.log(`updated ${e.id}: ${e.issuer ? e.issuer + ': ' : ''}${e.name}`);
      return;
    }

    case 'rm':
    case 'remove':
    case 'delete': {
      const target = positional[0];
      if (!target) die('rm requires a target');
      const res = await api(cfg, 'DELETE', '/api/entries/' + encodeURIComponent(target), undefined, insecure);
      console.log(`removed ${res.removed.id}: ${res.removed.issuer ? res.removed.issuer + ': ' : ''}${res.removed.name}`);
      return;
    }

    case 'uri': {
      const target = positional[0];
      if (!target) die('uri requires a target');
      const res = await api(cfg, 'GET', '/api/entries/' + encodeURIComponent(target) + '/uri', undefined, insecure);
      console.log(res.uri);
      return;
    }

    case 'export': {
      const res = await api(cfg, 'GET', '/api/export', undefined, insecure);
      for (const uri of res.entries) console.log(uri);
      return;
    }

    case 'help':
    case '-h':
    case '--help':
      return usage();

    default:
      die('unknown command: ' + cmd + ' (try --help)');
  }
}

main().catch((e) => die(e && e.message ? e.message : String(e)));
