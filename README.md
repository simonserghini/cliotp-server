# cliotp-server

**TOTP / HOTP / Steam Guard codes, self-hosted on a VPS, fetched from your terminal.**

The cloud sibling of [`cliotp`](https://github.com/yourname/cliotp) — same
crypto, same plain-`cliotpc code alice` output, but the secrets live on a
server you control and every client talks to it over a small REST API.

One Node.js file, **zero runtime dependencies**. Implements RFC 4226 / RFC 6238
with the built-in `crypto` module, stores secrets encrypted at rest
(AES-256-GCM), requires an API key for every request, and ships a web UI.

```
$ cliotpc code github
022863
```

---

## What it does

- **TOTP** (RFC 6238), **HOTP** (RFC 4226), and **Steam Guard**
- 6 or 8 digits, custom periods, SHA-1 / SHA-256 / SHA-512
- import `otpauth://` links and Google Authenticator "transfer accounts"
  exports (`otpauth-migration://`) — every account at once
- **encrypted at rest** (AES-256-GCM, key in `master.key`)
- **authenticated API** — every `/api/*` route requires an API key
- **multiple API keys** — create and revoke named keys (stored as sha256 hashes)
- **web UI** — live codes, entry management, and key management in the browser
- server runs in **Node**, **pm2**, or **Docker**; client is a single
  `cliotpc` command

---

## Quick start

### Docker (easiest)

```sh
cd cliotp-server
cp .env.example .env
# put a strong token in .env:  openssl rand -hex 32
docker compose up -d --build
```

The server listens on `127.0.0.1:8080` inside the compose file — put a TLS
reverse proxy (Caddy/nginx) in front, or change the port binding to expose it
directly.

### Install script (pm2 or plain Node)

```sh
./install.sh
# PREFIX="$HOME/.local" ./install.sh   # custom location
```

- installs `server.js` + `client.js` into `~/.local/share/cliotp-server`
- generates `master.key` and `api.token` (or reuses `CLIOTP_TOKEN`)
- symlinks `cliotpc` into `~/.local/bin`
- starts with **pm2 if installed**, otherwise a background `nohup` process
- prints the API token — **save it**, it is not recoverable from the server

### Bare Node

```sh
export CLIOTP_DATA_DIR=~/.config/cliotp-server
export CLIOTP_TOKEN=$(openssl rand -hex 32)
node server.js
```

On first start the server generates the token itself if `CLIOTP_TOKEN` is
unset, and prints it to stdout.

---

## Client setup

On any machine that should reach the server:

```sh
export CLIOTP_SERVER=https://your-vps.example.com
export CLIOTP_TOKEN=<the token from install>
cliotpc list
```

Or persist them in a config file at `~/.config/cliotp/client.conf`:

```
server=https://your-vps.example.com
token=YOUR_TOKEN
```

### Client usage

```sh
cliotpc list                      # see everything
cliotpc code alice                # print the code (just the code — pipeable)
cliotpc code 1                    # ...or by id/index
cliotpc code alice -c             # also copy to clipboard
cliotpc code alice -v             # label + seconds remaining
cliotpc show alice                # details + live code
cliotpc add alice --secret JBSWY3DPEHPK3PXP --issuer GitHub
cliotpc add "otpauth://totp/GitHub:alice?secret=...&issuer=GitHub"
cliotpc add "otpauth-migration://offline?data=..."   # google export, all accounts
cliotpc edit alice --issuer Work
cliotpc rm alice
cliotpc uri alice                 # print the otpauth:// URI
cliotpc export                    # all URIs (backup)
```

`OTP=$(cliotpc code 1)` works — output is just the code.

---

## Web UI

The server serves a browser UI at `/`. Open `http://<host>:8080/`, paste an
API key, and you get:

- a **live codes** grid with countdown bars (HOTP shows a "Next code" button)
- an **entries** manager — add (fields or `otpauth://` URI), edit, delete
- an **API keys** manager — create named keys (shown once, with a copy button)
  and revoke them

The key stays in your browser's `localStorage` only and is sent as a bearer
token, exactly like the CLI.

---

## API reference

Every route except `/healthz` requires:

```
Authorization: Bearer <token>      # or X-API-Token: <token>
```

| Method | Path | Description |
| --- | --- | --- |
| GET | `/healthz` | Liveness probe (no auth) |
| GET | `/api/entries` | List entries (no secrets) |
| POST | `/api/entries` | Add from fields or `{ "uri": "otpauth://…" }` |
| GET | `/api/entries/:id` | Entry details (no secret) |
| GET | `/api/entries/:id/code` | Current code (advances HOTP counter) |
| PATCH | `/api/entries/:id` | Edit fields |
| DELETE | `/api/entries/:id` | Remove |
| GET | `/api/entries/:id/uri` | otpauth URI for one entry |
| GET | `/api/codes` | Current codes for all entries (peek; does not advance HOTP) |
| GET | `/api/export` | All otpauth URIs (sensitive) |
| GET | `/api/keys` | List API keys (metadata only) |
| POST | `/api/keys` | Create a key — secret returned exactly once |
| DELETE | `/api/keys/:id` | Revoke a key (never the last one) |

`:id` may be a stored id, a 1-based index, or a case-insensitive name
substring (must be unique).

```sh
# add
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"github","secret":"JBSWY3DPEHPK3PXP","issuer":"GitHub"}' \
  https://vps/api/entries

# code
curl -H "Authorization: Bearer $TOKEN" https://vps/api/entries/github/code
```

### POST /api/entries fields

`name` (required), `secret` (required, unless `uri` is given), `issuer`,
`digits` (6|8), `period` (default 30), `algorithm` (SHA1|SHA256|SHA512),
`kind` (totp|hotp|steam), `counter` (HOTP only).

---

## Configuration

Server reads from environment variables:

| Var | Default | Purpose |
| --- | --- | --- |
| `CLIOTP_DATA_DIR` | `~/.config/cliotp-server` | Where `secrets.tsv`, `master.key`, `api.token` live |
| `CLIOTP_TOKEN` | auto-generated | Rescue key, always accepted (also seeded as the `default` key) |
| `PORT` | `8080` | Listen port |
| `HOST` | `0.0.0.0` | Listen address |
| `CLIOTP_TLS_CERT` / `CLIOTP_TLS_KEY` | — | Optional; serve HTTPS directly |

Client reads `CLIOTP_SERVER`, `CLIOTP_TOKEN`, `CLIOTP_CONFIG`, or
`--server` / `--token` / `--insecure` flags.

---

## Storage & security

- `secrets.tsv` — entries, **encrypted** with AES-256-GCM. Header line is
  `cliotp-server-encrypted-v1`; the payload is `iv || tag || ciphertext`,
  base64. A random 32-byte key in `master.key` (mode `0600`) does the work.
- `api-keys.json` — API keys as **sha256 hashes only** (raw keys are never
  written to disk after creation).
- `api.token` — legacy plaintext copy of the first ("default") key, mode `0600`.
- All files live in a `0700` directory.

**Back up `secrets.tsv` and `master.key` together** — lose the key, lose the
secrets. Or run `cliotpc export` and stash the plaintext URIs somewhere safe.

### Threat model

- An API key is the whole ball game: anyone with it can read every code.
  Use strong keys, revoke anything you don't recognize, and **always serve
  over TLS** (reverse proxy or `CLIOTP_TLS_CERT`/`CLIOTP_TLS_KEY`). `docker
  compose` binds to localhost by default for exactly this reason.
- Secrets are protected at rest from someone who copies the disk, but not
  from someone who can read the process memory of the running server.
- Run a **single server instance** against one data dir; HOTP counters
  advance on read and concurrent multi-process writes are not coordinated.

---

## Development

```sh
npm test        # or: node --test
```

The suite covers the RFC 4226/6238 vectors, Steam (cross-checked against the
reference implementation), Google migration import, otpauth round-trip,
encryption-at-rest, and the full authenticated API lifecycle.

---

## License

MIT. Go wild.
