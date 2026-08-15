#!/usr/bin/env bash
# cliotp-server installer.
# Copies the server + client into a prefix dir, generates the master key and
# API token, installs the `cliotpc` client, and starts the server (pm2 if
# available, otherwise a plain background process).
#
#   curl -fsSL https://raw.githubusercontent.com/<you>/cliotp-server/main/install.sh | bash
#   # or, from a checkout:
#   ./install.sh
#
# Config (env):
#   PREFIX          install root            (default: $HOME/.local)
#   CLIOTP_DATA_DIR server data dir          (default: $PREFIX/share/cliotp-server/data)
#   PORT            server listen port       (default: 8080)
#   CLIOTP_TOKEN    API token (auto-generated if unset)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
LIB="$PREFIX/share/cliotp-server"
BIN="$PREFIX/bin"
DATA_DIR="${CLIOTP_DATA_DIR:-$LIB/data}"
PORT="${PORT:-8080}"
TOKEN="${CLIOTP_TOKEN:-}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: $1 is required" >&2; exit 1; }; }
need node

echo "==> installing to $LIB"
mkdir -p "$LIB" "$BIN" "$DATA_DIR"
chmod 700 "$DATA_DIR"
install -m 0644 "$HERE/server.js" "$HERE/package.json" "$LIB/"
install -m 0755 "$HERE/client.js" "$LIB/client.js"

# symlink the client into PATH
ln -sf "$LIB/client.js" "$BIN/cliotpc"

# generate master key if missing
if [ ! -f "$DATA_DIR/master.key" ]; then
  echo "==> generating master key"
  ( umask 077; openssl rand -out "$DATA_DIR/master.key" 32 )
  chmod 600 "$DATA_DIR/master.key"
fi

# generate API token if not provided
if [ -z "$TOKEN" ] && [ ! -f "$DATA_DIR/api.token" ]; then
  echo "==> generating API token"
  ( umask 077; openssl rand -hex 32 > "$DATA_DIR/api.token" )
  chmod 600 "$DATA_DIR/api.token"
fi
if [ -z "$TOKEN" ]; then
  TOKEN="$(cat "$DATA_DIR/api.token")"
fi

start_server() {
  local env_vars=("CLIOTP_DATA_DIR=$DATA_DIR" "PORT=$PORT" "HOST=0.0.0.0")
  if command -v pm2 >/dev/null 2>&1; then
    echo "==> starting with pm2"
    env "${env_vars[@]}" pm2 start "$LIB/server.js" --name cliotp-server --update-env
    pm2 save >/dev/null 2>&1 || true
  else
    echo "==> starting in background (install pm2 for process supervision)"
    nohup env "${env_vars[@]}" node "$LIB/server.js" > "$LIB/server.log" 2>&1 &
  fi
}

start_server

cat <<EOF

Done. cliotp-server is running on http://$(hostname -I 2>/dev/null | awk '{print $1}'):$PORT

Client setup (run on any machine that should reach this server):
  export CLIOTP_SERVER=http://YOUR_VPS_IP:$PORT
  export CLIOTP_TOKEN=$TOKEN
  cliotpc list

Save the token somewhere safe — it is NOT recoverable from the server.
EOF
