#!/usr/bin/env bash
# cliotp-server installer.
# Two modes:
#   ./install.sh            user install (pm2 if present, else background nohup)
#   sudo ./install.sh --systemd   root install as a systemd service
#
# Config (env):
#   PREFIX          install root for user mode   (default: $HOME/.local)
#   CLIOTP_DATA_DIR server data dir               (default: $PREFIX/share/cliotp-server/data)
#   PORT            server listen port            (default: 8080)
#   CLIOTP_TOKEN    API token (auto-generated if unset)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-8080}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: $1 is required" >&2; exit 1; }; }
need node

# ---------------------------------------------------------------------------
# systemd mode
# ---------------------------------------------------------------------------

install_systemd() {
  need systemctl
  [ "$(id -u)" = 0 ] || { echo "error: --systemd requires root (run with sudo)" >&2; exit 1; }

  echo "==> installing to /opt/cliotp-server"
  mkdir -p /opt/cliotp-server/public /var/lib/cliotp-server
  install -m 0644 "$HERE/server.js" "$HERE/package.json" /opt/cliotp-server/
  install -m 0755 "$HERE/client.js" /opt/cliotp-server/
  cp -r "$HERE/public/." /opt/cliotp-server/public/

  id -u cliotp >/dev/null 2>&1 || useradd --system --home /var/lib/cliotp-server --shell /usr/sbin/nologin cliotp
  chown -R cliotp:cliotp /var/lib/cliotp-server /opt/cliotp-server
  chmod 700 /var/lib/cliotp-server

  if [ ! -f /var/lib/cliotp-server/master.key ]; then
    echo "==> generating master key"
    ( umask 077; openssl rand -out /var/lib/cliotp-server/master.key 32 )
    chown cliotp:cliotp /var/lib/cliotp-server/master.key
    chmod 600 /var/lib/cliotp-server/master.key
  fi

  TOKEN="${CLIOTP_TOKEN:-$(openssl rand -hex 32)}"
  echo "==> writing /etc/cliotp-server.env"
  ( umask 077; printf 'CLIOTP_TOKEN=%s\n' "$TOKEN" > /etc/cliotp-server.env )
  chmod 600 /etc/cliotp-server.env

  install -m 0644 "$HERE/cliotp-server.service" /etc/systemd/system/cliotp-server.service
  systemctl daemon-reload
  systemctl enable --now cliotp-server

  cat <<EOF

Done. cliotp-server is running as a systemd service on http://127.0.0.1:$PORT
(put a TLS reverse proxy in front — see README).

API token (save it, it is not stored anywhere recoverable):
  $TOKEN

Manage it with:
  systemctl status cliotp-server
  journalctl -u cliotp-server -f
EOF
}

if [ "${1:-}" = "--systemd" ]; then
  install_systemd
  exit 0
fi

# ---------------------------------------------------------------------------
# User mode
# ---------------------------------------------------------------------------

PREFIX="${PREFIX:-$HOME/.local}"
LIB="$PREFIX/share/cliotp-server"
BIN="$PREFIX/bin"
DATA_DIR="${CLIOTP_DATA_DIR:-$LIB/data}"
TOKEN="${CLIOTP_TOKEN:-}"

echo "==> installing to $LIB"
mkdir -p "$LIB" "$BIN" "$DATA_DIR"
chmod 700 "$DATA_DIR"
install -m 0644 "$HERE/server.js" "$HERE/package.json" "$LIB/"
install -m 0755 "$HERE/client.js" "$LIB/client.js"
mkdir -p "$LIB/public"
cp -r "$HERE/public/." "$LIB/public/"

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
