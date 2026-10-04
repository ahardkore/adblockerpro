#!/usr/bin/env bash
#
# adblockerpro installer for Raspberry Pi OS / Debian / Ubuntu.
#
#   curl -fsSL https://raw.githubusercontent.com/ahardkore/adblockerpro/main/deploy/install.sh | sudo bash
#
# or, from a clone:   sudo ./deploy/install.sh --local
#
set -euo pipefail

REPO="ahardkore/adblockerpro"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/adblockerpro"
DATA_DIR="/var/lib/adblockerpro"
SERVICE="/etc/systemd/system/adblockerpro.service"
USER_NAME="adblockerpro"
LOCAL_BUILD=0
WEB_PORT="${WEB_PORT:-8080}"

for arg in "$@"; do
  case "$arg" in
    --local) LOCAL_BUILD=1 ;;
    --help|-h)
      sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 1 ;;
  esac
done

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m warn:\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run this with sudo"
command -v systemctl >/dev/null || die "this installer needs systemd"

# ---------------------------------------------------------------- binary ----
detect_arch() {
  case "$(uname -m)" in
    aarch64|arm64) echo linux-arm64 ;;
    armv7l)        echo linux-armv7 ;;
    armv6l)        echo linux-armv6 ;;
    x86_64|amd64)  echo linux-amd64 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
}

install_binary() {
  if [ "$LOCAL_BUILD" -eq 1 ]; then
    local src
    src="$(dirname "$(dirname "$(readlink -f "$0")")")"
    if [ -x "$src/adblockerpro" ]; then
      log "installing locally built binary"
      install -m 0755 "$src/adblockerpro" "$BIN_DIR/adblockerpro"
      [ -x "$src/abpctl" ] && install -m 0755 "$src/abpctl" "$BIN_DIR/abpctl"
      return
    fi
    command -v go >/dev/null || die "no binary found and Go is not installed; run 'make build' first"
    log "building from source"
    ( cd "$src" && make build )
    install -m 0755 "$src/adblockerpro" "$BIN_DIR/adblockerpro"
    [ -x "$src/abpctl" ] && install -m 0755 "$src/abpctl" "$BIN_DIR/abpctl"
    return
  fi

  local arch url tmp
  arch="$(detect_arch)"
  url="https://github.com/$REPO/releases/latest/download/adblockerpro-$arch"
  tmp="$(mktemp)"
  log "downloading $url"
  curl -fsSL "$url" -o "$tmp" || die "download failed — build locally with: make pi64 && sudo ./deploy/install.sh --local"
  install -m 0755 "$tmp" "$BIN_DIR/adblockerpro"
  rm -f "$tmp"

  # abpctl is the optional command line client; a missing one is not fatal.
  tmp="$(mktemp)"
  if curl -fsSL "https://github.com/$REPO/releases/latest/download/abpctl-$arch" -o "$tmp" 2>/dev/null; then
    install -m 0755 "$tmp" "$BIN_DIR/abpctl"
    log "installed abpctl"
  fi
  rm -f "$tmp"
}

# ------------------------------------------------------------------ user ----
create_user() {
  if ! id "$USER_NAME" >/dev/null 2>&1; then
    log "creating service user $USER_NAME"
    useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$USER_NAME"
  fi
  install -d -o "$USER_NAME" -g "$USER_NAME" -m 0755 "$DATA_DIR" "$DATA_DIR/lists"
  install -d -o "$USER_NAME" -g "$USER_NAME" -m 0755 "$CONFIG_DIR"
}

# ------------------------------------------------------------- port 53 ------
free_port_53() {
  # Raspberry Pi OS Lite usually has neither of these, but Ubuntu Server and
  # desktop images ship systemd-resolved listening on 127.0.0.53:53.
  if systemctl is-active --quiet systemd-resolved; then
    log "freeing port 53 from systemd-resolved"
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/adblockerpro.conf <<'EOF'
# Installed by adblockerpro: stop resolved from owning port 53 and make the
# host itself use our resolver.
[Resolve]
DNSStubListener=no
DNS=127.0.0.1
EOF
    systemctl restart systemd-resolved || warn "could not restart systemd-resolved"
    # /etc/resolv.conf must not point at the stub any more.
    if [ -L /etc/resolv.conf ] && readlink /etc/resolv.conf | grep -q stub-resolv; then
      ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    fi
  fi

  for svc in dnsmasq bind9 named unbound; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      warn "$svc is running and may already own port 53 — stop it or change its port"
    fi
  done
}

# ----------------------------------------------------------------- config ---
write_config() {
  if [ -f "$CONFIG_DIR/config.json" ]; then
    log "keeping existing $CONFIG_DIR/config.json"
    return
  fi
  log "writing default configuration"
  local src
  src="$(dirname "$(dirname "$(readlink -f "$0")")")"
  if [ -f "$src/deploy/config.example.json" ]; then
    install -o "$USER_NAME" -g "$USER_NAME" -m 0644 "$src/deploy/config.example.json" "$CONFIG_DIR/config.json"
  else
    # The binary writes a full default file on first start.
    sudo -u "$USER_NAME" "$BIN_DIR/adblockerpro" --config "$CONFIG_DIR/config.json" --check example.com >/dev/null 2>&1 || true
  fi
  chown "$USER_NAME:$USER_NAME" "$CONFIG_DIR/config.json" 2>/dev/null || true
}

install_service() {
  log "installing systemd service"
  local src
  src="$(dirname "$(dirname "$(readlink -f "$0")")")"
  if [ -f "$src/deploy/adblockerpro.service" ]; then
    install -m 0644 "$src/deploy/adblockerpro.service" "$SERVICE"
  else
    curl -fsSL "https://raw.githubusercontent.com/$REPO/main/deploy/adblockerpro.service" -o "$SERVICE"
  fi
  systemctl daemon-reload
  systemctl enable adblockerpro
  systemctl restart adblockerpro
}

main() {
  install_binary
  create_user
  free_port_53
  write_config
  install_service

  sleep 2
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo
  if systemctl is-active --quiet adblockerpro; then
    log "adblockerpro is running"
  else
    warn "the service did not start — check: journalctl -u adblockerpro -n 50"
  fi
  cat <<EOF

  Dashboard:  http://${ip:-<pi-ip>}:${WEB_PORT}
  DNS server: ${ip:-<pi-ip>}:53

  Finish the job on your router:
    1. Give this Pi a static IP or a DHCP reservation.
    2. Set the router's DHCP "DNS server" to ${ip:-<pi-ip>}.
    3. Reboot your TVs, sticks and consoles so they pick up the new DNS.
    4. Optional but recommended: block outbound port 53 (and DoH on 443 for
       known resolvers) for every device except the Pi, so hard-coded
       resolvers in streaming hardware cannot bypass the filter.

  Useful commands:
    systemctl status adblockerpro
    journalctl -u adblockerpro -f
    adblockerpro --check ads.example.com

EOF
}

main "$@"
