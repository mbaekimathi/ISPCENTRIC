#!/bin/bash
# Register one MikroTik WireGuard peer on the billing VPS.
# Usage: wireguard_apply_peer.sh PUBLIC_KEY TUNNEL_ADDRESS [LABEL]
# Intended to run via sudo from WIREGUARD_SYNC_COMMAND in .env.

set -euo pipefail

PUBKEY="${1:-}"
ADDR="${2:-}"
LABEL="${3:-MikroTik}"
IFACE="${WIREGUARD_INTERFACE:-wg0}"
CONF="${WIREGUARD_CONF_PATH:-/etc/wireguard/wg0.conf}"

if [[ -z "$PUBKEY" || -z "$ADDR" ]]; then
  echo "usage: $0 PUBLIC_KEY TUNNEL_ADDRESS [LABEL]" >&2
  exit 1
fi

if ! wg show "$IFACE" >/dev/null 2>&1; then
  if [[ -f "$CONF" ]]; then
    echo "==> Bringing up $IFACE from $CONF"
    wg-quick up "$IFACE"
  else
    echo "!! WireGuard interface $IFACE is down and $CONF is missing." >&2
    echo "   Enable: sudo systemctl enable --now wg-quick@${IFACE}.service" >&2
    exit 1
  fi
fi

wg set "$IFACE" peer "$PUBKEY" allowed-ips "${ADDR}/32"

if [[ -f "$CONF" ]] && ! grep -qF "$PUBKEY" "$CONF"; then
  {
    echo ""
    echo "# ${LABEL}"
    echo "[Peer]"
    echo "PublicKey = ${PUBKEY}"
    echo "AllowedIPs = ${ADDR}/32"
  } >>"$CONF"
fi
