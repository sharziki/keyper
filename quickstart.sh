#!/usr/bin/env bash
# keyper quickstart — installs deps, creates the vault if needed, opens the web UI.
# Usage:  bash quickstart.sh
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$DIR/keyper.py"
PY="$(command -v python3 || command -v python)"
VAULT="${KEYPER_VAULT:-$HOME/.config/keyper/vault.json}"

cat <<'ART'
██╗  ██╗███████╗██╗   ██╗██████╗ ███████╗██████╗
██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
█████╔╝ █████╗   ╚████╔╝ ██████╔╝█████╗  ██████╔╝
██╔═██╗ ██╔══╝    ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗
██║  ██╗███████╗   ██║   ██║     ███████╗██║  ██║
╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝
      your keys, kept — encrypted, local, MCP-native
ART

echo "==> Using python: $PY"
echo "==> Installing dependencies (cryptography, mcp, keyring)…"
"$PY" -m pip install --quiet --upgrade cryptography "mcp[cli]" keyring \
  || "$PY" -m pip install --quiet --upgrade --break-system-packages cryptography "mcp[cli]" keyring

if [ ! -f "$VAULT" ]; then
  echo "==> No vault yet — creating one (keychain mode)…"
  "$PY" "$SCRIPT" init || {
    echo "   Keychain unavailable — falling back to passphrase mode."
    "$PY" "$SCRIPT" init --passphrase
  }
else
  echo "==> Vault found at $VAULT"
fi

echo
echo "==> Next: add this to your AI client so it can pull keys."
echo "    Claude Code:"
echo "      claude mcp add keyper -- \"$PY\" \"$SCRIPT\" serve"
echo "    Claude Desktop / Cowork (mcpServers entry):"
echo "      { \"command\": \"$PY\", \"args\": [\"$SCRIPT\", \"serve\"] }"
echo
echo "==> Launching the web UI to add/name keys…"
exec "$PY" "$SCRIPT" ui
