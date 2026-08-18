#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if ! command -v vhs >/dev/null 2>&1; then
  cat >&2 <<'EOF'
VHS is required to record the real terminal session.

Install it, then run this script again:
  brew install vhs
  ./demo/record.sh

Other installation options: https://github.com/charmbracelet/vhs#installation
No GIF was generated.
EOF
  exit 1
fi

npm run build
rm -f demo/interception.gif
vhs demo/interception.tape

if [[ ! -s demo/interception.gif ]]; then
  echo "VHS completed without creating demo/interception.gif" >&2
  exit 1
fi

echo "Recorded demo/interception.gif"
