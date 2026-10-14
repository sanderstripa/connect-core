#!/usr/bin/env bash
# Fetch only the explicitly selected immutable source; never execute a mutable
# "latest" release as root. Python verifies and applies its own transaction.
set -euo pipefail
[[ $(uname -s) == Linux && $EUID == 0 ]] || { echo 'Run on a Linux systemd VPS via sudo'; exit 1; }
for command in curl python3 tar; do command -v "$command" >/dev/null || { echo "Missing dependency: $command"; exit 1; }; done
revision=''
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --revision) [[ $# -ge 2 ]] || exit 1; revision=$2; args+=("$1" "$2"); shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
[[ $revision =~ ^[0-9a-f]{40}$ ]] || { echo 'Pass --revision with a reviewed full Git commit SHA'; exit 1; }
stage=$(mktemp -d /var/tmp/connect-installer.XXXXXXXX)
trap 'rm -rf -- "$stage"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL "https://codeload.github.com/sanderstripa/connect-core/tar.gz/$revision" -o "$stage/source.tar.gz"
python3 - "$stage" <<'PY'
import pathlib, sys, tarfile
stage = pathlib.Path(sys.argv[1])
with tarfile.open(stage / 'source.tar.gz') as archive:
    archive.extractall(stage / 'source', filter='data')
PY
python3 "$stage/source/connect-core-$revision/scripts/connect-install.py" "${args[@]}"
