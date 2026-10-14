#!/usr/bin/env bash
# Resolve the installation channel once, then build only that immutable source.
set -euo pipefail
[[ $(uname -s) == Linux ]] || { echo 'Run on a Linux systemd VPS'; exit 1; }
[[ -d /run/systemd/system && -c /dev/net/tun ]] || { echo 'A running systemd VPS with /dev/net/tun is required'; exit 1; }
packages=()
command -v python3 >/dev/null || packages+=(python3)
command -v tar >/dev/null || packages+=(tar)
if [[ ${#packages[@]} -gt 0 ]]; then
  command -v apt-get >/dev/null || { echo 'Missing python3/tar; this automatic bootstrap requires apt-get'; exit 1; }
  privilege=()
  if [[ $EUID != 0 ]]; then
    command -v sudo >/dev/null || { echo 'Root privileges are required; sudo is unavailable'; exit 1; }
    privilege=(sudo)
  fi
  "${privilege[@]}" env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get update
  "${privilege[@]}" env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install -y --no-upgrade --no-install-recommends "${packages[@]}"
fi
for command in curl python3 tar; do command -v "$command" >/dev/null || { echo "Missing dependency: $command"; exit 1; }; done
revision=''
args=(install)
if [[ $# -gt 0 && $1 != --* ]]; then args=("$1"); shift; fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --revision) [[ $# -ge 2 ]] || exit 1; revision=$2; args+=("$1" "$2"); shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
if [[ -z $revision ]]; then
  revision=$(curl --proto '=https' --tlsv1.2 -fsSL 'https://api.github.com/repos/sanderstripa/connect-core/commits/main' | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')
  args+=(--revision "$revision")
fi
[[ $revision =~ ^[0-9a-f]{40}$ ]] || { echo 'Cannot resolve an immutable CONNECT revision'; exit 1; }
stage=$(mktemp -d /var/tmp/connect-installer.XXXXXXXX)
trap 'rm -rf -- "$stage"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL "https://codeload.github.com/sanderstripa/connect-core/tar.gz/$revision" -o "$stage/source.tar.gz"
python3 - "$stage" <<'PY'
import pathlib, sys, tarfile
stage = pathlib.Path(sys.argv[1])
with tarfile.open(stage / 'source.tar.gz') as archive:
    archive.extractall(stage / 'source', filter='data')
PY
if [[ $EUID == 0 ]]; then
  python3 "$stage/source/connect-core-$revision/scripts/connect-install.py" "${args[@]}"
else
  command -v sudo >/dev/null || { echo 'Root privileges are required; sudo is unavailable'; exit 1; }
  # The full script/source is already in a private, seekable staging directory.
  # Preserve the exact resolved revision and options when elevating, not stdin.
  sudo bash "$stage/source/connect-core-$revision/scripts/install-vps.sh" "${args[@]}"
fi
