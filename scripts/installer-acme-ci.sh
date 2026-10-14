#!/usr/bin/env bash
# Actual ACME IP validation in an opted-in disposable runner, never public CA bypass.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${CONNECT_DISPOSABLE_INSTALL_TEST:-} == 1 && $EUID == 0 ]] || exit 1
stage="$PWD/installer-acme"
mkdir -p "$stage"
go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1
for file in localhost/cert.pem localhost/key.pem pebble.minica.pem; do
  mkdir -p "$stage/$(dirname "$file")"
  curl --proto '=https' --tlsv1.2 -fsSL "https://raw.githubusercontent.com/letsencrypt/pebble/v2.10.1/test/certs/$file" -o "$stage/$file"
done
python3 - "$stage" <<'PY'
import pathlib,json,sys
s=pathlib.Path(sys.argv[1])
c={'pebble':{'listenAddress':'127.0.0.1:14000','managementListenAddress':'127.0.0.1:15000','certificate':str(s/'localhost/cert.pem'),'privateKey':str(s/'localhost/key.pem'),'httpPort':80,'tlsPort':443,'profiles':{'default':{'validityPeriod':7776000},'shortlived':{'validityPeriod':172800}}}}
(s/'config.json').write_text(json.dumps(c))
PY
PEBBLE_VA_NOSLEEP=1 "$(go env GOPATH)/bin/pebble" -config "$stage/config.json" -strict=false > "$stage/pebble.log" 2>&1 &
pebble_pid=$!
trap 'kill "$pebble_pid" 2>/dev/null || true' EXIT
for attempt in $(seq 1 50); do
  if curl --noproxy '*' --cacert "$stage/pebble.minica.pem" -fsS https://127.0.0.1:15000/roots/0 -o "$stage/issued-ca.pem"; then break; fi
  sleep .2
done
test -s "$stage/issued-ca.pem"
cat "$stage/pebble.minica.pem" >> "$stage/issued-ca.pem"
export LEGO_CA_CERTIFICATES="$stage/pebble.minica.pem"
export CONNECT_TEST_CA="$stage/issued-ca.pem"
export CONNECT_TEST_ACME=https://127.0.0.1:14000/dir
python3 scripts/installer-smoke.py
