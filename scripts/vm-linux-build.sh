#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/vm-boot"
mkdir -p "$out"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$out/connect-core" ./cmd/connect-core
"$out/connect-core" init-lab "$out/lab"
python3 - "$out/lab" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])
for role in ('server','client'):
 f=p/f'ip-{role}.json'; c=json.loads(f.read_text()); c['endpoint']='10.0.2.15:17444' if role=='server' else '127.0.0.1:17444'
 for field in ('ca','cert','key'): c['trust'][field]='/lab/'+pathlib.Path(c['trust'][field]).name
 f.write_text(json.dumps(c,indent=2))
PY
container=$(docker create alpine:3.24.1 sh -c 'apk add --no-cache linux-virt iproute2 bash python3 tcpdump && cp /boot/vmlinuz-virt /vmlinuz')
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT
docker start -a "$container"
docker cp "$container:/vmlinuz" "$out/vmlinuz"
docker cp "$out/connect-core" "$container:/connect-core"
docker cp "$out/lab" "$container:/lab"
docker cp "$root/scripts/ip-lab-services.py" "$container:/services.py"
docker cp "$root/scripts/vm-linux-init.sh" "$container:/init"
mkdir -p "$out/rootfs"
docker export "$container" | tar -xf - -C "$out/rootfs"
chmod +x "$out/rootfs/init" "$out/rootfs/connect-core"
sudo mknod -m 600 "$out/rootfs/dev/console" c 5 1
sudo mknod -m 666 "$out/rootfs/dev/null" c 1 3
(cd "$out/rootfs" && find . -print0 | cpio --null -o --format=newc | gzip -1) > "$out/rootfs.cpio.gz"
# The boot image holds only disposable 24h lab credentials; never upload it as a
# product/release. CI's ephemeral provisioning artifact has one-day retention.
sha256sum "$out/vmlinuz" "$out/rootfs.cpio.gz" > "$out/boot-sha256.txt"
