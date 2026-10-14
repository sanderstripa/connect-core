#!/usr/bin/env python3
"""Transactional systemd installer. Requires a reviewed, immutable source revision."""
import argparse
import fcntl
import getpass
import hashlib
import ipaddress
import json
import os
import pathlib
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.request
import uuid

ROOT = pathlib.Path('/opt/connect-core')
STATE = pathlib.Path('/var/lib/connect-core')
CONFIG = pathlib.Path('/etc/connect-core')
JOURNAL = pathlib.Path('/var/lib/connect-core-installer')
UNITS = pathlib.Path('/etc/systemd/system')
NAMES = ['connect-core-network.service', 'connect-core.service', 'connect-ui.service']
USERS = ['connectcore', 'connectui']
GROUP = 'connectadmin'

def run(*args, input=None, check=True):
    p = subprocess.run(args, input=input, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode:
        raise RuntimeError(f'{args[0]} failed: {p.stderr.strip()}')
    return p

def save(path, value):
    tmp = path.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, indent=2); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def dependencies():
    needed = ['systemctl', 'ip', 'iptables', 'sysctl', 'useradd', 'userdel', 'groupadd', 'groupdel', 'getent', 'ss']
    missing = [n for n in needed if not shutil.which(n)]
    if missing: raise RuntimeError('Missing dependencies: ' + ', '.join(missing) + '. Install systemd/iproute2/iptables/passwd with your package manager, then rerun.')
    if not pathlib.Path('/run/systemd/system').exists(): raise RuntimeError('A running systemd host is required')
    if not pathlib.Path('/dev/net/tun').exists(): raise RuntimeError('/dev/net/tun is unavailable; enable it with the VPS provider')

def check_ports(ports):
    if len(set(ports)) != len(ports) or any(p < 1024 or p > 65535 for p in ports):
        raise RuntimeError('Ports must be distinct and in 1024..65535')
    output = run('ss', '-H', '-lntu').stdout
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 5:
            match = re.search(r':(\d+)$', fields[4])
            if match and int(match.group(1)) in ports:
                raise RuntimeError(f'Port {match.group(1)} is already occupied; nothing will be stopped')
    for port, kind in ports.items():
        with socket.socket(socket.AF_INET, kind) as s:
            s.bind(('0.0.0.0', port))  # Detect bind failures as well as existing listeners.

def ensure_fresh():
    for path in [ROOT, STATE, CONFIG, JOURNAL] + [UNITS / n for n in NAMES]:
        if path.exists() or path.is_symlink(): raise RuntimeError(f'Occupied path {path}; install will not adopt it')
    for n in NAMES:
        if run('systemctl', 'show', n, '--property=LoadState', '--value').stdout.strip() != 'not-found':
            raise RuntimeError(f'Service {n} already exists; no takeover')
    for name in USERS:
        if run('getent', 'passwd', name, check=False).returncode == 0: raise RuntimeError(f'User {name} already exists')
    if run('getent', 'group', GROUP, check=False).returncode == 0: raise RuntimeError(f'Group {GROUP} already exists')

def extract_source(archive, destination):
    import tarfile
    with tarfile.open(archive) as tar:
        # Python's data filter prevents path traversal, links outside the stage,
        # device nodes and archive-supplied ownership.
        tar.extractall(destination, filter='data')

def build(args, stage):
    if args.source:
        source = pathlib.Path(args.source).resolve()
        revision = run('git', '-C', str(source), 'rev-parse', 'HEAD').stdout.strip()
        if args.revision and args.revision != revision: raise RuntimeError('Source revision mismatch')
        if run('git', '-C', str(source), 'status', '--porcelain', '--untracked-files=no').stdout.strip():
            raise RuntimeError('Local source has uncommitted changes')
    else:
        revision = args.revision
        if not revision or not re.fullmatch(r'[0-9a-f]{40}', revision): raise RuntimeError('A full immutable --revision SHA is required')
        archive = stage / 'source.tar.gz'
        urllib.request.urlretrieve(f'https://codeload.github.com/sanderstripa/connect-core/tar.gz/{revision}', archive)
        extract_source(archive, stage / 'source')
        source = stage / 'source' / ('connect-core-' + revision)
    go = shutil.which('go')
    if not go:
        machine = os.uname().machine
        arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(machine)
        if not arch: raise RuntimeError('Only Linux amd64/arm64 are supported')
        with urllib.request.urlopen('https://go.dev/dl/?mode=json&include=all', timeout=30) as response:
            versions = json.load(response)
        version = next(v for v in versions if v['version'] == 'go1.27.0')
        item = next(v for v in version['files'] if v['os'] == 'linux' and v['arch'] == arch and v['kind'] == 'archive')
        archive = stage / 'go.tar.gz'
        urllib.request.urlretrieve('https://go.dev/dl/' + item['filename'], archive)
        if sha(archive) != item['sha256']: raise RuntimeError('Go toolchain checksum mismatch')
        extract_source(archive, stage / 'toolchain'); go = str(stage / 'toolchain' / 'go' / 'bin' / 'go')
    release = stage / 'release'; (release / 'bin').mkdir(parents=True); (release / 'scripts').mkdir()
    env = dict(os.environ, GOCACHE=str(stage / 'gocache'), GOPATH=str(stage / 'gopath'), CGO_ENABLED='0')
    for name in ['connect-core', 'connect-control', 'connect-ui']:
        p = subprocess.run([go, 'build', '-trimpath', '-o', str(release / 'bin' / name), './cmd/' + name], cwd=source, env=env, capture_output=True, text=True)
        if p.returncode: raise RuntimeError('Build failed: ' + p.stderr)
    for name in ['connect-install.py', 'connect-vps-network.py']:
        shutil.copy2(source / 'scripts' / name, release / 'scripts' / name)
    version = run(str(release / 'bin' / 'connect-control'), 'version').stdout.strip()
    if version != '0.2.0': raise RuntimeError('Unsupported installer/schema compatibility version')
    return revision, release

def unit_files():
    hardening = 'NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nUMask=0077\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n'
    return {
        'connect-core-network.service': '[Unit]\nDescription=CONNECT owned TUN and scoped rules\nAfter=network-online.target\nWants=network-online.target\nBefore=connect-core.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 /opt/connect-core/current/scripts/connect-vps-network.py apply /var/lib/connect-core-installer/network.json\nExecStop=/usr/bin/python3 /opt/connect-core/current/scripts/connect-vps-network.py rollback /var/lib/connect-core-installer/network.json\n\n[Install]\nWantedBy=multi-user.target\n',
        'connect-core.service': '[Unit]\nDescription=CONNECT Core control and IP v2 server\nRequires=connect-core-network.service\nAfter=connect-core-network.service\n\n[Service]\nUser=connectcore\nSupplementaryGroups=connectadmin\nExecStart=/opt/connect-core/current/bin/connect-control serve /var/lib/connect-core/control/control.json\nRestart=on-failure\nRestartSec=3\nTimeoutStopSec=20\n' + hardening + 'ReadWritePaths=/var/lib/connect-core/control\nCapabilityBoundingSet=\nDevicePolicy=closed\nDeviceAllow=/dev/net/tun rw\n\n[Install]\nWantedBy=multi-user.target\n',
        'connect-ui.service': '[Unit]\nDescription=CONNECT UI local panel\nAfter=connect-core.service\n\n[Service]\nUser=connectui\nSupplementaryGroups=connectadmin\nExecStart=/opt/connect-core/current/bin/connect-ui serve /etc/connect-core/ui.json\nRestart=on-failure\nRestartSec=3\nTimeoutStopSec=20\n' + hardening + 'CapabilityBoundingSet=\n\n[Install]\nWantedBy=multi-user.target\n',
    }

def health(m):
    import time
    config = json.loads((STATE / 'control' / 'control.json').read_text())
    token = pathlib.Path(config['token_file']).read_text().strip()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(100):
        try:
            for name in NAMES:
                if run('systemctl', 'is-active', name, check=False).stdout.strip() != 'active': raise RuntimeError('owned service not active')
            req = urllib.request.Request('http://' + config['listen'] + '/v1/status', headers={'Authorization': 'Bearer ' + token})
            with opener.open(req, timeout=2) as response: status = json.load(response)
            if status['api_version'] != 1 or status['status'] != 'running': raise RuntimeError('real server not ready')
            with opener.open('http://127.0.0.1:' + str(m['panel_port']), timeout=2) as response:
                if response.status != 200: raise RuntimeError('panel not ready')
            return
        except (OSError, RuntimeError): time.sleep(.1)
    raise RuntimeError('Owned services did not become healthy; rolling back')

def verify_owned(m):
    if m.get('schema') != 1 or not re.fullmatch(r'[a-f0-9]{32}', m.get('owner', '')): raise RuntimeError('Invalid ownership journal')
    for name, digest in m.get('unit_hashes', {}).items():
        if name not in NAMES or not (UNITS / name).is_file() or sha(UNITS / name) != digest:
            raise RuntimeError('Service file changed outside installer; refusing to overwrite/remove it')
    for name, uid in m.get('uids', {}).items():
        if name not in USERS or pwd.getpwnam(name).pw_uid != uid: raise RuntimeError('Account ownership changed')

def rollback_install(m):
    verify_owned(m)
    for name in reversed(NAMES): run('systemctl', 'stop', name, check=False); run('systemctl', 'disable', name, check=False)
    if (JOURNAL / 'network-journal.json').exists():
        run('/usr/bin/python3', str(ROOT / 'current' / 'scripts' / 'connect-vps-network.py'), 'rollback', str(JOURNAL / 'network.json'))
    for name in m.get('unit_hashes', {}): (UNITS / name).unlink(missing_ok=True)
    run('systemctl', 'daemon-reload')
    for name in reversed(list(m.get('uids', {}))): run('userdel', name)
    if m.get('group_created'): run('groupdel', GROUP)
    for path in [CONFIG, STATE, ROOT]:
        if str(path) in m.get('created_dirs', []): shutil.rmtree(path)
    shutil.rmtree(JOURNAL)

def install(args, revision, release):
    ensure_fresh()
    address, port_text = args.endpoint.rsplit(':', 1); address = str(ipaddress.IPv4Address(address)); port = int(port_text)
    if address == '0.0.0.0' or ipaddress.ip_address(address).is_multicast: raise RuntimeError('An assigned IPv4 endpoint is required')
    local = json.loads(run('ip', '-j', '-4', 'addr').stdout)
    if not any(v.get('local') == address for interface in local for v in interface.get('addr_info', [])):
        raise RuntimeError('Endpoint IPv4 is not assigned to this VPS; do not infer cloud NAT')
    ports = {port: socket.SOCK_DGRAM, args.panel_port: socket.SOCK_STREAM, args.control_port: socket.SOCK_STREAM, args.enrollment_port: socket.SOCK_STREAM}
    if len(ports) != 4: raise RuntimeError('CONNECT ports must be distinct')
    check_ports(ports)
    route = json.loads(run('ip', '-j', '-4', 'route', 'get', '1.1.1.1').stdout)[0]
    uplink = args.uplink or route['dev']
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', uplink): raise RuntimeError('Invalid egress interface')
    owner = uuid.uuid4().hex
    settings = {'owner': owner, 'interface': 'cc-vps0', 'pool': args.pool, 'endpoint': args.endpoint, 'uplink': uplink, 'enrollment_port': args.enrollment_port, 'uid': 0}
    # Read-only preflight from the same network helper used on boot/rollback.
    import importlib.util
    spec = importlib.util.spec_from_file_location('connect_network', release / 'scripts' / 'connect-vps-network.py'); network = importlib.util.module_from_spec(spec); spec.loader.exec_module(network)
    before = network.preflight(settings)
    print('Plan: dedicated connectcore/connectui accounts, 3 CONNECT services, cc-vps0 ' + args.pool)
    print(f'Local panel {args.panel_port}; local admin API {args.control_port}; UDP {port}; registration HTTPS {args.enrollment_port}.')
    print('Only scoped CONNECT firewall/NAT rules will be added. Existing services, routes and rules will not be removed.')
    if before['uplink_forwarding'] == '0': print('Forwarding will be enabled only on the CONNECT TUN and selected egress interface. Its previous shared flag is recorded for conditional rollback; global ip_forward is untouched.')
    print('Existing VPN/panel services:')
    for line in run('systemctl', 'list-units', '--all', '--type=service', '--no-pager', '--no-legend').stdout.splitlines():
        if re.search(r'xray|sudoku|x-ui|wireguard|openvpn|vpn', line, re.I): print('  ' + line.split()[0])
    if not args.yes:
        with open('/dev/tty', 'r+') as tty:
            tty.write('Apply only this CONNECT plan? [yes/no] '); tty.flush()
            if tty.readline().strip() != 'yes': raise RuntimeError('Installation cancelled without changes')
    if args.password_file:
        pp = pathlib.Path(args.password_file)
        if pp.stat().st_mode & 0o077: raise RuntimeError('Password file must be private (0600 or 0400)')
        password = pp.read_text().rstrip('\r\n')
    else:
        password = getpass.getpass('CONNECT UI administrator password (12+ bytes): ')
        if password != getpass.getpass('Repeat password: '): raise RuntimeError('Passwords differ')
    if len(password.encode()) < 12 or len(password.encode()) > 1024: raise RuntimeError('Password must contain 12..1024 bytes')
    ensure_fresh(); check_ports(ports)  # Recheck after build/operator input.
    JOURNAL.mkdir(mode=0o700)
    m = {'schema': 1, 'owner': owner, 'revision': revision, 'created_dirs': [], 'uids': {}, 'unit_hashes': {}, 'panel_port': args.panel_port}
    save(JOURNAL / 'manifest.json', m)
    try:
        for directory in [ROOT, STATE, CONFIG]:
            directory.mkdir(mode=0o700); m['created_dirs'].append(str(directory)); save(JOURNAL / 'manifest.json', m)
        ROOT.chmod(0o755); (ROOT / 'releases').mkdir(mode=0o755)
        target = ROOT / 'releases' / revision; shutil.copytree(release, target); (ROOT / 'current').symlink_to(target)
        run('groupadd', '--system', GROUP); m['group_created'] = True; save(JOURNAL / 'manifest.json', m)
        for name in USERS:
            run('useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', '--gid', GROUP, name)
            m['uids'][name] = pwd.getpwnam(name).pw_uid; save(JOURNAL / 'manifest.json', m)
        creds = STATE / 'control'; origin = f'https://{address}:{args.enrollment_port}'
        run(str(target / 'bin' / 'connect-control'), 'init-vps', str(creds), args.endpoint, origin)
        cpath = creds / 'control.json'; c = json.loads(cpath.read_text()); c.update(listen=f'127.0.0.1:{args.control_port}', owned_tun=True, auto_start=True, enrollment_listen=f'{address}:{args.enrollment_port}')
        token = CONFIG / 'control-token'; shutil.move(str(creds / 'control-token'), token); c['token_file'] = str(token); save(cpath, c)
        s = json.loads((creds / 'state.json').read_text()); s['config']['device_network'] = args.pool; save(creds / 'state.json', s)
        # Initialize UI in a temporary private directory, then relocate its config.
        ui_stage = STATE / 'ui-initial'; run(str(target / 'bin' / 'connect-ui'), 'init', str(ui_stage), 'http://' + c['listen'], str(token), input=password + '\n')
        uc = json.loads((ui_stage / 'ui.json').read_text()); uc['listen'] = f'127.0.0.1:{args.panel_port}'; save(CONFIG / 'ui.json', uc); shutil.rmtree(ui_stage)
        admin_gid = int(run('getent', 'group', GROUP).stdout.split(':')[2]); CONFIG.chmod(0o750); os.chown(CONFIG, 0, admin_gid); os.chown(token, 0, admin_gid); token.chmod(0o640)
        os.chown(CONFIG / 'ui.json', m['uids']['connectui'], admin_gid)
        STATE.chmod(0o755)
        for directory, dirs, files in os.walk(creds):
            os.chown(directory, m['uids']['connectcore'], admin_gid)
            for filename in files: os.chown(pathlib.Path(directory) / filename, m['uids']['connectcore'], admin_gid)
        settings['uid'] = m['uids']['connectcore']; save(JOURNAL / 'network.json', settings)
        for name, body in unit_files().items():
            (UNITS / name).write_text(body); (UNITS / name).chmod(0o644); m['unit_hashes'][name] = sha(UNITS / name); save(JOURNAL / 'manifest.json', m)
        run('systemctl', 'daemon-reload')
        for name in NAMES: run('systemctl', 'enable', name); run('systemctl', 'start', name)
        health(m)
        m['installed'] = True; save(JOURNAL / 'manifest.json', m)
        print(f'CONNECT installed. Panel: http://127.0.0.1:{args.panel_port} (admin). Use SSH forwarding for remote administration.')
        print(f'Update: sudo python3 {ROOT}/current/scripts/connect-install.py update --revision FULL_COMMIT_SHA')
        print(f'Rollback installation: sudo python3 {ROOT}/current/scripts/connect-install.py uninstall')
    except BaseException:
        rollback_install(m)
        raise

def update(args, m, revision, release):
    verify_owned(m)
    if revision == m['revision']: print('Already installed this immutable revision'); return
    old = (ROOT / 'current').resolve(); target = ROOT / 'releases' / revision
    if target.exists(): raise RuntimeError('Release directory already exists; refusing overwrite')
    shutil.copytree(release, target)
    # Compatibility check is read-only: never restore a stale state backup that
    # could undo newer certificate revocations.
    run(str(target / 'bin' / 'connect-control'), 'check', str(STATE / 'control' / 'control.json'))
    for name in ['connect-ui.service', 'connect-core.service']: run('systemctl', 'stop', name)
    try:
        next_link = ROOT / 'current.next'; next_link.symlink_to(target); os.replace(next_link, ROOT / 'current')
        for name in ['connect-core.service', 'connect-ui.service']: run('systemctl', 'start', name)
        health(m)
    except BaseException:
        for name in ['connect-ui.service', 'connect-core.service']: run('systemctl', 'stop', name, check=False)
        next_link = ROOT / 'current.next'; next_link.unlink(missing_ok=True); next_link.symlink_to(old); os.replace(next_link, ROOT / 'current')
        for name in ['connect-core.service', 'connect-ui.service']: run('systemctl', 'start', name)
        health(m); shutil.rmtree(target); raise
    m['previous_revision'] = m['revision']; m['revision'] = revision; save(JOURNAL / 'manifest.json', m)
    print('CONNECT updated; credentials, device registrations and revocations preserved. Previous binary revision retained.')

def main():
    p = argparse.ArgumentParser(); p.add_argument('action', choices=['install', 'update', 'rollback', 'uninstall', 'status'])
    p.add_argument('--revision'); p.add_argument('--source'); p.add_argument('--endpoint'); p.add_argument('--pool', default='10.231.0.0/24'); p.add_argument('--uplink')
    p.add_argument('--panel-port', type=int, default=17890); p.add_argument('--control-port', type=int, default=17891); p.add_argument('--enrollment-port', type=int, default=17900)
    p.add_argument('--password-file'); p.add_argument('--yes', action='store_true'); a = p.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0: raise RuntimeError('Run on a Linux systemd VPS as root')
    dependencies()
    with open('/run/connect-core-installer.lock', 'a') as lock:
        os.chmod(lock.name, 0o600); fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if a.action == 'install':
            if not a.endpoint: raise RuntimeError('--endpoint ASSIGNED_IPV4:UDP_PORT is required')
            ensure_fresh()
        else:
            m = json.loads((JOURNAL / 'manifest.json').read_text()); verify_owned(m)
            if a.action == 'status': print(json.dumps({k:v for k,v in m.items() if k in ['schema','revision','previous_revision','panel_port','installed']}, indent=2)); return
            if a.action == 'uninstall':
                if not a.yes and input('Remove CONNECT including its credentials and devices? Type yes: ') != 'yes': return
                rollback_install(m); print('Only installer-owned CONNECT resources removed'); return
            if a.action == 'rollback':
                old_revision = m.get('previous_revision')
                if not old_revision: raise RuntimeError('No previous binary revision is recorded')
                with tempfile.TemporaryDirectory(prefix='connect-rollback-') as stage:
                    release = pathlib.Path(stage) / 'release'; shutil.copytree(ROOT / 'releases' / old_revision, release)
                    # Make a unique target to retain audit history, without changing state.
                    rollback_revision = old_revision + '-rollback-' + uuid.uuid4().hex[:8]
                    update(a, m, rollback_revision, release)
                return
        with tempfile.TemporaryDirectory(prefix='connect-build-') as stage:
            revision, release = build(a, pathlib.Path(stage))
            if a.action == 'install': install(a, revision, release)
            else: update(a, m, revision, release)

if __name__ == '__main__':
    try: main()
    except Exception as e: print('CONNECT installation/update failed: ' + str(e), file=sys.stderr); sys.exit(1)
