#!/usr/bin/env python3
"""Transactional systemd installer with automatic, read-only VPS discovery."""
import argparse
import fcntl
import hashlib
import ipaddress
import itertools
import json
import os
import pathlib
import pwd
import re
import shutil
import socket
import secrets
import ssl
import time
import urllib.parse
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
RUNTIME_NAMES = ['connect-core-network.service', 'connect-core.service', 'connect-ui.service']
NAMES = ['connect-core-network.service','connect-core.socket','connect-core.service','connect-ui.service','connect-ui-cert.service','connect-ui-cert.timer']
USERS = ['connectcore', 'connectui']
GROUP = 'connectadmin'

def run(*args, input=None, check=True, env=None):
    p = subprocess.run(args, input=input, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
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
    if not pathlib.Path('/run/systemd/system').exists(): raise RuntimeError('A running systemd host is required')
    if not pathlib.Path('/dev/net/tun').exists(): raise RuntimeError('/dev/net/tun is unavailable; enable it with the VPS provider')
    needed = ['systemctl', 'ip', 'iptables', 'sysctl', 'useradd', 'userdel', 'groupadd', 'groupdel', 'getent', 'ss', 'openssl', 'curl']
    missing = [n for n in needed if not shutil.which(n)]
    if missing and shutil.which('apt-get'):
        packages={'systemctl':'systemd','ip':'iproute2','ss':'iproute2','iptables':'iptables','sysctl':'procps','useradd':'passwd','userdel':'passwd','groupadd':'passwd','groupdel':'passwd','getent':'libc-bin','openssl':'openssl','curl':'curl'}
        print('Installing required system packages (no system upgrade)...', flush=True)
        run('apt-get','update')
        run('apt-get','install','-y','--no-upgrade','--no-install-recommends',*sorted({packages[n] for n in missing} | {'ca-certificates'}),env=dict(os.environ,DEBIAN_FRONTEND='noninteractive',NEEDRESTART_MODE='l'))
        missing=[n for n in needed if not shutil.which(n)]
    if missing: raise RuntimeError('Missing dependencies: '+', '.join(missing))

def check_ports(ports):
    if len(set(ports)) != len(ports) or any(p < 1 or p > 65535 for p in ports):
        raise RuntimeError('Ports must be distinct and in 1..65535')
    output = run('ss', '-H', '-lntu').stdout
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 5:
            match = re.search(r':(\d+)$', fields[4])
            if match and int(match.group(1)) in ports:
                raise RuntimeError(f'Port {match.group(1)} is already occupied; nothing will be stopped')
    for port, kind in ports.items():
        with socket.socket(socket.AF_INET, kind) as s:
            # Match Go's listener semantics: closed TIME_WAIT connections are
            # not an occupied service. The ss check still rejects live listeners.
            if kind == socket.SOCK_STREAM: s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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

def prepare_install(args):
    if args.panel_port==0: args.panel_port=None
    """Choose unused defaults; explicit operator choices must pass unchanged."""
    route = json.loads(run('ip', '-j', '-4', 'route', 'get', '1.1.1.1').stdout)[0]
    args.uplink = args.uplink or route['dev']
    if not args.endpoint:
        interfaces = json.loads(run('ip', '-j', '-4', 'addr').stdout)
        candidates = [v['local'] for interface in interfaces if interface.get('ifname') == args.uplink
                      for v in interface.get('addr_info', []) if v.get('local') and ipaddress.IPv4Address(v['local']).is_global]
        if route.get('prefsrc') in candidates: candidates = [route['prefsrc']] + [v for v in candidates if v != route['prefsrc']]
        if not candidates: raise RuntimeError('No assigned public IPv4 on the egress interface; cloud NAT requires a separate bind/advertised endpoint setup')
        args.endpoint = candidates[0] + ':0'
        automatic_endpoint = True
    else: automatic_endpoint = False
    address, port = args.endpoint.rsplit(':', 1)
    used = {}
    def choose(explicit, default, kind):
        if explicit is not None:
            if explicit in used: raise RuntimeError('CONNECT ports must be distinct')
            check_ports({explicit: kind}); used[explicit] = kind; return explicit
        for candidate in itertools.chain(range(default,65536),range(1024,default)):
            if candidate in used: continue
            try: check_ports({candidate: kind})
            except (RuntimeError, OSError): continue
            used[candidate] = kind; return candidate
        raise RuntimeError('No free CONNECT port in 1024..65535')
    # Reserve all explicit choices before selecting any defaults.
    explicit = [(int(port) if not automatic_endpoint else None, socket.SOCK_DGRAM),
                (args.panel_port, socket.SOCK_STREAM), (args.control_port, socket.SOCK_STREAM), (args.enrollment_port, socket.SOCK_STREAM)]
    for value, kind in explicit:
        if value is not None: choose(value, 0, kind)
    data_port = int(port) if not automatic_endpoint else choose(None, 17444, socket.SOCK_DGRAM)
    args.endpoint = str(ipaddress.IPv4Address(address)) + ':' + str(data_port)
    if args.panel_port is None:
        args.panel_port = choose(None, 17890, socket.SOCK_STREAM)
    args.acme_port = None
    certificate_source=getattr(args,'tls_cert',None);key_source=getattr(args,'tls_key',None)
    if bool(certificate_source)!=bool(key_source): raise RuntimeError('Specify both --tls-cert and --tls-key')
    for candidate in (443, 80):
        if candidate in used and candidate != args.panel_port: continue
        try:
            check_ports({candidate:socket.SOCK_STREAM})
            args.acme_port = candidate
            break
        except (RuntimeError,OSError): continue
    if args.acme_port is None and not certificate_source:
        raise RuntimeError('Both 443 and 80 are occupied; the panel supports any port but automatic IP certificate validation needs one free ACME port. No neighbor service will be stopped')
    if args.acme_port is not None: used[args.acme_port] = socket.SOCK_STREAM
    for name, default in [('control_port', 17891), ('enrollment_port', 17900)]:
        if getattr(args, name) is None: setattr(args, name, choose(None, default, socket.SOCK_STREAM))
    if not args.pool:
        routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'table', 'all').stdout)
        networks = [ipaddress.IPv4Network(v['dst'], strict=False) for v in routes if v.get('dst') not in (None, 'default', '0.0.0.0/0')]
        args.pool = next((str(n) for i in range(231, 256) for n in [ipaddress.IPv4Network(f'10.{i}.0.0/24')]
                          if not any(n.overlaps(existing) for existing in networks)), None)
        if args.pool is None: raise RuntimeError('No unused private CONNECT subnet; no routes were changed')
    check_ports(used)

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
    for name in ['connect-core', 'connect-control', 'connect-ui', 'connect-cert']:
        print('Building ' + name + '...', flush=True)
        p = subprocess.run([go, 'build', '-trimpath', '-o', str(release / 'bin' / name), './cmd/' + name], cwd=source, env=env, capture_output=True, text=True)
        if p.returncode: raise RuntimeError('Build failed: ' + p.stderr)
    for name in ['connect-install.py', 'connect-vps-network.py']:
        shutil.copy2(source / 'scripts' / name, release / 'scripts' / name)
    version = run(str(release / 'bin' / 'connect-control'), 'version').stdout.strip()
    if not re.fullmatch(r'0\.2\.\d+', version): raise RuntimeError('Unsupported installer/schema compatibility version')
    return revision, release

def publish_release(release, target):
    """Program files must be traversable/executable under any caller umask.

    Credentials live in STATE/CONFIG, never in this program-only directory.
    Do not weaken permissions on keys or installer journals.
    """
    shutil.copytree(release, target)
    for directory, dirs, files in os.walk(target):
        pathlib.Path(directory).chmod(0o755)
        for name in files:
            path=pathlib.Path(directory)/name
            if path.is_symlink(): raise RuntimeError('Unexpected symlink in program release')
            path.chmod(0o755 if path.parent==target/'bin' else 0o644)

def unit_files(endpoint=None):
    hardening = 'NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nUMask=0077\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n'
    core_hardening = hardening.replace('AF_INET AF_INET6 AF_UNIX', 'AF_INET AF_INET6 AF_UNIX AF_NETLINK')
    units = {
        'connect-core-network.service': '[Unit]\nDescription=CONNECT owned TUN and scoped rules\nAfter=network-online.target\nWants=network-online.target\nBefore=connect-core.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 /opt/connect-core/current/scripts/connect-vps-network.py apply /var/lib/connect-core-installer/network.json\nExecStop=/usr/bin/python3 /opt/connect-core/current/scripts/connect-vps-network.py rollback /var/lib/connect-core-installer/network.json\n\n[Install]\nWantedBy=multi-user.target\n',
        'connect-core.service': '[Unit]\nDescription=CONNECT Core control and IP v2 server\nRequires=connect-core-network.service\nAfter=connect-core-network.service\n\n[Service]\nUser=connectcore\nSupplementaryGroups=connectadmin\nExecStart=/opt/connect-core/current/bin/connect-control serve /var/lib/connect-core/control/control.json\nRestart=on-failure\nRestartSec=3\nTimeoutStopSec=20\n' + core_hardening + 'ReadWritePaths=/var/lib/connect-core/control\nCapabilityBoundingSet=\nDevicePolicy=closed\nDeviceAllow=/dev/net/tun rw\n\n[Install]\nWantedBy=multi-user.target\n',
        'connect-ui.service': '[Unit]\nDescription=CONNECT UI public HTTPS panel\nAfter=connect-core.service\n\n[Service]\nUser=connectui\nSupplementaryGroups=connectadmin\nExecStart=/opt/connect-core/current/bin/connect-ui serve /etc/connect-core/ui.json\nRestart=on-failure\nRestartSec=3\nTimeoutStopSec=20\n' + hardening + 'AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n\n[Install]\nWantedBy=multi-user.target\n',
    }
    if endpoint is not None:
        units['connect-core.service']=units['connect-core.service'].replace('Requires=connect-core-network.service\n','Requires=connect-core-network.service connect-core.socket\n').replace('After=connect-core-network.service\n','After=connect-core-network.service connect-core.socket\n')
        units['connect-core.socket']='[Unit]\nDescription=CONNECT owned buffered UDP socket\nRequires=connect-core-network.service\nAfter=connect-core-network.service\n\n[Socket]\nListenDatagram='+endpoint+'\nReceiveBuffer=8M\nSendBuffer=8M\nFileDescriptorName=connect-data\nService=connect-core.service\n\n[Install]\nWantedBy=sockets.target\n'
    return units


def panel_url(m):
    if not m.get('public_https'): return 'http://127.0.0.1:' + str(m['panel_port'])
    return 'https://' + m['panel_ip'] + ('' if m['panel_port'] == 443 else ':' + str(m['panel_port']))

def tls_context(m):
    return ssl.create_default_context(cafile=m.get('test_ca'))

def health(m, password=None):
    config = json.loads((STATE / 'control' / 'control.json').read_text())
    token = pathlib.Path(config['token_file']).read_text().strip()
    cookies = __import__('http.cookiejar', fromlist=['CookieJar']).CookieJar()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls_context(m)), urllib.request.HTTPCookieProcessor(cookies))
    last_error = None
    for _ in range(100):
        try:
            for name in RUNTIME_NAMES:
                service_state=run('systemctl','is-active',name,check=False).stdout.strip()
                if service_state != 'active': raise RuntimeError(name + ' is ' + service_state)
            req = urllib.request.Request('http://' + config['listen'] + '/v1/status', headers={'Authorization': 'Bearer ' + token})
            with opener.open(req, timeout=2) as response: status = json.load(response)
            if status['api_version'] != 1 or status['status'] != 'running': raise RuntimeError('real server not ready')
            if m.get('socket_activation'):
                buffers=status.get('udp_buffers',{})
                if min(buffers.get('receive_bytes',0),buffers.get('send_bytes',0))<7*1024*1024: raise RuntimeError('Owned UDP socket buffers were not applied; keeping previous installation')
            origin = panel_url(m)
            with opener.open(origin, timeout=2) as response:
                if response.status != 200 or b'CONNECT' not in response.read(65536): raise RuntimeError('panel not ready')
            if password is not None:
                req = urllib.request.Request(origin + '/auth/login', data=json.dumps({'username':'admin', 'password':password}).encode(), headers={'Content-Type':'application/json','Origin':origin,'X-Connect-UI':'1'})
                with opener.open(req, timeout=5) as response: login = json.load(response)
                if not login.get('csrf') or not any(c.name == 'connect_session' and c.secure for c in cookies): raise RuntimeError('HTTPS login/session check failed')
                req = urllib.request.Request(origin + '/auth/logout', data=b'{}', headers={'Content-Type':'application/json','Origin':origin,'X-Connect-UI':'1','X-CSRF-Token':login['csrf']})
                with opener.open(req, timeout=5) as response: response.read()
            return
        except (OSError, RuntimeError, ValueError) as e: last_error=e; time.sleep(.1)
    raise RuntimeError('Owned HTTPS services did not become healthy; rolling back: ' + str(last_error))

def remote_panel_check(m):
    # A server's own GET is insufficient evidence for provider firewall rules.
    # No credentials or tokens are shared with this public monitoring service.
    url = panel_url(m)
    if m.get('test_probe'):
        command = ['ip','netns','exec',m['test_probe'],'curl','--noproxy','*','--fail','--silent','--show-error','--max-time','10','--cacert',m['test_ca'],url]
        if 'CONNECT' not in run(*command).stdout: raise RuntimeError('Separate peer could not load HTTPS panel')
        return {'source':'disposable peer namespace', 'url':url}
    def get(url):
        req = urllib.request.Request(url, headers={'Accept':'application/json','User-Agent':'CONNECT-installer'})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=15) as r: return json.load(r)
    result = get('https://check-host.net/check-http?' + urllib.parse.urlencode({'host':url,'max_nodes':3}))
    request_id = result.get('request_id','')
    if result.get('ok') != 1 or not re.fullmatch(r'[a-zA-Z0-9_-]{1,128}',request_id): raise RuntimeError('Public panel reachability check could not start')
    for _ in range(20):
        results = get('https://check-host.net/check-result/' + request_id)
        good = [node for node, rows in results.items() if isinstance(rows,list) and any(isinstance(row,list) and len(row)>=5 and row[0]==1 and str(row[3])=='200' and row[4]==m['panel_ip'] for row in rows)]
        if len(good) >= 2: return {'source':'check-host.net', 'request_id':request_id, 'nodes':good, 'url':url}
        time.sleep(3)
    raise RuntimeError('Public HTTPS panel could not be reached from two external nodes; check provider firewall/access. Installation is not successful')

def certificate_issue(m):
    tls_root = CONFIG / 'panel-tls'; tls_root.mkdir(mode=0o750, exist_ok=True); tls_root.chmod(0o750)
    admin_gid = int(run('getent', 'group', GROUP).stdout.split(':')[2]); os.chown(tls_root,0,admin_gid)
    stage = tls_root / ('cert-' + uuid.uuid4().hex); stage.mkdir(mode=0o700)
    challenge_port = m.get('acme_port',m['panel_port'])
    # ACME listeners are temporary and independent of the HTTPS panel port.
    # Bind/preflight first; never stop or take over a neighbor's listener.
    rule=['-p','tcp','-d',m['panel_ip'],'--dport',str(challenge_port),'-m','comment','--comment','connect-acme:'+m['owner'],'-j','ACCEPT']
    opened=False
    try:
        if m.get('tls_source'):
            shutil.copyfile(m['tls_source']['cert'],stage/'cert.pem');shutil.copyfile(m['tls_source']['key'],stage/'key.pem')
            public_cert=run('openssl','x509','-in',str(stage/'cert.pem'),'-pubkey','-noout').stdout
            public_key=run('openssl','pkey','-in',str(stage/'key.pem'),'-pubout').stdout
            if public_cert!=public_key: raise RuntimeError('HTTPS certificate/key mismatch')
            run('openssl','x509','-checkend','3600','-noout','-in',str(stage/'cert.pem'))
        else:
            check_ports({challenge_port:socket.SOCK_STREAM})
            if challenge_port != m['panel_port']:
                run('iptables','-w','5','-I','INPUT','1',*rule);opened=True
            run(str(ROOT/'current'/'bin'/'connect-cert'),m['panel_ip'],str(STATE/'acme'),str(stage),str(challenge_port),m['acme_directory'],env=dict(os.environ,LEGO_CA_CERTIFICATES=m['test_ca']) if m.get('test_ca') else None)
        # Verify IP SAN, chain and expiry against system trust, never curl -k.
        run('openssl','verify','-verify_ip',m['panel_ip'],'-purpose','sslserver','-untrusted',str(stage/'cert.pem'),*(['-CAfile',m['test_ca']] if m.get('test_ca') else []),str(stage/'cert.pem'))
        stage.chmod(0o750); os.chown(stage,0,admin_gid)
        for path in stage.iterdir(): path.chmod(0o640); os.chown(path,0,admin_gid)
        current = tls_root/'current'; previous = current.resolve() if current.is_symlink() else None
        next_link=tls_root/'current.next'; next_link.unlink(missing_ok=True); next_link.symlink_to(stage.name); os.replace(next_link,current)
        if previous and previous.parent==tls_root: shutil.rmtree(previous)
    except BaseException:
        shutil.rmtree(stage); raise
    finally:
        if opened: run('iptables','-w','5','-D','INPUT',*rule)

def renew_certificate(m):
    verify_owned(m)
    if not m.get('public_https'): return
    cert=CONFIG/'panel-tls'/'current'/'cert.pem'
    if run('openssl','x509','-checkend',str(72*3600),'-noout','-in',str(cert),check=False).returncode==0: return
    shared=m.get('acme_port',m['panel_port'])==m['panel_port']
    if shared: run('systemctl','stop','connect-ui.service')
    try: certificate_issue(m)
    finally:
        if shared: start_owned('connect-ui.service')
    if not shared: run('systemctl','restart','connect-ui.service')
    health(m)
    print('CONNECT panel certificate renewed')

def verify_owned(m):
    if m.get('schema') != 1 or not re.fullmatch(r'[a-f0-9]{32}', m.get('owner', '')): raise RuntimeError('Invalid ownership journal')
    for name, digest in m.get('unit_hashes', {}).items():
        if name not in NAMES or not (UNITS / name).is_file() or sha(UNITS / name) != digest:
            raise RuntimeError('Service file changed outside installer; refusing to overwrite/remove it')
    for name, uid in m.get('uids', {}).items():
        if name not in USERS or pwd.getpwnam(name).pw_uid != uid: raise RuntimeError('Account ownership changed')

def rollback_install(m):
    verify_owned(m)
    for name in reversed(NAMES):
        if name in m.get('unit_hashes',{}): run('systemctl', 'stop', name, check=False); run('systemctl', 'disable', name, check=False)
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
    settings = {'panel_port': args.panel_port, 'owner': owner, 'interface': 'cc-vps0', 'pool': args.pool, 'endpoint': args.endpoint, 'uplink': uplink, 'enrollment_port': args.enrollment_port, 'uid': 0}
    # Read-only preflight from the same network helper used on boot/rollback.
    import importlib.util
    spec = importlib.util.spec_from_file_location('connect_network', release / 'scripts' / 'connect-vps-network.py'); network = importlib.util.module_from_spec(spec); spec.loader.exec_module(network)
    before = network.preflight(settings)
    print('Plan: dedicated connectcore/connectui accounts, 3 CONNECT services, cc-vps0 ' + args.pool)
    print(f'Public HTTPS panel {address}:{args.panel_port}; local admin API {args.control_port}; UDP {port}; registration HTTPS {args.enrollment_port}.')
    print('Only scoped CONNECT firewall/NAT rules will be added. Existing services, routes and rules will not be removed.')
    if before['uplink_forwarding'] == '0': print('Forwarding will be enabled only on the CONNECT TUN and selected egress interface. Its previous shared flag is recorded for conditional rollback; global ip_forward is untouched.')
    print('Existing VPN/panel services:')
    for line in run('systemctl', 'list-units', '--all', '--type=service', '--no-pager', '--no-legend').stdout.splitlines():
        if re.search(r'xray|sudoku|x-ui|wireguard|openvpn|vpn', line, re.I): print('  ' + line.split()[0])
    password = secrets.token_urlsafe(24)
    ensure_fresh(); check_ports(ports)  # Recheck after build/operator input.
    m = {'schema': 1, 'owner': owner, 'revision': revision, 'created_dirs': [], 'uids': {}, 'unit_hashes': {}, 'panel_port': args.panel_port, 'panel_ip':address, 'public_https':True, 'acme_port':getattr(args,'acme_port',args.panel_port), 'acme_directory':getattr(args,'acme_directory','https://acme-v02.api.letsencrypt.org/directory')}
    if getattr(args,'tls_cert',None): m['tls_source']={'cert':str(pathlib.Path(args.tls_cert).absolute()),'key':str(pathlib.Path(args.tls_key).absolute())}
    test_ca=getattr(args,'test_acme_ca',None); test_probe=getattr(args,'test_probe',None)
    if test_ca or test_probe:
        if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('CONNECT_DISPOSABLE_INSTALL_TEST')!='1' or ipaddress.ip_address(address).is_global or not test_ca or not test_probe:
            raise RuntimeError('Test CA/peer allowed only on opted-in disposable CI with a nonpublic endpoint')
        m.update(test_ca=str(pathlib.Path(test_ca).resolve()),test_probe=test_probe)
    JOURNAL.mkdir(mode=0o700)
    save(JOURNAL / 'manifest.json', m)
    try:
        for directory in [ROOT, STATE, CONFIG]:
            directory.mkdir(mode=0o700); m['created_dirs'].append(str(directory)); save(JOURNAL / 'manifest.json', m)
        ROOT.chmod(0o755); (ROOT / 'releases').mkdir(mode=0o755); (ROOT / 'releases').chmod(0o755)
        target = ROOT / 'releases' / revision; publish_release(release, target); (ROOT / 'current').symlink_to(target)
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
        uc = json.loads((ui_stage / 'ui.json').read_text()); uc.update(listen=f'{address}:{args.panel_port}',public_https=True,tls_cert=str(CONFIG/'panel-tls'/'current'/'cert.pem'),tls_key=str(CONFIG/'panel-tls'/'current'/'key.pem')); save(CONFIG / 'ui.json', uc); shutil.rmtree(ui_stage)
        admin_gid = int(run('getent', 'group', GROUP).stdout.split(':')[2]); CONFIG.chmod(0o750); os.chown(CONFIG, 0, admin_gid); os.chown(token, 0, admin_gid); token.chmod(0o640)
        os.chown(CONFIG / 'ui.json', m['uids']['connectui'], admin_gid)
        STATE.chmod(0o755)
        for directory, dirs, files in os.walk(creds):
            os.chown(directory, m['uids']['connectcore'], admin_gid)
            for filename in files: os.chown(pathlib.Path(directory) / filename, m['uids']['connectcore'], admin_gid)
        settings['uid'] = m['uids']['connectcore']; save(JOURNAL / 'network.json', settings)
        units=unit_files(args.endpoint);m['socket_activation']=True
        units['connect-ui-cert.service']='[Unit]\nDescription=Renew CONNECT public IP HTTPS certificate\nAfter=network-online.target connect-core.service\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /opt/connect-core/current/scripts/connect-install.py renew-cert\nUMask=0077\n'
        units['connect-ui-cert.timer']='[Unit]\nDescription=Check CONNECT short-lived HTTPS certificate hourly\n\n[Timer]\nOnActiveSec=5min\nOnUnitActiveSec=1h\nRandomizedDelaySec=5min\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n'
        for name, body in units.items():
            (UNITS / name).write_text(body); (UNITS / name).chmod(0o644); m['unit_hashes'][name] = sha(UNITS / name); save(JOURNAL / 'manifest.json', m)
        run('systemctl', 'daemon-reload')
        for name in ['connect-core-network.service','connect-core.socket','connect-core.service']: run('systemctl','enable',name); run('systemctl','start',name)
        print('Obtaining trusted public IP HTTPS certificate...',flush=True)
        certificate_issue(m)
        run('systemctl','enable','connect-ui.service'); run('systemctl','start','connect-ui.service')
        health(m,password)
        print('Checking HTTPS login and panel access from outside the VPS...',flush=True)
        m['public_probe']=remote_panel_check(m)
        run('systemctl','enable','connect-ui-cert.timer'); run('systemctl','start','connect-ui-cert.timer')
        m['installed'] = True; save(JOURNAL / 'manifest.json', m)
        save(CONFIG/'install-access.json', {'panel':panel_url(m),'username':'admin','password':password})
        print('CONNECT successfully installed; HTTPS login and external panel access verified.')
        print('Panel: ' + panel_url(m))
        print('Login: admin')
        print('Password: ' + password)
        print('Update: curl --proto \'=https\' --tlsv1.2 -fsSL https://raw.githubusercontent.com/sanderstripa/connect-core/main/scripts/install-vps.sh | sudo bash -s -- update')
        print(f'Rollback installation: sudo python3 {ROOT}/current/scripts/connect-install.py uninstall')
    except BaseException:
        rollback_install(m)
        raise

def start_owned(name):
    if name not in RUNTIME_NAMES+['connect-core.socket']: raise RuntimeError('Refusing to reset/start a foreign service')
    # An intentional failed update may exhaust systemd's start-rate limit.
    # Reset only the owned service before an explicit recovery/release switch;
    # leave automatic restart limiting in force during normal operation.
    run('systemctl','reset-failed',name)
    run('systemctl','start',name)

def change_panel_port(m, requested):
    """Move only the owned HTTPS listener/rules; TUN/Core stay running."""
    verify_owned(m)
    if not m.get('public_https'): raise RuntimeError('Public HTTPS configuration is required for a panel port change')
    old_port=m['panel_port']
    if requested==old_port: return
    if requested==0:
        for candidate in itertools.chain(range(17890,65536),range(1024,17890)):
            try: check_ports({candidate:socket.SOCK_STREAM}); requested=candidate; break
            except (RuntimeError,OSError): continue
        if requested==0: raise RuntimeError('No free panel port in 1024..65535')
    check_ports({requested:socket.SOCK_STREAM})
    settings_path=JOURNAL/'network.json'; settings=json.loads(settings_path.read_text())
    if settings.get('owner')!=m['owner'] or settings.get('panel_port')!=old_port: raise RuntimeError('Panel/network ownership mismatch')
    ui_path=CONFIG/'ui.json'; ui=json.loads(ui_path.read_text()); metadata=ui_path.stat()
    if ui.get('listen')!=f"{m['panel_ip']}:{old_port}" or not ui.get('public_https'): raise RuntimeError('Panel configuration changed outside installer')
    def publish_ui(value):
        save(ui_path,value);os.chown(ui_path,metadata.st_uid,metadata.st_gid);os.chmod(ui_path,metadata.st_mode & 0o777)
    chain='CC_'+m['owner'][:8]+'_I'
    def entries(port):
        base=['-p','tcp','-d',m['panel_ip'],'--dport',str(port)]
        return [(chain,base+['-j','ACCEPT']),('INPUT',base+['-m','comment','--comment','connect-core:'+m['owner'],'-j',chain])]
    def add(entries):
        for name,rule in entries:
            if run('iptables','-w','5','-C',name,*rule,check=False).returncode:
                run('iptables','-w','5','-I',name,'1',*rule)
    def remove(entries):
        for name,rule in reversed(entries):
            if run('iptables','-w','5','-C',name,*rule,check=False).returncode==0:
                run('iptables','-w','5','-D',name,*rule)
    next_manifest=dict(m,panel_port=requested,acme_port=m.get('acme_port',old_port))
    next_ui=dict(ui,listen=f"{m['panel_ip']}:{requested}")
    next_settings=dict(settings,panel_port=requested)
    with open(JOURNAL/'network.lock','a') as lock:
        os.chmod(lock.name,0o600);fcntl.flock(lock,fcntl.LOCK_EX)
        try:
            add(entries(requested));publish_ui(next_ui)
            run('systemctl','restart','connect-ui.service')
            health(next_manifest)
            next_manifest['public_probe']=remote_panel_check(next_manifest)
            save(settings_path,next_settings);save(JOURNAL/'manifest.json',next_manifest)
            remove(entries(old_port))
        except BaseException:
            publish_ui(ui);save(settings_path,settings);save(JOURNAL/'manifest.json',m)
            add(entries(old_port));remove(entries(requested))
            run('systemctl','restart','connect-ui.service');health(m)
            raise
    m.clear();m.update(next_manifest)
    access=CONFIG/'install-access.json'
    if access.is_file():
        value=json.loads(access.read_text());value['panel']=panel_url(m);save(access,value)
    print('Panel: '+panel_url(m))

def prepare_socket_migration(m):
    if m.get('socket_activation'): return None
    if (UNITS/'connect-core.socket').exists(): raise RuntimeError('Unowned connect-core.socket exists; refusing adoption')
    settings=json.loads((JOURNAL/'network.json').read_text())
    if settings.get('owner')!=m['owner']: raise RuntimeError('Network ownership mismatch')
    return {'core':(UNITS/'connect-core.service').read_bytes(),'hashes':dict(m['unit_hashes']),'units':unit_files(settings['endpoint']),'created':False}

def apply_socket_migration(m,backup):
    if backup is None: return
    fd=os.open(UNITS/'connect-core.socket',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644)
    backup['created']=True
    with os.fdopen(fd,'w') as f: f.write(backup['units']['connect-core.socket'])
    (UNITS/'connect-core.service').write_text(backup['units']['connect-core.service'])
    for name in ['connect-core.socket','connect-core.service']:
        (UNITS/name).chmod(0o644);m['unit_hashes'][name]=sha(UNITS/name)
    m['socket_activation']=True;save(JOURNAL/'manifest.json',m)
    run('systemctl','daemon-reload');run('systemctl','enable','connect-core.socket');start_owned('connect-core.socket')

def undo_socket_migration(m,backup):
    if backup is None: return
    if backup['created']:
        run('systemctl','stop','connect-core.socket',check=False);run('systemctl','disable','connect-core.socket',check=False)
        (UNITS/'connect-core.socket').unlink(missing_ok=True)
    (UNITS/'connect-core.service').write_bytes(backup['core']);(UNITS/'connect-core.service').chmod(0o644)
    m['unit_hashes']=backup['hashes'];m.pop('socket_activation',None);save(JOURNAL/'manifest.json',m)
    run('systemctl','daemon-reload')

def update(args, m, revision, release):
    verify_owned(m)
    certificate_source=getattr(args,'tls_cert',None);key_source=getattr(args,'tls_key',None)
    if bool(certificate_source)!=bool(key_source): raise RuntimeError('Specify both --tls-cert and --tls-key')
    if certificate_source:
        candidate=dict(m,tls_source={'cert':str(pathlib.Path(certificate_source).absolute()),'key':str(pathlib.Path(key_source).absolute())},acme_port=None)
        certificate_issue(candidate)
        m.clear();m.update(candidate);save(JOURNAL/'manifest.json',m)
        run('systemctl','restart','connect-ui.service');health(m)
    if revision == m['revision']:
        if getattr(args,'panel_port',None) is not None: change_panel_port(m,args.panel_port)
        print('Already installed this immutable revision'); return
    old = (ROOT / 'current').resolve(); target = ROOT / 'releases' / revision
    if target.exists(): raise RuntimeError('Release directory already exists; refusing overwrite')
    publish_release(release, target)
    # Compatibility check is read-only: never restore a stale state backup that
    # could undo newer certificate revocations.
    try:
        target_version=run(str(target/'bin'/'connect-control'),'version').stdout.strip()
        if (m['panel_port'] not in (80,443) or m.get('tls_source') or m.get('socket_activation')) and target_version in ('0.2.0','0.2.1','0.2.2','0.2.3','0.2.4'):
            raise RuntimeError('Target installer cannot renew certificates on a custom panel port; keeping current installation')
        checked = run(str(target / 'bin' / 'connect-control'), 'check', str(STATE / 'control' / 'control.json')).stdout.strip()
        if checked != 'api_version=1 state_version=1 invitations_version=1':
            raise RuntimeError('Unrecognized persisted-state compatibility contract')
    except BaseException:
        shutil.rmtree(target); raise
    try: migration=prepare_socket_migration(m) if tuple(map(int,target_version.split('.'))) >= (0,2,5) else None
    except BaseException: shutil.rmtree(target);raise
    for name in ['connect-ui.service', 'connect-core.service']: run('systemctl', 'stop', name)
    try:
        next_link = ROOT / 'current.next'; next_link.symlink_to(target); os.replace(next_link, ROOT / 'current')
        apply_socket_migration(m,migration)
        for name in ['connect-core.service', 'connect-ui.service']: start_owned(name)
        health(m)
        interfaces=json.loads(run('ip','-j','-d','link','show','dev','cc-vps0').stdout)
        if not interfaces or interfaces[0].get('ifalias')!='connect-core:'+m['owner']:
            raise RuntimeError('Owned TUN identity changed; refusing queue tuning')
        run('ip','link','set','dev','cc-vps0','txqueuelen','4096')
    except BaseException:
        for name in ['connect-ui.service', 'connect-core.service']: run('systemctl', 'stop', name, check=False)
        undo_socket_migration(m,migration)
        next_link = ROOT / 'current.next'; next_link.unlink(missing_ok=True); next_link.symlink_to(old); os.replace(next_link, ROOT / 'current')
        for name in ['connect-core.service', 'connect-ui.service']: start_owned(name)
        health(m); shutil.rmtree(target); raise
    m['previous_revision'] = m['revision']; m['revision'] = revision; save(JOURNAL / 'manifest.json', m)
    if getattr(args,'panel_port',None) is not None: change_panel_port(m,args.panel_port)
    print('CONNECT updated; credentials, device registrations and revocations preserved. Previous binary revision retained.')

def main():
    p = argparse.ArgumentParser(); p.add_argument('action', nargs='?', default='install', choices=['install', 'update', 'rollback', 'uninstall', 'status', 'renew-cert'])
    p.add_argument('--tls-cert',help='Existing trusted public-IP certificate, read-only source'); p.add_argument('--tls-key',help='Matching private key, copied into protected CONNECT storage')
    p.add_argument('--revision'); p.add_argument('--source'); p.add_argument('--endpoint'); p.add_argument('--pool'); p.add_argument('--uplink')
    p.add_argument('--panel-port', type=int); p.add_argument('--control-port', type=int); p.add_argument('--enrollment-port', type=int)
    p.add_argument('--test-acme-ca', help=argparse.SUPPRESS); p.add_argument('--test-probe', help=argparse.SUPPRESS)
    p.add_argument('--acme-directory', default='https://acme-v02.api.letsencrypt.org/directory'); p.add_argument('--yes', action='store_true'); a = p.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0: raise RuntimeError('Run on a Linux systemd VPS as root')
    if not a.acme_directory.startswith('https://'): raise RuntimeError('ACME directory must use verified HTTPS')
    dependencies()
    with open('/run/connect-core-installer.lock', 'a') as lock:
        os.chmod(lock.name, 0o600); fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if a.action == 'install' and (JOURNAL / 'manifest.json').is_file():
            # The update path verifies ownership before changing anything.
            # Never adopt an unowned directory or reset existing credentials.
            a.action = 'update'
        if a.action == 'install':
            ensure_fresh()
            prepare_install(a)
        else:
            m = json.loads((JOURNAL / 'manifest.json').read_text()); verify_owned(m)
            if a.action == 'renew-cert': renew_certificate(m); return
            if a.action == 'status': print(json.dumps({k:v for k,v in m.items() if k in ['schema','revision','previous_revision','panel_port','panel_ip','public_https','public_probe','installed']}, indent=2)); return
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
