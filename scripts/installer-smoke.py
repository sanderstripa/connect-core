#!/usr/bin/env python3
"""Real disposable CI host test. Opt-in only, never run on a live VPS."""
import base64
import hashlib
import http.cookiejar
import importlib.util
import json
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('CONNECT_DISPOSABLE_INSTALL_TEST') != '1' or os.geteuid() != 0:
    raise SystemExit('This destructive-to-own-fixture test requires an opted-in disposable GitHub runner')
root = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installer', root / 'scripts' / 'connect-install.py')
installer = importlib.util.module_from_spec(spec); spec.loader.exec_module(installer)
network_spec = importlib.util.spec_from_file_location('network', root / 'scripts' / 'connect-vps-network.py')
network = importlib.util.module_from_spec(network_spec); network_spec.loader.exec_module(network)
run = installer.run
origin = 'https://198.18.0.2'
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=os.environ['CONNECT_TEST_CA'])), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf = ''
def api(path, data=None):
    headers = {'Content-Type':'application/json','Origin':origin,'X-Connect-UI':'1','X-CSRF-Token':csrf}
    request = urllib.request.Request(origin+path, data=None if data is None else json.dumps(data).encode(), headers=headers)
    with opener.open(request, timeout=15) as response: return json.load(response)

with tempfile.TemporaryDirectory(prefix='connect-installer-check-') as td:
    stage = pathlib.Path(td)
    # A terminal opened r+ is non-seekable: reproduce the removed old prompt.
    import pty
    master, slave=pty.openpty()
    try:
        try: open(os.ttyname(slave),'r+')
        except OSError: pass
        else: raise AssertionError('old tty seek failure did not reproduce')
    finally: os.close(master);os.close(slave)
    # A real neighboring service + firewall chain survive installation/uninstall.
    neighbor = subprocess.Popen([sys.executable,'-m','http.server','17889','--bind','127.0.0.1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run('iptables','-N','CONNECT_NEIGHBOR_FIXTURE');run('iptables','-A','CONNECT_NEIGHBOR_FIXTURE','-j','RETURN')
    # A separate service namespace proves actual forwarding and masquerade,
    # instead of merely injecting a packet into a host-local UDP socket.
    run('ip','netns','add','connect-install-fixture')
    run('ip','link','add','cc-eg0','type','veth','peer','name','cc-es0','netns','connect-install-fixture')
    run('ip','addr','add','198.18.0.2/24','dev','cc-eg0');run('ip','link','set','cc-eg0','up')
    run('ip','-n','connect-install-fixture','addr','add','198.18.0.1/24','dev','cc-es0');run('ip','-n','connect-install-fixture','link','set','cc-es0','up');run('ip','-n','connect-install-fixture','link','set','lo','up')
    echo=subprocess.Popen(['ip','netns','exec','connect-install-fixture',str(root/'bin'/'connect-vps-probe'),'serve'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
    assert echo.stdout.readline().strip()=='ready', 'UDP service fixture not ready'
    before_firewall=network.firewall();before_routes=network.routes();before_global=pathlib.Path('/proc/sys/net/ipv4/ip_forward').read_text()
    args = [sys.executable,str(root/'scripts'/'connect-install.py'),'install','--source',str(root),'--endpoint','198.18.0.2:17444','--uplink','cc-eg0','--acme-directory',os.environ['CONNECT_TEST_ACME'],'--test-acme-ca',os.environ['CONNECT_TEST_CA'],'--test-probe','connect-install-fixture']
    importer = None
    try:
        # Occupied-port check rejects before accounts/services/interfaces are created.
        occupied=subprocess.run(args+['--panel-port','17889'],capture_output=True,text=True)
        assert occupied.returncode != 0 and not installer.ROOT.exists(), 'occupied port install made system changes'
        result = subprocess.run(['bash','-o','pipefail','-c','cat "$1" | bash -s -- "${@:2}"','--',str(root/'scripts'/'install-vps.sh'),*args[2:],'--panel-port','443','--revision',run('git','-C',str(root),'rev-parse','HEAD').stdout.strip()],input='',capture_output=True,text=True)
        if result.returncode: raise RuntimeError('real installer failed: '+result.stderr)
        assert (installer.CONFIG/'panel-tls').stat().st_mode & 0o777 == 0o750, 'TLS directory inaccessible to panel group'
        assert (installer.ROOT/'releases').stat().st_mode & 0o777 == 0o755, 'restrictive caller umask blocked release traversal'
        assert (installer.ROOT/'current'/'bin'/'connect-control').stat().st_mode & 0o777 == 0o755, 'service executable permissions wrong'
        credentials=json.loads((installer.CONFIG/'install-access.json').read_text())
        password=credentials['password']
        assert len(password)>=32 and credentials['username']=='admin' and credentials['panel']==origin
        assert ('Panel: '+origin) in result.stdout and ('Login: admin') in result.stdout and ('Password: '+password) in result.stdout, 'ready credentials missing'
        assert 'password (' not in result.stdout and 'Repeat password' not in result.stdout, 'interactive password prompt'
        assert (installer.CONFIG/'install-access.json').stat().st_mode & 0o077 == 0, 'password persisted with public permissions'
        assert neighbor.poll() is None, 'neighbor service stopped'
        with urllib.request.urlopen('http://127.0.0.1:17889',timeout=5) as r: assert r.status==200
        # Short-lived test certificates exercise the actual timer's renewal
        # service: retained credentials, fresh cert and HTTPS available again.
        certpath=installer.CONFIG/'panel-tls'/'current'/'cert.pem'
        old_cert=certpath.read_bytes()
        run('systemctl','start','connect-ui-cert.service')
        assert certpath.read_bytes()!=old_cert, 'short-lived certificate not renewed'
        csrf=api('/auth/login',{'username':'admin','password':password})['csrf']
        status=api('/api/status');assert status['status']=='running' and status['active_sessions']==0, 'fake/bootstrap session'
        assert min(status['udp_buffers'].values())>=7*1024*1024, 'privilege-separated UDP buffers missing'
        core_pid=run('systemctl','show','connect-core.service','--property=MainPID','--value').stdout.strip()
        capabilities=next(v for v in pathlib.Path('/proc',core_pid,'status').read_text().splitlines() if v.startswith('CapEff:'))
        assert int(capabilities.split()[1],16)==0, 'Core received network/root capabilities'
        for _ in range(2):
            api('/api/server',{'action':'stop','confirm':True})
            assert api('/api/status')['status']=='stopped'
            api('/api/server',{'action':'start'})
            assert api('/api/status')['status']=='running'
        invite=api('/api/invite',{'name':'Actual installer client','ip':'10.231.0.2'})
        png=stage/'invite.png';png.write_bytes(base64.b64decode(invite['qr_png']))
        decoded=run('zbarimg','--quiet','--raw',str(png)).stdout.strip()
        assert decoded==invite['link'], 'QR does not encode the supported URI'
        clientdir=stage/'client'
        importer=subprocess.Popen([str(installer.ROOT/'current'/'bin'/'connect-core'),'import-link',str(clientdir)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        importer.stdin.write(invite['link']+'\n');importer.stdin.close()
        for _ in range(100):
            rows=api('/api/registrations')
            pending=next((v for v in rows if v['id']==invite['id'] and v['status']=='approved'),None)
            if pending:break
            time.sleep(.1)
        assert pending, 'real client registration not received'
        # Compare against actual client-generated proof, not a copied server value.
        raw=run('openssl','req','-in',str(clientdir/'proof.csr'),'-pubkey','-noout').stdout
        keypem=stage/'public.pem';keypem.write_text(raw)
        der=subprocess.check_output(['openssl','pkey','-pubin','-in',str(keypem),'-outform','DER'])
        fingerprint=hashlib.sha256(der).hexdigest();assert fingerprint==pending['fingerprint']
        assert importer.wait(timeout=20)==0, 'client import did not finish'
        server_state=json.loads((installer.STATE/'control'/'state.json').read_text())
        client_key=(clientdir/'device-key.pem').read_text();assert client_key not in json.dumps(server_state)
        # Real QUIC + OS TUN connection using exported config, no network fixture.
        # Probe authenticates using the actual exported configuration and sends
        # only a raw test packet; no client host routing is changed.
        probe=subprocess.run([str(root/'bin'/'connect-vps-probe'),str(clientdir/'connect-ip-client.json')],cwd=clientdir,capture_output=True,text=True)
        if probe.returncode: raise RuntimeError('real VPS QUIC/TUN probe failed: '+probe.stderr)
        status=api('/api/status');assert status['received_bytes']>0 and status['sent_bytes']>0, 'no real TUN byte counters'
        rows=api('/api/status')['devices'];device=rows[0]
        api('/api/device',{'id':device['id'],'action':'revoke','confirm':True})
        # Move only the HTTPS panel, without restarting the Core/TUN or neighbors.
        manifest=json.loads((installer.JOURNAL/'manifest.json').read_text())
        old_core_pid=run('systemctl','show','connect-core.service','--property=MainPID','--value').stdout.strip()
        try: installer.change_panel_port(manifest,17889)
        except RuntimeError: pass
        else: raise AssertionError('occupied panel port was adopted')
        installer.change_panel_port(manifest,24443)
        origin='https://198.18.0.2:24443'
        csrf=api('/auth/login',{'username':'admin','password':password})['csrf']
        assert api('/api/status')['status']=='running'
        assert run('systemctl','show','connect-core.service','--property=MainPID','--value').stdout.strip()==old_core_pid, 'panel move restarted Core'
        assert neighbor.poll() is None
        # Health failure during an update restores the exact previous binaries,
        # without restoring a state backup that could undo the revocation.
        manifest=json.loads((installer.JOURNAL/'manifest.json').read_text());old=(installer.ROOT/'current').resolve()
        # Replaced files do not replace the executable held by a running process.
        binary=old/'bin'/'connect-control'; replacement=binary.with_name('connect-control.next')
        shutil.copy2(binary,replacement);os.replace(replacement,binary)
        try: installer.health(manifest)
        except RuntimeError: pass
        else: raise AssertionError('stale running executable falsely passed health')
        installer.update(None,manifest,manifest['revision'],old)
        installer.health(manifest)
        assert neighbor.poll() is None, 'repeat update disturbed neighbor'
        # Reproduce the installed 0.2.4 service layout: no activation socket and
        # an unprivileged Core binding UDP itself. State/credentials stay intact.
        for name in ['connect-ui.service','connect-core.service','connect-core.socket']:
            run('systemctl','stop',name)
        run('systemctl','disable','connect-core.socket')
        (installer.UNITS/'connect-core.socket').unlink()
        (installer.UNITS/'connect-core.service').write_text(installer.unit_files()['connect-core.service'])
        manifest['unit_hashes'].pop('connect-core.socket');manifest['unit_hashes']['connect-core.service']=installer.sha(installer.UNITS/'connect-core.service')
        manifest.pop('socket_activation');installer.save(installer.JOURNAL/'manifest.json',manifest)
        run('systemctl','daemon-reload')
        for name in ['connect-core.service','connect-ui.service']: installer.start_owned(name)
        installer.health(manifest)
        release=stage/'broken-release';shutil.copytree(old,release);(release/'bin'/'connect-ui').write_text('#!/bin/sh\nexit 71\n');(release/'bin'/'connect-ui').chmod(0o755)
        try: installer.update(None,manifest,'f'*40,release)
        except RuntimeError: pass
        else: raise AssertionError('broken update falsely succeeded')
        assert (installer.ROOT/'current').resolve()==old, 'binary rollback failed'
        assert not (installer.UNITS/'connect-core.socket').exists(), 'failed migration left an activation unit'
        csrf=api('/auth/login',{'username':'admin','password':password})['csrf']
        assert api('/api/status')['devices'][0]['access']=='revoked', 'rollback resurrected revoked credential'
        # Successful update path, then the explicit previous-version rollback.
        release=stage/'good-release';shutil.copytree(old,release);installer.update(None,manifest,'e'*40,release)
        assert manifest.get('socket_activation') and run('systemctl','is-active','connect-core.socket').stdout.strip()=='active', 'legacy installation did not migrate'
        assert manifest['previous_revision']==old.name
        run(sys.executable,str(installer.ROOT/'current'/'scripts'/'connect-install.py'),'rollback')
        csrf=api('/auth/login',{'username':'admin','password':password})['csrf']
        assert api('/api/status')['devices'][0]['access']=='revoked'
        probe=subprocess.run([str(root/'bin'/'connect-vps-probe'),str(clientdir/'connect-ip-client.json')],cwd=clientdir,capture_output=True,text=True)
        assert probe.returncode!=0, 'revoked client reconnected after binary update/rollback'
        manifest=json.loads((installer.JOURNAL/'manifest.json').read_text());installer.rollback_install(manifest)
        assert neighbor.poll() is None and network.firewall()==before_firewall, 'neighbor rules changed'
        assert pathlib.Path('/proc/sys/net/ipv4/ip_forward').read_text()==before_global, 'global forwarding changed'
        assert sorted(json.dumps(v,sort_keys=True) for v in network.routes())==sorted(json.dumps(v,sort_keys=True) for v in before_routes), 'routes not rolled back'
        assert not installer.ROOT.exists() and not installer.CONFIG.exists() and not installer.STATE.exists()
        # A neighbor owning 443 survives. Obtain a real IP certificate through
        # HTTP-01 on 80, then serve/login over HTTPS on that same port only.
        https_neighbor=subprocess.Popen([sys.executable,'-m','http.server','443','--bind','198.18.0.2'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(('198.18.0.2',443),timeout=.1): break
                except OSError: time.sleep(.05)
            import argparse,contextlib,io
            ns=argparse.Namespace(endpoint='198.18.0.2:17444',pool='10.231.0.0/24',uplink='cc-eg0',panel_port=None,control_port=None,enrollment_port=None,yes=True,acme_directory=os.environ['CONNECT_TEST_ACME'],test_acme_ca=os.environ['CONNECT_TEST_CA'],test_probe='connect-install-fixture')
            installer.prepare_install(ns); assert ns.panel_port==17890 and ns.acme_port==80
            with contextlib.redirect_stdout(io.StringIO()): installer.install(ns,'b'*40,release)
            fallback=json.loads((installer.CONFIG/'install-access.json').read_text())
            origin='https://198.18.0.2:17890'
            assert fallback['panel']==origin and https_neighbor.poll() is None
            csrf=api('/auth/login',{'username':'admin','password':fallback['password']})['csrf']
            assert api('/api/status')['status']=='running'
            try: urllib.request.urlopen('http://198.18.0.2:17890',timeout=5)
            except urllib.error.HTTPError as e: assert e.code==400
            else: raise AssertionError('panel accepted plaintext HTTP')
            supplied_cert=stage/'supplied-cert.pem';supplied_key=stage/'supplied-key.pem'
            shutil.copyfile(installer.CONFIG/'panel-tls'/'current'/'cert.pem',supplied_cert)
            shutil.copyfile(installer.CONFIG/'panel-tls'/'current'/'key.pem',supplied_key)
            installer.rollback_install(json.loads((installer.JOURNAL/'manifest.json').read_text()))
            assert https_neighbor.poll() is None and network.firewall()==before_firewall
            http_neighbor=subprocess.Popen([sys.executable,'-m','http.server','80','--bind','198.18.0.2'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    try:
                        with socket.create_connection(('198.18.0.2',80),timeout=.1): break
                    except OSError: time.sleep(.05)
                ns.panel_port=24443;ns.tls_cert=str(supplied_cert);ns.tls_key=str(supplied_key)
                installer.prepare_install(ns);assert ns.acme_port is None
                with contextlib.redirect_stdout(io.StringIO()): installer.install(ns,'d'*40,release)
                access=json.loads((installer.CONFIG/'install-access.json').read_text());origin='https://198.18.0.2:24443'
                csrf=api('/auth/login',{'username':'admin','password':access['password']})['csrf']
                assert api('/api/status')['status']=='running'
                assert https_neighbor.poll() is None and http_neighbor.poll() is None
                installer.rollback_install(json.loads((installer.JOURNAL/'manifest.json').read_text()))
                assert network.firewall()==before_firewall
            finally:
                http_neighbor.terminate();http_neighbor.wait()
        finally:
            https_neighbor.terminate();https_neighbor.wait();origin='https://198.18.0.2'
        # Successful services do not imply externally accessible UI. A failed
        # remote verification rolls back and MUST NOT print ready credentials.
        original_probe=installer.remote_panel_check
        installer.remote_panel_check=lambda m: (_ for _ in ()).throw(RuntimeError('injected unreachable panel'))
        try:
            import argparse,contextlib,io
            ns=argparse.Namespace(endpoint='198.18.0.2:17444',pool='10.231.0.0/24',uplink='cc-eg0',panel_port=443,control_port=17891,enrollment_port=17900,yes=True,acme_directory=os.environ['CONNECT_TEST_ACME'],test_acme_ca=os.environ['CONNECT_TEST_CA'],test_probe='connect-install-fixture')
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                try: installer.install(ns,'c'*40,release)
                except RuntimeError as e: assert 'unreachable panel' in str(e)
                else: raise AssertionError('unreachable public panel falsely succeeded')
            assert 'Password:' not in output.getvalue() and 'successfully installed' not in output.getvalue()
            assert not installer.ROOT.exists() and network.firewall()==before_firewall
        finally: installer.remote_panel_check=original_probe
        # Deliberately fail after the network unit applied its own rules. The
        # install transaction must remove only its mutations, not the neighbor.
        original_run=installer.run
        def fail_owned_start(*command, **kwargs):
            if command==('systemctl','start','connect-core.service'):
                raise RuntimeError('deliberate own-service startup failure')
            return original_run(*command,**kwargs)
        installer.run=fail_owned_start
        try:
            import argparse
            ns=argparse.Namespace(endpoint='198.18.0.2:17444',pool='10.231.0.0/24',uplink='cc-eg0',panel_port=443,control_port=17891,enrollment_port=17900,yes=True,acme_directory=os.environ['CONNECT_TEST_ACME'],test_acme_ca=os.environ['CONNECT_TEST_CA'],test_probe='connect-install-fixture')
            try: installer.install(ns,'d'*40,release)
            except RuntimeError: pass
            else: raise AssertionError('deliberately failed install falsely succeeded')
        finally: installer.run=original_run
        assert not installer.ROOT.exists() and not installer.JOURNAL.exists(), 'failed install left owned resources'
        assert neighbor.poll() is None and network.firewall()==before_firewall, 'failed install changed neighbor rules'
        assert sorted(json.dumps(v,sort_keys=True) for v in network.routes())==sorted(json.dumps(v,sort_keys=True) for v in before_routes), 'failed install left routes'
        print('Real systemd installer, occupied ports, QR decode, client key/CSR approval, QUIC/TUN, failed-update recovery, update/rollback and neighbor preservation passed')
    finally:
        if importer and importer.poll() is None: importer.kill();importer.wait()
        if (installer.JOURNAL/'manifest.json').exists():
            installer.rollback_install(json.loads((installer.JOURNAL/'manifest.json').read_text()))
        neighbor.terminate();neighbor.wait();run('iptables','-F','CONNECT_NEIGHBOR_FIXTURE');run('iptables','-X','CONNECT_NEIGHBOR_FIXTURE')
        echo.terminate();echo.wait();run('ip','link','delete','cc-eg0');run('ip','netns','del','connect-install-fixture')
