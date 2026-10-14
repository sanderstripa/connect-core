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
origin = 'http://127.0.0.1:17890'
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf = ''
def api(path, data=None):
    headers = {'Content-Type':'application/json','Origin':origin,'X-Connect-UI':'1','X-CSRF-Token':csrf}
    request = urllib.request.Request(origin+path, data=None if data is None else json.dumps(data).encode(), headers=headers)
    with opener.open(request, timeout=15) as response: return json.load(response)

with tempfile.TemporaryDirectory(prefix='connect-installer-check-') as td:
    stage = pathlib.Path(td); password = 'isolated-installer-test-password'
    secret = stage / 'password'; secret.write_text(password+'\n'); secret.chmod(0o600)
    # A real neighboring service + firewall chain survive installation/uninstall.
    neighbor = subprocess.Popen([sys.executable,'-m','http.server','17889','--bind','127.0.0.1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run('iptables','-N','CONNECT_NEIGHBOR_FIXTURE');run('iptables','-A','CONNECT_NEIGHBOR_FIXTURE','-j','RETURN')
    run('ip','addr','add','198.18.0.1/32','dev','lo')
    before_firewall=network.firewall();before_routes=network.routes();before_global=pathlib.Path('/proc/sys/net/ipv4/ip_forward').read_text()
    args = [sys.executable,str(root/'scripts'/'connect-install.py'),'install','--source',str(root),'--endpoint','127.0.0.1:17444','--password-file',str(secret),'--yes']
    importer = None
    try:
        # Occupied-port check rejects before accounts/services/interfaces are created.
        occupied=subprocess.run(args+['--panel-port','17889'],capture_output=True,text=True)
        assert occupied.returncode != 0 and not installer.ROOT.exists(), 'occupied port install made system changes'
        result = subprocess.run(args,capture_output=True,text=True)
        if result.returncode: raise RuntimeError('real installer failed: '+result.stderr)
        assert neighbor.poll() is None, 'neighbor service stopped'
        with urllib.request.urlopen('http://127.0.0.1:17889',timeout=5) as r: assert r.status==200
        csrf=api('/auth/login',{'username':'admin','password':password})['csrf']
        status=api('/api/status');assert status['status']=='running' and status['active_sessions']==0, 'fake/bootstrap session'
        invite=api('/api/invite',{'name':'Actual installer client','ip':'10.231.0.2'})
        png=stage/'invite.png';png.write_bytes(base64.b64decode(invite['qr_png']))
        decoded=run('zbarimg','--quiet','--raw',str(png)).stdout.strip()
        assert decoded==invite['link'], 'QR does not encode the supported URI'
        clientdir=stage/'client'
        importer=subprocess.Popen([str(installer.ROOT/'current'/'bin'/'connect-core'),'import-link',str(clientdir)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        importer.stdin.write(invite['link']+'\n');importer.stdin.close()
        for _ in range(100):
            rows=api('/api/registrations')
            pending=next((v for v in rows if v['id']==invite['id'] and v['status']=='pending'),None)
            if pending:break
            time.sleep(.1)
        assert pending, 'real client registration not received'
        # Compare against actual client-generated proof, not a copied server value.
        raw=run('openssl','req','-in',str(clientdir/'proof.csr'),'-pubkey','-noout').stdout
        keypem=stage/'public.pem';keypem.write_text(raw)
        der=subprocess.check_output(['openssl','pkey','-pubin','-in',str(keypem),'-outform','DER'])
        fingerprint=hashlib.sha256(der).hexdigest();assert fingerprint==pending['fingerprint']
        api('/api/registration',{'id':invite['id'],'action':'approve','fingerprint':fingerprint,'confirm':True})
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
        # Health failure during an update restores the exact previous binaries,
        # without restoring a state backup that could undo the revocation.
        manifest=json.loads((installer.JOURNAL/'manifest.json').read_text());old=(installer.ROOT/'current').resolve()
        release=stage/'broken-release';shutil.copytree(old,release);(release/'bin'/'connect-ui').write_text('#!/bin/sh\nexit 71\n');(release/'bin'/'connect-ui').chmod(0o755)
        try: installer.update(None,manifest,'f'*40,release)
        except RuntimeError: pass
        else: raise AssertionError('broken update falsely succeeded')
        assert (installer.ROOT/'current').resolve()==old, 'binary rollback failed'
        assert api('/api/status')['devices'][0]['access']=='revoked', 'rollback resurrected revoked credential'
        # Successful update path, then the explicit previous-version rollback.
        release=stage/'good-release';shutil.copytree(old,release);installer.update(None,manifest,'e'*40,release)
        assert manifest['previous_revision']==old.name
        run(sys.executable,str(installer.ROOT/'current'/'scripts'/'connect-install.py'),'rollback')
        assert api('/api/status')['devices'][0]['access']=='revoked'
        probe=subprocess.run([str(root/'bin'/'connect-vps-probe'),str(clientdir/'connect-ip-client.json')],cwd=clientdir,capture_output=True,text=True)
        assert probe.returncode!=0, 'revoked client reconnected after binary update/rollback'
        manifest=json.loads((installer.JOURNAL/'manifest.json').read_text());installer.rollback_install(manifest)
        assert neighbor.poll() is None and network.firewall()==before_firewall, 'neighbor rules changed'
        assert pathlib.Path('/proc/sys/net/ipv4/ip_forward').read_text()==before_global, 'global forwarding changed'
        assert sorted(json.dumps(v,sort_keys=True) for v in network.routes())==sorted(json.dumps(v,sort_keys=True) for v in before_routes), 'routes not rolled back'
        assert not installer.ROOT.exists() and not installer.CONFIG.exists() and not installer.STATE.exists()
        print('Real systemd installer, occupied ports, QR decode, client key/CSR approval, QUIC/TUN, failed-update recovery, update/rollback and neighbor preservation passed')
    finally:
        if importer and importer.poll() is None: importer.kill();importer.wait()
        if (installer.JOURNAL/'manifest.json').exists():
            installer.rollback_install(json.loads((installer.JOURNAL/'manifest.json').read_text()))
        neighbor.terminate();neighbor.wait();run('iptables','-F','CONNECT_NEIGHBOR_FIXTURE');run('iptables','-X','CONNECT_NEIGHBOR_FIXTURE')
        run('ip','addr','del','198.18.0.1/32','dev','lo')
