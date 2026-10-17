"""Read-only discovery tests; no services, routes or firewall are modified."""
import argparse
import importlib.util
import json
import pathlib
import sys
import types
import unittest
from unittest.mock import patch

if sys.platform == 'win32': sys.modules['fcntl'] = types.ModuleType('fcntl'); sys.modules['pwd'] = types.ModuleType('pwd')
spec = importlib.util.spec_from_file_location('installer', pathlib.Path(__file__).with_name('connect-install.py'))
installer = importlib.util.module_from_spec(spec); spec.loader.exec_module(installer)

class DiscoveryTests(unittest.TestCase):
    @patch.object(installer, 'check_ports')
    @patch.object(installer, 'run')
    def test_panel_port_is_independent_of_acme(self, run, ports):
        run.side_effect=self.run_fixture
        args=self.args(panel_port=24443)
        installer.prepare_install(args)
        self.assertEqual(args.panel_port,24443)
        self.assertEqual(args.acme_port,443)

    @patch.object(installer, 'check_ports')
    @patch.object(installer, 'run')
    def test_existing_certificate_allows_both_standard_ports_occupied(self, run, ports):
        run.side_effect=self.run_fixture
        def busy(values):
            if 443 in values or 80 in values: raise RuntimeError('neighbor listener')
        ports.side_effect=busy
        args=self.args(panel_port=24443,tls_cert='/owned-source/cert.pem',tls_key='/owned-source/key.pem')
        installer.prepare_install(args)
        self.assertEqual(args.panel_port,24443)
        self.assertIsNone(args.acme_port)

    def args(self, **values):
        defaults = dict(endpoint=None, uplink=None, pool=None, panel_port=None, control_port=None, enrollment_port=None)
        defaults.update(values); return argparse.Namespace(**defaults)

    def run_fixture(self, *command):
        if command[-1] == '1.1.1.1': value = [{'dev': 'eth0', 'prefsrc': '8.8.4.4'}]
        elif command[-1] == 'addr': value = [{'ifname': 'eth0', 'addr_info': [{'local': '8.8.4.4'}]}, {'ifname': 'vpn0', 'addr_info': [{'local': '1.1.1.1'}]}]
        else: value = [{'dst': 'default'}, {'dst': '10.231.0.0/16'}, {'dst': '10.232.0.0/24'}]
        return types.SimpleNamespace(stdout=json.dumps(value))

    def ports_fixture(self, ports):
        if 17890 in ports: raise RuntimeError('neighbor listener')

    @patch.object(installer, 'check_ports')
    @patch.object(installer, 'run')
    def test_busy_https_falls_back_without_taking_over(self, run, ports):
        run.side_effect = self.run_fixture
        def busy(values):
            if 443 in values: raise RuntimeError('neighbor HTTPS')
        ports.side_effect = busy
        args=self.args(); installer.prepare_install(args)
        self.assertEqual(args.panel_port,17890)
        self.assertEqual(args.acme_port,80)

    @patch.object(installer, 'check_ports')
    @patch.object(installer, 'run')
    def test_no_acme_port_refuses_without_mutating_neighbors(self, run, ports):
        run.side_effect = self.run_fixture
        def busy(values):
            if 443 in values or 80 in values: raise RuntimeError('neighbor HTTP/HTTPS')
        ports.side_effect = busy
        with self.assertRaisesRegex(RuntimeError,'Both 443 and 80'):
            installer.prepare_install(self.args())

    @patch.object(installer, 'check_ports')
    @patch.object(installer, 'run')
    def test_defaults_skip_neighbors_and_overlapping_routes(self, run, ports):
        run.side_effect = self.run_fixture; ports.side_effect = self.ports_fixture
        args = self.args(); installer.prepare_install(args)
        self.assertEqual(args.endpoint, '8.8.4.4:17444')
        self.assertEqual(args.uplink, 'eth0')
        self.assertEqual(args.pool, '10.233.0.0/24')
        self.assertEqual((args.panel_port, args.control_port, args.enrollment_port), (17891, 17892, 17900))

    @patch.object(installer, 'check_ports')
    @patch.object(installer, 'run')
    def test_explicit_busy_port_fails(self, run, ports):
        run.side_effect = self.run_fixture; ports.side_effect = self.ports_fixture
        with self.assertRaisesRegex(RuntimeError, 'neighbor'): installer.prepare_install(self.args(panel_port=17890))

    @patch.object(installer, 'check_ports')
    @patch.object(installer, 'run')
    def test_explicit_port_reserved_before_defaults(self, run, ports):
        run.side_effect = self.run_fixture
        args = self.args(control_port=17890, endpoint='127.0.0.1:17444', pool='10.240.0.0/24')
        installer.prepare_install(args)
        self.assertEqual(args.control_port, 17890)
        self.assertEqual(args.panel_port, 17891)
        self.assertEqual(args.endpoint, '127.0.0.1:17444')
        self.assertEqual(args.pool, '10.240.0.0/24')

    @patch.object(installer, 'check_ports')
    @patch.object(installer, 'run')
    def test_nat_address_not_advertised_as_public(self, run, ports):
        run.side_effect = lambda *cmd: types.SimpleNamespace(stdout=json.dumps([{'dev': 'eth0'}] if cmd[-1] == '1.1.1.1' else [{'ifname': 'eth0', 'addr_info': [{'local': '192.168.1.2'}]}]))
        with self.assertRaisesRegex(RuntimeError, 'cloud NAT'): installer.prepare_install(self.args())
        ports.assert_not_called()

class RuntimeIdentityTests(unittest.TestCase):
    def test_old_server_version_cannot_pass(self):
        with self.assertRaisesRegex(RuntimeError, 'differs from installed'):
            installer.verify_runtime({'core_version':'0.2.6'}, {'version':'0.2.10','revision':'unknown'})

    def test_wrong_revision_cannot_pass(self):
        with self.assertRaisesRegex(RuntimeError, 'revision differs'):
            installer.verify_runtime({'core_version':'0.2.10','core_revision':'b'*40}, {'version':'0.2.10','revision':'a'*40})

    @patch.object(installer.os, 'stat')
    @patch.object(installer, 'run')
    def test_replaced_executable_cannot_pass(self, run, stat):
        run.return_value=types.SimpleNamespace(stdout='123')
        stat.side_effect=[types.SimpleNamespace(st_dev=1,st_ino=10),types.SimpleNamespace(st_dev=1,st_ino=11)]
        with self.assertRaisesRegex(RuntimeError, 'different binary'):
            installer.verify_runtime({'core_version':'0.2.10'}, {'version':'0.2.10','revision':'unknown'})

    @patch.object(installer.os, 'stat')
    @patch.object(installer, 'run')
    def test_matching_running_executables_pass(self, run, stat):
        run.return_value=types.SimpleNamespace(stdout='123')
        stat.return_value=types.SimpleNamespace(st_dev=1,st_ino=10)
        installer.verify_runtime({'core_version':'0.2.10','core_revision':'a'*40}, {'version':'0.2.10','revision':'a'*40})
        self.assertEqual(stat.call_count,4)

class ServerPackageTests(unittest.TestCase):
    revision='a'*40

    def package(self, base, arch='amd64', bad_file=False, extra=None):
        import hashlib,io,tarfile
        header=b'\x7fELF\x02\x01'+b'\0'*12+(62).to_bytes(2,'little')
        files={'bin/'+n:header for n in ['connect-core','connect-control','connect-ui','connect-cert']}
        files.update({'scripts/connect-install.py':b'# installer','scripts/connect-vps-network.py':b'# network','THIRD-PARTY-NOTICES.md':b'notices','third_party/licenses/test-MIT.txt':b'license'})
        hashes={name:hashlib.sha256(data).hexdigest() for name,data in files.items()}
        if bad_file: files['bin/connect-core']+=b'changed'
        files['package.json']=json.dumps({'schema':1,'revision':self.revision,'arch':arch,'files':hashes}).encode()
        if extra: files[extra]=b'injected'
        archive=base/'server.tar.gz'
        with tarfile.open(archive,'w:gz') as tar:
            for name,data in files.items():
                member=tarfile.TarInfo(name);member.size=len(data);tar.addfile(member,io.BytesIO(data))
        return archive,hashlib.sha256(archive.read_bytes()).hexdigest()

    def unpack(self, base, archive, digest):
        stage=base/'stage';stage.mkdir()
        with patch.object(installer,'ROOT',base/'installed'),patch.object(installer,'release_identity',return_value={'version':'0.2.12','revision':self.revision}):
            return installer.unpack_server_package(archive,stage,self.revision,'amd64',digest)

    def test_valid_package_without_compiler(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            base=pathlib.Path(td);archive,digest=self.package(base)
            revision,release=self.unpack(base,archive,digest)
            self.assertEqual(revision,self.revision)
            self.assertTrue((release/'bin'/'connect-cert').is_file())

    def test_archive_and_per_file_integrity(self):
        import tempfile
        for corrupt in ['archive','file']:
            with tempfile.TemporaryDirectory() as td:
                base=pathlib.Path(td);archive,digest=self.package(base,bad_file=corrupt=='file')
                with self.assertRaisesRegex(RuntimeError,'checksum|SHA256'):
                    self.unpack(base,archive,'0'*64 if corrupt=='archive' else digest)

    def test_wrong_architecture_and_traversal_rejected(self):
        import tempfile
        for arch,extra in [('arm64',None),('amd64','../outside')]:
            with tempfile.TemporaryDirectory() as td:
                base=pathlib.Path(td);archive,digest=self.package(base,arch=arch,extra=extra)
                with self.assertRaises(RuntimeError): self.unpack(base,archive,digest)
                self.assertFalse((base/'outside').exists())

    def test_insufficient_disk_fails_before_extraction(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            base=pathlib.Path(td);archive,digest=self.package(base)
            with patch.object(installer.shutil,'disk_usage',return_value=types.SimpleNamespace(free=0)):
                with self.assertRaisesRegex(RuntimeError,'Not enough free space'): self.unpack(base,archive,digest)
            self.assertFalse((base/'stage'/'release').exists())

    def test_published_exact_revision_and_digest_selected(self):
        import tempfile,io
        with tempfile.TemporaryDirectory() as td:
            base=pathlib.Path(td);archive,digest=self.package(base)
            asset={'name':'ConnectCore-Linux-amd64-aaaaaaa.tar.gz','state':'uploaded','size':archive.stat().st_size,'digest':'sha256:'+digest,'browser_download_url':'https://github.com/sanderstripa/connect-core/releases/download/v0.2.12/server.tar.gz'}
            metadata=[{'draft':False,'target_commitish':self.revision,'assets':[asset]}]
            stage=base/'stage';stage.mkdir()
            with patch.object(installer.os,'uname',create=True,return_value=types.SimpleNamespace(machine='x86_64')),patch.object(installer.urllib.request,'urlopen',side_effect=[io.BytesIO(json.dumps(metadata).encode()),io.BytesIO(archive.read_bytes())]),patch.object(installer,'ROOT',base/'installed'),patch.object(installer,'release_identity',return_value={'version':'0.2.12','revision':self.revision}):
                result=installer.build(types.SimpleNamespace(source=None,revision=self.revision,package=None),stage)
                self.assertEqual(result[0],self.revision)

if __name__ == '__main__': unittest.main()
