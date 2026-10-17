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

if __name__ == '__main__': unittest.main()
