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

if __name__ == '__main__': unittest.main()
