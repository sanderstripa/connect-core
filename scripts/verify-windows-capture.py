"""Check separately exported PktMon NIC captures, not mixed TUN/plaintext data."""
import collections
import json
import pathlib
import socket
import struct
import sys

root = pathlib.Path(sys.argv[1])
components = json.loads((root / 'windows-capture-components.json').read_text(encoding='utf-8-sig'))
results = []
for component in components:
    data = (root / f"windows-component-{component['id']}.pcapng").read_bytes()
    offset, links, counts = 0, [], collections.Counter()
    while offset < len(data):
        assert offset + 12 <= len(data), 'truncated pcapng block'
        kind, size = struct.unpack_from('<II', data, offset)
        assert size >= 12 and size % 4 == 0 and offset + size <= len(data)
        assert struct.unpack_from('<I', data, offset + size - 4)[0] == size
        if kind == 0x0a0d0d0a:
            assert data[offset+8:offset+12] == b'\x4d\x3c\x2b\x1a', 'unexpected byte order'
            links = []
        elif kind == 1:
            links.append(struct.unpack_from('<H', data, offset+8)[0])
        elif kind == 6:
            interface, _, _, captured, original = struct.unpack_from('<IIIII', data, offset+8)
            assert interface < len(links) and captured <= original and 28 + captured <= size - 4
            packet = data[offset+28:offset+28+captured]
            counts['frames'] += 1
            if component['role'] == 'tunnel':
                ip = packet if packet and packet[0] >> 4 == 4 else packet[14:]
                assert len(ip) >= 20 and ip[0] >> 4 == 4, 'unexpected tunnel capture framing'
                src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
                assert {src, dst} == {'10.231.0.2', '10.232.0.1'}, 'unexpected tunneled addresses'
                counts['tunnel_tcp' if ip[9] == 6 else 'tunnel_udp' if ip[9] == 17 else 'tunnel_other'] += 1
                offset += size
                continue
            assert b'CONNECT-IP-LAB-PRIVATE-CANARY-2026' not in packet, 'plaintext test payload on underlay'
            assert b'\x07example\x04test' not in packet, 'plaintext test DNS on underlay'
            # PktMon labels a mixed capture Ethernet even for raw Wintun. These
            # files are exported by component; an underlay must be Ethernet.
            assert links[interface] == 1 and len(packet) >= 14, 'unsupported underlay link'
            ether = struct.unpack_from('!H', packet, 12)[0]
            if ether == 0x0800:
                ip = packet[14:]
                assert len(ip) >= 20 and ip[0] >> 4 == 4
                header = (ip[0] & 15) * 4
                src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
                assert '10.232.0.1' not in (src, dst), 'service bypassed Wintun'
                assert dst != '1.1.1.1', 'direct IPv4/DNS probe reached underlay'
                counts['ipv4'] += 1
                if ip[9] == 17 and len(ip) >= header + 8:
                    ports = struct.unpack_from('!HH', ip, header)
                    assert 53 not in ports, 'external UDP DNS on underlay'
                if ip[9] == 6 and len(ip) >= header + 20:
                    ports = struct.unpack_from('!HH', ip, header)
                    assert 53 not in ports, 'external TCP DNS on underlay'
                    length = struct.unpack_from('!H', ip, 2)[0]
                    payload = length - header - (ip[header+12] >> 4) * 4
                    counts['background_tcp_payload_packets' if payload else 'background_tcp_control_packets'] += 1
                    assert payload == 0, 'background TCP data escaped static lab guard'
            elif ether == 0x86dd:
                ip = packet[14:]
                assert len(ip) >= 40
                counts['ipv6'] += 1
                # Neighbor discovery is OS link control, not tunneled IPv6 data.
                assert ip[6] == 58 and len(ip) >= 41 and ip[40] in (133, 134, 135, 136), 'unsupported IPv6 data on underlay'
                counts['ipv6_neighbor_discovery'] += 1
            else:
                counts['non_ip'] += 1
        offset += size
    results.append({'component_id': component['id'], 'role': component['role'], 'description': component['description'], 'counts': dict(counts)})
assert any(x['role'] == 'underlay' for x in results), 'no alternate NIC captures: leakage validation unavailable'
assert any(x['role'] == 'tunnel' and x['counts'].get('tunnel_tcp', 0) and x['counts'].get('tunnel_udp', 0) for x in results), 'no captured native TCP/UDP traffic: capture coverage unproved'
print(json.dumps({'scope': 'static lab NIC components; known test data/DNS/direct probes', 'components': results, 'known_test_leaks': False, 'background_control_is_reported': True}, indent=2))
