"""Selected pre-existing NICs only, never the inner Wintun or stack components."""
import json, struct, sys
data = open(sys.argv[1], 'rb').read()
assert data[:4] == b'\x0a\x0d\x0d\x0a', 'pcapng required'
offset = frames = 0
while offset < len(data):
    assert offset + 12 <= len(data)
    kind, size = struct.unpack_from('<II', data, offset)
    assert size >= 12 and size % 4 == 0 and offset + size <= len(data)
    assert struct.unpack_from('<I', data, offset + size - 4)[0] == size
    if kind == 6:
        captured = struct.unpack_from('<I', data, offset + 20)[0]
        packet = data[offset + 28:offset + 28 + captured]
        assert b'CONNECT-IP-LAB-PRIVATE-CANARY-2026' not in packet
        assert b'\x07example\x04test\x00' not in packet
        frames += 1
    offset += size
assert frames > 0, 'physical capture did not observe its pre-VPN baseline'
print(json.dumps({'physical_frames': frames, 'plaintext_canary': False,
                  'plaintext_test_dns': False, 'scope': 'pre-existing selected NICs; tunnel excluded'}))
