import socket

for family, host, port in [(socket.AF_INET,'1.1.1.1',80),(socket.AF_INET,'1.1.1.1',53),(socket.AF_INET6,'2606:4700:4700::1111',53)]:
    with socket.socket(family,socket.SOCK_DGRAM if port==53 else socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            if port==53:
                s.sendto(b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01',(host,port))
                s.recv(512)
            else:
                s.connect((host,port))
        except OSError:
            continue
        raise AssertionError(f'unsupported direct path accepted: {host}:{port}')
print('IPv4, IPv6 and external DNS probes blocked')
