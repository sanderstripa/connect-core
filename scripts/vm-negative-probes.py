import socket
import json

results=[]

for family, host, port in [(socket.AF_INET,'1.1.1.1',80),(socket.AF_INET,'1.1.1.1',53),(socket.AF_INET6,'2606:4700:4700::1111',53)]:
    with socket.socket(family,socket.SOCK_DGRAM if port==53 else socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            if port==53:
                s.sendto(b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01',(host,port))
                s.recv(512)
            else:
                s.connect((host,port))
        except OSError as error:
            results.append({'host':host,'port':port,'result':'no direct response','error_type':type(error).__name__,'errno':error.errno,'winerror':getattr(error,'winerror',None)})
            continue
        raise AssertionError(f'unsupported direct path accepted: {host}:{port}')
print(json.dumps({'direct_probe_results':results,'scope':'negative responses; combine with NIC captures and route inventory'},indent=2))
