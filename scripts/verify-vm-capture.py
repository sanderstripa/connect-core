import collections,json,socket,struct,sys
data=open(sys.argv[1],'rb').read();assert data[:4] in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4')
order='<' if data[:4]==b'\xd4\xc3\xb2\xa1' else '>';assert struct.unpack(order+'I',data[20:24])[0]==1
offset=24;counts=collections.Counter()
while offset<len(data):
    assert offset+16<=len(data)
    _,_,size,_=struct.unpack(order+'IIII',data[offset:offset+16]);offset+=16;p=data[offset:offset+size];offset+=size;assert len(p)==size
    kind=struct.unpack('!H',p[12:14])[0]
    if kind==0x806:counts['arp']+=1;continue
    assert kind==0x800,'unexpected underlay Ethernet/IPv6';p=p[14:];assert p[0]>>4==4
    src,dst=socket.inet_ntoa(p[12:16]),socket.inet_ntoa(p[16:20]);assert {src,dst}=={'10.0.2.2','10.0.2.15'},(src,dst)
    if p[9]==17:
        ports=struct.unpack('!HH',p[(p[0]&15)*4:(p[0]&15)*4+4]);assert 17444 in ports;counts['endpoint_udp']+=1
    elif p[9]==1:counts['icmp']+=1
    else:raise AssertionError('unexpected underlay IP protocol')
assert counts['endpoint_udp']>0
assert b'CONNECT-IP-LAB-PRIVATE-CANARY-2026' not in data
assert b'\x07example\x04test' not in data
print(json.dumps({'frames':sum(counts.values()),'types':dict(counts),'snapshot_bytes':struct.unpack(order+'I',data[16:20])[0],'plaintext_canary_in_snapshot':False,'plaintext_dns_question_in_snapshot':False},indent=2))
