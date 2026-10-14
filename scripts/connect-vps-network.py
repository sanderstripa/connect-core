#!/usr/bin/env python3
"""Own TUN + exact scoped firewall rules. Never restore another service's rules."""
import argparse
import fcntl
import ipaddress
import json
import os
import pathlib
import subprocess
import sys

def run(*args, check=True):
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode:
        raise RuntimeError(f"{args[0]} operation failed: {p.stderr.strip()}")
    return p

def save(path, value):
    temporary = path.with_suffix('.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, indent=2); f.flush(); os.fsync(f.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)

def links(): return json.loads(run('ip', '-j', '-d', 'link').stdout)
def routes(): return json.loads(run('ip', '-j', '-4', 'route', 'show', 'table', 'all').stdout)
def firewall(): return {t: run('iptables', '-w', '5', '-t', t, '-S').stdout for t in ['filter', 'nat']}

def preflight(settings):
    pool = ipaddress.ip_network(settings['pool'])
    if pool.prefixlen != 24 or not pool.is_private or pool.version != 4:
        raise RuntimeError('private IPv4 /24 pool required')
    if settings['interface'] != 'cc-vps0': raise RuntimeError('fixed owned TUN required')
    if any(v['ifname'] == 'cc-vps0' for v in links()): raise RuntimeError('cc-vps0 is occupied; never adopting it')
    for r in routes():
        if r.get('dst', 'default') == 'default': continue
        try: other = ipaddress.ip_network(r['dst'], strict=False)
        except ValueError: continue
        if other.overlaps(pool): raise RuntimeError(f'address pool overlaps existing route {other}')
    forwarding = pathlib.Path('/proc/sys/net/ipv4/conf') / settings['uplink'] / 'forwarding'
    return {'uplink_forwarding': forwarding.read_text().strip(), 'firewall': firewall(), 'routes': routes()}

def rules(s):
    prefix = 'CC_' + s['owner'][:8]
    comment = 'connect-core:' + s['owner']
    interface, uplink, pool = s['interface'], s['uplink'], s['pool']
    address, port = s['endpoint'].rsplit(':', 1)
    chains = [('filter', prefix + '_F'), ('filter', prefix + '_I'), ('nat', prefix + '_N')]
    entries = [
        ('filter', prefix + '_F', ['-i', interface, '-s', pool, '-o', uplink, '-j', 'ACCEPT'], False),
        ('filter', prefix + '_F', ['-i', uplink, '-o', interface, '-d', pool, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'], False),
        ('filter', 'FORWARD', ['-i', interface, '-m', 'comment', '--comment', comment, '-j', prefix + '_F'], True),
        ('filter', 'FORWARD', ['-o', interface, '-m', 'comment', '--comment', comment, '-j', prefix + '_F'], True),
        ('filter', prefix + '_I', ['-p', 'udp', '-d', address, '--dport', port, '-j', 'ACCEPT'], False),
        ('filter', prefix + '_I', ['-p', 'tcp', '-d', address, '--dport', str(s['enrollment_port']), '-j', 'ACCEPT'], False),
        ('filter', 'INPUT', ['-p', 'udp', '-d', address, '--dport', port, '-m', 'comment', '--comment', comment, '-j', prefix + '_I'], True),
        ('filter', 'INPUT', ['-p', 'tcp', '-d', address, '--dport', str(s['enrollment_port']), '-m', 'comment', '--comment', comment, '-j', prefix + '_I'], True),
        ('nat', prefix + '_N', ['-s', pool, '-o', uplink, '-j', 'MASQUERADE'], False),
        ('nat', 'POSTROUTING', ['-s', pool, '-o', uplink, '-m', 'comment', '--comment', comment, '-j', prefix + '_N'], False),
    ]
    if s.get('panel_port'):
        entries += [
            ('filter', prefix + '_I', ['-p','tcp','-d',address,'--dport',str(s['panel_port']),'-j','ACCEPT'], False),
            ('filter', 'INPUT', ['-p','tcp','-d',address,'--dport',str(s['panel_port']),'-m','comment','--comment',comment,'-j',prefix + '_I'], True),
        ]
    return chains, entries

def apply(s, journal_path):
    if journal_path.exists():
        j = json.loads(journal_path.read_text())
        if j['owner'] != s['owner']: raise RuntimeError('network ownership mismatch')
    else:
        j = {'owner': s['owner'], 'before': preflight(s)}
        save(journal_path, j)  # Intent precedes every system mutation.
    current = next((v for v in links() if v['ifname'] == s['interface']), None)
    if current and current.get('ifalias') != 'connect-core:' + s['owner']:
        raise RuntimeError('refusing a foreign replacement interface')
    if not current:
        run('ip', 'tuntap', 'add', 'dev', s['interface'], 'mode', 'tun', 'user', str(s['uid']))
        run('ip', 'link', 'set', 'dev', s['interface'], 'alias', 'connect-core:' + s['owner'])
    run('ip', 'link', 'set', 'dev', s['interface'], 'mtu', '1100')
    interfaces = json.loads(run('ip', '-j', '-4', 'addr', 'show', 'dev', s['interface']).stdout)
    addresses = [address for interface in interfaces for address in interface.get('addr_info', [])]
    server = str(ipaddress.ip_network(s['pool']).network_address + 1)
    if not any(v.get('local') == server for v in addresses):
        run('ip', 'addr', 'add', server + '/24', 'dev', s['interface'])
    run('ip', 'link', 'set', 'dev', s['interface'], 'up')
    for table, chain in rules(s)[0]:
        exists = run('iptables', '-w', '5', '-t', table, '-S', chain, check=False).returncode == 0
        if not exists: run('iptables', '-w', '5', '-t', table, '-N', chain)
    for table, chain, rule, first in rules(s)[1]:
        if run('iptables', '-w', '5', '-t', table, '-C', chain, *rule, check=False).returncode:
            command = ['iptables', '-w', '5', '-t', table, '-I' if first else '-A', chain]
            if first: command.append('1')
            run(*command, *rule)
    # Per-interface forwarding avoids the global ip_forward switch, which can
    # reset unrelated IPv4 sysctl defaults. The only shared flag is journaled.
    for interface in [s['interface'], s['uplink']]:
        if (pathlib.Path('/proc/sys/net/ipv4/conf') / interface / 'forwarding').read_text().strip() != '1':
            (pathlib.Path('/proc/sys/net/ipv4/conf') / interface / 'forwarding').write_text('1\n')
    j['applied'] = True; save(journal_path, j)

def rollback(s, journal_path):
    if not journal_path.exists(): return
    j = json.loads(journal_path.read_text())
    if j['owner'] != s['owner']: raise RuntimeError('network ownership mismatch')
    chains, entries = rules(s)
    # Remove only exact rules including our installation-specific comment.
    for table, chain, rule, _ in reversed(entries):
        if run('iptables', '-w', '5', '-t', table, '-C', chain, *rule, check=False).returncode == 0:
            run('iptables', '-w', '5', '-t', table, '-D', chain, *rule)
    for table, chain in reversed(chains):
        if run('iptables', '-w', '5', '-t', table, '-S', chain, check=False).returncode == 0:
            # No flush: refuse deletion if anybody put foreign rules in our chain.
            run('iptables', '-w', '5', '-t', table, '-X', chain)
    current = next((v for v in links() if v['ifname'] == s['interface']), None)
    if current:
        if current.get('ifalias') != 'connect-core:' + s['owner']:
            raise RuntimeError('foreign TUN replacement; manual reconciliation required')
        run('ip', 'link', 'delete', 'dev', s['interface'])
    before = j['before']
    same_routes = sorted(json.dumps(v, sort_keys=True) for v in routes()) == sorted(json.dumps(v, sort_keys=True) for v in before['routes'])
    flag = pathlib.Path('/proc/sys/net/ipv4/conf') / s['uplink'] / 'forwarding'
    if before['uplink_forwarding'] == '0' and flag.read_text().strip() == '1':
        if firewall() == before['firewall'] and same_routes:
            flag.write_text('0\n')
        else:
            print('Shared forwarding left enabled: other network state changed since installation.', file=sys.stderr)
    j['applied'] = False; save(journal_path, j)

def main():
    p = argparse.ArgumentParser(); p.add_argument('action', choices=['check', 'apply', 'rollback']); p.add_argument('settings'); a = p.parse_args()
    if os.geteuid() != 0: raise RuntimeError('root required for the owned network transaction')
    settings = pathlib.Path(a.settings).resolve(); s = json.loads(settings.read_text())
    journal = settings.parent / 'network-journal.json'
    with open(settings.parent / 'network.lock', 'a') as lock:
        os.chmod(lock.name, 0o600); fcntl.flock(lock, fcntl.LOCK_EX)
        if a.action == 'check': preflight(s); print('Own network preflight passed')
        elif a.action == 'apply': apply(s, journal)
        else: rollback(s, journal)

if __name__ == '__main__':
    try: main()
    except Exception as e: print(str(e), file=sys.stderr); sys.exit(1)
