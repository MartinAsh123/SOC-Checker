#!/usr/bin/env python3
"""Scoped SOC activity runner. Network tools run only after argument validation."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import xml.etree.ElementTree as ET

NSE_SCRIPTS = ('http-title', 'ssh-hostkey', 'ssl-cert', 'smb-os-discovery')
AUTH_SERVICES = ('ssh', 'ftp', 'rdp', 'smb')
MAX_HOSTS = 256


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def ipv4_scope(text):
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('Expected an IPv4 address or CIDR') from exc
    if network.version != 4:
        raise argparse.ArgumentTypeError('Only IPv4 is supported')
    if network.num_addresses > MAX_HOSTS:
        raise argparse.ArgumentTypeError('Maximum scope is 256 addresses (/24)')
    return network


def positive_int(text):
    value = int(text)
    if value <= 0:
        raise argparse.ArgumentTypeError('Must be positive')
    return value


def scoped_ip(text, scope):
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValueError('Follow-up target must be an IPv4 address') from exc
    if address.version != 4 or address not in scope:
        raise ValueError('Follow-up target is outside the approved scope')
    return str(address)


def parse_nmap(path, scope):
    """Accept only in-scope IPv4 hosts; exact open state, not open|filtered."""
    root = ET.parse(path).getroot()
    if root.tag != 'nmaprun':
        raise ValueError('Unexpected Nmap XML root')
    finished = root.find('runstats/finished')
    if finished is None or finished.get('exit') != 'success':
        raise ValueError('Nmap XML has no successful completion marker')
    hosts = []
    for host in root.findall('host'):
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            continue
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            continue
        address = scoped_ip(addr.get('addr', ''), scope)
        ports = []
        for port in host.findall('ports/port'):
            state = port.find('state')
            if state is not None and state.get('state') == 'open':
                service = port.find('service')
                ports.append({'port': int(port.get('portid')), 'protocol': port.get('protocol'),
                              'service': service.get('name', 'unknown') if service is not None else 'unknown'})
        hosts.append({'ip': address, 'ports': ports})
    return hosts


class Runner:
    def __init__(self, output, timeout):
        self.output = output
        self.timeout = timeout
        self.lock = threading.Lock()
        self.processes = set()
        self.stopped = threading.Event()

    def record(self, event):
        with self.lock:
            with (self.output / 'events.jsonl').open('a', encoding='utf-8') as handle:
                handle.write(json.dumps(event) + '\n')

    def cancel(self):
        self.stopped.set()
        with self.lock:
            processes = list(self.processes)
        for process in processes:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        for process in processes:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def run(self, command, label):
        if self.stopped.is_set():
            raise RuntimeError('Run cancelled')
        event = {'label': label, 'started_at': timestamp(), 'argv': command}
        process = None
        try:
            with (self.output / (label + '.stdout')).open('w') as stdout, (self.output / (label + '.stderr')).open('w') as stderr:
                # Check cancellation while holding the same lock used to register jobs.
                with self.lock:
                    if self.stopped.is_set():
                        raise RuntimeError('Run cancelled')
                    process = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                               cwd=self.output, start_new_session=True)
                    self.processes.add(process)
                try:
                    code = process.wait(timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    event['timed_out'] = True
                    code = 124
            event['exit_code'] = code
            if code:
                raise RuntimeError(f'{label} failed (exit {code}); see saved stderr')
            return code
        except (OSError, RuntimeError) as exc:
            event['error'] = str(exc)
            raise
        except BaseException:
            # A signal can interrupt a main-thread discovery/follow-up wait.
            # Keep ownership until that process has actually stopped.
            event['interrupted'] = True
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                event['exit_code'] = process.returncode
            raise
        finally:
            if process is not None:
                with self.lock:
                    self.processes.discard(process)
            event['finished_at'] = timestamp()
            self.record(event)


def scan_command(target, mode, timing, output):
    command = ['nmap', '-n', '-T' + str(timing)]
    if mode == 'discover':
        command += ['-sn']
    elif mode == 'null':
        command += ['-sN']
    else:
        command += ['-sT', '-Pn', '-p-']
    return command + ['-oX', str(output), target]


def credential_budget(user_file, password_file):
    def entries(path):
        values = path.read_text(encoding='utf-8').splitlines()
        if not values or any(not value or any(ord(c) < 32 for c in value) for value in values):
            raise ValueError('Credential lists must contain nonempty lines without control characters')
        return values
    users, passwords = entries(user_file), entries(password_file)
    per_user = max(Counter(users).values()) * len(passwords)
    total = len(users) * len(passwords)
    if per_user > 3 or total > 10:
        raise ValueError('Budget exceeded: at most 3 candidate pairs per account and 10 in total')
    return users, passwords, total


def follow_up(args, runner, observed):
    if args.follow_up == 'none':
        return
    if args.follow_up == 'menu':
        choice = input('Follow-up: [0] finish [1] NSE [2] authentication test: ').strip()
        args.follow_up = {'0': 'none', '1': 'nse', '2': 'auth'}.get(choice)
        if args.follow_up is None:
            raise ValueError('Invalid menu selection')
        if args.follow_up == 'none':
            return
    target = scoped_ip(args.host or input('Follow-up IP: ').strip(), args.target)
    if target not in {item['ip'] for item in observed}:
        raise ValueError('Follow-up host was not successfully scanned in this run')
    if args.follow_up == 'nse':
        script = args.nse_script or input('Choose ' + ', '.join(NSE_SCRIPTS) + ': ').strip()
        if script not in NSE_SCRIPTS:
            raise ValueError('NSE script is not in the allowlist')
        runner.run(['nmap', '-n', '-sT', '-Pn', '-sV', '-T' + str(args.timing), '--script', script,
                    '-oX', str(runner.output / 'nse.xml'), target], 'nse')
        return
    if not shutil.which('hydra'):
        raise ValueError('Hydra is required for the authentication-test action')
    if not args.user_list or not args.password_list:
        raise ValueError('Authentication test requires --user-list and --password-list')
    users, passwords, count = credential_budget(args.user_list, args.password_list)
    service = args.service or input('Choose ' + ', '.join(AUTH_SERVICES) + ': ').strip()
    if service not in AUTH_SERVICES:
        raise ValueError('Service is not in the allowlist')
    print(f'Authentication test: {target}, {service}, up to {count} candidate pairs, one worker.')
    print('Protocol retries and server lockout rules can still cause lockouts. Use approved test accounts.')
    if input('Type AUTH TEST to approve this action: ').strip() != 'AUTH TEST':
        raise ValueError('Authentication test was not confirmed')
    # Snapshot exactly the checked inputs to avoid list changes after validation.
    with tempfile.TemporaryDirectory(prefix='credentials-', dir=runner.output) as tmp:
        u, p = Path(tmp) / 'users.txt', Path(tmp) / 'passwords.txt'
        u.write_text('\n'.join(users) + '\n')
        p.write_text('\n'.join(passwords) + '\n')
        runner.run(['hydra', '-L', str(u), '-P', str(p), '-t', '1', '-f', target, service], 'auth')


def parser():
    p = argparse.ArgumentParser(description='Generate scoped SOC test activity and preserve run evidence (Linux).')
    p.add_argument('target', type=ipv4_scope, help='Authorized IPv4 or CIDR; maximum /24')
    p.add_argument('--mode', choices=('discover', 'all', 'null'), default='discover',
                   help='Discovery before full TCP scans, all hosts, or explicit NULL scan then full scans')
    p.add_argument('--jobs', type=positive_int, default=4, help='Parallel scan processes (1-16; default 4)')
    p.add_argument('--timing', type=int, choices=range(0, 6), default=3, help='Nmap timing template (default 3)')
    p.add_argument('--timeout', type=positive_int, default=600, help='Seconds per tool invocation (default 600)')
    p.add_argument('--output-dir', type=Path, default=Path('soc-runs'), help='Parent for a new unique run directory')
    p.add_argument('--dry-run', action='store_true', help='Show scan plan; no tools, files, or connections')
    p.add_argument('--scan-only', action='store_true', help='Explicitly disable follow-up actions (also the default)')
    p.add_argument('--follow-up', choices=('none', 'menu', 'nse', 'auth'), default='none')
    p.add_argument('--host', help='In-scope follow-up IP, also required to appear in successful scan results')
    p.add_argument('--nse-script', choices=NSE_SCRIPTS)
    p.add_argument('--service', choices=AUTH_SERVICES)
    p.add_argument('--user-list', type=Path, help='Approved test usernames, one per line')
    p.add_argument('--password-list', type=Path, help='Small approved test password list, one per line')
    return p


def main(argv=None):
    cli = parser()
    args = cli.parse_args(argv)
    if args.jobs > 16:
        cli.error('--jobs must be between 1 and 16')
    if args.scan_only and args.follow_up != 'none':
        cli.error('--scan-only cannot be combined with a follow-up action')
    if args.host:
        try:
            args.host = scoped_ip(args.host, args.target)
        except ValueError as exc:
            cli.error(str(exc))
    if args.follow_up == 'auth':
        if not args.user_list or not args.password_list:
            cli.error('Authentication test requires --user-list and --password-list')
        try:
            credential_budget(args.user_list, args.password_list)
        except (ValueError, OSError) as exc:
            cli.error(str(exc))
    for name in ('user_list', 'password_list'):
        value = getattr(args, name)
        if value:
            setattr(args, name, value.resolve())
    if args.dry_run:
        print(f'Scope: {args.target}; mode: {args.mode}; parallel jobs: {args.jobs}; follow-up: {args.follow_up}')
        if args.mode != 'all':
            print(shlex.join(scan_command(str(args.target), args.mode, args.timing, Path('<run>/discovery.xml'))))
        print(shlex.join(scan_command('<in-scope-host>', 'all', args.timing, Path('<run>/<host>.xml'))))
        print('No commands executed. Follow-up selection/confirmation occurs only during a live run.')
        return 0
    if args.follow_up != 'none' and not sys.stdin.isatty():
        cli.error('Follow-up actions require an interactive terminal; use --scan-only for unattended runs')
    if not shutil.which('nmap'):
        cli.error('Nmap is required')
    if args.mode == 'null' and os.geteuid() != 0:
        cli.error('NULL scan mode requires root; no automatic sudo is used')
    os.umask(0o077)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-'),
                                   dir=args.output_dir)).resolve()
    runner = Runner(output, args.timeout)
    summary = {'started_at': timestamp(), 'scope': str(args.target), 'mode': args.mode,
               'jobs': args.jobs, 'timing': args.timing, 'hosts': [], 'errors': [], 'status': 'running'}
    print(f'Run output: {output}')
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        runner.run(['nmap', '--version'], 'nmap-version')
        if args.mode == 'all':
            targets = [str(ip) for ip in args.target.hosts()]
        else:
            xml_path = output / 'discovery.xml'
            runner.run(scan_command(str(args.target), args.mode, args.timing, xml_path), 'discovery')
            targets = list(dict.fromkeys(host['ip'] for host in parse_nmap(xml_path, args.target)))
        executor = ThreadPoolExecutor(max_workers=args.jobs)
        def scan(target):
            xml = output / (target + '.xml')
            runner.run(scan_command(target, 'all', args.timing, xml), target)
            hosts = parse_nmap(xml, args.target)
            if any(host['ip'] != target for host in hosts):
                raise ValueError('Scan result contains an unexpected host')
            return hosts
        try:
            futures = {executor.submit(scan, target): target for target in targets}
            for future in as_completed(futures):
                try:
                    summary['hosts'].extend(future.result())
                except (OSError, ValueError, RuntimeError, ET.ParseError) as exc:
                    summary['errors'].append(f'{futures[future]}: {exc}')
        except BaseException:
            runner.cancel()
            raise
        finally:
            executor.shutdown(wait=True, cancel_futures=True)
        for host in sorted(summary['hosts'], key=lambda h: ipaddress.ip_address(h['ip'])):
            print(host['ip'] + ': ' + ', '.join(f"{p['port']}/{p['protocol']} {p['service']}" for p in host['ports']))
        if summary['errors']:
            raise RuntimeError('One or more host scans failed; follow-up actions skipped')
        follow_up(args, runner, summary['hosts'])
        summary['status'] = 'complete'
        return 0
    except KeyboardInterrupt:
        runner.cancel()
        summary['status'] = 'interrupted'
        return 130
    except (OSError, ValueError, RuntimeError, EOFError, ET.ParseError) as exc:
        summary['status'] = 'failed'
        summary['errors'].append(str(exc))
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        runner.cancel()
        summary['finished_at'] = timestamp()
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        signal.signal(signal.SIGTERM, previous)


if __name__ == '__main__':
    sys.exit(main())
