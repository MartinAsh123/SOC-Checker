import argparse
import importlib.util
import ipaddress
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('soc_checker', ROOT / 'soc_checker.py')
soc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(soc)
XML = '''<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="80"><state state="open|filtered"/></port>
</ports></host><runstats><finished exit="success"/></runstats></nmaprun>'''
STUB = '''#!/usr/bin/env python3
import ipaddress,json,os,pathlib,sys,time
args=sys.argv[1:]
with open(os.environ['CALLS'],'a') as f:f.write(json.dumps({'event':'start','pid':os.getpid(),'args':args,'time':time.time()})+'\\n')
if '--version' in args:
 print('mock nmap');sys.exit(0)
if os.environ.get('SLOW'):time.sleep(4)
if os.environ.get('FAIL') and args[-1].endswith('.2'):sys.exit(7)
time.sleep(0.1)
ip=str(next(ipaddress.ip_network(args[-1],strict=False).hosts())) if '/' in args[-1] else args[-1]
xml='<nmaprun><host><status state="up"/><address addr="'+ip+'" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'
pathlib.Path(args[args.index('-oX')+1]).write_text(xml)
with open(os.environ['CALLS'],'a') as f:f.write(json.dumps({'event':'end','pid':os.getpid(),'time':time.time()})+'\\n')
'''


class UnitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)

    def test_scope_rejects_options_ipv6_and_large_network(self):
        for value in ('--script=x', '::1', '192.0.0.0/16', 'a;echo b'):
            with self.assertRaises(argparse.ArgumentTypeError):
                soc.ipv4_scope(value)
        self.assertEqual(str(soc.ipv4_scope('192.0.2.5/24')), '192.0.2.0/24')

    def test_followup_must_stay_in_scope(self):
        with self.assertRaises(ValueError):
            soc.scoped_ip('192.0.3.1', soc.ipv4_scope('192.0.2.0/24'))

    def test_xml_exact_open(self):
        path = self.path / 'scan.xml'
        path.write_text(XML)
        hosts = soc.parse_nmap(path, soc.ipv4_scope('192.0.2.0/24'))
        self.assertEqual([p['port'] for p in hosts[0]['ports']], [22])

    def test_xml_incomplete_and_wrong_scope_rejected(self):
        path = self.path / 'scan.xml'
        for content in (XML.replace('exit="success"', 'exit="error"'), XML.replace('192.0.2.1', '203.0.113.1')):
            path.write_text(content)
            with self.assertRaises(ValueError):
                soc.parse_nmap(path, soc.ipv4_scope('192.0.2.0/24'))

    def test_credential_budget_and_duplicate_users(self):
        users, passwords = self.path / 'users', self.path / 'passwords'
        users.write_text('test\n')
        passwords.write_text('one\ntwo\nthree\n')
        self.assertEqual(soc.credential_budget(users, passwords)[2], 3)
        users.write_text('test\ntest\n')
        with self.assertRaises(ValueError):
            soc.credential_budget(users, passwords)
        users.write_text('a\nb\nc\nd\n')
        with self.assertRaises(ValueError):
            soc.credential_budget(users, passwords)

    def test_nse_rejects_unscanned_host(self):
        args = soc.parser().parse_args(['192.0.2.0/24','--follow-up','nse','--host','192.0.2.1','--nse-script','http-title'])
        with self.assertRaises(ValueError):
            soc.follow_up(args, None, [])

    def test_auth_confirmation_prevents_execution(self):
        users, passwords = self.path / 'users', self.path / 'passwords'
        users.write_text('lab\n'); passwords.write_text('test\n')
        args = soc.parser().parse_args(['192.0.2.1','--follow-up','auth','--host','192.0.2.1','--service','ssh',
                                       '--user-list',str(users),'--password-list',str(passwords)])
        with patch('builtins.input',return_value='no'), patch.object(soc.shutil,'which',return_value='/mock/hydra'):
            with self.assertRaisesRegex(ValueError,'not confirmed'):
                soc.follow_up(args,None,[{'ip':'192.0.2.1'}])


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='soc test ')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.bin = self.path / 'bin'; self.bin.mkdir()
        stub = self.bin / 'nmap'; stub.write_text(STUB); stub.chmod(0o755)
        self.calls = self.path / 'calls.jsonl'
        self.output = self.path / 'run output'
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ['PATH'],CALLS=str(self.calls))

    def run_script(self, *args, env=None):
        return subprocess.run(['bash',str(ROOT/'sochecker.sh'),*args],env=env or self.env,
                              text=True,capture_output=True,timeout=15)

    def events(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def test_dry_run_no_execution_or_files(self):
        result = self.run_script('192.0.2.0/24','--dry-run','--output-dir',str(self.output))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(self.calls.exists()); self.assertFalse(self.output.exists())

    def test_all_hosts_waits_bounds_concurrency_and_retains_output(self):
        result = self.run_script('192.0.2.0/29','--mode','all','--jobs','2','--output-dir',str(self.output))
        self.assertEqual(result.returncode,0,result.stderr)
        run = next(self.output.iterdir())
        summary=json.loads((run/'summary.json').read_text())
        self.assertEqual(len(summary['hosts']),6)
        self.assertEqual(len(list(run.glob('*.xml'))),6)
        active=set(); peak=0
        for event in self.events():
            if '--version' in event.get('args',[]):continue
            if event['event']=='start':active.add(event['pid'])
            else:active.discard(event['pid'])
            peak=max(peak,len(active))
        self.assertLessEqual(peak,2); self.assertFalse(active)
        self.assertEqual(run.stat().st_mode & 0o777,0o700)

    def test_failure_report_and_nonzero_exit(self):
        result=self.run_script('192.0.2.0/30','--mode','all','--output-dir',str(self.output),env=dict(self.env,FAIL='1'))
        self.assertEqual(result.returncode,1,result.stderr)
        run=next(self.output.iterdir())
        summary=json.loads((run/'summary.json').read_text())
        self.assertEqual(summary['status'],'failed')
        self.assertTrue((run/'192.0.2.2.stderr').exists())

    def test_discovery_structured_output(self):
        result=self.run_script('192.0.2.0/30','--output-dir',str(self.output))
        self.assertEqual(result.returncode,0,result.stderr)
        calls=[x['args'] for x in self.events() if x['event']=='start']
        self.assertTrue(any('-sn' in x for x in calls))
        self.assertEqual(sum('-p-' in x for x in calls),1)

    def test_tool_timeout_recorded(self):
        result=self.run_script('192.0.2.1','--mode','all','--timeout','1','--output-dir',str(self.output),env=dict(self.env,SLOW='1'))
        self.assertEqual(result.returncode,1,result.stderr)
        events=[json.loads(x) for x in (next(self.output.iterdir())/'events.jsonl').read_text().splitlines()]
        self.assertTrue(any(x.get('timed_out') for x in events))

    def test_unique_run_directories(self):
        for _ in range(2):
            result=self.run_script('192.0.2.1','--mode','all','--output-dir',str(self.output))
            self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(len(list(self.output.iterdir())),2)

    def test_interrupt_discovery_stops_owned_child(self):
        process=subprocess.Popen(['bash',str(ROOT/'sochecker.sh'),'192.0.2.1','--output-dir',str(self.output)],
                                 env=dict(self.env,SLOW='1'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        child=None
        try:
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                if self.calls.exists():
                    calls=self.events()
                    discovery=[x for x in calls if '-sn' in x.get('args',[])]
                    if discovery:
                        child=discovery[0]['pid']
                        break
                time.sleep(0.02)
            self.assertIsNotNone(child)
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=5)
            self.assertEqual(process.returncode,130)
            with self.assertRaises(ProcessLookupError):
                os.kill(child,0)
            summary=json.loads((next(self.output.iterdir())/'summary.json').read_text())
            self.assertEqual(summary['status'],'interrupted')
        finally:
            if process.poll() is None:
                process.kill();process.communicate()
            if child is not None:
                try:os.kill(child,signal.SIGKILL)
                except ProcessLookupError:pass

    def test_missing_argument_does_not_start_tools(self):
        result=self.run_script()
        self.assertEqual(result.returncode,2)
        self.assertFalse(self.calls.exists())


if __name__=='__main__':
    unittest.main()
