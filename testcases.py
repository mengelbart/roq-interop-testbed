
import abc
import time
import os
import subprocess
import json

from pathlib import Path
from pyroute2 import NSPopen
from network.network import setup, clean
from subprocess import Popen
from signal import SIGTERM

from trace_analyzer import TraceAnalyzer

ROQ = {
  'name': 'roq',
  'bin': './roq/examples/interop/interop',
}

def run_tcpdump(iface, out):
    return Popen(f'tcpdump ip -i {iface} -w {out}'.split(' '))

def roq_interop_test(emulation=False):
    server_client_pairs = [(ROQ, ROQ)]
    testcases = [TestCaseHelloWorld]
    for pair in server_client_pairs:
        for tc in testcases:
            left_name = pair[0]['name']
            left_bin = pair[0]['bin']
            right_name = pair[1]['name']
            right_bin = pair[1]['bin']
            out_dir = f'results/{left_name}-{right_name}/{tc.name()}'
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            testcase = tc(out_dir, f'{out_dir}/client_keys.log', f'{out_dir}/server_keys.log')
            env = {
                **os.environ,
                'QLOGDIR': out_dir,
                'TESTCASE': testcase.name(),
                'CERT': 'cert.pem',
                'KEY': 'cert-key.pem',
            }
            addr = "127.0.0.1:8080"
            tcpdump = []
            if emulation:
                print('running roq test on emulation')
                setup()
                addr = "10.1.0.10:8080"
                tcpdump.append(run_tcpdump('v3p2', f'{out_dir}/left_router.pcap'))
                tcpdump.append(run_tcpdump('v4p2', f'{out_dir}/right_router.pcap'))
                server = NSPopen('ns1', [left_bin], env={
                    **env,
                    'SSLKEYLOGFILE': testcase.server_keylog_file,
                    'ENDPOINT': 'server',
                    'ROLE': 'sender',
                    'FFMPEG': 'TRUE',
                    'ADDR': addr,
                }, start_new_session=True)
                client = NSPopen('ns4', [right_bin], env={
                    **env,
                    'SSLKEYLOGFILE': testcase.client_keylog_file,
                    'ENDPOINT': 'client',
                    'ROLE': 'receiver',
                    'DESTINATION': f'{out_dir}/out.ivf',
                    'ADDR': addr,
                }, start_new_session=True)
            else:
                print('running roq test on localhost')
                tcpdump.append(run_tcpdump('lo', f'{out_dir}/left_router.pcap'))
                time.sleep(1)
                server = Popen([left_bin], env={
                    **env,
                    'SSLKEYLOGFILE': testcase.server_keylog_file,
                    'ENDPOINT': 'server',
                    'ROLE': 'sender',
                    'FFMPEG': 'TRUE',
                    'ADDR': addr,
                }, start_new_session=True)
                client = Popen([right_bin], env={
                    **env,
                    'SSLKEYLOGFILE': testcase.client_keylog_file,
                    'ENDPOINT': 'client',
                    'ROLE': 'receiver',
                    'DESTINATION': f'{out_dir}/out.ivf',
                    'ADDR': addr,
                }, start_new_session=True)
            
            time.sleep(testcase.duration())
            server.wait(timeout=testcase.duration())
            client.wait(timeout=testcase.duration())
            try:
                os.killpg(os.getpgid(server.pid), SIGTERM)
                os.killpg(os.getpgid(client.pid), SIGTERM)
            except Exception as e:
                print(e)

            for t in tcpdump:
                t.terminate()

            if emulation:
                clean()
            
            testcase.check()



class TestCase(abc.ABC):
    client_keylog_file = None
    server_keylog_file = None
    out_dir = None

    def __init__(self, out_dir, client_keylog_file, server_keylog_file):
        self.out_dir = out_dir
        self.client_keylog_file = client_keylog_file
        self.server_keylog_file = server_keylog_file

    @abc.abstractmethod
    def name(self):
        pass


    def __str__(self):
        return self.name()


    @abc.abstractmethod
    def desc(self):
        pass


    @abc.abstractmethod
    def duration() -> int:
        pass


    @abc.abstractmethod
    def check(self):
        pass


    def _keylog_file(self) -> str:
        pass


    def _get_client_trace(self):
        print(f'get trace for {self.client_keylog_file}')
        trace = TraceAnalyzer(f'{self.out_dir}/left_router.pcap', self.client_keylog_file)
        return trace.get_packets()

    
    def _get_server_trace(self):
        print(f'get trace for {self.server_keylog_file}')
        trace = TraceAnalyzer(f'{self.out_dir}/right_router.pcap', self.server_keylog_file)
        return trace.get_packets()


    def probe_file(self):
        cmd = ["ffprobe", "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", f'{self.out_dir}/out.ivf']
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if result.returncode == 0:
            streams = json.loads(result.stdout)['streams']
            if len(streams) != 1:
                print("FAIL: WRONG NUMBER OF STREAMS")
                return
            stream = streams[0]
            if stream['codec_name'] != 'vp8':
                print("FAIL: WRONG CODEC")
                return
        else:
            print("FAIL: FFPROBE")
            print(result)
            return
        print("SUCCESS")


class TestCaseHelloWorld(TestCase):
    @staticmethod
    def name():
        return 'datagrams'
    
    @staticmethod
    def desc():
        return 'test whether QUIC datagrams containing flow ID prefixed RTP packets are sent'

    @staticmethod
    def duration() -> int:
        return 15
    
    def check(self):
        packets = self._get_client_trace()
        self.probe_file()
