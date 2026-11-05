"""Isolated Linux smoke & sustained load test: six real protocol tunnels + subscription server, no existing service changes."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from urllib.parse import quote, urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import protocols as p
import runtime as rt


def rss(pid):
    values = {}
    for line in Path(f'/proc/{pid}/status').read_text().splitlines():
        if line.startswith(('VmRSS:', 'VmHWM:')):
            k, v = line.split(':', 1)
            values[k] = int(v.split()[0])
    return values


def sustained_load(nodes, rounds=3, concurrency=3):
    tasks = [n for _ in range(rounds) for n in nodes]
    latencies = []
    failures = 0
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        for res in pool.map(rt.self_test, tasks):
            if res.get('ok'):
                latencies.append(res.get('latency_ms', 0))
            else:
                failures += 1
    return {
        'totalRequests': len(tasks),
        'concurrency': concurrency,
        'succeeded': len(latencies),
        'failed': failures,
        'avgLatencyMs': round(sum(latencies)/len(latencies), 1) if latencies else None,
        'maxLatencyMs': max(latencies) if latencies else None,
    }


def main():
    report = {'scope': 'isolated-linux-loopback', 'nodes': [], 'time': int(time.time())}
    with tempfile.TemporaryDirectory(prefix='lite-protocols-') as d:
        rt.ROOT = Path(d)
        nodes = []
        used = set()
        for protocol in p.PROTOCOLS:
            port = rt.free_tcp_port()
            while port in used:
                port = rt.free_tcp_port()
            used.add(port)
            n = p.new_node(protocol, '测试-'+protocol, '203.0.113.10', port)
            rt.prepare_credentials(n)
            nodes.append(n)
        config = p.server_config(nodes)
        for inbound in config['inbounds']:
            inbound['listen'] = '127.0.0.1'
        path = Path(d)/'server.json'
        rt.write_json(path, config)
        rt.checked([rt.CORE, 'check', '-c', path])
        report['configCheck'] = True
        with (Path(d)/'server.log').open('w+') as log:
            child = subprocess.Popen([str(rt.CORE), 'run', '-c', str(path)], env=rt.core_env(),
                                     stdout=log, stderr=log)
            try:
                time.sleep(1)
                if child.poll() is not None:
                    raise RuntimeError('isolated core exited')
                report['idleBeforeKiB'] = rss(child.pid)
                for n in nodes:
                    result = rt.self_test(n)
                    report['nodes'].append({'protocol': n['protocol'], **result})
                time.sleep(2)
                report['afterSixProbesKiB'] = rss(child.pid)
                report['managerRSSKiB'] = rss(os.getpid())
                stress_rounds = int(os.environ.get('LITE_TEST_STRESS_ROUNDS', '0'))
                if stress_rounds > 0:
                    report['sustainedLoad'] = sustained_load(nodes, rounds=stress_rounds)
                    report['afterSustainedLoadKiB'] = rss(child.pid)
                # Optional, independently implemented client used by FlClash.
                mihomo = os.environ.get('LITE_TEST_MIHOMO')
                if mihomo:
                    report['mihomo'] = mihomo_checks(mihomo, nodes, Path(d))
            finally:
                child.terminate()
                try: child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if all(n['ok'] for n in report['nodes']+report.get('mihomo', [])) else 1


def mihomo_checks(binary, nodes, directory):
    cfg = p.clash_config(nodes)
    for node in cfg['proxies']:
        node['server'] = '127.0.0.1'
    port, token = rt.free_tcp_port(), secrets.token_hex(16)
    cfg.update({'mixed-port': 0, 'external-controller': f'127.0.0.1:{port}',
                'secret': token, 'geo-auto-update': False, 'log-level': 'silent',
                'dns': {'enable': False}, 'tun': {'enable': False}})
    path = directory/'mihomo.yaml'
    rt.write_json(path, cfg)
    rt.checked([binary, '-t', '-d', directory, '-f', path])
    result = []
    with (directory/'mihomo.log').open('w+') as log:
        process = subprocess.Popen([binary, '-d', str(directory), '-f', str(path)],
                                   stdout=log, stderr=log, env=rt.core_env())
        try:
            time.sleep(1)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            for node in nodes:
                q = urlencode({'url': 'https://cp.cloudflare.com/generate_204', 'timeout': 8000, 'expected': '204'})
                url = f'http://127.0.0.1:{port}/proxies/'+quote(node['name'], safe='')+'/delay?'+q
                try:
                    req = urllib.request.Request(url, headers={'Authorization': 'Bearer '+token})
                    with opener.open(req, timeout=12) as response:
                        answer = json.load(response)
                    result.append({'protocol': node['protocol'], 'ok': isinstance(answer.get('delay'), (int, float)),
                                   'latency_ms': answer.get('delay')})
                except Exception as error:
                    result.append({'protocol': node['protocol'], 'ok': False, 'reason': str(error)})
        finally:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return result


if __name__ == '__main__':
    sys.exit(main())
