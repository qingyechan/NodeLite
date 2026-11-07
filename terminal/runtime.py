"""Linux service lifecycle, lightweight subscription server, core upgrades & legacy cleanup."""
import base64
import contextlib
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
from socketserver import ThreadingMixIn
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from urllib.parse import quote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from protocols import (
    PROTOCOLS,
    TOKEN_RE,
    build_relay_proxies,
    inbound,
    new_node,
    new_token,
    outbound,
    parse_node_uri,
    server_config,
    subscription_bundle,
    subscription_urls,
    valid_host,
    valid_name,
    valid_port,
    valid_sni,
    valid_ssh_port,
    valid_sub_host,
    valid_token,
)

ROOT = Path('/etc/nodelite')
CORE = Path('/opt/nodelite/sing-box')
SERVICE = 'nodelite'
SUB_SERVICE = 'nodelite-sub'

CORE_VERSION = '1.14.4'
CORE_HASHES = {
    'amd64': '699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968',
    'arm64': '436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26',
    'armv7': 'fd164ed45ebc784f657a3e1d0e0ad0f68afdcff864ee57122c2cfed3ddb80a00',
    '386': 'efb46daaa48ee55e090bd1dfcaee34bfbe9bdbd9b89fa9f328d25f81a619e865',
}

LEGACY_SERVICE_META = {
    'nodepilot-sing-box': {
        'paths': ['/etc/sing-box', '/etc/nodepilot'],
        'ownership': 'subprogress',
        'description': '早期版本 NodePilot 管理的 sing-box 节点服务',
    },
    'subprogress-auto': {
        'paths': ['/etc/subprogress-auto'],
        'ownership': 'subprogress',
        'description': '旧网页版 SubProgress 自动部署的节点服务',
    },
    'subprogress-sub': {
        'paths': ['/var/lib/subprogress-sub'],
        'ownership': 'subprogress',
        'description': '旧网页版 SubProgress 独立订阅 HTTP 服务',
    },
    'nodepilot-subscription': {
        'paths': ['/usr/local/bin/nodepilot-subscription.py', '/root/.nodepilot-sub-token'],
        'ownership': 'subprogress',
        'description': '早期版本 NodePilot 独立订阅服务',
    },
    'sing-box': {
        'paths': ['/usr/local/etc/sing-box'],
        'ownership': 'third-party',
        'description': '外部或其他脚本安装的 sing-box 服务（非本工具创建，默认不自动停用）',
    },
}
LEGACY_SERVICES = {k: v['paths'] for k, v in LEGACY_SERVICE_META.items()}
USERINFO_RE = re.compile(r'^[A-Za-z0-9=; ]{0,200}$')


def detect_arch(machine=None):
    m = (machine or platform.machine() or '').strip().lower()
    mapping = {
        'x86_64': 'amd64',
        'amd64': 'amd64',
        'aarch64': 'arm64',
        'arm64': 'arm64',
        'armv7l': 'armv7',
        'armv7': 'armv7',
        'i386': '386',
        'i686': '386',
        '386': '386',
    }
    if m not in mapping:
        raise RuntimeError(f'不支持的系统架构：{m}（仅支持 amd64、arm64、armv7、386）')
    return mapping[m]


def run(args, **kw):
    return subprocess.run([str(x) for x in args], text=True, encoding='utf-8',
                          errors='replace', capture_output=True, timeout=kw.pop('timeout', 30), **kw)


def checked(args, **kw):
    r = run(args, **kw)
    if r.returncode:
        raise RuntimeError((r.stderr or r.stdout or '命令执行失败')[-1600:])
    return r.stdout.strip()


def write_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    path.chmod(0o600)


def core_env():
    return dict(os.environ, GOMEMLIMIT='32MiB', GOGC='50')


def init_system():
    if Path('/run/systemd/system').is_dir() and shutil.which('systemctl'):
        return 'systemd'
    if Path('/run/openrc').exists() and shutil.which('rc-service'):
        return 'openrc'
    raise RuntimeError('需要正在运行的 systemd 或 OpenRC。普通 Docker 容器不在本版支持范围内。')


def service_name( action, check=True, name=SERVICE):
    init = init_system()
    cmd = ['systemctl', action, name] if init == 'systemd' else ['rc-service', name, action]
    if action == 'status' and init == 'systemd':
        cmd = ['systemctl', 'is-active', '--quiet', name]
    r = run(cmd)
    if check and r.returncode:
        raise RuntimeError('服务'+action+'失败：'+(r.stderr or r.stdout)[-1000:])
    return r.returncode == 0


def service(action, check=True):
    return service_name(action, check=check, name=SERVICE)


def enable_service_name(enable=True, name=SERVICE):
    if init_system() == 'systemd':
        checked(['systemctl', 'enable' if enable else 'disable', name])
    else:
        if enable:
            checked(['rc-update', 'add', name, 'default'])
        elif service_enabled_name(name):
            checked(['rc-update', 'del', name, 'default'])


def enable_service(enable=True):
    return enable_service_name(enable, SERVICE)


def service_enabled_name(name=SERVICE):
    if init_system() == 'systemd':
        return run(['systemctl', 'is-enabled', '--quiet', name]).returncode == 0
    return (Path('/etc/runlevels/default')/name).exists()


def service_enabled():
    return service_enabled_name(SERVICE)


def load_state():
    path = ROOT/'current'/'nodes.json'
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else {'schema': 1, 'nodes': []}


def load_setup():
    path = ROOT/'setup.json'
    try:
        return json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
    except (OSError, ValueError):
        return {}


def detect_ssh_ports():
    ssh = os.environ.get('SSH_CONNECTION', '').split()
    internal_port = int(ssh[3]) if len(ssh) == 4 and ssh[3].isdigit() else 22
    setup = load_setup()
    public_port = setup.get('ssh_public_port')
    try:
        public_port = valid_ssh_port(public_port) if public_port else None
    except ValueError:
        public_port = None
    return {'internal': internal_port, 'public': public_port}


@contextlib.contextmanager
def lock():
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (ROOT/'manager.lock').open('a') as f:
        try:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:
            pass
        except BlockingIOError:
            raise RuntimeError('另一个菜单正在修改节点，请稍后重试。') from None
        yield


def check_ports(nodes, previous, extra_reserved_internal=(), extra_reserved_public=()):
    old = {(n['port'], PROTOCOLS[n['protocol']][1]) for n in previous}
    used, used_public, names = set(), set(), set()
    reserved_names = {'节点选择', '⚡ 自动优选最快', 'DIRECT', 'REJECT'}
    ssh_info = detect_ssh_ports()
    ssh_port = ssh_info['internal']
    ssh_public = ssh_info['public']
    sub_cfg = load_sub_config()
    sub_internal = sub_cfg.get('port') if sub_cfg.get('enabled') else None
    sub_public = (sub_cfg.get('public_port') or sub_cfg.get('port')) if sub_cfg.get('enabled') else None
    reserved_int = set(extra_reserved_internal)
    reserved_pub = set(extra_reserved_public)
    if sub_internal:
        reserved_int.add(int(sub_internal))
    if sub_public:
        reserved_pub.add(int(sub_public))

    for n in nodes:
        transport = PROTOCOLS[n['protocol']][1]
        pub_port = n.get('public_port') or n['port']
        key = (n['port'], transport)
        pub_key = (pub_port, transport)
        if n['name'] in names or n['name'] in reserved_names:
            raise ValueError(f"节点名称“{n['name']}”重复或为保留字；请修改“节点名称”一项。")
        if key in used:
            raise ValueError(f"节点监听端口重复：{n['port']}/{transport.upper()} 已被本工具另一节点使用；请修改“节点内部端口”一项。")
        if pub_key in used_public:
            raise ValueError(f"节点公网端口重复：{pub_port}/{transport.upper()} 已被另一节点使用；请到商家后台「端口映射」换一行空闲映射并修改“节点公网端口”一项。")
        used.add(key)
        used_public.add(pub_key)
        names.add(n['name'])
        if n['port'] == ssh_port or pub_port == ssh_port:
            raise ValueError(f'端口 {ssh_port} 用于 SSH 登录服务器；请修改“节点端口”一项，切勿填写 SSH 端口。')
        if ssh_public and (n['port'] == ssh_public or pub_port == ssh_public):
            raise ValueError(f'端口 {ssh_public} 是当前 SSH 公网登录端口；请到商家后台选另一行映射，修改“节点公网端口”一项。')
        if transport == 'tcp' and n['port'] in reserved_int:
            raise ValueError(f"内部端口 {n['port']} 已被在线订阅服务占用；请修改“节点内部端口”一项，或在菜单 4 修改订阅端口。")
        if transport == 'tcp' and pub_port in reserved_pub:
            raise ValueError(f"公网端口 {pub_port} 已被在线订阅服务占用；请修改“节点公网端口”一项，或在菜单 4 修改订阅公网端口。")
        if key in old and service('status', check=False):
            continue
        family = socket.AF_INET6 if ':' in n['host'] else socket.AF_INET
        kind = socket.SOCK_DGRAM if transport == 'udp' else socket.SOCK_STREAM
        try:
            with socket.socket(family, kind) as s:
                s.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', n['port']))
        except OSError as e:
            raise RuntimeError(f"内部端口 {n['port']}/{transport.upper()} 不能使用：{e}。不会停止其他程序；请修改“节点内部端口”一项（NAT 请在商家后台换一组映射）。") from None


def free_tcp_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def self_test(node, local=True, target=None):
    """Real protocol authentication + HTTPS request. Local != public reachability."""
    port = free_tcp_port()
    cfg = {'log': {'level': 'error'}, 'inbounds': [
        {'type': 'http', 'tag': 'probe', 'listen': '127.0.0.1', 'listen_port': port}],
        'outbounds': [outbound(node, local=local)], 'route': {'final': 'proxy'}}
    with tempfile.TemporaryDirectory(prefix='probe-', dir=ROOT) as d:
        path = Path(d)/'client.json'
        write_json(path, cfg)
        with (Path(d)/'core.log').open('w+', encoding='utf-8') as log:
            probe_env = dict(core_env(), GOMEMLIMIT='16MiB', GOGC='20')
            child = subprocess.Popen([str(CORE), 'run', '-c', str(path)], stdout=log, stderr=log,
                                     env=probe_env)
            try:
                for _ in range(50):
                    if child.poll() is not None:
                        return {'ok': False, 'scope': 'local' if local else 'server-public-loop',
                                'reason': '实测客户端启动失败，请运行诊断检查核心和配置'}
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.1)
                targets = [target] if target else ['https://cp.cloudflare.com/generate_204',
                                                  'https://www.gstatic.com/generate_204']
                for url in targets:
                    start = time.monotonic()
                    r = run(['curl', '--silent', '--show-error', '--noproxy', '', '--proxy',
                             f'http://127.0.0.1:{port}', '--connect-timeout', '5', '--max-time', '12',
                             '--output', os.devnull, '--write-out', '%{http_code}', url], timeout=16)
                    if r.returncode == 0 and r.stdout.strip() == '204':
                        return {'ok': True, 'scope': 'local' if local else 'server-public-loop',
                                'latency_ms': round((time.monotonic()-start)*1000),
                                'at': int(time.time())}
                return {'ok': False, 'scope': 'local' if local else 'server-public-loop',
                        'reason': '协议认证或 HTTPS 出站请求失败；检查伪装域名、DNS、证书及 VPS 出站网络'}
            finally:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()


def _is_managed_link(path):
    return path.is_symlink() or (os.name == 'nt' and hasattr(path, 'is_junction') and path.is_junction())


def _remove_link(path):
    if not (_is_managed_link(path) or path.exists()):
        return
    with contextlib.suppress(OSError):
        path.unlink()
    if _is_managed_link(path) or path.exists():
        with contextlib.suppress(OSError):
            os.rmdir(path)


def switch_current(target, link_path=None):
    link = link_path or (ROOT/'current')
    temp = link.parent/('.'+link.name+'-'+str(os.getpid()))
    _remove_link(temp)
    try:
        temp.symlink_to(target, target_is_directory=True)
    except OSError:
        if os.name == 'nt':
            import _winapi
            _winapi.CreateJunction(str(target), str(temp))
        else:
            raise
    if os.name == 'nt' and _is_managed_link(link):
        _remove_link(link)
    os.replace(temp, link)


def commit(nodes, test_ids=()):
    """Caller holds lock. Invalid config never replaces a running config."""
    previous = load_state()
    check_ports(nodes, previous['nodes'])
    releases = ROOT/'releases'
    releases.mkdir(mode=0o700, parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='rev-', dir=releases))
    stage.chmod(0o700)
    current = ROOT/'current'
    if current.exists() and not _is_managed_link(current):
        raise RuntimeError('current 不是本工具管理的符号链接，停止以保护现有文件。')
    old = current.resolve() if _is_managed_link(current) else None
    if old and old.parent != releases.resolve():
        raise RuntimeError('current 指向工具目录以外，停止以保护其他文件。')
    was_active = service('status', check=False)
    was_enabled = service_enabled()
    switched = False
    try:
        write_json(stage/'config.json', server_config(nodes))
        write_json(stage/'nodes.json', {'schema': 1, 'nodes': nodes})
        checked([CORE, 'check', '-c', stage/'config.json'], env=core_env())
        switch_current(stage)
        switched = True
        service('restart' if nodes else 'stop')
        if nodes:
            time.sleep(.8)
            if not service('status', check=False):
                raise RuntimeError('核心启动后退出，请查看诊断信息。')
        for n in nodes:
            if n['id'] in test_ids:
                result = self_test(n)
                if not result['ok']:
                    raise RuntimeError(n['name']+' 自测失败：'+result['reason'])
                n['self_test'] = result
        write_json(stage/'nodes.json', {'schema': 1, 'nodes': nodes})
        enable_service(bool(nodes))
    except BaseException as error:
        rollback_error = None
        if switched:
            try:
                service('stop')
                if old:
                    switch_current(old)
                else:
                    _remove_link(current)
                if was_active:
                    service('start')
                enable_service(was_enabled)
            except Exception as e:
                rollback_error = e
        if not rollback_error:
            shutil.rmtree(stage)
        if rollback_error:
            raise RuntimeError(f'变更失败；恢复旧服务也失败：{rollback_error}。请运行 nl doctor。') from error
        raise
    # Generated exports are snapshots, not a live subscription. Remove stale secrets.
    for name in ('links.txt', 'subscription.txt', 'flclash.yaml'):
        (ROOT/'exports'/name).unlink(missing_ok=True)
    # Keep one previous revision for recovery, bound disk usage.
    for entry in releases.iterdir():
        if entry.is_dir() and entry != stage and entry != old and entry.name.startswith('rev-'):
            shutil.rmtree(entry)
    # Automatically synchronize the public subscription snapshot if configured.
    if (ROOT/'sub'/'config.json').exists():
        sync_subscription(nodes, manage_service=True)


def update_node_port(node_id, new_port, new_public_port=None, new_host=None):
    """Change a node's internal/public port (and optionally host) while preserving UUID/keys."""
    with lock():
        nodes = load_state()['nodes']
        target = next((n for n in nodes if n['id'] == node_id or n['name'] == node_id), None)
        if not target:
            raise ValueError('未找到指定的节点。')
        old_port = target['port']
        transport = PROTOCOLS[target['protocol']][1]
        port = valid_port(new_port)
        pub = valid_port(new_public_port if new_public_port is not None else port)
        updated = dict(target, port=port, public_port=pub, public_verified=False)
        if new_host is not None:
            updated['host'] = valid_host(new_host)
        candidate = [updated if n['id'] == target['id'] else n for n in nodes]
        commit(candidate, test_ids=[target['id']])
        with contextlib.suppress(RuntimeError, OSError):
            firewall(updated)
            still_used = any(
                n['port'] == old_port and PROTOCOLS[n['protocol']][1] == transport
                for n in candidate
            )
            if old_port != port and not still_used:
                firewall_remove_port(old_port, transport)
        return load_state()['nodes'][[n['id'] for n in candidate].index(target['id'])]


def rollback_previous():
    """Restore the previous saved revision in ROOT/releases if available."""
    with lock():
        releases = ROOT/'releases'
        current = ROOT/'current'
        if not releases.is_dir():
            raise ValueError('没有可恢复的历史配置版本。')
        cur_target = current.resolve() if _is_managed_link(current) else None
        candidates = sorted(
            [d for d in releases.iterdir() if d.is_dir() and d != cur_target and (d/'config.json').exists() and (d/'nodes.json').exists()],
            key=lambda d: d.stat().st_mtime,
            reverse=True,
        )
        if not candidates:
            raise ValueError('没有找到上一版备份配置。')
        prev_dir = candidates[0]
        prev_nodes = json.loads((prev_dir/'nodes.json').read_text(encoding='utf-8')).get('nodes', [])
        checked([CORE, 'check', '-c', prev_dir/'config.json'], env=core_env())
        switch_current(prev_dir)
        service('restart' if prev_nodes else 'stop')
        if prev_nodes:
            time.sleep(0.8)
            if not service('status', check=False):
                raise RuntimeError('恢复上一版配置后核心未能保持运行，请运行 nl doctor 查看日志。')
        enable_service(bool(prev_nodes))
        if (ROOT/'sub'/'config.json').exists():
            sync_subscription(prev_nodes, manage_service=True)
        return prev_nodes


def prepare_credentials(n):
    if n['protocol'] == 'vless':
        keys = checked([CORE, 'generate', 'reality-keypair'])
        for line in keys.splitlines():
            key, _, value = line.partition(':')
            if key.strip() == 'PrivateKey':
                n['private_key'] = value.strip()
            elif key.strip() == 'PublicKey':
                n['public_key'] = value.strip()
        if not n.get('public_key') or not n.get('private_key'):
            raise RuntimeError('核心没有返回 Reality 密钥；检查核心版本。')
    if n['protocol'] in ('trojan', 'hysteria2', 'tuic') and not n.get('cert'):
        directory = ROOT/'certs'/n['id']
        directory.mkdir(parents=True, mode=0o700)
        n.update(cert=str(directory/'cert.pem'), key=str(directory/'key.pem'), self_signed=True)
        checked(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                 '-nodes', '-days', '365', '-subj', '/CN='+n['sni'], '-addext',
                 'subjectAltName=DNS:'+n['sni'], '-keyout', n['key'], '-out', n['cert']])
        Path(n['key']).chmod(0o600)


def firewall_port(port, transport='tcp'):
    rule = f'{int(port)}/{transport}'
    if shutil.which('ufw') and 'Status: active' in run(['ufw', 'status'], env=dict(os.environ, LC_ALL='C')).stdout:
        checked(['ufw', 'allow', rule])
        return '已在 UFW 放行 '+rule
    if shutil.which('firewall-cmd') and run(['firewall-cmd', '--state']).returncode == 0:
        checked(['firewall-cmd', '--permanent', '--add-port='+rule])
        checked(['firewall-cmd', '--add-port='+rule])
        return '已在 firewalld 放行 '+rule
    return '如果商家有安全组/防火墙，请放行 '+rule+'；NAT 还需商家端口映射。'


def firewall_remove_port(port, transport='tcp'):
    rule = f'{int(port)}/{transport}'
    if shutil.which('ufw') and 'Status: active' in run(['ufw', 'status'], env=dict(os.environ, LC_ALL='C')).stdout:
        run(['ufw', 'delete', 'allow', rule])
        return '已从 UFW 移除旧端口 '+rule
    if shutil.which('firewall-cmd') and run(['firewall-cmd', '--state']).returncode == 0:
        run(['firewall-cmd', '--permanent', '--remove-port='+rule])
        run(['firewall-cmd', '--remove-port='+rule])
        return '已从 firewalld 移除旧端口 '+rule
    return ''


def firewall(node):
    """Only add this node's port; never disable/flush a firewall."""
    transport = PROTOCOLS[node['protocol']][1]
    return firewall_port(node['port'], transport)


def check_cert_expiry(cert_path):
    """Return certificate remaining days and expiry warning without external dependencies."""
    if not cert_path or not Path(cert_path).is_file():
        return None
    r = run(['openssl', 'x509', '-enddate', '-noout', '-in', str(cert_path)])
    if r.returncode != 0 or 'notAfter=' not in r.stdout:
        return None
    raw = r.stdout.strip().split('notAfter=', 1)[1].strip()
    try:
        from datetime import datetime, timezone
        exp_ts = ssl.cert_time_to_seconds(raw)
        days_left = round((exp_ts - time.time()) / 86400, 1)
        return {
            'path': str(cert_path),
            'expiresAt': datetime.fromtimestamp(exp_ts, tz=timezone.utc).strftime('%Y-%m-%d'),
            'daysLeft': days_left,
            'expired': days_left <= 0,
            'expiringSoon': days_left <= 30,
        }
    except Exception:
        return None


def recent_logs(lines=15):
    if init_system() == 'systemd':
        r = run(['journalctl', '-u', SERVICE, '-u', SUB_SERVICE, '-n', str(int(lines)), '--no-pager'])
        return (r.stdout or r.stderr or '').strip()[-2400:]
    r = run(['logread'])
    if r.returncode == 0 and r.stdout:
        matched = [ln for ln in r.stdout.splitlines() if 'nodelite' in ln or 'sing-box' in ln]
        return '\n'.join(matched[-int(lines):])[-2400:]
    return ''


def _iter_proc_rss():
    proc = Path('/proc')
    if os.name == 'nt' or not proc.is_dir():
        return
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmd = (entry/'cmdline').read_bytes().replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()
            if not cmd:
                continue
            rss_kib = 0
            for line in (entry/'status').read_text(encoding='utf-8', errors='replace').splitlines():
                if line.startswith('VmRSS:'):
                    rss_kib = int(line.split()[1])
                    break
            yield int(entry.name), rss_kib, cmd
        except (OSError, ValueError, IndexError):
            continue


def runtime_memory_footprint():
    """Measure exact kernel VmRSS across all NodeLite processes via /proc."""
    components = {'sing-box': 0, 'sub-server': 0, 'cloudflared': 0, 'manager-cli': 0}
    my_pid = os.getpid()
    for pid, rss, cmd in _iter_proc_rss() or ():
        if pid == my_pid:
            components['manager-cli'] += rss
        elif '/opt/nodelite/sing-box' in cmd and 'supervise-daemon' not in cmd:
            components['sing-box'] += rss
        elif 'runtime.py serve-sub' in cmd and 'supervise-daemon' not in cmd:
            components['sub-server'] += rss
        elif '/opt/nodelite/cloudflared' in cmd:
            components['cloudflared'] += rss
    daemon_kib = components['sing-box'] + components['sub-server'] + components['cloudflared']
    return {
        'componentsKiB': components,
        'daemonTotalMiB': round(daemon_kib / 1024, 1),
        'withMenuTotalMiB': round((daemon_kib + components['manager-cli']) / 1024, 1),
    }


def node_status_stages(node, core_active=None):
    """Explicit 4-stage status so loopback self-test is never conflated with client public reachability."""
    if core_active is None:
        with contextlib.suppress(RuntimeError):
            core_active = service('status', check=False)
    local_ok = bool(node.get('self_test', {}).get('ok'))
    pub_ok = bool(node.get('public_verified'))
    return {
        'configGenerated': True,
        'serviceStarted': bool(core_active),
        'localSelfTestOk': local_ok,
        'publicClientVerified': pub_ok,
        'summary': (
            '1.配置已生成 | '
            + ('2.服务已启动 | ' if core_active else '2.服务未运行 | ')
            + (f"3.服务器内部自测通过({node['self_test'].get('latency_ms', '?')}ms) | " if local_ok else '3.内部自测未通过 | ')
            + ('4.公网客户端已验证' if pub_ok else '4.公网待手机/电脑客户端导入验证')
        ),
    }


def memory_info():
    info = {}
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            name, value = line.split(':', 1)
            if name in ('MemTotal', 'MemAvailable'):
                info[name] = int(value.split()[0])*1024
        for limit_path, used_path in [('/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory.current'),
                                      ('/sys/fs/cgroup/memory/memory.limit_in_bytes', '/sys/fs/cgroup/memory/memory.usage_in_bytes')]:
            if Path(limit_path).exists():
                limit = Path(limit_path).read_text().strip()
                if limit.isdigit():
                    info['MemTotal'] = min(info.get('MemTotal', int(limit)), int(limit))
                    used = int(Path(used_path).read_text().strip())
                    # cgroup.current includes reclaimable file cache, not just process RAM.
                    # Use the conservative inactive-file allowance used for working sets.
                    stat_path = Path(limit_path).parent/'memory.stat'
                    stat = dict(line.split() for line in stat_path.read_text().splitlines())
                    reclaimable = int(stat.get('inactive_file', stat.get('total_inactive_file', '0')))
                    available = max(0, min(int(limit), int(limit)-used+reclaimable))
                    info['MemAvailable'] = min(info.get('MemAvailable', int(limit)), available)
    except (OSError, ValueError):
        pass
    return {k: round(v/1048576, 1) for k, v in info.items()}


# ---------------- Lightweight Public Subscription URL Service ----------------

def load_sub_config():
    path = ROOT/'sub'/'config.json'
    try:
        return json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
    except (OSError, ValueError):
        return {}


def discover_legacy_sub_token():
    try:
        old_lite_sub = Path('/etc/subprogress-lite/sub/config.json')
        if old_lite_sub.exists():
            tok = json.loads(old_lite_sub.read_text(encoding='utf-8')).get('token', '').strip()
            if TOKEN_RE.fullmatch(tok):
                return tok
    except (OSError, ValueError):
        pass
    for candidate in [
        ROOT/'legacy_sub_token',
        Path('/etc/subprogress-lite/legacy_sub_token'),
        Path('/var/lib/subprogress-sub/current/token'),
        Path('/var/lib/subprogress-sub/current/legacy_token'),
        Path('/root/.nodepilot-sub-token'),
    ]:
        try:
            if candidate.exists():
                value = candidate.read_text(encoding='utf-8').strip()
                if TOKEN_RE.fullmatch(value):
                    return value
        except OSError:
            continue
    return ''


def _billing_userinfo():
    try:
        from datetime import datetime, timezone
        p = ROOT/'billing.json'
        if not p.exists():
            # Older deployments stored provider billing separately from the node manager.
            p = Path('/etc/subprogress/billing.json')
        if not p.exists():
            return ''
        data = json.loads(p.read_text(encoding='utf-8'))
        fields = []
        total, used = data.get('totalTrafficGb'), data.get('usedTrafficGb')
        end = datetime.fromisoformat(data['cycleEnd'].replace('Z', '+00:00'))
        if datetime.now(timezone.utc) < end and isinstance(total, (int, float)) and total > 0 and isinstance(used, (int, float)) and used >= 0:
            fields.extend(['upload=0', 'download='+str(round(used*1073741824)), 'total='+str(round(total*1073741824))])
        expiry = data.get('expireTimestamp')
        if isinstance(expiry, int) and expiry > 0:
            fields.append('expire='+str(expiry))
        return '; '.join(fields)
    except Exception:
        return ''


CF_FAST_IPS = [
    ('香港极速1', '104.19.151.1'),
    ('香港极速2', '104.19.154.88'),
    ('香港极速3', '104.19.153.88'),
    ('香港极速4', '104.19.157.88'),
    ('香港极速5', '104.19.150.1'),
]

REALITY_SNI_CANDIDATES = (
    'www.apple.com',
    'gateway.icloud.com',
    'www.microsoft.com',
    'www.amd.com',
    'swdist.apple.com',
    'dl.google.com',
)


def _probe_single_sni(domain, timeout=1.5):
    start = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                ver = ssock.version() or ''
        ms = round((time.monotonic() - start) * 1000, 1)
        if ver not in ('TLSv1.3', 'TLSv1.2'):
            return {'sni': domain, 'ok': False, 'reason': f'unsupported TLS ({ver})'}
        return {'sni': domain, 'ok': True, 'latency_ms': ms, 'tls': ver}
    except Exception as err:
        return {'sni': domain, 'ok': False, 'reason': str(err)}


def probe_reality_sni_candidates(candidates=None, timeout=1.5, probe_fn=None):
    """Concurrently test candidate Reality SNI domains from the VPS and pick the lowest-latency TLS 1.3 host."""
    domains = list(candidates or REALITY_SNI_CANDIDATES)
    fn = probe_fn or (lambda d: _probe_single_sni(d, timeout=timeout))
    results = []
    lock_obj = threading.Lock()

    def _worker(d):
        res = fn(d)
        with lock_obj:
            results.append(res)

    threads = [threading.Thread(target=_worker, args=(d,), daemon=True) for d in domains]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 0.5)

    ok_list = [r for r in results if r.get('ok')]
    ok_list.sort(key=lambda r: (0 if r.get('tls') == 'TLSv1.3' else 1, r.get('latency_ms', 9999)))
    failed_list = [r for r in results if not r.get('ok')]
    best = ok_list[0]['sni'] if ok_list else 'www.microsoft.com'
    return {
        'best': best,
        'bestLatencyMs': ok_list[0]['latency_ms'] if ok_list else None,
        'results': ok_list + failed_list,
    }


def load_external_config():
    path = ROOT/'sub'/'external.json'
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding='utf-8'))
            return {
                'external_nodes': list(data.get('external_nodes') or []),
                'relay_chains': list(data.get('relay_chains') or []),
            }
    except (OSError, ValueError):
        pass
    return {'external_nodes': [], 'relay_chains': []}


def save_external_config(data, sync=True):
    sub_root = ROOT/'sub'
    sub_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = {
        'schema': 1,
        'external_nodes': list(data.get('external_nodes') or []),
        'relay_chains': list(data.get('relay_chains') or []),
    }
    write_json(sub_root/'external.json', payload)
    if sync and (sub_root/'config.json').exists():
        sync_subscription(manage_service=True)
    return payload


def effective_subscription_nodes(nodes=None, sub_cfg=None, ext_cfg=None):
    """Combine local VPS nodes, Cloudflare fast IP variants, external VPS nodes, and relay chains."""
    if nodes is None:
        nodes = load_state()['nodes']
    if sub_cfg is None:
        sub_cfg = load_sub_config()
    if ext_cfg is None:
        ext_cfg = load_external_config()
    cf_domain = (sub_cfg or {}).get('cf_domain', '')
    cf_ips = (sub_cfg or {}).get('cf_ips') or CF_FAST_IPS
    native_nodes = []
    cf_nodes = []
    for n in nodes:
        if n['protocol'] == 'vmess' and cf_domain and not n.get('cf_domain'):
            for item in cf_ips:
                suffix, ip = (item[0], item[1]) if isinstance(item, (list, tuple)) else ('优选', str(item))
                cf_nodes.append(dict(n, name=f"{n['name']}-{suffix}", cf_domain=cf_domain, cf_ip=ip))
            cf_nodes.append(dict(n, name=n['name']+'-默认域名', cf_domain=cf_domain, cf_ip=cf_domain))
        else:
            native_nodes.append(n)
    ext_nodes = list(ext_cfg.get('external_nodes') or [])
    relay_chains = list(ext_cfg.get('relay_chains') or [])
    return native_nodes + ext_nodes + cf_nodes, relay_chains


def add_external_node(raw_uri, custom_name=''):
    """Parse and add an external VPS node URI into the aggregated subscription."""
    with lock():
        node = parse_node_uri(raw_uri, custom_name=custom_name or None)
        ext_cfg = load_external_config()
        local_names = {n['name'] for n in load_state()['nodes']}
        ext_names = {n['name'] for n in ext_cfg['external_nodes']}
        if node['name'] in local_names or node['name'] in ext_names:
            raise ValueError(f"节点名称 {node['name']} 已存在，请指定一个不同的名称。")
        ext_cfg['external_nodes'].append(node)
        save_external_config(ext_cfg, sync=True)
        return node


def remove_external_node(node_id_or_name):
    with lock():
        ext_cfg = load_external_config()
        target = next((n for n in ext_cfg['external_nodes'] if n['id'] == node_id_or_name or n['name'] == node_id_or_name), None)
        if not target:
            raise ValueError('未找到指定的外部节点。')
        ext_cfg['external_nodes'] = [n for n in ext_cfg['external_nodes'] if n['id'] != target['id']]
        ext_cfg['relay_chains'] = [
            c for c in ext_cfg['relay_chains']
            if c.get('front') != target['name'] and c.get('exit') != target['name']
        ]
        save_external_config(ext_cfg, sync=True)
        return target


def add_relay_chain(front_name, exit_name, chain_name=''):
    """Create a `dialer-proxy` relay chain (front entry node -> exit landing node) in the subscription."""
    with lock():
        front_name = valid_name(front_name)
        exit_name = valid_name(exit_name)
        if front_name == exit_name:
            raise ValueError('前置入口节点与落地节点不能是同一个节点。')
        ext_cfg = load_external_config()
        all_nodes, _ = effective_subscription_nodes(ext_cfg=ext_cfg)
        available_names = {n['name'] for n in all_nodes}
        if front_name not in available_names:
            raise ValueError(f'未找到前置入口节点：{front_name}')
        if exit_name not in available_names:
            raise ValueError(f'未找到落地节点：{exit_name}')
        resolved_name = valid_name(chain_name or f'🔗 链式：{front_name} → {exit_name}')
        existing_chain_names = {c.get('name') for c in ext_cfg['relay_chains']}
        if resolved_name in available_names or resolved_name in existing_chain_names:
            raise ValueError(f'链式节点名称 {resolved_name} 已存在。')
        chain = {
            'id': 'chain-' + secrets.token_hex(5),
            'name': resolved_name,
            'front': front_name,
            'exit': exit_name,
        }
        ext_cfg['relay_chains'].append(chain)
        save_external_config(ext_cfg, sync=True)
        return chain


def remove_relay_chain(chain_id_or_name):
    with lock():
        ext_cfg = load_external_config()
        target = next((c for c in ext_cfg['relay_chains'] if c.get('id') == chain_id_or_name or c.get('name') == chain_id_or_name), None)
        if not target:
            raise ValueError('未找到指定的链式代理。')
        ext_cfg['relay_chains'] = [c for c in ext_cfg['relay_chains'] if c.get('id') != target['id']]
        save_external_config(ext_cfg, sync=True)
        return target


def sync_subscription(nodes=None, manage_service=True):
    """Atomically write the verified node snapshot for the public subscription server."""
    sub_root = ROOT/'sub'
    cfg = load_sub_config()
    if not cfg or not cfg.get('token'):
        return None
    if nodes is None:
        nodes = load_state()['nodes']
    effective_nodes, relay_chains = effective_subscription_nodes(nodes=nodes, sub_cfg=cfg)
    bundle = subscription_bundle(
        effective_nodes,
        title=cfg.get('title', 'NodeLite'),
        userinfo=cfg.get('userinfo') or _billing_userinfo(),
        relay_chains=relay_chains,
    )
    releases = sub_root/'releases'
    releases.mkdir(mode=0o700, parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='sub-', dir=releases))
    stage.chmod(0o700)
    for name in ('clash.yaml', 'singbox.json', 'links.b64', 'raw.txt', 'meta.json'):
        f = stage/name
        f.write_text(bundle[name], encoding='utf-8')
        f.chmod(0o600)
    (stage/'token').write_text(cfg['token']+'\n', encoding='utf-8')
    (stage/'token').chmod(0o600)
    legacy = '' if cfg.get('token_rotated') else cfg.get('legacy_token', '')
    if legacy and TOKEN_RE.fullmatch(legacy) and legacy != cfg['token']:
        (stage/'legacy_token').write_text(legacy+'\n', encoding='utf-8')
        (stage/'legacy_token').chmod(0o600)

    current = sub_root/'current'
    old = current.resolve() if _is_managed_link(current) else None
    switch_current(stage, current)
    for entry in releases.iterdir():
        if entry.is_dir() and entry != stage and entry != old and entry.name.startswith('sub-'):
            shutil.rmtree(entry, ignore_errors=True)

    if manage_service and cfg.get('enabled'):
        try:
            if effective_nodes:
                if not service_name('status', check=False, name=SUB_SERVICE):
                    service_name('start', check=True, name=SUB_SERVICE)
                enable_service_name(True, name=SUB_SERVICE)
            else:
                service_name('stop', check=False, name=SUB_SERVICE)
                enable_service_name(False, name=SUB_SERVICE)
        except RuntimeError as err:
            raise RuntimeError(f'节点配置已保存，但在线订阅服务同步/启动失败：{err}') from err
    return bundle['meta']


def sub_unit_text(init):
    exe = sys.executable or 'python3'
    script = str((CORE.parent/'runtime.py') if (CORE.parent/'runtime.py').exists() else Path(__file__).resolve())
    if init == 'systemd':
        return (
            '[Unit]\n'
            'Description=NodeLite subscription server\n'
            'After=network-online.target\n'
            'Wants=network-online.target\n'
            'StartLimitIntervalSec=60\n'
            'StartLimitBurst=3\n'
            '[Service]\n'
            'Type=simple\n'
            'Environment=PYTHONMALLOC=malloc\n'
            'UMask=0077\n'
            f'ExecStart={exe} -B {script} serve-sub\n'
            'Restart=on-failure\n'
            'RestartSec=5\n'
            'NoNewPrivileges=true\n'
            'ProtectSystem=strict\n'
            f'ReadWritePaths={ROOT}\n'
            'PrivateTmp=true\n'
            '[Install]\n'
            'WantedBy=multi-user.target\n'
        )
    return (
        '#!/sbin/openrc-run\n'
        'name="NodeLite Subscription"\n'
        'description="NodeLite subscription server"\n'
        'supervisor="supervise-daemon"\n'
        f'command="{exe}"\n'
        f'command_args="-B {script} serve-sub"\n'
        'export PYTHONMALLOC=malloc\n'
        'umask 077\n'
        'respawn_delay=5\n'
        'respawn_max=3\n'
        'respawn_period=60\n'
        'output_logger="logger -t nodelite-sub"\n'
        'error_logger="logger -t nodelite-sub"\n'
        'depend() { need net; }\n'
    )


def install_sub_unit():
    init = init_system()
    if init == 'systemd':
        unit = Path('/etc/systemd/system/nodelite-sub.service')
        unit.write_text(sub_unit_text(init), encoding='utf-8')
        unit.chmod(0o644)
        checked(['systemctl', 'daemon-reload'])
    else:
        unit = Path('/etc/init.d/nodelite-sub')
        unit.write_text(sub_unit_text(init), encoding='utf-8')
        unit.chmod(0o755)
    return unit


def _stop_conflicting_legacy_sub(port):
    """If legacy subprogress-lite-sub, subprogress-sub or nodepilot-subscription occupies `port`, stop it safely."""
    r = run(['ss', '-H', '-lntp', f'sport = :{int(port)}'])
    if r.returncode != 0 or not r.stdout.strip():
        return
    for pid in re.findall(r'pid=(\d+)', r.stdout):
        try:
            cmd = (Path('/proc')/pid/'cmdline').read_bytes().replace(b'\x00', b' ').decode(errors='replace')
        except OSError:
            continue
        if any(tag in cmd for tag in ('subprogress-lite', 'subprogress-sub', 'nodepilot-subscription', 'subServer.py')):
            for svc in ('subprogress-lite-sub', 'subprogress-sub', 'nodepilot-subscription'):
                try:
                    service_name('stop', check=False, name=svc)
                    enable_service_name(False, name=svc)
                except Exception:
                    pass
            try:
                os.kill(int(pid), 15)
                time.sleep(0.2)
            except OSError:
                pass


def configure_subscription(host, port, public_port=None, scheme='http', cert='', key='',
                           self_signed=False, title='NodeLite', token=None, start_daemon=True):
    """Enable or update the lightweight public subscription service."""
    with lock():
        host = valid_sub_host(host)
        port = valid_port(port)
        pub = valid_port(public_port if public_port is not None else port)
        if scheme not in ('http', 'https'):
            raise ValueError('订阅协议仅支持 http 或 https')
        ssh_info = detect_ssh_ports()
        if port == ssh_info['internal'] or pub == ssh_info['internal']:
            raise ValueError(f"订阅端口不能使用 SSH 登录端口 {ssh_info['internal']}。")
        if ssh_info['public'] and (port == ssh_info['public'] or pub == ssh_info['public']):
            raise ValueError(f"订阅端口不能使用 SSH 公网登录端口 {ssh_info['public']}。")
        nodes = load_state()['nodes']
        for n in nodes:
            if PROTOCOLS[n['protocol']][1] == 'tcp':
                if n['port'] == port:
                    raise ValueError(f"内部端口 {port} 已被节点 {n['name']} 占用，订阅需使用独立端口。")
                if n.get('public_port') == pub:
                    raise ValueError(f"公网端口 {pub} 已被节点 {n['name']} 占用，订阅需使用独立公网端口。")

        existing = load_sub_config()
        token_rotated = bool(existing.get('token_rotated'))
        legacy_token = '' if token_rotated else (existing.get('legacy_token') or discover_legacy_sub_token())
        chosen_token = valid_token(token) if token else (existing.get('token') or legacy_token or new_token())

        if scheme == 'https':
            if cert and key:
                cert_path = str(Path(cert).resolve(strict=True))
                key_path = str(Path(key).resolve(strict=True))
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(cert_path, key_path)
                self_signed = False
            elif self_signed:
                cert_dir = ROOT/'certs'/'subscription'
                cert_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
                cert_path = str(cert_dir/'cert.pem')
                key_path = str(cert_dir/'key.pem')
                san = f'IP:{host}' if _is_ip(host) else f'DNS:{host}'
                checked(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                         '-nodes', '-days', '365', '-subj', '/CN='+host, '-addext',
                         'subjectAltName='+san, '-keyout', key_path, '-out', cert_path])
                Path(key_path).chmod(0o600)
            else:
                raise ValueError('HTTPS 订阅需要提供证书与私钥路径，或确认使用自签证书。')
        else:
            cert_path, key_path, self_signed = '', '', False

        if start_daemon:
            _stop_conflicting_legacy_sub(port)
            was_running = service_name('status', check=False, name=SUB_SERVICE)
            if not (was_running and existing.get('port') == port):
                family = socket.AF_INET6 if ':' in host else socket.AF_INET
                try:
                    with socket.socket(family, socket.SOCK_STREAM) as s:
                        s.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', port))
                except OSError as e:
                    raise RuntimeError(f'订阅内部端口 {port}/TCP 已被其他程序占用：{e}；请修改“订阅内部端口”一项。') from None

        cfg = {
            **existing,
            'enabled': True,
            'host': host,
            'port': port,
            'public_port': pub,
            'bind': '::' if ':' in host else '0.0.0.0',
            'scheme': scheme,
            'cert': cert_path,
            'key': key_path,
            'self_signed': bool(self_signed),
            'title': valid_name(title) if title else 'NodeLite',
            'token': chosen_token,
            'legacy_token': '' if token_rotated else (legacy_token if legacy_token != chosen_token else ''),
            'token_rotated': token_rotated,
            'updatedAt': int(time.time()),
        }
        write_json(ROOT/'sub'/'config.json', cfg)
        meta = sync_subscription(nodes, manage_service=False)
        if start_daemon:
            install_sub_unit()
            if nodes:
                service_name('restart', check=True, name=SUB_SERVICE)
                enable_service_name(True, name=SUB_SERVICE)
                wait_sub_local(cfg, expected_generation=meta['generation'])
            else:
                service_name('stop', check=False, name=SUB_SERVICE)
                enable_service_name(False, name=SUB_SERVICE)
        return dict(cfg, urls=subscription_urls(cfg), meta=meta)


def rotate_sub_token(start_daemon=True):
    """Generate a brand new subscription token and permanently revoke any legacy alias."""
    with lock():
        cfg = load_sub_config()
        if not cfg:
            raise ValueError('尚未配置在线订阅服务，请先开启在线订阅。')
        cfg['token'] = new_token()
        cfg['legacy_token'] = ''
        cfg['token_rotated'] = True
        cfg['updatedAt'] = int(time.time())
        (ROOT/'legacy_sub_token').unlink(missing_ok=True)
        write_json(ROOT/'sub'/'config.json', cfg)
        nodes = load_state()['nodes']
        meta = sync_subscription(nodes, manage_service=start_daemon)
        if start_daemon and cfg.get('enabled') and nodes:
            wait_sub_local(cfg, expected_generation=meta['generation'])
        return dict(cfg, urls=subscription_urls(cfg), meta=meta)


def disable_subscription(stop_daemon=True):
    with lock():
        cfg = load_sub_config()
        if not cfg:
            return False
        cfg['enabled'] = False
        write_json(ROOT/'sub'/'config.json', cfg)
        if stop_daemon:
            try:
                service_name('stop', check=False, name=SUB_SERVICE)
                enable_service_name(False, name=SUB_SERVICE)
            except RuntimeError:
                pass
        return True


def _is_ip(value):
    try:
        valid_host(value)
        return True
    except ValueError:
        return False


def check_sub_local(sub_cfg=None, port=None, expected_generation=None):
    cfg = sub_cfg or load_sub_config()
    if not cfg or not cfg.get('token'):
        raise RuntimeError('未配置在线订阅')
    target_port = port or cfg['port']
    path = f"/s/{cfg['token']}/manifest.json"
    if cfg.get('scheme') == 'https' and cfg.get('cert'):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.load_verify_locations(cafile=cfg['cert'])
        raw = socket.create_connection(('127.0.0.1', target_port), timeout=3)
        sock = ctx.wrap_socket(raw, server_hostname=cfg.get('host') or '127.0.0.1')
        conn = http.client.HTTPConnection('127.0.0.1', target_port, timeout=3)
        conn.sock = sock
    else:
        conn = http.client.HTTPConnection('127.0.0.1', target_port, timeout=3)
    try:
        conn.request('GET', path)
        resp = conn.getresponse()
        body = json.loads(resp.read(65536).decode('utf-8'))
        if resp.status != 200:
            raise RuntimeError(f'订阅本地自检状态码异常：{resp.status}')
        if expected_generation and body.get('generation') != expected_generation:
            raise RuntimeError('订阅快照版本未同步')
        return body
    finally:
        conn.close()


def wait_sub_local(sub_cfg=None, port=None, expected_generation=None):
    last_err = None
    for _ in range(25):
        try:
            return check_sub_local(sub_cfg, port=port, expected_generation=expected_generation)
        except Exception as e:
            last_err = e
            time.sleep(0.15)
    raise RuntimeError(f'在线订阅本地健康检查失败：{last_err}')


_VMESS_CACHE = {'at': 0.0, 'nodes': []}


def _cached_vmess_nodes():
    now = time.monotonic()
    if now - _VMESS_CACHE['at'] > 5.0:
        _VMESS_CACHE['nodes'] = [n for n in load_state().get('nodes', []) if n['protocol'] == 'vmess']
        _VMESS_CACHE['at'] = now
    return _VMESS_CACHE['nodes']


class _SubHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = os.name != 'nt'

    def __init__(self, server_address, handler_class, sub_root, tls_context=None):
        self.sub_root = Path(sub_root)
        self.tls_context = tls_context
        self.slots = threading.BoundedSemaphore(16)
        self.ws_slots = threading.BoundedSemaphore(12)
        self.address_family = socket.AF_INET6 if ':' in server_address[0] else socket.AF_INET
        super().__init__(server_address, handler_class)

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            with contextlib.suppress(OSError):
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()

    def process_request(self, request, client_address):
        if not self.slots.acquire(False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            with contextlib.suppress(OSError):
                request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            request.settimeout(5)
            if self.tls_context is not None:
                request = self.tls_context.wrap_socket(request, server_side=True)
            else:
                first = request.recv(64, socket.MSG_PEEK)
                vnodes = _cached_vmess_nodes()
                matched = next((n for n in vnodes if first.startswith(b'GET ' + n['ws_path'].encode())), None) if first else None
                if matched is not None:
                    self._splice_to_vmess(request, int(matched['port']))
                    self.shutdown_request(request)
                    return
            super().process_request_thread(request, client_address)
        except OSError:
            self.shutdown_request(request)
        finally:
            self.slots.release()

    def _splice_to_vmess(self, client_sock, port):
        if not self.ws_slots.acquire(False):
            return
        try:
            upstream = socket.create_connection(('127.0.0.1', port), timeout=5)
            upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            self.ws_slots.release()
            return
        try:
            client_sock.settimeout(300)
            upstream.settimeout(300)

            def pipe(src, dst):
                try:
                    while True:
                        chunk = src.recv(16384)
                        if not chunk:
                            break
                        dst.sendall(chunk)
                except OSError:
                    pass
                finally:
                    with contextlib.suppress(OSError):
                        dst.shutdown(socket.SHUT_WR)

            t = threading.Thread(target=pipe, args=(upstream, client_sock), daemon=True)
            t.start()
            pipe(client_sock, upstream)
            t.join(timeout=5)
        finally:
            self.ws_slots.release()
            with contextlib.suppress(OSError):
                upstream.close()


class _SubRequestHandler(BaseHTTPRequestHandler):
    server_version = 'NodeLite'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(5)
        with contextlib.suppress(OSError):
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def log_message(self, *args):
        pass

    def _reply(self, status, body, content_type='text/plain; charset=utf-8', extra=None):
        self.send_response(status)
        headers = {
            'Content-Type': content_type,
            'Content-Length': str(len(body)),
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer',
            **(extra or {}),
        }
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            with contextlib.suppress(OSError, socket.timeout):
                self.wfile.write(body)

    def _proxy_websocket(self, req_path):
        vnodes = _cached_vmess_nodes()
        vmess = next((n for n in vnodes if n.get('ws_path') == req_path), None) or (vnodes[0] if vnodes else None)
        if not vmess:
            return self._reply(404, b'Not found\n')
        try:
            upstream = socket.create_connection(('127.0.0.1', int(vmess['port'])), timeout=5)
            upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            return self._reply(502, b'Bad gateway\n')
        try:
            self.connection.settimeout(300)
            upstream.settimeout(300)
            raw_hdr = f'{self.command} {self.path} {self.request_version}\r\n'
            for k, v in self.headers.items():
                raw_hdr += f'{k}: {v}\r\n'
            raw_hdr += '\r\n'
            upstream.sendall(raw_hdr.encode('latin-1', errors='replace'))

            def pipe(src, dst):
                try:
                    while True:
                        chunk = src.recv(65536)
                        if not chunk:
                            break
                        dst.sendall(chunk)
                except OSError:
                    pass
                finally:
                    with contextlib.suppress(OSError):
                        dst.shutdown(socket.SHUT_WR)

            t = threading.Thread(target=pipe, args=(upstream, self.connection), daemon=True)
            t.start()
            pipe(self.connection, upstream)
            t.join(timeout=5)
        finally:
            self.close_connection = True
            with contextlib.suppress(OSError):
                upstream.close()

    _CLASH_UA = ('clash', 'flclash', 'mihomo', 'verge', 'stash', 'nyanpasu', 'surfboard', 'karing', 'openclash', 'party')
    _URI_UA = ('v2ray', 'shadowrocket', 'nekobox', 'nekoray', 'streisand', 'quantumult', 'loon', 'v2box', 'passwall', 'ssrplus', 'hiddify', 'matsuri', 'sagernet', 'anxray')
    _SINGBOX_UA = ('sing-box', 'sfa/', 'sfi/', 'sfm/', 'sfx/')

    def _resolve_sub_format(self, entry, query_str):
        from urllib.parse import parse_qs
        q = {k.lower(): v[0].lower() for k, v in parse_qs(query_str or '').items() if v}
        flag = q.get('flag') or q.get('target') or q.get('type') or ''
        if flag in ('clash', 'flclash', 'meta', 'mihomo', 'stash'):
            return 'clash'
        if flag in ('v2ray', 'v2rayn', 'v2rayng', 'shadowrocket', 'base64', 'links', 'nekobox', 'streisand'):
            return 'b64'
        if flag in ('singbox', 'sing-box', 'sfa', 'sfi'):
            return 'singbox'
        if flag in ('raw', 'uri', 'plain'):
            return 'raw'

        ua = (self.headers.get('User-Agent') or '').lower()
        if entry == 'raw.txt':
            return 'raw'
        if entry == 'singbox.json':
            return 'singbox'
        if any(k in ua for k in self._SINGBOX_UA):
            return 'singbox'
        if entry in ('flclash.yaml', 'clash.yaml'):
            if any(k in ua for k in self._URI_UA):
                return 'b64'
            return 'clash'
        if entry in ('links.txt', 'v2ray.txt', 'shadowrocket.txt'):
            if any(k in ua for k in self._CLASH_UA):
                return 'clash'
            return 'b64'
        # entry in ('', 'sub') -> universal auto-adaptation by User-Agent
        if any(k in ua for k in self._CLASH_UA):
            return 'clash'
        return 'b64'

    def do_GET(self):
        try:
            split_url = urlsplit(self.path)
            req_path = split_url.path
            if self.headers.get('Upgrade', '').lower() == 'websocket':
                return self._proxy_websocket(req_path)
            sub_root = self.server.sub_root
            snap = (sub_root/'current').resolve(strict=True) if _is_managed_link(sub_root/'current') else (sub_root/'current')
            if not snap.is_dir():
                return self._reply(503, b'Unavailable\n')
            tokens = []
            for tname in ('token', 'legacy_token'):
                tfile = snap/tname
                if tfile.is_file():
                    val = tfile.read_text(encoding='utf-8').strip()
                    if TOKEN_RE.fullmatch(val):
                        tokens.append(val)
            entry = None
            for tok in tokens:
                base_prefix = '/s/' + tok
                prefix = base_prefix + '/'
                if req_path == base_prefix:
                    entry = ''
                    break
                if len(req_path) >= len(prefix) and hmac.compare_digest(req_path[:len(prefix)].encode(), prefix.encode()):
                    entry = req_path[len(prefix):]
                    break
            valid_entries = ('', 'sub', 'flclash.yaml', 'clash.yaml', 'links.txt',
                             'v2ray.txt', 'shadowrocket.txt', 'singbox.json', 'raw.txt', 'manifest.json')
            if entry not in valid_entries:
                return self._reply(404, b'Not found\n')
            meta = json.loads((snap/'meta.json').read_text(encoding='utf-8'))
            if entry == 'manifest.json':
                safe = {k: meta.get(k) for k in ('generation', 'nodeCount', 'yamlSha256', 'linksSha256', 'updatedAt')}
                return self._reply(200, json.dumps(safe).encode('utf-8'), 'application/json')
            if meta.get('verified') is not True or meta.get('nodeCount', 0) < 1:
                return self._reply(503, b'No verified nodes published\n')

            fmt = self._resolve_sub_format(entry, split_url.query)
            if fmt == 'clash':
                body = (snap/'clash.yaml').read_bytes()
                ctype = 'application/yaml; charset=utf-8'
            elif fmt == 'singbox':
                sb_file = snap/'singbox.json'
                body = sb_file.read_bytes() if sb_file.is_file() else (snap/'clash.yaml').read_bytes()
                ctype = 'application/json; charset=utf-8'
            elif fmt == 'b64':
                body = (snap/'links.b64').read_bytes()
                ctype = 'text/plain; charset=utf-8'
            else:
                body = (snap/'raw.txt').read_bytes()
                ctype = 'text/plain; charset=utf-8'
            extra = {'Profile-Update-Interval': '24'}
            title = meta.get('title', '')
            if isinstance(title, str) and title:
                extra['Profile-Title'] = 'base64:' + base64.b64encode(title.encode('utf-8')).decode('ascii')
                if fmt == 'clash':
                    extra['Content-Disposition'] = f"attachment; filename=\"flclash.yaml\"; filename*=UTF-8''{quote(title)}.yaml"
            info = meta.get('userinfo', '')
            if isinstance(info, str) and info and USERINFO_RE.fullmatch(info):
                extra['Subscription-Userinfo'] = info
            return self._reply(200, body, ctype, extra)
        except (OSError, ValueError, TypeError):
            return self._reply(503, b'Unavailable\n')

    do_HEAD = do_GET


def create_sub_server(sub_root=None, bind=None, port=None, cert=None, key=None):
    sub_root = Path(sub_root or (ROOT/'sub'))
    cfg = {}
    try:
        if (sub_root/'config.json').exists():
            cfg = json.loads((sub_root/'config.json').read_text(encoding='utf-8'))
    except (OSError, ValueError):
        cfg = {}
    bind_addr = bind or cfg.get('bind', '0.0.0.0')
    listen_port = int(port if port is not None else cfg.get('port', 20000))
    cert_file = cert if cert is not None else cfg.get('cert', '')
    key_file = key if key is not None else cfg.get('key', '')
    tls_ctx = None
    if cert_file and key_file:
        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_ctx.load_cert_chain(cert_file, key_file)
    return _SubHTTPServer((bind_addr, listen_port), _SubRequestHandler, sub_root, tls_context=tls_ctx)


CLOUDFLARED = Path('/opt/nodelite/cloudflared')
CF_URL_RE = re.compile(r'https://([a-z0-9-]+\.trycloudflare\.com)', re.IGNORECASE)


def ensure_cloudflared():
    if CLOUDFLARED.is_file() and os.access(CLOUDFLARED, os.X_OK):
        return CLOUDFLARED
    arch = detect_arch()
    cf_arch = {'amd64': 'amd64', 'arm64': 'arm64', 'armv7': 'arm', '386': '386'}[arch]
    url = f'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}'
    CLOUDFLARED.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = CLOUDFLARED.with_suffix('.tmp')
    checked(['curl', '-fL', '--proto', '=https', '--tlsv1.2', '--retry', '2',
             '--connect-timeout', '15', '--max-time', '240', url, '-o', str(tmp)], timeout=260)
    tmp.chmod(0o700)
    checked([tmp, '--version'])
    os.replace(tmp, CLOUDFLARED)
    return CLOUDFLARED


_CF_PROC = [None]


def _maintain_cf_tunnel(sub_root, listen_port):
    while True:
        try:
            cfg = json.loads((Path(sub_root)/'config.json').read_text(encoding='utf-8'))
        except Exception:
            cfg = {}
        if not cfg.get('cf_tunnel') or not CLOUDFLARED.is_file():
            time.sleep(5)
            continue
        env = dict(os.environ, GOMEMLIMIT='14MiB', GOGC='20')
        mode = cfg.get('cf_mode', 'quick')
        scheme = cfg.get('scheme', 'http')
        origin_url = f'{scheme}://127.0.0.1:{int(listen_port)}'
        cmd = [str(CLOUDFLARED), 'tunnel', '--no-autoupdate', '--protocol', 'http2', '--ha-connections', '1']
        if scheme == 'https':
            cmd.append('--no-tls-verify')
        if mode == 'named' and cfg.get('cf_token'):
            env['TUNNEL_TOKEN'] = cfg['cf_token']
            cmd.extend(['run'])
        else:
            cmd.extend(['--url', origin_url])
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            encoding='utf-8', errors='replace', env=env,
        )
        _CF_PROC[0] = proc
        try:
            for line in proc.stdout:
                if mode == 'quick':
                    m = CF_URL_RE.search(line)
                    if m:
                        domain = m.group(1).lower()
                        with contextlib.suppress(Exception):
                            cur = load_sub_config()
                            if cur.get('cf_domain') != domain:
                                cur['cf_domain'] = domain
                                write_json(Path(sub_root)/'config.json', cur)
                                sync_subscription(manage_service=False)
        finally:
            _CF_PROC[0] = None
            with contextlib.suppress(Exception):
                proc.terminate()
                proc.wait(timeout=3)
        time.sleep(3)


def enable_cf_tunnel(wait_seconds=25, mode='quick', cf_domain='', cf_token=''):
    """Configure Cloudflare rescue:
    - mode='named': Permanent Named Tunnel using user's Cloudflare Tunnel token + permanent domain
    - mode='cdn'  : Permanent Cloudflare CDN domain (Origin Rules -> public_port, 0 extra RAM)
    - mode='quick': Temporary trycloudflare.com tunnel (domain changes on restart)
    """
    if mode not in ('quick', 'named', 'cdn'):
        raise ValueError('Cloudflare 模式仅支持 quick、named 或 cdn')
    if mode == 'cdn':
        domain = valid_sni(cf_domain)
        with lock():
            cfg = load_sub_config()
            if not cfg:
                raise ValueError('请先开启在线订阅服务')
            cfg.update(cf_tunnel=False, cf_mode='cdn', cf_domain=domain, cf_token='')
            write_json(ROOT/'sub'/'config.json', cfg)
            sync_subscription(manage_service=False)
        run(['pkill', '-f', 'cloudflared'])
        return dict(cfg, urls=subscription_urls(cfg))

    if memory_info().get('MemAvailable', 100) < 32:
        raise RuntimeError('当前可用内存不足 32 MiB，无法再启动 cloudflared 守护进程；建议使用自有域名 CDN Origin Rules 回源（零额外内存）或先清理后台进程。')
    ensure_cloudflared()
    with lock():
        cfg = load_sub_config()
        if not cfg:
            raise ValueError('请先开启在线订阅服务')
        if mode == 'named':
            domain = valid_sni(cf_domain)
            tok = str(cf_token or '').strip()
            if len(tok) < 24 or any(c.isspace() for c in tok):
                raise ValueError('请提供有效的 Cloudflare 命名隧道 Token（在 Cloudflare Zero Trust → Networks → Tunnels 复制）')
            cfg.update(cf_tunnel=True, cf_mode='named', cf_domain=domain, cf_token=tok)
            write_json(ROOT/'sub'/'config.json', cfg)
            sync_subscription(manage_service=False)
        else:
            cfg.update(cf_tunnel=True, cf_mode='quick', cf_domain='', cf_token='')
            write_json(ROOT/'sub'/'config.json', cfg)
    run(['pkill', '-f', 'cloudflared'])
    service_name('restart', check=True, name=SUB_SERVICE)
    if mode == 'named':
        cur = load_sub_config()
        return dict(cur, urls=subscription_urls(cur))
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        cur = load_sub_config()
        if cur.get('cf_domain'):
            return dict(cur, urls=subscription_urls(cur))
        time.sleep(0.5)
    raise RuntimeError('Cloudflare 隧道启动超时，请检查 VPS 出站网络')


def serve_subscription_forever(sub_root=None):
    import signal
    with contextlib.suppress(ValueError, RuntimeError):
        threading.stack_size(131072)

    def _shutdown(signum, frame):
        if _CF_PROC[0] is not None:
            with contextlib.suppress(Exception):
                _CF_PROC[0].terminate()
        raise SystemExit(0)

    import gc
    with contextlib.suppress(ValueError, RuntimeError):
        threading.stack_size(131072)
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(Exception):
            signal.signal(sig, _shutdown)
    server = create_sub_server(sub_root=sub_root)
    sroot = Path(sub_root or (ROOT/'sub'))
    t = threading.Thread(target=_maintain_cf_tunnel, args=(sroot, server.server_port), daemon=True)
    t.start()
    gc.collect()
    server.serve_forever()


# ---------------- Transactional Core Upgrade ----------------

def current_core_version(binary=None):
    target = Path(binary or CORE)
    if not target.is_file():
        return ''
    r = run([target, 'version'])
    if r.returncode != 0:
        return ''
    first = (r.stdout or '').splitlines()
    if not first:
        return ''
    m = re.search(r'version\s+([0-9A-Za-z._-]+)', first[0])
    return m.group(1) if m else first[0].strip()


def _sha256_file_chunked(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().lower()


def upgrade_core(version=CORE_VERSION, sha256=None, archive_path=None, arch=None):
    """Download/verify sing-box tarball in 64KiB chunks, check config, atomically upgrade with verified rollback."""
    with lock():
        resolved_arch = arch or detect_arch()
        expected_hash = (sha256 or (CORE_HASHES.get(resolved_arch) if version == CORE_VERSION else '') or '').lower()
        if not re.fullmatch(r'[0-9a-f]{64}', expected_hash):
            raise ValueError(f'升级核心 v{version} ({resolved_arch}) 需要提供 64 位 SHA-256 校验值。')

        CORE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.upgrade-', dir=CORE.parent) as tmp:
            tmp_dir = Path(tmp)
            if archive_path:
                tar_path = Path(archive_path)
            else:
                tar_path = tmp_dir/'core.tar.gz'
                url = f'https://github.com/SagerNet/sing-box/releases/download/v{version}/sing-box-{version}-linux-{resolved_arch}.tar.gz'
                checked(['curl', '-fL', '--proto', '=https', '--tlsv1.2', '--retry', '2',
                         '--connect-timeout', '15', '--max-time', '240', url, '-o', str(tar_path)], timeout=260)

            actual_hash = _sha256_file_chunked(tar_path)
            if actual_hash != expected_hash:
                raise RuntimeError(f'核心安装包 SHA-256 校验不匹配（期望 {expected_hash[:12]}…，实际 {actual_hash[:12]}…），已中止升级。')

            member_name = f'sing-box-{version}-linux-{resolved_arch}/sing-box'
            staged_bin = tmp_dir/'sing-box.new'
            with tarfile.open(tar_path, mode='r:gz') as archive:
                try:
                    member = archive.getmember(member_name)
                except KeyError:
                    member = next((m for m in archive.getmembers() if m.isfile() and m.name.endswith('/sing-box')), None)
                if not member or not member.isfile():
                    raise RuntimeError('核心压缩包内未找到 sing-box 可执行文件。')
                src_stream = archive.extractfile(member)
                with staged_bin.open('wb') as dst_file:
                    shutil.copyfileobj(src_stream, dst_file, length=65536)
            staged_bin.chmod(0o700)

            ver_out = checked([staged_bin, 'version'])
            cfg_path = ROOT/'current'/'config.json'
            if cfg_path.exists():
                checked([staged_bin, 'check', '-c', cfg_path], env=core_env())

            old_version = current_core_version(CORE)
            backup_bin = CORE.parent/'sing-box.bak'
            had_old = CORE.is_file()
            if had_old:
                shutil.copy2(CORE, backup_bin)
                backup_bin.chmod(0o700)

            was_active = False
            try:
                was_active = service('status', check=False)
            except RuntimeError:
                was_active = False

            os.replace(staged_bin, CORE)
            nodes = load_state()['nodes']
            if nodes and was_active:
                try:
                    service('restart')
                    time.sleep(0.8)
                    if not service('status', check=False):
                        raise RuntimeError('新核心启动后退出')
                    for n in nodes:
                        probe = self_test(n)
                        if not probe['ok']:
                            raise RuntimeError(f"节点 {n['name']} 在新核心下自测失败：{probe['reason']}")
                except BaseException as err:
                    restored_ok = False
                    if had_old and backup_bin.is_file():
                        os.replace(backup_bin, CORE)
                        with contextlib.suppress(Exception):
                            service('restart')
                            time.sleep(0.8)
                            restored_ok = bool(service('status', check=False))
                    if restored_ok:
                        raise RuntimeError(f'新核心自测未通过，已自动回滚并确认旧核心（{old_version or "原版本"}）恢复运行：{err}') from err
                    raise RuntimeError(f'新核心自测未通过，且回滚旧核心后服务未能恢复运行，请立即运行 nl doctor 检查：{err}') from err

            return {
                'upgraded': True,
                'arch': resolved_arch,
                'previousVersion': old_version,
                'currentVersion': current_core_version(CORE) or version,
                'versionOutput': ver_out.splitlines()[0] if ver_out else version,
                'backup': str(backup_bin) if had_old else '',
            }


GITHUB_RAW_BASE = 'https://raw.githubusercontent.com/qingyechan/NodeLite/main/dist'


def _read_script_version(path):
    try:
        text = Path(path).read_text(encoding='utf-8')
        m = re.search(r"^VERSION\s*=\s*['\"]([^'\"]+)['\"]", text, re.MULTILINE)
        return m.group(1) if m else ''
    except OSError:
        return ''


def self_update_from_github(installer_url=None, sha256_url=None, installer_path=None, sha256_text=None, install_dir=None):
    """Download dist/nodelite.run and dist/nodelite.run.sha256 from GitHub, verify SHA-256, and hot-update scripts without dropping nodes."""
    import io
    with lock():
        target_dir = Path(install_dir or CORE.parent)
        target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        old_ver = _read_script_version(target_dir/'nodelite.py') or _read_script_version(Path(__file__).resolve().parent/'nodelite.py')
        resolved_installer_url = installer_url or f'{GITHUB_RAW_BASE}/nodelite.run'
        resolved_sha256_url = sha256_url or f'{GITHUB_RAW_BASE}/nodelite.run.sha256'

        with tempfile.TemporaryDirectory(prefix='.self-update-', dir=target_dir) as tmp:
            tmp_dir = Path(tmp)
            if sha256_text is None:
                sha_file = tmp_dir/'nodelite.run.sha256'
                checked(['curl', '-fsSL', '--proto', '=https', '--tlsv1.2', '--retry', '2',
                         '--connect-timeout', '10', '--max-time', '30', resolved_sha256_url, '-o', str(sha_file)], timeout=35)
                sha256_text = sha_file.read_text(encoding='utf-8')
            m_hash = re.search(r'\b([0-9a-fA-F]{64})\b', str(sha256_text or ''))
            if not m_hash:
                raise RuntimeError('未能从 GitHub 获取有效的 64 位 SHA-256 校验值。')
            expected_hash = m_hash.group(1).lower()

            if installer_path:
                run_file = Path(installer_path)
            else:
                run_file = tmp_dir/'nodelite.run'
                checked(['curl', '-fsSL', '--proto', '=https', '--tlsv1.2', '--retry', '2',
                         '--connect-timeout', '10', '--max-time', '90', resolved_installer_url, '-o', str(run_file)], timeout=100)

            actual_hash = _sha256_file_chunked(run_file)
            if actual_hash != expected_hash:
                raise RuntimeError(f'GitHub 安装包 SHA-256 校验不一致（期望 {expected_hash[:12]}…，实际 {actual_hash[:12]}…），已中止更新。')

            script_text = run_file.read_text(encoding='utf-8')
            m_payload = re.search(r"<<'PAYLOAD'[^\n]*\n(.*?)\nPAYLOAD\b", script_text, re.DOTALL)
            if not m_payload:
                raise RuntimeError('安装包格式不正确：未找到内嵌程序载荷。')

            raw_tar_gz = base64.b64decode(m_payload.group(1).encode('ascii'))
            stage_dir = tmp_dir/'staged'
            stage_dir.mkdir(mode=0o700, exist_ok=True)
            required_files = ('nodelite.py', 'runtime.py', 'protocols.py')
            with tarfile.open(fileobj=io.BytesIO(raw_tar_gz), mode='r:gz') as archive:
                for fname in required_files:
                    try:
                        member = archive.getmember(fname)
                    except KeyError as err:
                        raise RuntimeError(f'安装包内缺少必要文件：{fname}') from err
                    src = archive.extractfile(member)
                    if not src:
                        raise RuntimeError(f'无法读取安装包文件：{fname}')
                    out_file = stage_dir/fname
                    out_file.write_bytes(src.read())
                    out_file.chmod(0o700 if fname == 'nodelite.py' else 0o600)

            new_ver = _read_script_version(stage_dir/'nodelite.py')
            if not new_ver:
                raise RuntimeError('更新包内的 nodelite.py 版本号校验失败。')

            for fname in required_files:
                dst = target_dir/fname
                if dst.is_file():
                    shutil.copy2(dst, target_dir/(fname + '.bak'))
                os.replace(stage_dir/fname, dst)

            if (ROOT/'sub'/'config.json').exists():
                with contextlib.suppress(Exception):
                    sync_subscription(manage_service=True)

            return {
                'updated': True,
                'previousVersion': old_ver,
                'currentVersion': new_ver,
                'sha256': actual_hash,
                'installDir': str(target_dir),
            }


# ---------------- Legacy Service Inspection, Backup & Cleanup ----------------

def _service_unit_paths(name):
    return [
        Path(f'/etc/systemd/system/{name}.service'),
        Path(f'/etc/init.d/{name}'),
    ]


def inspect_legacy_services():
    """Inspect legacy NodePilot / older SubProgress / third-party services with explicit ownership."""
    results = []
    procs = list(_iter_proc_rss() or ())
    for name, paths in LEGACY_SERVICES.items():
        meta = LEGACY_SERVICE_META.get(name, {'ownership': 'subprogress', 'description': '旧版服务'})
        units = [str(u) for u in _service_unit_paths(name) if u.exists()]
        existing_paths = [p for p in paths if Path(p).exists()]
        active = False
        enabled = False
        with contextlib.suppress(RuntimeError):
            active = service_name('status', check=False, name=name)
            enabled = service_enabled_name(name)
        rss_kib = 0
        pids = []
        for pid, rss, cmd in procs:
            if '/opt/nodelite/' in cmd or '/opt/subprogress-lite/' in cmd:
                continue
            if name in cmd or any(p in cmd for p in paths) or (name == 'subprogress-sub' and 'subServer.py' in cmd):
                pids.append(pid)
                rss_kib += rss
        if units or existing_paths or active or enabled or pids:
            results.append({
                'name': name,
                'ownership': meta.get('ownership', 'subprogress'),
                'description': meta.get('description', '旧版服务'),
                'active': active,
                'enabled': enabled,
                'pids': pids,
                'rssKiB': rss_kib,
                'units': units,
                'paths': existing_paths,
            })
    return results


def cleanup_legacy_services(backup_root=None, recover_sub_token=True, stop_services=True, include_third_party=False):
    """Phase 1: Back up all target configs/units (abort on any error).
    Phase 2: Stop/disable only confirmed SubProgress-owned legacy services (unless include_third_party=True).
    """
    with lock():
        found = inspect_legacy_services()
        targets = [
            item for item in found
            if include_third_party or item.get('ownership', 'subprogress') == 'subprogress'
        ]
        skipped_third_party = [
            item['name'] for item in found
            if item.get('ownership') == 'third-party' and not include_third_party
        ]
        base = Path(backup_root or '/root')
        backup_dir = base/f'nodelite-legacy-backup-{int(time.time())}'
        backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

        # Phase 1: Mandatory backup before stopping anything. Any copy failure aborts immediately.
        copied = []
        for item in targets:
            name = item['name']
            svc_backup = backup_dir/name
            svc_backup.mkdir(mode=0o700, exist_ok=True)
            for p_str in item['units'] + item['paths']:
                src = Path(p_str)
                if not src.exists():
                    continue
                dst = svc_backup/src.name
                try:
                    if src.is_dir():
                        shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)
                    else:
                        shutil.copy2(src, dst)
                    if not dst.exists():
                        raise OSError(f'备份目标文件未生成：{dst}')
                    copied.append(str(src))
                except OSError as err:
                    raise RuntimeError(f'备份旧服务 {name} 的文件 {src} 失败，已停止清理，未停用任何服务：{err}') from err

        recovered_token = discover_legacy_sub_token()
        if recover_sub_token and recovered_token:
            ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
            (ROOT/'legacy_sub_token').write_text(recovered_token+'\n', encoding='utf-8')
            (ROOT/'legacy_sub_token').chmod(0o600)

        # Phase 2: Stop and disable only after backup succeeded completely.
        stopped = []
        if stop_services:
            for item in targets:
                name = item['name']
                with contextlib.suppress(RuntimeError):
                    service_name('stop', check=False, name=name)
                    enable_service_name(False, name=name)
                for pid in item.get('pids', []):
                    with contextlib.suppress(OSError):
                        os.kill(int(pid), 15)
                stopped.append(name)

        manifest = {
            'timestamp': int(time.time()),
            'servicesFound': found,
            'copiedPaths': copied,
            'stoppedServices': stopped,
            'skippedThirdParty': skipped_third_party,
            'recoveredSubToken': bool(recovered_token),
        }
        write_json(backup_dir/'manifest.json', manifest)
        return {
            'backupDir': str(backup_dir),
            'servicesFound': found,
            'stoppedServices': stopped,
            'skippedThirdParty': skipped_third_party,
            'recoveredSubToken': bool(recovered_token),
        }


# ---------------- Multi-Layer Connectivity & Direct Failure Diagnosis ----------------

def diagnose_network(run_public_loop=True):
    """Structured diagnosis separating VPS internal state, public loop, subscription, certs, and memory."""
    sys_info = {
        'os': platform.system(),
        'arch': platform.machine(),
        'init': init_system(),
        'coreVersion': current_core_version(),
        'memory': memory_info(),
        'runtimeMemory': runtime_memory_footprint(),
        'coreActive': service('status', check=False),
        'sshPorts': detect_ssh_ports(),
    }
    nodes = load_state()['nodes']
    config_ok = None
    config_err = ''
    if nodes and (ROOT/'current'/'config.json').exists():
        r = run([CORE, 'check', '-c', ROOT/'current'/'config.json'], env=core_env())
        config_ok = (r.returncode == 0)
        if not config_ok:
            config_err = (r.stderr or r.stdout)[-1200:]

    node_reports = []
    for n in nodes:
        entry = {
            'name': n['name'],
            'protocol': n['protocol'],
            'transport': PROTOCOLS[n['protocol']][1],
            'host': n['host'],
            'port': n['port'],
            'public_port': n['public_port'],
            'is_nat': n['port'] != n['public_port'],
            'stages': node_status_stages(n, core_active=sys_info['coreActive']),
        }
        if n.get('cert'):
            entry['certExpiry'] = check_cert_expiry(n['cert'])
        if sys_info['coreActive']:
            entry['localProbe'] = self_test(n, local=True)
            if run_public_loop:
                entry['publicLoopProbe'] = self_test(n, local=False)
        node_reports.append(entry)

    sub_cfg = load_sub_config()
    sub_status = {'configured': bool(sub_cfg), 'enabled': bool(sub_cfg.get('enabled'))}
    if sub_cfg.get('enabled'):
        sub_status.update(
            scheme=sub_cfg.get('scheme', 'http'),
            port=sub_cfg.get('port'),
            public_port=sub_cfg.get('public_port'),
            cf_mode=sub_cfg.get('cf_mode', ''),
            cf_domain=sub_cfg.get('cf_domain', ''),
            active=service_name('status', check=False, name=SUB_SERVICE),
            urls=subscription_urls(sub_cfg),
        )
        if sub_cfg.get('cert'):
            sub_status['certExpiry'] = check_cert_expiry(sub_cfg['cert'])
        try:
            sub_status['localHealth'] = check_sub_local(sub_cfg)
            sub_status['healthy'] = True
        except Exception as e:
            sub_status['healthy'] = False
            sub_status['error'] = str(e)

    legacy = inspect_legacy_services()
    return {
        'system': sys_info,
        'configValid': config_ok,
        'configError': config_err,
        'nodes': node_reports,
        'subscription': sub_status,
        'legacyServices': legacy,
        'recentLogs': recent_logs(12),
    }


def migrate_from_subprogress_lite(old_root=None, old_opt=None, start_services=True):
    """Migrate an existing /etc/subprogress-lite installation into /etc/nodelite preserving all credentials & tokens."""
    old_root = Path(old_root or '/etc/subprogress-lite')
    old_opt = Path(old_opt or '/opt/subprogress-lite')
    if (old_opt/'cloudflared').is_file() and not CLOUDFLARED.is_file():
        CLOUDFLARED.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copy2(old_opt/'cloudflared', CLOUDFLARED)
        CLOUDFLARED.chmod(0o700)

    if not old_root.is_dir() or _is_managed_link(ROOT/'current'):
        if start_services and (ROOT/'sub'/'config.json').exists():
            with contextlib.suppress(Exception):
                sync_subscription(manage_service=True)
        return {'migrated': False}

    old_current = old_root/'current'
    if not (_is_managed_link(old_current) or old_current.is_dir()):
        return {'migrated': False}

    active_rev = old_current.resolve().name
    old_sub_current = old_root/'sub'/'current'
    active_sub_rev = old_sub_current.resolve().name if (_is_managed_link(old_sub_current) or old_sub_current.is_dir()) else ''

    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    for item in old_root.iterdir():
        if item.name in ('current', 'manager.lock') or item.name.startswith('.current-'):
            continue
        dst = ROOT/item.name
        if item.is_dir():
            shutil.copytree(
                item, dst, symlinks=False, dirs_exist_ok=True,
                ignore=shutil.ignore_patterns('current', '.current-*'),
            )
        elif item.is_file():
            shutil.copy2(item, dst)
            dst.chmod(0o600)

    # Rewrite internal certificate paths from old_root to ROOT inside JSON files
    old_prefix = str(old_root).replace('\\', '/')
    new_prefix = str(ROOT).replace('\\', '/')
    for json_file in list(ROOT.rglob('*.json')):
        try:
            text = json_file.read_text(encoding='utf-8')
            if old_prefix in text or '/etc/subprogress-lite' in text:
                updated = text.replace(old_prefix, new_prefix).replace('/etc/subprogress-lite', new_prefix)
                json_file.write_text(updated, encoding='utf-8')
                json_file.chmod(0o600)
        except OSError:
            continue

    target_rev = ROOT/'releases'/active_rev
    if not target_rev.is_dir():
        raise RuntimeError(f'迁移失败：未找到目标配置版本目录 {target_rev}')
    switch_current(target_rev, ROOT/'current')

    if active_sub_rev and (ROOT/'sub'/'releases'/active_sub_rev).is_dir():
        switch_current(ROOT/'sub'/'releases'/active_sub_rev, ROOT/'sub'/'current')

    if start_services:
        cfg_file = ROOT/'current'/'config.json'
        if cfg_file.is_file() and CORE.is_file():
            checked([CORE, 'check', '-c', cfg_file], env=core_env())
        for old_svc in ('subprogress-lite-sub', 'subprogress-lite'):
            with contextlib.suppress(Exception):
                service_name('stop', check=False, name=old_svc)
                enable_service_name(False, name=old_svc)
            for u in _service_unit_paths(old_svc):
                u.unlink(missing_ok=True)
        run(['pkill', '-f', '/opt/subprogress-lite/'])
        if init_system() == 'systemd':
            with contextlib.suppress(Exception):
                checked(['systemctl', 'daemon-reload'])

        backup_target = old_root.with_name(f'{old_root.name}.migrated-{int(time.time())}')
        old_root.rename(backup_target)

        nodes = load_state()['nodes']
        if nodes:
            service('restart')
            enable_service(True)
        sub_cfg = load_sub_config()
        if sub_cfg.get('enabled'):
            install_sub_unit()
            sync_subscription(nodes, manage_service=True)

    return {
        'migrated': True,
        'nodeCount': len(load_state()['nodes']),
        'subEnabled': bool(load_sub_config().get('enabled')),
    }


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'serve-sub':
        serve_subscription_forever()
    elif len(sys.argv) > 1 and sys.argv[1] == 'migrate-old':
        print(json.dumps(migrate_from_subprogress_lite(), ensure_ascii=False))

