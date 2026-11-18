"""Protocol definitions shared by the terminal manager, exports and self-test.

Standard library only. No daemon, DNS database or subscription converter.
"""
import base64
import hashlib
import ipaddress
import json
import re
import secrets
import time
import uuid
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

PROTOCOLS = {
    'vless': ('VLESS Reality（推荐首选，无需域名）【只需 TCP 映射 — 没有 UDP 时必选】', 'tcp'),
    'trojan': ('Trojan TLS【只需 TCP 映射】', 'tcp'),
    'ss2022': ('Shadowsocks 2022【只需 TCP 映射】', 'tcp'),
    'vmess': ('VMess WebSocket（可配 Cloudflare 隧道救急）【只需 TCP 映射】', 'tcp'),
    'hysteria2': ('Hysteria2【必须商家有 UDP 映射；没有 UDP 请勿选，先用 1】', 'udp'),
    'tuic': ('TUIC v5【必须商家有 UDP 映射；没有 UDP 请勿选，先用 1】', 'udp'),
}

RESERVED_PORTS = {22}
TOKEN_RE = re.compile(r'^[A-Za-z0-9_-]{32,128}$')


def valid_host(value):
    value = str(value).strip().strip('[]')
    address = ipaddress.ip_address(value)
    internal = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', 'fc00::/7']
    if (address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local
            or any(address in ipaddress.ip_network(net) for net in internal)):
        raise ValueError('请填写商家提供的公网 IP；10.x、192.168.x 等内部地址不能用于跨设备连接')
    return str(address)


def valid_port(value):
    port = int(value)
    if port in RESERVED_PORTS or not (port in (80, 443) or 1024 <= port <= 65535):
        raise ValueError('端口支持 443（或 80）及 1024–65535；切勿填写 SSH 登录端口 22')
    return port


def valid_ssh_port(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError('SSH 端口需要在 1–65535 之间')
    return port


def valid_name(value):
    value = str(value).strip()
    if not value or len(value) > 80 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('名称需为 1–80 个字符，不能包含换行或控制字符')
    return value


def valid_sni(value):
    value = str(value).strip()
    if not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}', value):
        raise ValueError('域名格式不正确，例如 www.microsoft.com')
    return value.lower()


def valid_sub_host(value):
    value = str(value).strip().strip('[]')
    try:
        return valid_host(value)
    except ValueError:
        return valid_sni(value)


def valid_token(value):
    value = str(value).strip()
    if not TOKEN_RE.fullmatch(value):
        raise ValueError('订阅访问令牌需为 32–128 位字母、数字、下划线或连字符')
    return value


def new_token():
    return secrets.token_urlsafe(32)


def new_node(protocol, name, host, port, public_port=None, sni='www.microsoft.com', **extra):
    if protocol not in PROTOCOLS:
        raise ValueError('不支持此协议')
    return dict(id=secrets.token_hex(6), protocol=protocol, name=valid_name(name),
                host=valid_host(host), port=valid_port(port),
                public_port=valid_port(public_port if public_port is not None else port),
                sni=valid_sni(sni), uuid=str(uuid.uuid4()), password=secrets.token_urlsafe(24),
                ss_password=base64.b64encode(secrets.token_bytes(16)).decode(),
                short_id=secrets.token_hex(4), ws_path='/'+secrets.token_hex(8), **extra)


def inbound(n):
    p = n['protocol']
    item = dict(type={'ss2022': 'shadowsocks'}.get(p, p), tag=n['id'],
                listen='::' if ':' in n['host'] else '0.0.0.0', listen_port=n['port'])
    if p == 'vless':
        item.update(users=[dict(uuid=n['uuid'], flow='xtls-rprx-vision')], tls={
            'enabled': True, 'server_name': n['sni'], 'reality': {
                'enabled': True, 'handshake': {'server': n['sni'], 'server_port': 443},
                'private_key': n['private_key'], 'short_id': [n['short_id']]}})
    elif p in ('trojan', 'hysteria2', 'tuic'):
        user = {'password': n['password']}
        if p == 'tuic':
            user['uuid'] = n['uuid']
            item['congestion_control'] = 'cubic'
        item.update(users=[user], tls={'enabled': True, 'server_name': n['sni'],
                    'certificate_path': n['cert'], 'key_path': n['key']})
        if p in ('hysteria2', 'tuic'):
            item['tls']['alpn'] = ['h3']
    elif p == 'ss2022':
        item.update(method='2022-blake3-aes-128-gcm', password=n['ss_password'])
    elif p == 'vmess':
        item.update(users=[{'uuid': n['uuid'], 'alterId': 0}],
                    transport={'type': 'ws', 'path': n['ws_path'],
                               'max_early_data': 2048,
                               'early_data_header_name': 'Sec-WebSocket-Protocol'})
    return item


def server_config(nodes):
    return {'log': {'level': 'warn', 'timestamp': True},
            'inbounds': [inbound(n) for n in nodes],
            'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}


def outbound(n, local=False):
    p = n['protocol']
    cf = n.get('cf_domain', '') if (p == 'vmess' and not local) else ''
    cf_server = (n.get('cf_ip') or cf) if cf else ''
    o = dict(type={'ss2022': 'shadowsocks'}.get(p, p), tag='proxy',
             server=('::1' if ':' in n['host'] else '127.0.0.1') if local else (cf_server or n['host']),
             server_port=n['port'] if local else (443 if cf else n['public_port']))
    if p == 'vless':
        sec = n.get('security') or ('reality' if n.get('public_key') else 'none')
        net = (n.get('net') or 'tcp').lower()
        o['uuid'] = n['uuid']
        if net == 'tcp' and n.get('flow'):
            o['flow'] = n['flow']
        elif not n.get('external') and net == 'tcp':
            o['flow'] = 'xtls-rprx-vision'
        if sec == 'reality':
            o['tls'] = {
                'enabled': True, 'server_name': n['sni'],
                'utls': {'enabled': True, 'fingerprint': n.get('fp', 'chrome')},
                'reality': {'enabled': True, 'public_key': n['public_key'], 'short_id': n.get('short_id', '')},
            }
        elif sec == 'tls':
            tls_cfg = {
                'enabled': True, 'server_name': n['sni'],
                'insecure': bool(n.get('self_signed', False)),
                'utls': {'enabled': True, 'fingerprint': n.get('fp', 'chrome')},
            }
            if n.get('alpn'):
                tls_cfg['alpn'] = list(n['alpn'])
            o['tls'] = tls_cfg
        if net == 'ws':
            o['transport'] = {'type': 'ws', 'path': n.get('ws_path', '/'),
                              'headers': {'Host': n.get('ws_host') or n['sni']}}
        elif net == 'grpc':
            o['transport'] = {'type': 'grpc', 'service_name': n.get('service_name', '')}
    elif p in ('trojan', 'hysteria2', 'tuic'):
        o.update(password=n['password'], tls={'enabled': True, 'server_name': n['sni'],
                 'insecure': n.get('self_signed', True)})
        if p in ('hysteria2', 'tuic'):
            o['tls']['alpn'] = ['h3']
        if p == 'tuic':
            o.update(uuid=n['uuid'], congestion_control='cubic')
    elif p == 'ss2022':
        o.update(method=n.get('ss_method', '2022-blake3-aes-128-gcm'), password=n['ss_password'])
    else:
        net = (n.get('net') or 'ws').lower()
        host_hdr = cf or n.get('ws_host') or n['sni']
        o.update(uuid=n['uuid'], security=n.get('scy', 'auto'))
        if net == 'ws':
            ws_tr = {'type': 'ws', 'path': n.get('ws_path', '/'), 'headers': {'Host': host_hdr}}
            if not n.get('external'):
                ws_tr['max_early_data'] = 2048
                ws_tr['early_data_header_name'] = 'Sec-WebSocket-Protocol'
            o['transport'] = ws_tr
        elif net == 'grpc':
            o['transport'] = {'type': 'grpc', 'service_name': n.get('service_name') or n.get('ws_path', '')}
        if cf or n.get('tls_enabled'):
            tls_cfg = {'enabled': True, 'server_name': cf or n['sni']}
            if n.get('self_signed'):
                tls_cfg['insecure'] = True
            o['tls'] = tls_cfg
    if n.get('detour'):
        o['detour'] = n['detour']
    return o


def _b64_decode_padded(value):
    raw = str(value).strip()
    pad = (-len(raw)) % 4
    return base64.urlsafe_b64decode(raw + ('=' * pad))


def parse_node_uri(raw_uri, custom_name=None):
    """Parse a single-node URI (vless/vmess/hysteria2/hy2/tuic/trojan/ss) from another VPS."""
    text = str(raw_uri or '').strip()
    if not text or '://' not in text:
        raise ValueError('无效的节点分享链接，需以 vless://、vmess://、hysteria2://、hy2://、tuic://、trojan:// 或 ss:// 开头')
    scheme, _ = text.split('://', 1)
    scheme = scheme.lower()
    if scheme == 'vmess':
        body = text[len('vmess://'):].split('#', 1)[0].strip()
        try:
            data = json.loads(_b64_decode_padded(body).decode('utf-8'))
        except Exception as err:
            raise ValueError('VMess 链接 Base64 JSON 解析失败') from err
        host = valid_sub_host(data.get('add', ''))
        port = valid_port(data.get('port', 443))
        name = valid_name(custom_name or data.get('ps') or f'外部VMess-{host}:{port}')
        tls_on = str(data.get('tls', '')).lower() == 'tls'
        net = str(data.get('net') or 'tcp').lower()
        scy = str(data.get('scy') or 'auto')
        sni = data.get('sni') or data.get('host') or (host if not re.fullmatch(r'[0-9.:a-fA-F]+', host) else 'www.microsoft.com')
        ws_host = data.get('host') or sni
        insecure = str(data.get('allowInsecure', data.get('insecure', ''))).lower() in ('1', 'true')
        node = dict(
            id='ext-' + secrets.token_hex(5),
            external=True,
            protocol='vmess',
            name=name,
            host=host,
            port=port,
            public_port=port,
            sni=sni if re.fullmatch(r'[A-Za-z0-9.-]+', str(sni)) else 'www.microsoft.com',
            ws_host=ws_host,
            net=net,
            scy=scy,
            uuid=str(uuid.UUID(str(data.get('id', '')))),
            ws_path=str(data.get('path') or '/'),
            service_name=str(data.get('path') or ''),
            tls_enabled=tls_on,
            self_signed=insecure,
            raw_uri=text if not custom_name else '',
        )
        return node

    parsed = urlsplit(text)
    if not parsed.hostname or not parsed.port:
        raise ValueError('节点链接缺少服务器地址或端口')
    host = valid_sub_host(parsed.hostname)
    port = valid_port(parsed.port)
    frag_name = unquote(parsed.fragment or '').strip()
    q = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}

    if scheme == 'vless':
        user_uuid = str(uuid.UUID(unquote(parsed.username or '')))
        pbk = q.get('pbk', '')
        sec = q.get('security', '').lower() or ('reality' if pbk else ('tls' if q.get('sni') else 'none'))
        if sec == 'reality' and not pbk:
            raise ValueError('VLESS Reality 链接缺少 pbk 公钥参数')
        net = q.get('type', 'tcp').lower()
        sni = q.get('sni') or q.get('host') or (host if not re.fullmatch(r'[0-9.:a-fA-F]+', host) else 'www.microsoft.com')
        insecure = q.get('allowInsecure', q.get('insecure', '0')) in ('1', 'true', 'True')
        alpn = [x.strip() for x in q.get('alpn', '').split(',') if x.strip()]
        name = valid_name(custom_name or frag_name or f'外部VLESS-{host}:{port}')
        return dict(
            id='ext-' + secrets.token_hex(5),
            external=True,
            protocol='vless',
            name=name,
            host=host,
            port=port,
            public_port=port,
            sni=sni,
            uuid=user_uuid,
            security=sec,
            net=net,
            flow=q.get('flow', 'xtls-rprx-vision' if (sec == 'reality' and net == 'tcp') else ''),
            public_key=pbk,
            short_id=q.get('sid', ''),
            fp=q.get('fp', 'chrome'),
            ws_path=q.get('path', '/'),
            ws_host=q.get('host', ''),
            service_name=q.get('serviceName', ''),
            alpn=alpn,
            self_signed=insecure,
            raw_uri=text if not custom_name else '',
        )

    if scheme in ('hysteria2', 'hy2', 'trojan'):
        proto = 'hysteria2' if scheme in ('hysteria2', 'hy2') else 'trojan'
        password = unquote(parsed.username or '')
        if not password:
            raise ValueError(f'{proto} 节点链接缺少连接密码')
        sni = q.get('sni') or q.get('peer') or 'www.microsoft.com'
        insecure = q.get('insecure', q.get('allowInsecure', '1')) in ('1', 'true', 'True')
        name = valid_name(custom_name or frag_name or f'外部{proto.upper()}-{host}:{port}')
        return dict(
            id='ext-' + secrets.token_hex(5),
            external=True,
            protocol=proto,
            name=name,
            host=host,
            port=port,
            public_port=port,
            sni=sni,
            password=password,
            self_signed=insecure,
            raw_uri=text if not custom_name else '',
        )

    if scheme == 'tuic':
        user_uuid = str(uuid.UUID(unquote(parsed.username or '')))
        password = unquote(parsed.password or '')
        if not password:
            raise ValueError('TUIC 节点链接缺少密码')
        sni = q.get('sni') or 'www.microsoft.com'
        insecure = q.get('allow_insecure', q.get('insecure', q.get('allowInsecure', '1'))) in ('1', 'true', 'True')
        name = valid_name(custom_name or frag_name or f'外部TUIC-{host}:{port}')
        return dict(
            id='ext-' + secrets.token_hex(5),
            external=True,
            protocol='tuic',
            name=name,
            host=host,
            port=port,
            public_port=port,
            sni=sni,
            uuid=user_uuid,
            password=password,
            self_signed=insecure,
            raw_uri=text if not custom_name else '',
        )

    if scheme == 'ss':
        raw_user = unquote(parsed.username or '')
        if ':' in raw_user:
            method, ss_pass = raw_user.split(':', 1)
        else:
            try:
                decoded = _b64_decode_padded(raw_user).decode('utf-8')
                method, ss_pass = decoded.split(':', 1)
            except Exception as err:
                raise ValueError('Shadowsocks 链接认证字段解析失败') from err
        name = valid_name(custom_name or frag_name or f'外部SS-{host}:{port}')
        return dict(
            id='ext-' + secrets.token_hex(5),
            external=True,
            protocol='ss2022',
            name=name,
            host=host,
            port=port,
            public_port=port,
            sni='www.microsoft.com',
            ss_method=method,
            ss_password=ss_pass,
            raw_uri=text if not custom_name else '',
        )

    raise ValueError(f'暂不支持该节点协议：{scheme}')


def uri(n):
    if n.get('external') and n.get('raw_uri'):
        return n['raw_uri']
    p = n['protocol']
    host = '['+n['host']+']' if ':' in n['host'] else n['host']
    address = host+':'+str(n['public_port'])
    q = {'sni': n['sni']}
    if p == 'vless':
        auth = n['uuid']
        sec = n.get('security') or ('reality' if n.get('public_key') else 'none')
        net = (n.get('net') or 'tcp').lower()
        q = {'encryption': 'none', 'security': sec, 'type': net}
        if net == 'tcp':
            q['headerType'] = 'none'
            if n.get('flow'):
                q['flow'] = n['flow']
            elif not n.get('external'):
                q['flow'] = 'xtls-rprx-vision'
        elif net == 'ws':
            q['path'] = n.get('ws_path', '/')
            if n.get('ws_host'):
                q['host'] = n['ws_host']
        elif net == 'grpc' and n.get('service_name'):
            q['serviceName'] = n['service_name']
        if sec in ('reality', 'tls'):
            q['sni'] = n['sni']
            q['fp'] = n.get('fp', 'chrome')
        if sec == 'reality':
            q['pbk'] = n['public_key']
            q['sid'] = n.get('short_id', '')
        elif sec == 'tls' and n.get('self_signed'):
            q['allowInsecure'] = '1'
    elif p == 'vmess':
        cf = n.get('cf_domain', '')
        cf_server = (n.get('cf_ip') or cf) if cf else ''
        tls_on = bool(cf or n.get('tls_enabled'))
        net = (n.get('net') or 'ws').lower()
        ws_host = cf or n.get('ws_host') or n['sni']
        value = dict(v='2', ps=n['name'], add=cf_server or n['host'], port='443' if cf else str(n['public_port']),
                     id=n['uuid'], aid='0', scy=n.get('scy', 'auto'), net=net, type='none',
                     host=ws_host if net == 'ws' else '', path=n.get('ws_path', '/') if net in ('ws', 'grpc') else '',
                     tls='tls' if tls_on else '')
        if tls_on:
            value['sni'] = cf or n['sni']
            value['fp'] = 'chrome'
        return 'vmess://'+base64.b64encode(json.dumps(value, ensure_ascii=False).encode()).decode()
    elif p == 'ss2022':
        method = n.get('ss_method', '2022-blake3-aes-128-gcm')
        auth = base64.urlsafe_b64encode((method+':'+n['ss_password']).encode()).decode().rstrip('=')
        return 'ss://'+auth+'@'+address+'#'+quote(n['name'], safe='')
    else:
        auth = quote(n['password'], safe='')
        if p == 'tuic':
            auth = n['uuid']+':'+auth
            q.update(congestion_control='cubic', alpn='h3', udp_relay_mode='native')
        elif p == 'hysteria2':
            q.update(alpn='h3')
        elif p == 'trojan':
            q.update(security='tls', type='tcp', headerType='none')
        if n.get('self_signed', True):
            q['insecure'] = '1'
            q['allowInsecure'] = '1'
            if p == 'tuic':
                q['allow_insecure'] = '1'
    return p+'://'+auth+'@'+address+'?'+urlencode(q)+'#'+quote(n['name'], safe='')


def clash_proxy(n):
    p = n['protocol']
    cf = n.get('cf_domain', '') if p == 'vmess' else ''
    cf_server = (n.get('cf_ip') or cf) if cf else ''
    o = dict(name=n['name'], type={'ss2022': 'ss'}.get(p, p), server=cf_server or n['host'],
             port=443 if cf else n['public_port'], udp=True)
    if p == 'vless':
        sec = n.get('security') or ('reality' if n.get('public_key') else 'none')
        net = (n.get('net') or 'tcp').lower()
        o.update(uuid=n['uuid'], network=net, tls=sec in ('reality', 'tls'),
                 **{'skip-cert-verify': bool(n.get('self_signed', False))})
        if net == 'tcp':
            flow = n.get('flow') if n.get('external') else 'xtls-rprx-vision'
            if flow:
                o['flow'] = flow
        elif net == 'ws':
            o['ws-opts'] = {'path': n.get('ws_path', '/'),
                            'headers': {'Host': n.get('ws_host') or n['sni']}}
        elif net == 'grpc':
            o['grpc-opts'] = {'grpc-service-name': n.get('service_name', '')}
        if sec in ('reality', 'tls'):
            o['servername'] = n['sni']
            o['client-fingerprint'] = n.get('fp', 'chrome')
            if n.get('alpn'):
                o['alpn'] = list(n['alpn'])
        if sec == 'reality':
            o['reality-opts'] = {'public-key': n['public_key'], 'short-id': n.get('short_id', '')}
    elif p in ('trojan', 'hysteria2', 'tuic'):
        o.update(password=n['password'], sni=n['sni'], **{'skip-cert-verify': n.get('self_signed', True)})
        if p == 'trojan':
            o['network'] = 'tcp'
        elif p == 'hysteria2':
            o['alpn'] = ['h3']
        elif p == 'tuic':
            o.update(uuid=n['uuid'], **{'congestion-controller': 'cubic', 'alpn': ['h3'], 'udp-relay-mode': 'native'})
    elif p == 'ss2022':
        o.update(cipher=n.get('ss_method', '2022-blake3-aes-128-gcm'), password=n['ss_password'])
    else:
        net = (n.get('net') or 'ws').lower()
        host_hdr = cf or n.get('ws_host') or n['sni']
        o.update(uuid=n['uuid'], alterId=0, cipher=n.get('scy', 'auto'), network=net,
                 tls=bool(cf or n.get('tls_enabled')))
        if net == 'ws':
            o['ws-opts'] = {'path': n.get('ws_path', '/'), 'headers': {'Host': host_hdr}}
        elif net == 'grpc':
            o['grpc-opts'] = {'grpc-service-name': n.get('service_name') or n.get('ws_path', '')}
        if cf or n.get('tls_enabled'):
            o.update(servername=cf or n['sni'],
                     **{'skip-cert-verify': bool(n.get('self_signed', False)), 'client-fingerprint': 'chrome'})
    if n.get('dialer_proxy'):
        o['dialer-proxy'] = n['dialer_proxy']
    return o


AIRPORT_DNS_CONFIG = {
    'enable': True,
    'ipv6': False,
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'use-hosts': True,
    'nameserver-policy': {
        '+.google.com': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.googleapis.com': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.googleapis.cn': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.googlevideo.com': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.gstatic.com': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.youtube.com': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.youtu.be': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.facebook.com': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.twitter.com': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.x.com': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.github.com': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.githubusercontent.com': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.openai.com': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.chatgpt.com': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.anthropic.com': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.claude.ai': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.grok.com': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.x.ai': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.discord.com': 'https://dns.cloudflare.com/dns-query#节点选择',
        '+.telegram.org': 'https://dns.cloudflare.com/dns-query#节点选择',
    },
    'proxy-server-nameserver': ['223.5.5.5', '119.29.29.29'],
    'nameserver': [
        'https://doh.pub/dns-query',
        'https://dns.alidns.com/dns-query',
        'tls://dot.pub:853',
        'tls://dns.alidns.com:853',
    ],
    'fallback': [
        'https://dns.cloudflare.com/dns-query#节点选择',
        'https://dns.google/dns-query#节点选择',
        'tls://1.1.1.1:853#节点选择',
        'tls://8.8.8.8:853#节点选择',
    ],
    'fallback-filter': {
        'geoip': True,
        'geoip-code': 'CN',
        'ipcidr': [
            '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
            '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
            '224.0.0.0/4', '240.0.0.0/4',
        ],
        'domain': [
            '+.google.com', '+.facebook.com', '+.youtube.com',
            '+.githubusercontent.com', '+.googlevideo.com', '+.googleapis.cn',
        ],
    },
    'fake-ip-filter': [
        '*.lan', '*.local', '*.localhost', '*.test',
        'localhost.ptlogin2.qq.com', '+.stun.*.*', '+.stun.*.*.*', '+.stun.*.*.*.*',
        'lens.l.google.com', '*.srv.nintendo.net', '+.stun.playstation.net',
        'xbox.*.*.microsoft.com', '*.*.xboxlive.com',
        '+.msftncsi.com', '+.msftconnecttest.com',
    ],
}

# Standard commercial airport rule template (adapted from mainstream Clash/Mihomo airport configs)
CHINA_DIRECT_RULES = (
    'DOMAIN,services.googleapis.cn,节点选择',
    'DOMAIN-SUFFIX,googleapis.cn,节点选择',
    'DOMAIN,xn--ngstr-lra8j.com,节点选择',
    'DOMAIN,safebrowsing.urlsec.qq.com,DIRECT',
    'DOMAIN,safebrowsing.googleapis.com,DIRECT',
    'DOMAIN,captive.apple.com,DIRECT',
    'DOMAIN,cn.bing.com,DIRECT',
    'DOMAIN-SUFFIX,local,DIRECT',
    'DOMAIN-SUFFIX,localhost,DIRECT',
    'DOMAIN-SUFFIX,lan,DIRECT',
    'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
    'IP-CIDR,17.0.0.0/8,DIRECT,no-resolve',
    'IP-CIDR,100.64.0.0/10,DIRECT,no-resolve',
    'IP-CIDR,127.0.0.0/8,DIRECT,no-resolve',
    'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
    'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
    'IP-CIDR,198.18.0.0/16,DIRECT,no-resolve',
    'IP-CIDR,224.0.0.0/4,DIRECT,no-resolve',
    'IP-CIDR6,::1/128,DIRECT,no-resolve',
    'IP-CIDR6,fc00::/7,DIRECT,no-resolve',
    'IP-CIDR6,fe80::/10,DIRECT,no-resolve',
    'DOMAIN-SUFFIX,apps.apple.com,节点选择',
    'DOMAIN-SUFFIX,blobstore.apple.com,节点选择',
    'DOMAIN,testflight.apple.com,节点选择',
    'DOMAIN,sandbox.itunes.apple.com,节点选择',
    'DOMAIN-SUFFIX,mzstatic.com,DIRECT',
    'DOMAIN-SUFFIX,itunes.apple.com,DIRECT',
    'DOMAIN-SUFFIX,icloud.com,DIRECT',
    'DOMAIN-SUFFIX,icloud-content.com,DIRECT',
    'DOMAIN-SUFFIX,me.com,DIRECT',
    'DOMAIN-SUFFIX,aaplimg.com,DIRECT',
    'DOMAIN-SUFFIX,cdn20.com,DIRECT',
    'DOMAIN-SUFFIX,cdn-apple.com,DIRECT',
    'DOMAIN-SUFFIX,akadns.net,DIRECT',
    'DOMAIN-SUFFIX,akamaiedge.net,DIRECT',
    'DOMAIN-SUFFIX,edgekey.net,DIRECT',
    'DOMAIN-SUFFIX,mwcloudcdn.com,DIRECT',
    'DOMAIN-SUFFIX,mwcname.com,DIRECT',
    'DOMAIN-SUFFIX,apple.com,DIRECT',
    'DOMAIN-SUFFIX,apple.com.cn,DIRECT',
    'DOMAIN-SUFFIX,icloud.com.cn,DIRECT',
    'DOMAIN-SUFFIX,apple-cloudkit.com,DIRECT',
    'DOMAIN-SUFFIX,apple-mapkit.com,DIRECT',
    'DOMAIN-KEYWORD,baidu,DIRECT',
    'DOMAIN-KEYWORD,alibaba,DIRECT',
    'DOMAIN-KEYWORD,alicdn,DIRECT',
    'DOMAIN-KEYWORD,aliyun,DIRECT',
    'DOMAIN-KEYWORD,alipay,DIRECT',
    'DOMAIN-KEYWORD,taobao,DIRECT',
    'DOMAIN-KEYWORD,qianwen,DIRECT',
    'DOMAIN-KEYWORD,tongyi,DIRECT',
    'DOMAIN-KEYWORD,tencent,DIRECT',
    'DOMAIN-KEYWORD,bilibili,DIRECT',
    'DOMAIN-KEYWORD,weibo,DIRECT',
    'DOMAIN-KEYWORD,douyin,DIRECT',
    'DOMAIN-KEYWORD,bytedance,DIRECT',
    'DOMAIN-KEYWORD,xiaomi,DIRECT',
    'DOMAIN-KEYWORD,huawei,DIRECT',
    'DOMAIN-KEYWORD,netease,DIRECT',
    'DOMAIN-KEYWORD,meituan,DIRECT',
    'DOMAIN-KEYWORD,pinduoduo,DIRECT',
    'DOMAIN-KEYWORD,kuaishou,DIRECT',
    'DOMAIN-KEYWORD,jingdong,DIRECT',
    'DOMAIN-KEYWORD,officecdn,DIRECT',
    'DOMAIN-SUFFIX,qianwen.com,DIRECT',
    'DOMAIN-SUFFIX,tongyi.com,DIRECT',
    'DOMAIN-SUFFIX,qwen.ai,DIRECT',
    'DOMAIN-SUFFIX,deepseek.com,DIRECT',
    'DOMAIN-SUFFIX,kimi.com,DIRECT',
    'DOMAIN-SUFFIX,moonshot.cn,DIRECT',
    'DOMAIN-SUFFIX,doubao.com,DIRECT',
    'DOMAIN-SUFFIX,volces.com,DIRECT',
    'DOMAIN-SUFFIX,volcengine.com,DIRECT',
    'DOMAIN-SUFFIX,zhipuai.cn,DIRECT',
    'DOMAIN-SUFFIX,chatglm.cn,DIRECT',
    'DOMAIN-SUFFIX,bigmodel.cn,DIRECT',
    'DOMAIN-SUFFIX,minimaxi.com,DIRECT',
    'DOMAIN-SUFFIX,hailuoai.com,DIRECT',
    'DOMAIN-SUFFIX,baichuan-ai.com,DIRECT',
    'DOMAIN-SUFFIX,stepfun.com,DIRECT',
    'DOMAIN-SUFFIX,metaso.cn,DIRECT',
    'DOMAIN-SUFFIX,126.com,DIRECT',
    'DOMAIN-SUFFIX,126.net,DIRECT',
    'DOMAIN-SUFFIX,127.net,DIRECT',
    'DOMAIN-SUFFIX,163.com,DIRECT',
    'DOMAIN-SUFFIX,1688.com,DIRECT',
    'DOMAIN-SUFFIX,360buyimg.com,DIRECT',
    'DOMAIN-SUFFIX,36kr.com,DIRECT',
    'DOMAIN-SUFFIX,acfun.tv,DIRECT',
    'DOMAIN-SUFFIX,air-matters.com,DIRECT',
    'DOMAIN-SUFFIX,aixifan.com,DIRECT',
    'DOMAIN-SUFFIX,amap.com,DIRECT',
    'DOMAIN-SUFFIX,autonavi.com,DIRECT',
    'DOMAIN-SUFFIX,bdimg.com,DIRECT',
    'DOMAIN-SUFFIX,bdstatic.com,DIRECT',
    'DOMAIN-SUFFIX,baidupcs.com,DIRECT',
    'DOMAIN-SUFFIX,bilibili.com,DIRECT',
    'DOMAIN-SUFFIX,bilivideo.com,DIRECT',
    'DOMAIN-SUFFIX,hdslb.com,DIRECT',
    'DOMAIN-SUFFIX,biliapi.net,DIRECT',
    'DOMAIN-SUFFIX,byteimg.com,DIRECT',
    'DOMAIN-SUFFIX,ibytedtos.com,DIRECT',
    'DOMAIN-SUFFIX,zijieapi.com,DIRECT',
    'DOMAIN-SUFFIX,volccdn.com,DIRECT',
    'DOMAIN-SUFFIX,caiyunapp.com,DIRECT',
    'DOMAIN-SUFFIX,clouddn.com,DIRECT',
    'DOMAIN-SUFFIX,cnbeta.com,DIRECT',
    'DOMAIN-SUFFIX,cnbetacdn.com,DIRECT',
    'DOMAIN-SUFFIX,cnblogs.com,DIRECT',
    'DOMAIN-SUFFIX,cootekservice.com,DIRECT',
    'DOMAIN-SUFFIX,csdn.net,DIRECT',
    'DOMAIN-SUFFIX,ctrip.com,DIRECT',
    'DOMAIN-SUFFIX,dgtle.com,DIRECT',
    'DOMAIN-SUFFIX,dianping.com,DIRECT',
    'DOMAIN-SUFFIX,dingtalk.com,DIRECT',
    'DOMAIN-SUFFIX,douban.com,DIRECT',
    'DOMAIN-SUFFIX,doubanio.com,DIRECT',
    'DOMAIN-SUFFIX,duokan.com,DIRECT',
    'DOMAIN-SUFFIX,easou.com,DIRECT',
    'DOMAIN-SUFFIX,ele.me,DIRECT',
    'DOMAIN-SUFFIX,feishu.cn,DIRECT',
    'DOMAIN-SUFFIX,feng.com,DIRECT',
    'DOMAIN-SUFFIX,fir.im,DIRECT',
    'DOMAIN-SUFFIX,frdic.com,DIRECT',
    'DOMAIN-SUFFIX,g-cores.com,DIRECT',
    'DOMAIN-SUFFIX,gitee.com,DIRECT',
    'DOMAIN-SUFFIX,godic.net,DIRECT',
    'DOMAIN-SUFFIX,gtimg.com,DIRECT',
    'DOMAIN-SUFFIX,hongxiu.com,DIRECT',
    'DOMAIN-SUFFIX,hxcdn.net,DIRECT',
    'DOMAIN-SUFFIX,iciba.com,DIRECT',
    'DOMAIN-SUFFIX,ifeng.com,DIRECT',
    'DOMAIN-SUFFIX,ifengimg.com,DIRECT',
    'DOMAIN-SUFFIX,ipip.net,DIRECT',
    'DOMAIN-SUFFIX,iqiyi.com,DIRECT',
    'DOMAIN-SUFFIX,jd.com,DIRECT',
    'DOMAIN-SUFFIX,jianshu.com,DIRECT',
    'DOMAIN-SUFFIX,knewone.com,DIRECT',
    'DOMAIN-SUFFIX,le.com,DIRECT',
    'DOMAIN-SUFFIX,lecloud.com,DIRECT',
    'DOMAIN-SUFFIX,lemicp.com,DIRECT',
    'DOMAIN-SUFFIX,luoo.net,DIRECT',
    'DOMAIN-SUFFIX,meituan.com,DIRECT',
    'DOMAIN-SUFFIX,meituan.net,DIRECT',
    'DOMAIN-SUFFIX,mi.com,DIRECT',
    'DOMAIN-SUFFIX,miaopai.com,DIRECT',
    'DOMAIN-SUFFIX,copilot.microsoft.com,节点选择',
    'DOMAIN-SUFFIX,microsoft.com,DIRECT',
    'DOMAIN-SUFFIX,microsoftonline.com,DIRECT',
    'DOMAIN-SUFFIX,miui.com,DIRECT',
    'DOMAIN-SUFFIX,miwifi.com,DIRECT',
    'DOMAIN-SUFFIX,mob.com,DIRECT',
    'DOMAIN-SUFFIX,msn.com,DIRECT',
    'DOMAIN-SUFFIX,myqcloud.com,DIRECT',
    'DOMAIN-SUFFIX,netease.com,DIRECT',
    'DOMAIN-SUFFIX,office.com,DIRECT',
    'DOMAIN-SUFFIX,office365.com,DIRECT',
    'DOMAIN-SUFFIX,oschina.net,DIRECT',
    'DOMAIN-SUFFIX,ppsimg.com,DIRECT',
    'DOMAIN-SUFFIX,pstatp.com,DIRECT',
    'DOMAIN-SUFFIX,qcloud.com,DIRECT',
    'DOMAIN-SUFFIX,qdaily.com,DIRECT',
    'DOMAIN-SUFFIX,qdmm.com,DIRECT',
    'DOMAIN-SUFFIX,qhimg.com,DIRECT',
    'DOMAIN-SUFFIX,qhres.com,DIRECT',
    'DOMAIN-SUFFIX,qidian.com,DIRECT',
    'DOMAIN-SUFFIX,qihucdn.com,DIRECT',
    'DOMAIN-SUFFIX,qiniu.com,DIRECT',
    'DOMAIN-SUFFIX,qiniucdn.com,DIRECT',
    'DOMAIN-SUFFIX,qiyipic.com,DIRECT',
    'DOMAIN-SUFFIX,qpic.cn,DIRECT',
    'DOMAIN-SUFFIX,qq.com,DIRECT',
    'DOMAIN-SUFFIX,qqurl.com,DIRECT',
    'DOMAIN-SUFFIX,ruguoapp.com,DIRECT',
    'DOMAIN-SUFFIX,segmentfault.com,DIRECT',
    'DOMAIN-SUFFIX,sina.com,DIRECT',
    'DOMAIN-SUFFIX,sina.com.cn,DIRECT',
    'DOMAIN-SUFFIX,sinaapp.com,DIRECT',
    'DOMAIN-SUFFIX,sinaimg.cn,DIRECT',
    'DOMAIN-SUFFIX,smzdm.com,DIRECT',
    'DOMAIN-SUFFIX,snapdrop.net,DIRECT',
    'DOMAIN-SUFFIX,snssdk.com,DIRECT',
    'DOMAIN-SUFFIX,sogou.com,DIRECT',
    'DOMAIN-SUFFIX,sogoucdn.com,DIRECT',
    'DOMAIN-SUFFIX,sohu.com,DIRECT',
    'DOMAIN-SUFFIX,soku.com,DIRECT',
    'DOMAIN-SUFFIX,speedtest.net,DIRECT',
    'DOMAIN-SUFFIX,sspai.com,DIRECT',
    'DOMAIN-SUFFIX,suning.com,DIRECT',
    'DOMAIN-SUFFIX,taobao.com,DIRECT',
    'DOMAIN-SUFFIX,tencent.com,DIRECT',
    'DOMAIN-SUFFIX,tenpay.com,DIRECT',
    'DOMAIN-SUFFIX,tianyancha.com,DIRECT',
    'DOMAIN-SUFFIX,tmall.com,DIRECT',
    'DOMAIN-SUFFIX,toutiao.com,DIRECT',
    'DOMAIN-SUFFIX,tudou.com,DIRECT',
    'DOMAIN-SUFFIX,umetrip.com,DIRECT',
    'DOMAIN-SUFFIX,upaiyun.com,DIRECT',
    'DOMAIN-SUFFIX,upyun.com,DIRECT',
    'DOMAIN-SUFFIX,veryzhun.com,DIRECT',
    'DOMAIN-SUFFIX,vmall.com,DIRECT',
    'DOMAIN-SUFFIX,weather.com,DIRECT',
    'DOMAIN-SUFFIX,wechat.com,DIRECT',
    'DOMAIN-SUFFIX,servicewechat.com,DIRECT',
    'DOMAIN-SUFFIX,weibo.com,DIRECT',
    'DOMAIN-SUFFIX,weibocdn.com,DIRECT',
    'DOMAIN-SUFFIX,weixin.com,DIRECT',
    'DOMAIN-SUFFIX,weixin.qq.com,DIRECT',
    'DOMAIN-SUFFIX,windows.com,DIRECT',
    'DOMAIN-SUFFIX,windowsupdate.com,DIRECT',
    'DOMAIN-SUFFIX,wps.cn,DIRECT',
    'DOMAIN-SUFFIX,xiami.com,DIRECT',
    'DOMAIN-SUFFIX,xiami.net,DIRECT',
    'DOMAIN-SUFFIX,xiaohongshu.com,DIRECT',
    'DOMAIN-SUFFIX,xhscdn.com,DIRECT',
    'DOMAIN-SUFFIX,xiaomicp.com,DIRECT',
    'DOMAIN-SUFFIX,ximalaya.com,DIRECT',
    'DOMAIN-SUFFIX,xmcdn.com,DIRECT',
    'DOMAIN-SUFFIX,xunlei.com,DIRECT',
    'DOMAIN-SUFFIX,yangkeduo.com,DIRECT',
    'DOMAIN-SUFFIX,yeah.net,DIRECT',
    'DOMAIN-SUFFIX,yhd.com,DIRECT',
    'DOMAIN-SUFFIX,yihaodianimg.com,DIRECT',
    'DOMAIN-SUFFIX,yinxiang.com,DIRECT',
    'DOMAIN-SUFFIX,ykimg.com,DIRECT',
    'DOMAIN-SUFFIX,youdao.com,DIRECT',
    'DOMAIN-SUFFIX,youku.com,DIRECT',
    'DOMAIN-SUFFIX,zealer.com,DIRECT',
    'DOMAIN-SUFFIX,zhihu.com,DIRECT',
    'DOMAIN-SUFFIX,zhimg.com,DIRECT',
    'DOMAIN-SUFFIX,zimuzu.tv,DIRECT',
    'DOMAIN-SUFFIX,zoho.com,DIRECT',
    'DOMAIN-SUFFIX,cn,DIRECT',
    'DOMAIN-SUFFIX,xn--fiqs8s,DIRECT',
    'DOMAIN-KEYWORD,-cn,DIRECT',
    'DOMAIN-KEYWORD,google,节点选择',
    'DOMAIN-KEYWORD,gmail,节点选择',
    'DOMAIN-KEYWORD,youtube,节点选择',
    'DOMAIN-KEYWORD,facebook,节点选择',
    'DOMAIN-KEYWORD,twitter,节点选择',
    'DOMAIN-KEYWORD,instagram,节点选择',
    'DOMAIN-KEYWORD,whatsapp,节点选择',
    'DOMAIN-KEYWORD,telegram,节点选择',
    'DOMAIN-KEYWORD,github,节点选择',
    'DOMAIN-KEYWORD,blogspot,节点选择',
    'DOMAIN-KEYWORD,dropbox,节点选择',
    'DOMAIN-KEYWORD,wikipedia,节点选择',
    'DOMAIN-KEYWORD,pinterest,节点选择',
    'DOMAIN-KEYWORD,discord,节点选择',
    'DOMAIN-KEYWORD,openai,节点选择',
    'DOMAIN-KEYWORD,anthropic,节点选择',
    'DOMAIN-KEYWORD,netflix,节点选择',
    'DOMAIN-KEYWORD,spotify,节点选择',
    'DOMAIN-KEYWORD,amazon,节点选择',
    'DOMAIN-SUFFIX,chatgpt.com,节点选择',
    'DOMAIN-SUFFIX,oaistatic.com,节点选择',
    'DOMAIN-SUFFIX,oaiusercontent.com,节点选择',
    'DOMAIN-SUFFIX,claude.ai,节点选择',
    'DOMAIN-SUFFIX,gemini.google.com,节点选择',
    'DOMAIN-SUFFIX,perplexity.ai,节点选择',
    'DOMAIN-SUFFIX,huggingface.co,节点选择',
    'DOMAIN-SUFFIX,t.co,节点选择',
    'DOMAIN-SUFFIX,x.com,节点选择',
    'DOMAIN-SUFFIX,twimg.com,节点选择',
    'DOMAIN-SUFFIX,fb.me,节点选择',
    'DOMAIN-SUFFIX,fbcdn.net,节点选择',
    'DOMAIN-SUFFIX,youtu.be,节点选择',
    'DOMAIN-SUFFIX,ytimg.com,节点选择',
    'DOMAIN-SUFFIX,gstatic.com,节点选择',
    'DOMAIN-SUFFIX,ggpht.com,节点选择',
    'DOMAIN-SUFFIX,googlevideo.com,节点选择',
    'DOMAIN-SUFFIX,githubusercontent.com,节点选择',
    'DOMAIN-SUFFIX,githubassets.com,节点选择',
    'DOMAIN-SUFFIX,v2ex.com,节点选择',
    'DOMAIN-SUFFIX,medium.com,节点选择',
    'DOMAIN-SUFFIX,reddit.com,节点选择',
    'DOMAIN-SUFFIX,redd.it,节点选择',
    'DOMAIN-SUFFIX,imgur.com,节点选择',
    'DOMAIN-SUFFIX,pixiv.net,节点选择',
    'DOMAIN-SUFFIX,nytimes.com,节点选择',
    'DOMAIN-SUFFIX,nyt.com,节点选择',
    'DOMAIN-SUFFIX,bbc.com,节点选择',
    'DOMAIN-SUFFIX,bbc.co.uk,节点选择',
    'DOMAIN-SUFFIX,steamcommunity.com,节点选择',
    'DOMAIN-SUFFIX,twitch.tv,节点选择',
    'DOMAIN-SUFFIX,vimeo.com,节点选择',
    'DOMAIN-SUFFIX,tumblr.com,节点选择',
    'DOMAIN-SUFFIX,linkedin.com,节点选择',
    'DOMAIN-SUFFIX,mega.nz,节点选择',
    'DOMAIN-SUFFIX,archive.org,节点选择',
    'DOMAIN-SUFFIX,wikimedia.org,节点选择',
    'DOMAIN-SUFFIX,soundcloud.com,节点选择',
    'DOMAIN-SUFFIX,telegra.ph,节点选择',
    'DOMAIN-SUFFIX,telegram.org,节点选择',
    'IP-CIDR,91.108.4.0/22,节点选择,no-resolve',
    'IP-CIDR,91.108.8.0/21,节点选择,no-resolve',
    'IP-CIDR,91.108.12.0/22,节点选择,no-resolve',
    'IP-CIDR,91.108.16.0/22,节点选择,no-resolve',
    'IP-CIDR,91.108.56.0/22,节点选择,no-resolve',
    'IP-CIDR,149.154.160.0/20,节点选择,no-resolve',
    'IP-CIDR6,2001:67c:4e8::/48,节点选择,no-resolve',
    'IP-CIDR6,2001:b28:f23d::/48,节点选择,no-resolve',
    'IP-CIDR6,2001:b28:f23f::/48,节点选择,no-resolve',
    'GEOIP,CN,DIRECT',
    'MATCH,节点选择',
)


def build_relay_proxies(nodes, relay_chains=()):
    """Build Clash proxy objects for `dialer-proxy` relay chains (entry -> landing)."""
    by_name = {n['name']: n for n in nodes}
    relays = []
    for chain in relay_chains or ():
        front = chain.get('front')
        exit_name = chain.get('exit')
        if not front or not exit_name or front == exit_name:
            continue
        if front not in by_name or exit_name not in by_name:
            continue
        chain_name = valid_name(chain.get('name') or f'🔗 链式：{front} → {exit_name}')
        if chain_name in by_name:
            continue
        proxy = clash_proxy(dict(by_name[exit_name], name=chain_name, dialer_proxy=front))
        relays.append(proxy)
    return relays


def clash_config(nodes, relay_chains=()):
    # JSON is valid YAML 1.2; avoids PyYAML or a hand-written YAML serializer.
    base_proxies = [clash_proxy(n) for n in nodes]
    relay_proxies = build_relay_proxies(nodes, relay_chains)
    all_proxies = base_proxies + relay_proxies
    names = [p['name'] for p in all_proxies]
    if len(names) > 1:
        groups = [
            {'name': '节点选择', 'type': 'select', 'proxies': ['⚡ 自动优选最快', '🛡️ 故障转移'] + names + ['DIRECT']},
            {'name': '⚡ 自动优选最快', 'type': 'url-test', 'proxies': names,
             'url': 'http://www.gstatic.com/generate_204', 'interval': 300, 'tolerance': 50},
            {'name': '🛡️ 故障转移', 'type': 'fallback', 'proxies': names,
             'url': 'http://www.gstatic.com/generate_204', 'interval': 300},
            {'name': '国内直连', 'type': 'select', 'proxies': ['DIRECT', '节点选择']},
        ]
    else:
        groups = [
            {'name': '节点选择', 'type': 'select', 'proxies': (names + ['DIRECT']) if names else ['DIRECT']},
            {'name': '国内直连', 'type': 'select', 'proxies': ['DIRECT', '节点选择']},
        ]
    return {
        'mixed-port': 7890,
        'allow-lan': False,
        'bind-address': '*',
        'mode': 'rule',
        'log-level': 'warning',
        'unified-delay': True,
        'tcp-concurrent': True,
        'dns': AIRPORT_DNS_CONFIG,
        'proxies': all_proxies,
        'proxy-groups': groups,
        'rules': list(CHINA_DIRECT_RULES),
    }


def _singbox_route_rules():
    """Convert CHINA_DIRECT_RULES into ordered sing-box route rules without external rule-set downloads."""
    rules = [{'ip_is_private': True, 'outbound': 'direct'}]
    type_map = {
        'DOMAIN': 'domain',
        'DOMAIN-SUFFIX': 'domain_suffix',
        'DOMAIN-KEYWORD': 'domain_keyword',
        'IP-CIDR': 'ip_cidr',
        'IP-CIDR6': 'ip_cidr',
    }
    cur_out = None
    cur_bucket = {}

    def flush():
        if cur_out and cur_bucket:
            rule = dict(cur_bucket)
            rule['outbound'] = cur_out
            rules.append(rule)

    for raw in CHINA_DIRECT_RULES:
        parts = raw.split(',')
        if len(parts) < 3:
            continue
        rtype, val, target = parts[0], parts[1], parts[2]
        if rtype in ('GEOIP', 'MATCH'):
            continue
        sb_key = type_map.get(rtype)
        if not sb_key:
            continue
        out = 'direct' if target == 'DIRECT' else '节点选择'
        if rtype == 'DOMAIN-SUFFIX' and val in ('cn', 'local', 'lan'):
            val = '.' + val
        if out != cur_out:
            flush()
            cur_out = out
            cur_bucket = {}
        cur_bucket.setdefault(sb_key, []).append(val)
    flush()
    return rules


def singbox_client_config(nodes, relay_chains=()):
    """Build a standard sing-box client profile compatible with SFA / SFI / SFM / SFX."""
    outbounds = []
    names = []
    by_name = {}
    for n in nodes:
        o = outbound(n, local=False)
        o['tag'] = n['name']
        outbounds.append(o)
        names.append(n['name'])
        by_name[n['name']] = n
    for chain in relay_chains or ():
        front = chain.get('front')
        exit_name = chain.get('exit')
        if not front or not exit_name or front == exit_name:
            continue
        if front not in by_name or exit_name not in by_name:
            continue
        chain_name = valid_name(chain.get('name') or f'🔗 链式：{front} → {exit_name}')
        if chain_name in by_name:
            continue
        ro = outbound(dict(by_name[exit_name], detour=front), local=False)
        ro['tag'] = chain_name
        outbounds.append(ro)
        names.append(chain_name)
    selector_list = (['⚡ 自动优选最快'] + names + ['direct']) if len(names) > 1 else ((names + ['direct']) if names else ['direct'])
    groups = [{'type': 'selector', 'tag': '节点选择', 'outbounds': selector_list}]
    if len(names) > 1:
        groups.append({
            'type': 'urltest',
            'tag': '⚡ 自动优选最快',
            'outbounds': names,
            'url': 'https://www.gstatic.com/generate_204',
            'interval': '3m',
            'tolerance': 50,
        })
    return {
        'log': {'level': 'warn', 'timestamp': True},
        'inbounds': [{'type': 'mixed', 'tag': 'mixed-in', 'listen': '127.0.0.1', 'listen_port': 7890}],
        'outbounds': groups + outbounds + [{'type': 'direct', 'tag': 'direct'}],
        'route': {
            'rules': _singbox_route_rules(),
            'final': '节点选择',
        },
    }


def subscription_bundle(nodes, title='NodeLite', userinfo='', generation=None, relay_chains=()):
    yaml_text = json.dumps(clash_config(nodes, relay_chains=relay_chains), ensure_ascii=False, indent=2) + '\n'
    singbox_text = json.dumps(singbox_client_config(nodes, relay_chains=relay_chains), ensure_ascii=False, indent=2) + '\n'
    raw_links = '\n'.join(uri(n) for n in nodes) + ('\n' if nodes else '')
    b64_links = base64.b64encode(raw_links.strip().encode('utf-8')).decode('ascii')
    meta = {
        'schema': 1,
        'generation': generation or str(uuid.uuid4()),
        'verified': bool(nodes),
        'nodeCount': len(nodes),
        'relayCount': len(build_relay_proxies(nodes, relay_chains)),
        'title': valid_name(title) if title else 'NodeLite',
        'userinfo': str(userinfo or ''),
        'updatedAt': int(time.time()),
        'yamlSha256': hashlib.sha256(yaml_text.encode('utf-8')).hexdigest(),
        'linksSha256': hashlib.sha256(b64_links.encode('utf-8')).hexdigest(),
    }
    return {
        'clash.yaml': yaml_text,
        'singbox.json': singbox_text,
        'links.b64': b64_links,
        'raw.txt': raw_links,
        'meta.json': json.dumps(meta, ensure_ascii=False, indent=2) + '\n',
        'meta': meta,
    }


def subscription_urls(sub_cfg):
    host = sub_cfg['host']
    formatted = f'[{host}]' if ':' in host and not host.startswith('[') else host
    port = sub_cfg.get('public_port') or sub_cfg['port']
    scheme = sub_cfg.get('scheme', 'http')
    token = sub_cfg['token']
    base = f'{scheme}://{formatted}:{port}/s/{token}'
    result = {
        'universal': base + '/sub',
        'flclash': base + '/flclash.yaml',
        'clash': base + '/clash.yaml',
        'links': base + '/links.txt',
        'singbox': base + '/singbox.json',
        'raw': base + '/raw.txt',
        'manifest': base + '/manifest.json',
    }
    cf = sub_cfg.get('cf_domain', '')
    if cf:
        cf_base = f'https://{cf}/s/{token}'
        result.update(
            cf_universal=cf_base + '/sub',
            cf_flclash=cf_base + '/flclash.yaml',
            cf_links=cf_base + '/links.txt',
            cf_singbox=cf_base + '/singbox.json',
            cf_raw=cf_base + '/raw.txt',
            cf_manifest=cf_base + '/manifest.json',
        )
    return result

