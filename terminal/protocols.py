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
    'vless': ('VLESS Reality（推荐，无需域名）', 'tcp'),
    'trojan': ('Trojan TLS', 'tcp'),
    'ss2022': ('Shadowsocks 2022', 'tcp'),
    'vmess': ('VMess WebSocket', 'tcp'),
    'hysteria2': ('Hysteria2（需要 UDP）', 'udp'),
    'tuic': ('TUIC v5（需要 UDP）', 'udp'),
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
        item.update(method='2022-blake3-aes-128-gcm', password=n['ss_password'], network='tcp')
    elif p == 'vmess':
        item.update(users=[{'uuid': n['uuid'], 'alterId': 0}],
                    multiplex={'enabled': True, 'padding': False},
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
        o.update(uuid=n['uuid'], flow='xtls-rprx-vision', tls={
            'enabled': True, 'server_name': n['sni'],
            'utls': {'enabled': True, 'fingerprint': 'chrome'},
            'reality': {'enabled': True, 'public_key': n['public_key'], 'short_id': n['short_id']}})
    elif p in ('trojan', 'hysteria2', 'tuic'):
        o.update(password=n['password'], tls={'enabled': True, 'server_name': n['sni'],
                 'insecure': n.get('self_signed', True)})
        if p in ('hysteria2', 'tuic'):
            o['tls']['alpn'] = ['h3']
        if p == 'tuic':
            o.update(uuid=n['uuid'], congestion_control='cubic')
    elif p == 'ss2022':
        o.update(method='2022-blake3-aes-128-gcm', password=n['ss_password'])
    else:
        host_hdr = cf or n['sni']
        o.update(uuid=n['uuid'], security='auto',
                 transport={'type': 'ws', 'path': n['ws_path'], 'headers': {'Host': host_hdr},
                            'max_early_data': 2048, 'early_data_header_name': 'Sec-WebSocket-Protocol'})
        if cf:
            o['tls'] = {'enabled': True, 'server_name': cf}
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
        sni = data.get('sni') or data.get('host') or 'www.microsoft.com'
        ws_host = data.get('host') or sni
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
            uuid=str(uuid.UUID(str(data.get('id', '')))),
            ws_path=str(data.get('path') or '/'),
            tls_enabled=tls_on,
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
        sni = q.get('sni') or q.get('host') or 'www.microsoft.com'
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
            flow=q.get('flow', 'xtls-rprx-vision'),
            public_key=q.get('pbk', ''),
            short_id=q.get('sid', ''),
            fp=q.get('fp', 'chrome'),
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
        q.update(encryption='none', flow=n.get('flow', 'xtls-rprx-vision'), security='reality',
                 fp=n.get('fp', 'chrome'), pbk=n['public_key'], sid=n['short_id'], type='tcp')
    elif p == 'vmess':
        cf = n.get('cf_domain', '')
        cf_server = (n.get('cf_ip') or cf) if cf else ''
        tls_on = bool(cf or n.get('tls_enabled'))
        ws_host = cf or n.get('ws_host') or n['sni']
        value = dict(v='2', ps=n['name'], add=cf_server or n['host'], port='443' if cf else str(n['public_port']),
                     id=n['uuid'], aid='0', scy='auto', net='ws', type='none',
                     host=ws_host, path=n['ws_path'], tls='tls' if tls_on else '')
        if tls_on:
            value['sni'] = cf or n['sni']
        return 'vmess://'+base64.b64encode(json.dumps(value, ensure_ascii=False).encode()).decode()
    elif p == 'ss2022':
        method = n.get('ss_method', '2022-blake3-aes-128-gcm')
        auth = base64.urlsafe_b64encode((method+':'+n['ss_password']).encode()).decode().rstrip('=')
        return 'ss://'+auth+'@'+address+'#'+quote(n['name'], safe='')
    else:
        auth = quote(n['password'], safe='')
        if p == 'tuic':
            auth = n['uuid']+':'+auth
            q.update(congestion_control='cubic', alpn='h3')
        if p == 'trojan':
            q.update(security='tls', type='tcp')
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
             port=443 if cf else n['public_port'], udp=p != 'ss2022')
    if p == 'vless':
        o.update(uuid=n['uuid'], flow=n.get('flow', 'xtls-rprx-vision'), tls=True, servername=n['sni'],
                 **{'client-fingerprint': n.get('fp', 'chrome'), 'reality-opts': {
                     'public-key': n['public_key'], 'short-id': n['short_id']}})
    elif p in ('trojan', 'hysteria2', 'tuic'):
        o.update(password=n['password'], **{'skip-cert-verify': n.get('self_signed', True)})
        o['sni'] = n['sni']
        if p == 'tuic':
            o.update(uuid=n['uuid'], **{'congestion-controller': 'cubic', 'alpn': ['h3']})
    elif p == 'ss2022':
        o.update(cipher=n.get('ss_method', '2022-blake3-aes-128-gcm'), password=n['ss_password'])
    else:
        host_hdr = cf or n.get('ws_host') or n['sni']
        ws_opts = {'path': n['ws_path'], 'headers': {'Host': host_hdr},
                   'max-early-data': 2048, 'early-data-header-name': 'Sec-WebSocket-Protocol'}
        o.update(uuid=n['uuid'], alterId=0, cipher='auto', network='ws', **{'ws-opts': ws_opts})
        if cf or n.get('tls_enabled'):
            o.update(tls=True, servername=cf or n['sni'], **{'skip-cert-verify': False, 'client-fingerprint': 'chrome',
                     'smux': {'enabled': True, 'protocol': 'h2mux', 'max-connections': 2, 'min-streams': 4}})
    if n.get('dialer_proxy'):
        o['dialer-proxy'] = n['dialer_proxy']
    return o


CHINA_DIRECT_DOMAINS = (
    'cn', 'xn--fiqs8s', 'local', 'lan',
    'baidu.com', 'bdstatic.com', 'baidupcs.com',
    'qq.com', 'weixin.qq.com', 'wechat.com', 'qpic.cn', 'gtimg.cn', 'tencent.com', 'myqcloud.com',
    'taobao.com', 'tmall.com', 'tbcdn.cn', 'alicdn.com', 'aliyun.com', 'aliyuncs.com', 'alipay.com', '1688.com',
    'jd.com', '360buyimg.com', 'pinduoduo.com', 'yangkeduo.com',
    'bilibili.com', 'bilivideo.com', 'hdslb.com', 'biliapi.net',
    'douyin.com', 'douyincdn.com', 'toutiao.com', 'snssdk.com', 'pstatp.com', 'bytedance.com', 'feishu.cn',
    'xiaohongshu.com', 'xhscdn.com', 'kuaishou.com', 'kwai.net',
    '163.com', '126.com', '126.net', 'netease.com',
    'weibo.com', 'weibocdn.com', 'sina.com.cn', 'zhihu.com', 'zhimg.com',
    'meituan.com', 'dianping.com', 'ctrip.com', '12306.cn',
    'iqiyi.com', 'youku.com', 'mgtv.com', 'sohu.com', 'sogou.com',
    'xiaomi.com', 'mi.com', 'miui.com', 'huawei.com', 'vmall.com', 'hihonor.com',
    'apple.com.cn', 'icloud.com.cn', 'cdn-apple.com',
    'csdn.net', 'gitee.com', 'oschina.net', 'dingtalk.com', 'wps.cn', '360.cn',
)

CHINA_DIRECT_RULES = (
    [f'DOMAIN-SUFFIX,{d},DIRECT' for d in CHINA_DIRECT_DOMAINS]
    + [
        'IP-CIDR,127.0.0.0/8,DIRECT,no-resolve',
        'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
        'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
        'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
        'IP-CIDR,100.64.0.0/10,DIRECT,no-resolve',
        'IP-CIDR6,::1/128,DIRECT,no-resolve',
        'IP-CIDR6,fc00::/7,DIRECT,no-resolve',
        'IP-CIDR6,fe80::/10,DIRECT,no-resolve',
        'GEOIP,LAN,DIRECT,no-resolve',
        'GEOIP,CN,DIRECT,no-resolve',
        'MATCH,节点选择',
    ]
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
            {'name': '节点选择', 'type': 'select', 'proxies': ['⚡ 自动优选最快'] + names + ['DIRECT']},
            {'name': '⚡ 自动优选最快', 'type': 'url-test', 'proxies': names,
             'url': 'https://cp.cloudflare.com/generate_204', 'interval': 180, 'tolerance': 50},
            {'name': '国内直连', 'type': 'select', 'proxies': ['DIRECT', '节点选择']},
        ]
    else:
        groups = [
            {'name': '节点选择', 'type': 'select', 'proxies': (names + ['DIRECT']) if names else ['DIRECT']},
            {'name': '国内直连', 'type': 'select', 'proxies': ['DIRECT', '节点选择']},
        ]
    return {'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'log-level': 'warning',
            'proxies': all_proxies,
            'proxy-groups': groups,
            'rules': list(CHINA_DIRECT_RULES)}


def subscription_bundle(nodes, title='NodeLite', userinfo='', generation=None, relay_chains=()):
    yaml_text = json.dumps(clash_config(nodes, relay_chains=relay_chains), ensure_ascii=False, indent=2) + '\n'
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
        'flclash': base + '/flclash.yaml',
        'clash': base + '/clash.yaml',
        'links': base + '/links.txt',
        'raw': base + '/raw.txt',
        'manifest': base + '/manifest.json',
    }
    cf = sub_cfg.get('cf_domain', '')
    if cf:
        cf_base = f'https://{cf}/s/{token}'
        result.update(
            cf_flclash=cf_base + '/flclash.yaml',
            cf_links=cf_base + '/links.txt',
            cf_raw=cf_base + '/raw.txt',
            cf_manifest=cf_base + '/manifest.json',
        )
    return result

