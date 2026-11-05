#!/usr/bin/env python3
"""NodeLite: an on-demand, Chinese terminal node manager."""
import argparse
import base64
import json
import os
from pathlib import Path
import platform
import sys
import time

import runtime as rt
from protocols import (
    PROTOCOLS,
    clash_config,
    new_node,
    subscription_urls,
    uri,
    valid_host,
    valid_name,
    valid_port,
    valid_sni,
    valid_ssh_port,
    valid_sub_host,
)

VERSION = '0.2.0'


def ask(label, default=''):
    answer = input(label+(f' [{default}]' if default != '' else '')+'：').strip()
    return answer or str(default)


def select_node(nodes):
    if not nodes:
        raise ValueError('还没有节点，请先选择“创建节点”。')
    for index, node in enumerate(nodes, 1):
        print(f"  {index}. {node['name']} | {node['protocol']} | 内部 {node['port']} → 公网 {node['public_port']}")
    value = int(ask('选择节点编号', '1'))
    if not 1 <= value <= len(nodes):
        raise ValueError('没有这个节点编号。')
    return nodes[value-1]


def require_root():
    if platform.system() != 'Linux' or os.geteuid() != 0:
        raise RuntimeError('请在 Linux VPS 的 root 终端运行；或使用 sudo nl。')
    if not rt.CORE.is_file():
        raise RuntimeError('缺少代理核心，请重新运行安装包。现有节点文件不会被删除。')
    rt.init_system()


def saved_setup():
    return rt.load_setup()


def detect_address():
    # An egress address is only a suggested value: NAT forwarding may differ.
    r = rt.run(['curl', '-fsS', '--max-time', '5', 'https://api.ipify.org'], timeout=7)
    try:
        return valid_host(r.stdout)
    except ValueError:
        fields = os.environ.get('SSH_CONNECTION', '').split()
        try:
            return valid_host(fields[2]) if len(fields) == 4 else ''
        except ValueError:
            return ''


def print_port_guide(kind='1', ssh_ports=None):
    ssh_ports = ssh_ports or rt.detect_ssh_ports()
    ssh_desc = f"内部 {ssh_ports['internal']}" + (f" / 公网 {ssh_ports['public']}" if ssh_ports.get('public') else '')
    print('\n【四类端口区分说明（切勿混用）】')
    print(f'  1. SSH 登录端口  ：仅用于远程登录管理 VPS（当前 {ssh_desc}），绝对不要填到节点或订阅！')
    print('  2. 节点公网端口  ：手机/电脑客户端实际连接的外部端口（普通 VPS 与内部相同；NAT 填映射表左边的公网端口）')
    print('  3. 节点内部端口  ：VPS 内 sing-box 监听端口（支持 443 或 1024–65535；NAT 填映射表同一行右边的内部端口）')
    print('  4. 在线订阅端口  ：公网自动更新订阅 URL 专用端口，必须与 SSH 端口、节点端口分开')
    if kind == '2':
        print('\n【NAT 小鸡逐项填写示范】')
        print('  假设商家后台端口映射表有两行：')
        print('    第 1 行（SSH）：公网 23932 → 内部 22     （这是 SSH 登录，跳过不要动！）')
        print('    第 2 行（空闲）：公网 53440 → 内部 10086  （选这行：“公网端口”填 53440，“内部端口”填 10086）')


def prompt_nat_ssh_port(settings):
    current = settings.get('ssh_public_port', '')
    raw = ask('你连接 SSH 时填写的“SSH 公网端口”（用于防误填保护，不清楚可直接回车）', str(current) if current else '')
    if not raw:
        return None
    return valid_ssh_port(raw)


def recommend_free_port(protocol, name, host, start=20443):
    nodes = rt.load_state()['nodes']
    port = start
    for _ in range(80):
        probe = new_node(protocol, name, host, port)
        try:
            rt.check_ports(nodes+[probe], nodes)
            return port
        except (RuntimeError, ValueError):
            port += 1
    return start


def creation_wizard():
    settings = saved_setup()
    mem = rt.memory_info()
    ssh_ports = rt.detect_ssh_ports()
    detected_ip = settings.get('host') or detect_address()
    print(f"\n【第 1 步 / 共 3 步：检测服务器环境】")
    print(f"  系统与架构：{platform.system()} / {platform.machine()} / {rt.init_system()} | 可用内存：约 {mem.get('MemAvailable', '未知')} MiB")
    print(f"  当前 SSH 端口：内部 {ssh_ports['internal']}" + (f" / 公网 {ssh_ports['public']}" if ssh_ports.get('public') else ''))
    host = valid_host(ask('确认商家提供的公网 IP（请与后台核对）', detected_ip))
    print('  1. 普通 VPS：拥有独立公网 IP，端口直接使用（将自动推荐空闲端口）\n  2. NAT 小鸡：商家后台提供了“公网端口 → 内部端口”映射表')
    kind = ask('选择服务器类型；不确定时查看商家后台是否有端口映射表', settings.get('network', '1'))
    if kind not in ('1', '2'):
        raise ValueError('请输入 1 或 2。')
    ssh_pub = settings.get('ssh_public_port')
    if kind == '2':
        ssh_pub = prompt_nat_ssh_port(settings)
        if ssh_pub:
            settings['ssh_public_port'] = ssh_pub
            rt.write_json(rt.ROOT/'setup.json', dict(settings, host=host, network=kind))

    print('\n【第 2 步 / 共 3 步：填写连接协议与端口】')
    print('选择协议；第一次建议直接回车选 1（VLESS Reality）：')
    keys = list(PROTOCOLS)
    for i, key in enumerate(keys, 1):
        print(f'  {i}. {PROTOCOLS[key][0]}')
    choice = int(ask('协议编号', '1'))
    if not 1 <= choice <= len(keys):
        raise ValueError('没有这个协议编号。')
    protocol = keys[choice-1]
    if PROTOCOLS[protocol][1] == 'udp':
        if ask('商家明确允许 UDP，且 NAT 映射也是 UDP 吗？输入 yes 才继续', 'no') != 'yes':
            raise ValueError('已取消。UDP 未确认时请选择 VLESS Reality。')
    nodes = rt.load_state()['nodes']
    name = valid_name(ask('给节点取个名字', '我的节点-'+str(len(nodes)+1)))
    print_port_guide(kind)
    if kind == '2':
        public = valid_port(ask('第 1 项：这行映射的“节点公网端口”（外面连接的端口）'))
        port = valid_port(ask('第 2 项：同一行映射的“节点内部端口”（VPS 内部端口）'))
    else:
        rec = recommend_free_port(protocol, name, host)
        port = valid_port(ask('节点端口（已自动选择未占用端口，也支持直接填 443）', str(rec)))
        public = port
    sni = 'www.microsoft.com'
    if protocol == 'vless':
        sni = valid_sni(ask('Reality 握手域名（通常直接回车）', sni))
    node = new_node(protocol, name, host, port, public, sni)
    if protocol in ('trojan', 'hysteria2', 'tuic'):
        print('此协议需要证书。没有域名时可用自签证书，但客户端会跳过证书验证。')
        if ask('使用自己的域名证书？', 'no') == 'yes':
            node['sni'] = valid_sni(ask('证书对应的域名'))
            node['cert'] = str(Path(ask('证书链的绝对路径')).resolve(strict=True))
            node['key'] = str(Path(ask('私钥的绝对路径')).resolve(strict=True))
            node['self_signed'] = False
        elif ask('确认使用自签证书？输入 yes；取消后可选 VLESS', 'no') != 'yes':
            raise ValueError('已取消。')
    print(f"\n【第 3 步 / 共 3 步：校验配置、自测并输出订阅/链接】")
    print(f"即将创建：{name} / {protocol} / 公网入口 {host}:{public}（VPS 内部监听 {port}）。")
    print('只修改本工具管理的节点；创建或删除时现有 NodeLite 连接会短暂重连。')
    if ask('继续？', 'yes') != 'yes':
        return
    create(node)
    saved = dict(settings, host=host, network=kind)
    if ssh_pub:
        saved['ssh_public_port'] = ssh_pub
    rt.write_json(rt.ROOT/'setup.json', saved)


def create(node):
    with rt.lock():
        nodes = rt.load_state()['nodes']
        if len(nodes) >= 24:
            raise ValueError('轻量版最多管理 24 个监听节点；小内存 VPS 建议只创建 1–3 个。')
        if rt.memory_info().get('MemAvailable', 100) < 48:
            raise RuntimeError('当前可用内存不足 48 MiB，创建时的临时自测进程可能导致内存不足。请先关闭不需要的面板/程序，再重试。')
        rt.check_ports(nodes+[node], nodes)
        try:
            rt.prepare_credentials(node)
            print('正在校验配置、启动核心，并通过该协议访问 HTTPS 测试页……')
            rt.commit(nodes+[node], test_ids=[node['id']])
        except BaseException:
            # A failed new node owns only its own freshly generated certificate folder.
            import shutil
            own_cert = rt.ROOT/'certs'/node['id']
            still_referenced = any(n['id'] == node['id'] for n in rt.load_state()['nodes'])
            if node.get('self_signed') and own_cert.is_dir() and not still_referenced:
                shutil.rmtree(own_cert)
            raise
        try:
            print(rt.firewall(node))
        except (RuntimeError, OSError) as error:
            print('节点已启动，但系统防火墙放行失败：'+str(error))
    saved_node = next((n for n in rt.load_state()['nodes'] if n['id'] == node['id']), node)
    stages = rt.node_status_stages(saved_node, core_active=True)
    print('\n节点验证进度：'+stages['summary'])
    print('单节点分享链接（包含连接密码，请只分享给需要的人）：\n'+uri(saved_node))
    sub_cfg = rt.load_sub_config()
    if sub_cfg.get('enabled'):
        urls = subscription_urls(sub_cfg)
        print('公网订阅已自动同步：')
        if urls.get('cf_flclash'):
            print('  ★ Cloudflare HTTPS 订阅 URL：'+urls['cf_flclash'])
        print('  FlClash 订阅 URL：'+urls['flclash'])
        print('  通用 Base64 URL ：'+urls['links'])
    else:
        print('FlClash 可用菜单“3. 导出配置”导入文件，或用菜单“4. 公网订阅 URL”开启自动更新网址。')


def show_links():
    nodes = rt.load_state()['nodes']
    if not nodes:
        print('尚无节点；选择“创建节点”。')
        return
    core_active = rt.service('status', check=False)
    sub_cfg = rt.load_sub_config()
    cf_domain = sub_cfg.get('cf_domain', '')
    for node in nodes:
        stages = rt.node_status_stages(node, core_active=core_active)
        eff = dict(node, cf_domain=cf_domain, cf_ip=rt.CF_FAST_IPS[0][1]) if (node['protocol'] == 'vmess' and cf_domain and not node.get('cf_domain')) else node
        extra = f" | Cloudflare 香港优选直连：{eff.get('cf_ip')} (SNI: {cf_domain}:443)" if eff.get('cf_domain') else ''
        print(f"\n【{node['name']}】（内部端口 {node['port']} → 公网 {node['host']}:{node['public_port']}{extra}）")
        print(f"状态：{stages['summary']}")
        print(uri(eff))
    if sub_cfg.get('enabled'):
        urls = subscription_urls(sub_cfg)
        cf_mode = sub_cfg.get('cf_mode', '')
        cf_tag = '永久固定域名' if cf_mode in ('named', 'cdn') else '临时隧道(重启会变)'
        print('\n【在线自动更新订阅 URL（已与当前节点同步）】')
        if urls.get('cf_flclash'):
            print(f'  ★ Cloudflare HTTPS 订阅 ({cf_tag}) FlClash：'+urls['cf_flclash'])
            print(f'  ★ Cloudflare HTTPS 订阅 ({cf_tag}) Base64 ：'+urls['cf_links'])
        print('  VPS 原生 FlClash 订阅 URL：'+urls['flclash'])
        print('  VPS 原生 Base64 订阅 URL ：'+urls['links'])


def exports():
    nodes = rt.load_state()['nodes']
    if not nodes:
        raise ValueError('没有可导出的节点。')
    directory = rt.ROOT/'exports'
    directory.mkdir(mode=0o700, exist_ok=True)
    links = '\n'.join(uri(n) for n in nodes)+'\n'
    for name, data in [('links.txt', links), ('subscription.txt', base64.b64encode(links.encode()).decode()),
                       ('flclash.yaml', json.dumps(clash_config(nodes), ensure_ascii=False, indent=2))]:
        path = directory/name
        path.write_text(data, encoding='utf-8')
        path.chmod(0o600)
        print(str(path))
    print('用 SSH 软件的文件面板下载：FlClash 导入 flclash.yaml；通用客户端导入 links.txt。')
    sub_cfg = rt.load_sub_config()
    if sub_cfg.get('enabled'):
        urls = subscription_urls(sub_cfg)
        print('已启用公网订阅 URL（FlClash“添加配置 → URL”可直接粘贴自动更新）：\n  '+urls['flclash'])
    else:
        print('提示：如需在 FlClash 中粘贴 URL 自动更新，请选择主菜单“4. 开启 / 管理公网订阅 URL”。')


def print_sub_summary(cfg):
    urls = subscription_urls(cfg)
    active = rt.service_name('status', check=False, name=rt.SUB_SERVICE)
    mode = 'HTTPS（自签证书）' if cfg.get('scheme') == 'https' and cfg.get('self_signed') else (
        'HTTPS（域名证书）' if cfg.get('scheme') == 'https' else 'HTTP（明文，仅靠令牌保护）')
    cf_mode = cfg.get('cf_mode', '')
    cf_desc = {
        'named': 'Cloudflare 固定命名隧道（永久不变）',
        'cdn': 'Cloudflare CDN 域名回源（永久不变，零额外内存）',
        'quick': 'Cloudflare 临时救急隧道（重启后域名会变）',
    }.get(cf_mode, '未开启 Cloudflare')
    print(f"\n在线订阅状态：{'运行中' if active else '未运行'} | 模式：{mode} | 隧道：{cf_desc}")
    print(f"订阅端口映射：VPS 内部 {cfg['port']}/TCP → 外部访问 {cfg['host']}:{cfg.get('public_port') or cfg['port']}")
    if urls.get('cf_flclash'):
        print('  ★ Cloudflare HTTPS 自动更新 URL (FlClash) ：'+urls['cf_flclash'])
        print('  ★ Cloudflare HTTPS 通用订阅 URL (Base64)  ：'+urls['cf_links'])
        if cf_mode == 'quick':
            print('  ⚠️ 注意：当前为免域名临时隧道（*.trycloudflare.com），VPS 重启后地址会改变；长期使用请选“配置固定命名隧道或自有域名”。')
    print('  FlClash 自动更新 URL ：'+urls['flclash'])
    print('  通用 Base64 订阅 URL ：'+urls['links'])
    print('  单节点纯文本列表 URL ：'+urls['raw'])
    if cfg.get('scheme') == 'http' and not urls.get('cf_flclash'):
        print('  注意：HTTP 订阅未加密传输，请勿在公开群聊泄露此 URL；有域名证书或开启 Cloudflare 隧道可使用 HTTPS。')
    elif cfg.get('self_signed'):
        print('  注意：自签证书 HTTPS 需要客户端允许跳过证书验证，否则建议使用自有域名证书或 HTTP。')


def subscription_menu():
    settings = saved_setup()
    cfg = rt.load_sub_config()
    if cfg and cfg.get('enabled'):
        print_sub_summary(cfg)
    else:
        print('\n当前未开启公网订阅 URL（开启后会运行一个轻量标准库订阅服务，随节点增删改名自动同步）。')

    print('\n  1. 开启 / 修改公网订阅端口与 HTTPS 设置（保留已有隧道配置）\n'
          '  2. 配置【永久不变】的 Cloudflare 固定命名隧道或 CDN 域名（推荐长期使用）\n'
          '  3. 开启免域名【临时】Cloudflare 隧道（*.trycloudflare.com，重启后地址会变化）\n'
          '  4. 重置订阅访问令牌（所有旧令牌与历史迁移令牌立即 404 失效）\n'
          '  5. 关闭公网订阅服务（仅使用文件导出）\n'
          '  0. 返回主菜单')
    choice = ask('选择操作', '1' if not cfg.get('enabled') else '0')
    if choice == '0':
        return
    if choice == '4':
        if ask('重置后已分享的旧订阅 URL 将永久 404 失效，输入 yes 确认', 'no') != 'yes':
            return
        updated = rt.rotate_sub_token()
        print('已生成新订阅令牌并立即生效（旧令牌与迁移令牌均已作废）：')
        print_sub_summary(updated)
        return
    if choice == '5':
        rt.disable_subscription()
        print('已关闭公网订阅服务。')
        return
    if choice == '2':
        print('\n选择永久固定域名方案：\n'
              '  1. Cloudflare 固定命名隧道（Named Tunnel：填入绑定域名 + Tunnel Token，无需公网入站端口）\n'
              '  2. 自有 Cloudflare CDN 域名 + Origin Rules 回源（零额外内存，需在 Cloudflare 设置回源到公网端口）')
        sub_m = ask('选择 1 或 2', '1')
        domain = valid_sni(ask('你在 Cloudflare 绑定的完整域名（如 sub.example.com）', cfg.get('cf_domain', '')))
        if sub_m == '1':
            tok = ask('Cloudflare 命名隧道 Token（Zero Trust → Networks → Tunnels 复制）')
            updated = rt.enable_cf_tunnel(mode='named', cf_domain=domain, cf_token=tok)
        elif sub_m == '2':
            updated = rt.enable_cf_tunnel(mode='cdn', cf_domain=domain)
        else:
            raise ValueError('请输入 1 或 2。')
        print_sub_summary(updated)
        return
    if choice == '3':
        print('正在启动免域名临时 Cloudflare 隧道（注意：VPS 重启后临时域名会变）……')
        updated = rt.enable_cf_tunnel(mode='quick')
        print_sub_summary(updated)
        return
    if choice != '1':
        raise ValueError('请输入 0–5。')

    default_host = cfg.get('host') or settings.get('host') or detect_address()
    host = valid_sub_host(ask('订阅访问的公网 IP 或已解析域名', default_host))
    kind = ask('服务器类型（1=普通 VPS，2=NAT 小鸡）', settings.get('network', '1'))
    if kind not in ('1', '2'):
        raise ValueError('请输入 1 或 2。')
    print_port_guide(kind)
    default_int = str(cfg.get('port', 20000))
    if kind == '2':
        print('\n请在商家后台找一条【不同于 SSH、也不同于节点】的 TCP 端口映射给订阅使用：')
        print('例：商家映射 公网 40187 → 内部 20000，则先填 40187，再填 20000。')
        pub_port = valid_port(ask('订阅的“公网端口”（外部访问端口）', str(cfg.get('public_port', ''))))
        int_port = valid_port(ask('同一行的“内部端口”（VPS 内部监听端口）', default_int))
    else:
        int_port = valid_port(ask('订阅端口（需与节点端口分开，支持 443 或 1024–65535）', default_int))
        pub_port = int_port

    print('\n选择订阅传输协议：\n  1. HTTP（无需证书，FlClash 可直接粘贴更新）\n  2. HTTPS（需提供域名证书链与私钥路径，或生成自签证书）')
    scheme_choice = ask('选择 1 或 2', '2' if cfg.get('scheme') == 'https' else '1')
    scheme = 'https' if scheme_choice == '2' else 'http'
    cert, key, self_signed = '', '', False
    if scheme == 'https':
        if ask('使用已有域名证书文件？', 'yes' if (cfg.get('cert') and not cfg.get('self_signed')) else 'no') == 'yes':
            cert = str(Path(ask('证书链绝对路径 (.pem/.crt)', cfg.get('cert', ''))).resolve(strict=True))
            key = str(Path(ask('私钥绝对路径 (.pem/.key)', cfg.get('key', ''))).resolve(strict=True))
        elif ask('使用自动生成的自签证书？（部分客户端拉取订阅不支持自签证书）输入 yes 确认', 'no') == 'yes':
            self_signed = True
        else:
            raise ValueError('已取消。无证书时可选 1 (HTTP)。')

    title = valid_name(ask('在客户端显示的订阅名称', cfg.get('title', 'NodeLite')))
    result = rt.configure_subscription(
        host=host, port=int_port, public_port=pub_port, scheme=scheme,
        cert=cert, key=key, self_signed=self_signed, title=title,
    )
    try:
        print(rt.firewall_port(int_port, 'tcp'))
    except (RuntimeError, OSError) as err:
        print('订阅服务已配置，但防火墙放行失败：'+str(err))
    print_sub_summary(result)
    if not rt.load_state()['nodes']:
        print('提示：当前还没有节点；创建第一个节点后订阅服务将自动启动并发布。')


def edit_node_port():
    nodes = rt.load_state()['nodes']
    node = select_node(nodes)
    settings = saved_setup()
    kind = settings.get('network', '2' if node['port'] != node['public_port'] else '1')
    print(f"\n当前节点：{node['name']} ({node['protocol']}) | 内部端口 {node['port']} → 公网 {node['host']}:{node['public_port']}")
    print('修改端口不会更换 UUID、密码或 Reality 密钥。')
    print_port_guide(kind)
    host = valid_host(ask('公网 IP', node['host']))
    if ask('是否为 NAT 映射（公网端口与内部端口不同）？(yes/no)', 'yes' if kind == '2' else 'no') == 'yes':
        pub_port = valid_port(ask('新的“节点公网端口”', str(node['public_port'])))
        int_port = valid_port(ask('新的“节点内部端口”', str(node['port'])))
    else:
        int_port = valid_port(ask('新的节点端口（支持 443 或 1024–65535）', str(node['port'])))
        pub_port = int_port
    updated = rt.update_node_port(node['id'], int_port, pub_port, host)
    try:
        print(rt.firewall(updated))
    except (RuntimeError, OSError) as err:
        print('端口已更新，但防火墙放行失败：'+str(err))
    print(f"\n端口已更新并通过内部协议自测：{updated['name']} → {updated['host']}:{updated['public_port']}（内部 {updated['port']}）")
    print('最新单节点链接：\n'+uri(updated))
    if rt.load_sub_config().get('enabled'):
        print('在线订阅 URL 内容已自动同步，客户端刷新订阅即可。')


def upgrade_core_menu():
    cur_ver = rt.current_core_version() or '未知'
    arch = rt.detect_arch()
    print(f'\n当前代理核心版本：{cur_ver} ({arch}) | 内置固定验证版本：{rt.CORE_VERSION}')
    print('升级流程：校验 SHA-256 → 预检现有节点配置 → 备份旧核心 → 原子替换 → 实测全部节点（失败自动回滚）。')
    target_ver = ask('目标 sing-box 版本号', rt.CORE_VERSION).strip().lstrip('v')
    custom_hash = ''
    if target_ver != rt.CORE_VERSION:
        custom_hash = ask(f'请输入 sing-box-{target_ver}-linux-{arch}.tar.gz 的 64 位 SHA-256').strip()
    if ask('开始校验/升级核心？', 'yes') != 'yes':
        return
    res = rt.upgrade_core(version=target_ver, sha256=custom_hash or None)
    print(f"核心已就绪：{res['previousVersion'] or '无'} → {res['currentVersion']}（备份：{res['backup'] or '无'}）")


def legacy_menu():
    found = rt.inspect_legacy_services()
    if not found:
        print('\n未检测到旧版残留服务（nodepilot-sing-box / subprogress-auto / subprogress-sub）。')
        return
    print('\n检测到以下服务或配置目录（已明确区分归属）：')
    has_third_party = False
    for item in found:
        state = ('运行中' if item['active'] else '已停止') + ('，开机自启' if item['enabled'] else '')
        owner_tag = '【本工具旧版】' if item.get('ownership') == 'subprogress' else '【外部/第三方服务】'
        if item.get('ownership') != 'subprogress':
            has_third_party = True
        print(f"  - {owner_tag} {item['name']} ({item.get('description', '')})：{state} | PID {item['pids'] or '无'} | 内存约 {round(item['rssKiB']/1024, 1)} MiB | 路径 {', '.join(item['paths'] + item['units'])}")
    print('\n清理规则：先将上述配置完整备份到 /root/（若备份失败则立即中止，绝不误停服务）；默认仅停用【本工具旧版】服务，保留外部第三方服务。')
    if ask('确认备份并停用本工具旧版服务？输入 yes 继续', 'no') != 'yes':
        return
    inc_third = False
    if has_third_party:
        inc_third = (ask('同时检测到【外部/第三方 sing-box 服务】，是否也一并备份并停用？(yes/no)', 'no') == 'yes')
    res = rt.cleanup_legacy_services(include_third_party=inc_third)
    print('备份已完成：'+res['backupDir'])
    print('已停用旧服务：'+('、'.join(res['stoppedServices']) or '无'))
    if res.get('skippedThirdParty'):
        print('已保留未停用的第三方服务：'+'、'.join(res['skippedThirdParty']))
    if res.get('recoveredSubToken'):
        print('已提取并保存旧版订阅令牌，开启 NodeLite 公网订阅时将自动兼容原令牌。')


def rollback_menu():
    if ask('恢复到上一版保存的节点配置？输入 yes 确认', 'no') != 'yes':
        return
    restored = rt.rollback_previous()
    print(f'已恢复上一版配置（共 {len(restored)} 个节点），并已同步在线订阅。')


def doctor():
    diag = rt.diagnose_network(run_public_loop=True)
    sys_info = diag['system']
    mem = sys_info['memory']
    rmem = sys_info.get('runtimeMemory', {})
    comp = rmem.get('componentsKiB', {})
    ssh_p = sys_info['sshPorts']
    print(f"\n系统：{sys_info['os']} / {sys_info['arch']} / {sys_info['init']} | 核心版本：{sys_info['coreVersion'] or '未知'}")
    print(f"系统内存：总额度 {mem.get('MemTotal', '未知')} MiB，当前可用约 {mem.get('MemAvailable', '未知')} MiB")
    print(f"本工具总内存：常驻合计 {rmem.get('daemonTotalMiB', 0)} MiB "
          f"(sing-box {round(comp.get('sing-box', 0)/1024, 1)} MiB + "
          f"订阅服务 {round(comp.get('sub-server', 0)/1024, 1)} MiB + "
          f"cloudflared {round(comp.get('cloudflared', 0)/1024, 1)} MiB)；"
          f"当前菜单临时占用 {round(comp.get('manager-cli', 0)/1024, 1)} MiB（退出后释放）")
    print(f"SSH 端口：内部 {ssh_p['internal']}" + (f" / 记录的公网端口 {ssh_p['public']}" if ssh_p.get('public') else ''))
    print('NodeLite 核心：'+('运行中' if sys_info['coreActive'] else '未运行'))
    if diag['configValid'] is not None:
        print('配置校验：'+('通过' if diag['configValid'] else '失败：'+diag['configError']))

    for n in diag['nodes']:
        pub = n.get('publicLoopProbe', {})
        if pub:
            pub_txt = f"通过 ({pub.get('latency_ms')}ms)" if pub.get('ok') else (
                '未通（NAT 小鸡常见：宿主机不支持公网回流，需从外部网络实测）' if n['is_nat'] else f"失败 ({pub.get('reason')})")
        else:
            pub_txt = '未测'
        cert_info = n.get('certExpiry')
        cert_txt = ''
        if cert_info:
            warn = ' ⚠️即将到期/已过期！' if (cert_info['expired'] or cert_info['expiringSoon']) else ''
            cert_txt = f" | 证书剩余 {cert_info['daysLeft']} 天 ({cert_info['expiresAt']}){warn}"
        print(f"  节点 {n['name']}：内部 {n['port']}/{n['transport']} → 公网 {n['host']}:{n['public_port']}{cert_txt}")
        print(f"    状态：{n['stages']['summary']} | 本机公网回环：{pub_txt}")

    sub = diag['subscription']
    if sub.get('enabled'):
        cf_warn = ' (临时隧道：重启后地址会变，建议改用固定隧道)' if sub.get('cf_mode') == 'quick' else (
            f" (固定域名：{sub.get('cf_domain')})" if sub.get('cf_domain') else '')
        print(f"在线订阅：{'运行中' if sub.get('active') else '未运行'} | 内部 {sub.get('port')} → 公网 {sub.get('public_port')} ({sub.get('scheme')}){cf_warn} | 本地健康检查：{'通过' if sub.get('healthy') else sub.get('error')}")
    else:
        print('在线订阅：未开启（可在主菜单选 4 开启自动更新 URL）')

    if diag['legacyServices']:
        active_leg = [f"{x['name']}({'本工具旧版' if x.get('ownership')=='subprogress' else '第三方'})" for x in diag['legacyServices'] if x['active'] or x['enabled']]
        if active_leg:
            print('旧版/外部服务提示：检测到仍在运行或自启的服务：' + '、'.join(active_leg) + '（可在菜单选 10 查看详情与清理）')

    print('监听端口：')
    print(rt.run(['ss', '-lntu']).stdout.strip())
    if diag.get('recentLogs'):
        print('最近日志：')
        print(diag['recentLogs'])

    print('\n【直连失败四步排查指引】')
    print('  1. 内部自测失败       → 检查 VPS 出站网络、DNS 或 Reality 伪装域名。')
    print('  2. SSH 能直连，节点不通 → 核对商家后台 NAT 映射表（公网→内部端口是否填反/漏填）及云安全组。')
    print('  3. 内部自测通过、经海外代理连公网端口也通，但你电脑直连 SSH 与节点端口全部超时（即使 Ping 仍通）：')
    print('     → 该 VPS 公网 IP 遭到运营商/跨境链路 TCP 阻断（俗称 IP 被墙 TCP）。配置与映射本身正常，需在商家后台更换 IP 或经中转连接。')
    print('  4. UDP 节点（HY2/TUIC）不通 → 确认商家 NAT 映射及防火墙同时放行了 UDP，而非仅 TCP。')


def test_nodes():
    with rt.lock():
        nodes = rt.load_state()['nodes']
        if not nodes:
            raise ValueError('还没有节点。')
        if not rt.service('status', check=False):
            raise RuntimeError('核心没有运行。选择“重启服务”，失败后查看诊断信息。')
        failed = False
        for n in nodes:
            result = rt.self_test(n)
            failed |= not result['ok']
            print(n['name']+'：'+('服务器内部协议自测通过' if result['ok'] else result['reason']))
        print('以上测试没有经过商家 NAT 的公网入口，不能代替另一台设备的连接测试。')
        return not failed


def edit_or_delete(delete=False):
    with rt.lock():
        nodes = rt.load_state()['nodes']
        node = select_node(nodes)
        if delete:
            if ask('删除后该链接失效，输入 DELETE 确认') != 'DELETE':
                return
            nodes.remove(node)
        else:
            node['name'] = valid_name(ask('新名称；UUID、密码和端口保持不变', node['name']))
        rt.commit(nodes)
        # Exports are snapshots; revoke stale generated files on every mutation.
        clear_exports()
        sub_sync = '；公网订阅 URL 已自动同步。' if rt.load_sub_config().get('enabled') else '；单条链接/导出文件需要重新导入。'
        print(('已删除' if delete else '已改名') + sub_sync)


def clear_exports():
    for name in ('links.txt', 'subscription.txt', 'flclash.yaml'):
        (rt.ROOT/'exports'/name).unlink(missing_ok=True)


def restart():
    with rt.lock():
        if not rt.load_state()['nodes']:
            raise ValueError('还没有节点，请先创建。')
        rt.checked([rt.CORE, 'check', '-c', rt.ROOT/'current'/'config.json'], env=rt.core_env())
        rt.service('restart')
        if rt.load_sub_config().get('enabled'):
            rt.service_name('restart', check=False, name=rt.SUB_SERVICE)
        print('已重启，请运行“自测节点”。')


def remove_managed_launchers(directory=Path('/usr/local/bin')):
    """Remove only our launchers; leave the OS nl utility and unrelated commands alone."""
    for name in ('nl', 'NL', 'nodelite', 'subprogress'):
        launcher = directory/name
        try:
            text = launcher.read_text(encoding='utf-8')
        except (OSError, UnicodeError):
            continue
        if '# NodeLite managed launcher' in text.splitlines() and '/opt/nodelite/nodelite.py' in text:
            launcher.unlink(missing_ok=True)


def uninstall():
    print('仅停用 NodeLite，并移走它的配置。不会删除其他面板或原有节点。')
    if ask('输入 UNINSTALL 确认') != 'UNINSTALL':
        return
    with rt.lock():
        rt.service('stop', check=False)
        rt.enable_service(False)
        rt.service_name('stop', check=False, name=rt.SUB_SERVICE)
        rt.enable_service_name(False, name=rt.SUB_SERVICE)
        target = rt.ROOT.with_name(rt.ROOT.name+'.backup-'+str(time.time_ns()))
        rt.ROOT.rename(target)
    for svc in (rt.SERVICE, rt.SUB_SERVICE):
        unit = Path(f'/etc/systemd/system/{svc}.service') if rt.init_system() == 'systemd' else Path(f'/etc/init.d/{svc}')
        unit.unlink(missing_ok=True)
    if rt.init_system() == 'systemd':
        rt.checked(['systemctl', 'daemon-reload'])
    remove_managed_launchers()
    # Installed program retained for recovery; no recursive deletion of arbitrary paths.
    print('服务已卸载，配置备份：'+str(target))
    raise SystemExit(0)


def menu():
    while True:
        print('\nNodeLite（轻节点） '+VERSION+' | 输入 nl 或 NL 随时打开\n'
              '  1. 创建节点（三步引导：检测 → 填端口 → 自测出链）\n'
              '  2. 查看 / 复制分享链接与订阅地址（含验证状态）\n'
              '  3. 导出 FlClash / 通用配置文件\n'
              '  4. 开启 / 管理公网自动更新订阅 URL（支持固定隧道/自有域名）\n'
              '  5. 自测节点能否代理访问网站\n'
              '  6. 查看状态 / 内存明细 / 证书到期 / 排查连接问题\n'
              '  7. 给节点改名（保留原连接凭据）\n'
              '  8. 修改节点端口 / 公网映射（支持 443，自动更新防火墙）\n'
              '  9. 删除一个节点\n'
              '  10. 梳理 / 备份并清理旧版残留服务（区分归属）\n'
              '  11. 升级 / 校验 sing-box 核心（分块校验＋失败自动回滚）\n'
              '  12. 恢复上一版节点配置（回滚）\n'
              '  13. 重启 NodeLite 服务\n'
              '  14. 卸载 NodeLite 服务（保留备份）\n'
              '  0. 退出（节点继续运行，菜单不再占内存）')
        value = ask('输入数字', '0')
        if value == '0':
            return
        actions = {
            '1': creation_wizard,
            '2': show_links,
            '3': exports,
            '4': subscription_menu,
            '5': test_nodes,
            '6': doctor,
            '7': edit_or_delete,
            '8': edit_node_port,
            '9': lambda: edit_or_delete(True),
            '10': legacy_menu,
            '11': upgrade_core_menu,
            '12': rollback_menu,
            '13': restart,
            '14': uninstall,
        }
        try:
            if value not in actions:
                raise ValueError('请输入菜单中的数字。')
            actions[value]()
        except (ValueError, RuntimeError, OSError) as error:
            print('\n未完成：'+str(error))
        input('\n回车返回菜单……')


def main():
    parser = argparse.ArgumentParser(prog='nl', description='NodeLite（轻节点）中文终端节点管理；输入 nl 或 NL 打开菜单')
    parser.add_argument('action', nargs='?', default='menu',
                        choices=['menu', 'links', 'export', 'doctor', 'test', 'restart', 'add',
                                 'port', 'sub', 'upgrade-core', 'legacy', 'rollback'])
    parser.add_argument('--protocol', choices=PROTOCOLS, default='vless')
    parser.add_argument('--host')
    parser.add_argument('--port', type=int)
    parser.add_argument('--public-port', type=int)
    parser.add_argument('--name', default='我的节点')
    parser.add_argument('--node')
    parser.add_argument('--sni', default='www.microsoft.com')
    parser.add_argument('--scheme', choices=['http', 'https'], default='http')
    parser.add_argument('--cert', default='')
    parser.add_argument('--key', default='')
    parser.add_argument('--title', default='NodeLite')
    parser.add_argument('--token')
    parser.add_argument('--cf-tunnel', action='store_true')
    parser.add_argument('--cf-mode', choices=['quick', 'named', 'cdn'], default='quick')
    parser.add_argument('--cf-domain', default='')
    parser.add_argument('--cf-token', default='')
    parser.add_argument('--rotate-token', action='store_true')
    parser.add_argument('--disable', action='store_true')
    parser.add_argument('--version')
    parser.add_argument('--sha256')
    parser.add_argument('--archive')
    parser.add_argument('--cleanup', action='store_true')
    parser.add_argument('--include-third-party', action='store_true')
    parser.add_argument('--accept-self-signed', action='store_true')
    parser.add_argument('--udp-confirmed', action='store_true')
    args = parser.parse_args()
    require_root()
    os.umask(0o077)
    if args.action == 'add':
        if not args.host or not args.port:
            parser.error('add 需要 --host 公网IP --port 内部端口；NAT 另填 --public-port 公网端口')
        if args.protocol in ('hysteria2', 'tuic') and not args.udp_confirmed:
            parser.error('UDP 协议需要 --udp-confirmed 确认公网 UDP 可达')
        if args.protocol in ('trojan', 'hysteria2', 'tuic') and not args.accept_self_signed:
            parser.error('无域名证书时需要 --accept-self-signed；也可用交互菜单选择自己的证书')
        create(new_node(args.protocol, args.name, args.host, args.port, args.public_port, args.sni))
    elif args.action == 'port':
        if not args.node or not args.port:
            parser.error('port 需要 --node 节点ID或名称 --port 新内部端口 [--public-port 新公网端口]')
        updated = rt.update_node_port(args.node, args.port, args.public_port, args.host)
        print(uri(updated))
    elif args.action == 'sub':
        if args.disable:
            rt.disable_subscription()
            print('已关闭在线订阅服务。')
        elif args.rotate_token:
            res = rt.rotate_sub_token()
            print(json.dumps(res['urls'], ensure_ascii=False, indent=2))
        elif args.cf_tunnel or args.cf_domain:
            if args.host and args.port:
                rt.configure_subscription(
                    host=args.host, port=args.port, public_port=args.public_port,
                    scheme=args.scheme, cert=args.cert, key=args.key,
                    self_signed=args.accept_self_signed, title=args.title, token=args.token,
                )
            mode = args.cf_mode
            if args.cf_domain and args.cf_token and mode == 'quick':
                mode = 'named'
            elif args.cf_domain and not args.cf_token and not args.cf_tunnel and mode == 'quick':
                mode = 'cdn'
            res = rt.enable_cf_tunnel(mode=mode, cf_domain=args.cf_domain, cf_token=args.cf_token)
            print(json.dumps(res['urls'], ensure_ascii=False, indent=2))
        else:
            if not args.host or not args.port:
                parser.error('sub 需要 --host 公网IP或域名 --port 内部端口 [--public-port 公网端口]')
            res = rt.configure_subscription(
                host=args.host, port=args.port, public_port=args.public_port,
                scheme=args.scheme, cert=args.cert, key=args.key,
                self_signed=args.accept_self_signed, title=args.title, token=args.token,
            )
            print(json.dumps(res['urls'], ensure_ascii=False, indent=2))
    elif args.action == 'upgrade-core':
        res = rt.upgrade_core(version=args.version or rt.CORE_VERSION, sha256=args.sha256, archive_path=args.archive)
        print(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.action == 'legacy':
        if args.cleanup:
            res = rt.cleanup_legacy_services(include_third_party=args.include_third_party)
        else:
            res = rt.inspect_legacy_services()
        print(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.action == 'rollback':
        restored = rt.rollback_previous()
        print(json.dumps({'restoredCount': len(restored), 'nodes': [n['name'] for n in restored]}, ensure_ascii=False))
    else:
        result = {'menu': menu, 'links': show_links, 'export': exports, 'doctor': doctor,
                  'test': test_nodes, 'restart': restart}[args.action]()
        if result is False:
            return 1
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (EOFError, KeyboardInterrupt):
        print('\n已退出。')
        sys.exit(130)
    except (ValueError, RuntimeError, OSError) as error:
        print('未完成：'+str(error), file=sys.stderr)
        sys.exit(1)

