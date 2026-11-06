import base64
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import protocols as p
import runtime as rt
import nodelite as cli


class BrandingTests(unittest.TestCase):
    def test_new_paths_service_names_and_subscription_title(self):
        self.assertEqual(rt.ROOT, Path('/etc/nodelite'))
        self.assertEqual(rt.CORE, Path('/opt/nodelite/sing-box'))
        self.assertEqual(rt.CLOUDFLARED, Path('/opt/nodelite/cloudflared'))
        self.assertEqual((rt.SERVICE, rt.SUB_SERVICE), ('nodelite', 'nodelite-sub'))
        self.assertEqual(p.subscription_bundle([])['meta']['title'], 'NodeLite')
        for init in ('systemd', 'openrc'):
            self.assertIn('NodeLite', rt.sub_unit_text(init))
            self.assertNotIn('subprogress-lite', rt.sub_unit_text(init))

    def test_uninstall_only_removes_owned_shortcuts(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            managed = '#!/bin/sh\n# NodeLite managed launcher\nexec python3 -B /opt/nodelite/nodelite.py "$@"\n'
            for name in ('nodelite', 'subprogress'):
                (directory/name).write_text(managed, encoding='utf-8')
            (directory/'nl').write_text('unrelated existing command', encoding='utf-8')
            cli.remove_managed_launchers(directory)
            self.assertEqual((directory/'nl').read_text(encoding='utf-8'), 'unrelated existing command')
            self.assertFalse(any((directory/name).exists() for name in ('nodelite', 'subprogress')))

    def test_migrate_from_subprogress_lite_preserves_nodes_certs_and_subscription_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            old_root = base/'subprogress-lite'
            new_root = base/'nodelite'
            rev = old_root/'releases'/'rev-1'
            rev.mkdir(parents=True)
            node = p.new_node(
                'trojan', '迁移节点', '203.0.113.10', 24443, 28538,
                cert='/etc/subprogress-lite/certs/id1/cert.pem',
                key='/etc/subprogress-lite/certs/id1/key.pem',
            )
            rt.write_json(rev/'nodes.json', {'schema': 1, 'nodes': [node]})
            rt.write_json(rev/'config.json', p.server_config([node]))
            with patch.object(rt, 'ROOT', old_root):
                rt.switch_current(rev, old_root/'current')
            sub_tok = p.new_token()
            rt.write_json(old_root/'sub'/'config.json', {
                'enabled': True, 'host': '203.0.113.10', 'port': 20000, 'public_port': 40187,
                'scheme': 'http', 'token': sub_tok, 'title': 'OldLite',
            })

            with patch.object(rt, 'ROOT', new_root), \
                 patch.object(rt, 'CLOUDFLARED', base/'opt'/'cloudflared'):
                res = rt.migrate_from_subprogress_lite(old_root=old_root, old_opt=base/'old-opt', start_services=False)
                self.assertTrue(res['migrated'])
                self.assertEqual(res['nodeCount'], 1)
                migrated_node = rt.load_state()['nodes'][0]
                self.assertEqual(migrated_node['password'], node['password'])
                self.assertTrue(migrated_node['cert'].replace('\\', '/').endswith('/certs/id1/cert.pem'))
                self.assertNotIn('/etc/subprogress-lite', migrated_node['cert'])
                self.assertEqual(rt.load_sub_config()['token'], sub_tok)


class ProtocolTests(unittest.TestCase):
    def make(self, kind, host='203.0.113.10'):
        return p.new_node(kind, '日本 / 备用 & 2', host, 20443, 53440,
                          private_key='a'*43, public_key='b'*43,
                          cert='/test/cert.pem', key='/test/key.pem')

    def test_all_protocol_links_and_inbounds_match(self):
        for kind in p.PROTOCOLS:
            with self.subTest(kind=kind):
                n = self.make(kind)
                i, o, c = p.inbound(n), p.outbound(n), p.clash_proxy(n)
                self.assertEqual(i['listen_port'], 20443)
                self.assertEqual(o['server_port'], 53440)
                self.assertEqual(c['port'], 53440)
                self.assertEqual(p.outbound(n, True)['server_port'], 20443)
                self.assertTrue(p.uri(n).startswith({'ss2022': 'ss'}.get(kind, kind)+'://'))
                self.assertNotIn(n['private_key'], p.uri(n))
                self.assertEqual(c['name'], n['name'])

    def test_ipv6_names_reality_auth_and_subscription_urls(self):
        n = self.make('vless', '2001:db8::abc')
        u = urlsplit(p.uri(n))
        self.assertEqual(u.hostname, '2001:db8::abc')
        self.assertEqual(u.port, 53440)
        self.assertEqual(unquote(u.fragment), n['name'])
        self.assertEqual(parse_qs(u.query)['pbk'], [n['public_key']])
        self.assertEqual(p.inbound(n)['listen'], '::')
        self.assertEqual(p.outbound(n, True)['server'], '::1')
        tok = p.new_token()
        urls = p.subscription_urls({'host': '2001:db8::abc', 'port': 20000, 'public_port': 40187,
                                    'scheme': 'https', 'token': tok})
        self.assertEqual(urls['flclash'], f'https://[2001:db8::abc]:40187/s/{tok}/flclash.yaml')
        self.assertEqual(urls['links'], f'https://[2001:db8::abc]:40187/s/{tok}/links.txt')

    def test_invalid_input_port_443_allowed_and_distinct_secrets(self):
        for host in ['127.0.0.1', '0.0.0.0', '::', '169.254.1.2', '10.10.1.34', '192.168.1.1',
                     '100.64.1.2', 'fc00::1', 'x;reboot']:
            with self.assertRaises(ValueError): p.valid_host(host)
        for port in [0, 22, 25, 1023, 65536, 'abc']:
            with self.assertRaises(ValueError): p.valid_port(port)
        self.assertEqual(p.valid_port(443), 443)
        self.assertEqual(p.valid_port(80), 80)
        self.assertEqual(p.valid_port(1024), 1024)
        self.assertEqual(p.valid_sub_host('sub.example.com'), 'sub.example.com')
        self.assertEqual(p.valid_sub_host('203.0.113.10'), '203.0.113.10')
        with self.assertRaises(ValueError): p.valid_name('x\nshutdown')
        with self.assertRaises(ValueError): p.valid_sni('x.com;reboot')
        self.assertNotEqual(self.make('vless')['uuid'], self.make('vless')['uuid'])

    def test_real_cert_does_not_disable_validation(self):
        for kind in ['trojan', 'hysteria2', 'tuic']:
            n = self.make(kind)
            n['self_signed'] = False
            self.assertNotIn('insecure', p.uri(n).lower())
            self.assertFalse(p.clash_proxy(n)['skip-cert-verify'])
            self.assertFalse(p.outbound(n)['tls']['insecure'])

    def test_vmess_roundtrip_and_ss_key(self):
        n = self.make('vmess')
        payload = json.loads(base64.b64decode(p.uri(n).split('://')[1]))
        self.assertEqual((payload['id'], payload['path']), (n['uuid'], n['ws_path']))
        self.assertEqual(len(base64.b64decode(self.make('ss2022')['ss_password'])), 16)

    def test_rename_preserves_connection(self):
        n = self.make('vless')
        before = p.inbound(n)
        n['name'] = '新名称'
        self.assertEqual(p.inbound(n), before)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [patch.object(rt, 'ROOT', self.root), patch.object(rt, 'check_ports'),
                        patch.object(rt, 'checked'), patch.object(rt, 'enable_service'),
                        patch.object(rt, 'service_enabled', return_value=False),
                        patch.object(rt.time, 'sleep')]
        for p_ in self.patches: p_.start()
        self.node = p.new_node('ss2022', '节点', '203.0.113.10', 30001)
        self.service = patch.object(rt, 'service', return_value=True).start()
        self.addCleanup(patch.stopall)
        self.addCleanup(self.tmp.cleanup)

    def test_success_commits_test_evidence(self):
        with patch.object(rt, 'self_test', return_value={'ok': True, 'scope': 'local'}):
            rt.commit([self.node], [self.node['id']])
        state = rt.load_state()
        self.assertTrue(state['nodes'][0]['self_test']['ok'])
        self.assertEqual(state['nodes'][0]['self_test']['scope'], 'local')

    def test_bad_config_leaves_previous_revision_running(self):
        rt.commit([self.node])
        before = (self.root/'current').resolve()
        with patch.object(rt, 'checked', side_effect=RuntimeError('invalid config')):
            with self.assertRaises(RuntimeError): rt.commit([self.node])
        self.assertEqual((self.root/'current').resolve(), before)

    def test_failed_protocol_probe_restores_old_revision(self):
        rt.commit([self.node])
        before = (self.root/'current').resolve()
        candidate = copy.deepcopy(self.node)
        candidate['password'] = 'new'
        with patch.object(rt, 'self_test', return_value={'ok': False, 'reason': 'probe failed'}):
            with self.assertRaisesRegex(RuntimeError, 'probe failed'):
                rt.commit([candidate], [candidate['id']])
        self.assertEqual((self.root/'current').resolve(), before)
        self.assertNotEqual(rt.load_state()['nodes'][0]['password'], 'new')
        self.service.assert_any_call('start')

    def test_failed_initial_start_removes_current(self):
        def fail_restart(action, **kwargs):
            if action == 'restart': raise RuntimeError('failed start')
            return False if action == 'status' else True
        self.service.side_effect = fail_restart
        with self.assertRaises(RuntimeError): rt.commit([self.node])
        self.assertFalse((self.root/'current').exists())
        self.assertEqual(rt.load_state()['nodes'], [])

    def test_delete_removes_listener_and_keeps_one_backup(self):
        rt.commit([self.node])
        rt.commit([])
        self.assertEqual(rt.load_state()['nodes'], [])
        self.assertEqual(json.loads((self.root/'current/config.json').read_text())['inbounds'], [])
        self.assertEqual(len(list((self.root/'releases').iterdir())), 2)
        self.service.assert_any_call('stop')

    def test_failed_probe_restores_boot_setting_and_exports(self):
        rt.commit([self.node])
        directory = self.root/'exports'
        directory.mkdir()
        (directory/'links.txt').write_text('old exported link')
        with patch.object(rt, 'self_test', return_value={'ok': False, 'reason': 'fail'}), \
             patch.object(rt, 'service_enabled', return_value=True):
            with self.assertRaises(RuntimeError): rt.commit([self.node], [self.node['id']])
        rt.enable_service.assert_called_with(True)
        self.assertEqual((directory/'links.txt').read_text(), 'old exported link')

    def test_successful_change_revokes_stale_exports(self):
        rt.commit([self.node])
        directory = self.root/'exports'
        directory.mkdir()
        (directory/'links.txt').write_text('old exported link')
        self.node['name'] = 'changed'
        rt.commit([self.node])
        self.assertFalse((directory/'links.txt').exists())


class SubscriptionAndSyncTests(unittest.TestCase):
    """Cross-platform tests for Lite public subscription URL, HTTPS, token rotation, and live node sync."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [
            patch.object(rt, 'ROOT', self.root),
            patch.object(rt, 'checked', return_value=''),
            patch.object(rt, 'service', return_value=True),
            patch.object(rt, 'service_name', return_value=True),
            patch.object(rt, 'enable_service'),
            patch.object(rt, 'enable_service_name'),
            patch.object(rt, 'service_enabled', return_value=True),
            patch.object(rt, 'self_test', return_value={'ok': True, 'scope': 'local', 'latency_ms': 18}),
            patch.object(rt.time, 'sleep'),
        ]
        for p_ in self.patches:
            p_.start()
        self.addCleanup(patch.stopall)
        self.addCleanup(self.tmp.cleanup)

    def test_subscription_http_and_https_and_live_sync_on_add_rename_port_delete(self):
        vless_port = rt.free_tcp_port()
        vless = p.new_node('vless', '日本-VLESS', '203.0.113.10', vless_port, 53440,
                           private_key='a'*43, public_key='b'*43)
        rt.commit([vless], [vless['id']])
        sub_port = rt.free_tcp_port()
        cfg = rt.configure_subscription('203.0.113.10', sub_port, 40187, scheme='http',
                                        title='轻量订阅', start_daemon=False)
        server = rt.create_sub_server(self.root/'sub', bind='127.0.0.1', port=sub_port)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            manifest = rt.check_sub_local(cfg, port=sub_port)
            self.assertEqual(manifest['nodeCount'], 1)
            conn = http.client.HTTPConnection('127.0.0.1', sub_port, timeout=3)
            conn.request('GET', f"/s/{cfg['token']}/flclash.yaml")
            r = conn.getresponse()
            yaml_data = json.loads(r.read().decode('utf-8'))
            self.assertEqual(r.status, 200)
            self.assertEqual(yaml_data['proxies'][0]['name'], '日本-VLESS')
            self.assertEqual(yaml_data['proxies'][0]['port'], 53440)
            conn.close()

            # Wrong token returns 404
            conn = http.client.HTTPConnection('127.0.0.1', sub_port, timeout=3)
            conn.request('GET', '/s/wrong_token_00000000000000000000000000/flclash.yaml')
            self.assertEqual(conn.getresponse().status, 404)
            conn.close()

            # Modify port (including port 443) -> automatically syncs subscription
            new_int_port = rt.free_tcp_port()
            updated = rt.update_node_port(vless['id'], new_int_port, 443)
            self.assertEqual(updated['port'], new_int_port)
            self.assertEqual(updated['public_port'], 443)
            self.assertEqual(updated['uuid'], vless['uuid'])
            self.assertEqual(updated['public_key'], vless['public_key'])

            conn = http.client.HTTPConnection('127.0.0.1', sub_port, timeout=3)
            conn.request('GET', f"/s/{cfg['token']}/links.txt")
            b64_body = conn.getresponse().read().decode('utf-8')
            conn.close()
            decoded_uri = base64.b64decode(b64_body).decode('utf-8')
            self.assertIn(':443?', decoded_uri)

            # Rotate token -> old token returns 404, new token returns 200
            old_token = cfg['token']
            rotated = rt.rotate_sub_token(start_daemon=False)
            self.assertNotEqual(rotated['token'], old_token)
            conn = http.client.HTTPConnection('127.0.0.1', sub_port, timeout=3)
            conn.request('GET', f'/s/{old_token}/flclash.yaml')
            self.assertEqual(conn.getresponse().status, 404)
            conn.close()
            conn = http.client.HTTPConnection('127.0.0.1', sub_port, timeout=3)
            conn.request('GET', f"/s/{rotated['token']}/flclash.yaml")
            self.assertEqual(conn.getresponse().status, 200)
            conn.close()

            # Concurrent load test on subscription server (16 requests across 4 threads)
            def fetch_sub(_):
                c = http.client.HTTPConnection('127.0.0.1', sub_port, timeout=3)
                try:
                    c.request('GET', f"/s/{rotated['token']}/flclash.yaml")
                    return c.getresponse().status
                finally:
                    c.close()

            with ThreadPoolExecutor(max_workers=4) as pool:
                statuses = list(pool.map(fetch_sub, range(16)))
            self.assertEqual(statuses, [200]*16)

            # Delete all nodes -> subscription serves 503 for config so clients don't wipe working profiles
            rt.commit([])
            conn = http.client.HTTPConnection('127.0.0.1', sub_port, timeout=3)
            conn.request('GET', f"/s/{rotated['token']}/flclash.yaml")
            self.assertEqual(conn.getresponse().status, 503)
            conn.close()
        finally:
            server.shutdown()
            server.server_close()

        # Verify HTTPS subscription with embedded test certificate (self-contained on any host)
        test_cert_pem = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIC9DCCAdygAwIBAgIUGySZ/MxyUC/5WwngUr3oZc6U7hUwDQYJKoZIhvcNAQEL\n"
            "BQAwIDEeMBwGA1UEAwwVU3ViUHJvZ3Jlc3MgVEVTVCBPTkxZMCAXDTIwMDEwMTAw\n"
            "MDAwMFoYDzIxMjAwMTAxMDAwMDAwWjAgMR4wHAYDVQQDDBVTdWJQcm9ncmVzcyBU\n"
            "RVNUIE9OTFkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdAJMcKKY0\n"
            "W3NoluwCN+6mUUfv4EmVEAId/sdXL6HDWDK1UjH6NqOkPKheK21YQf96+5a6lPC4\n"
            "1GP6dJ3aobodKkhCU0WB1DSdXe2bij6EWvn/ZU8dXg4pmKfwlSXmmufqKEnqZWY4\n"
            "IHlryCJHOrrC3c1LBIylFtbSyvEsdf1gApr5wgOTWmWN9rJB0hJ5aifLWiRtFfXO\n"
            "PfHlY69+Os3YF3+/b64ISpbBvN30O48IULBSZ/V6Y15i2zL3G87UjRME/gGVE+8t\n"
            "QZeopjRGQtFzOauqFER6WWQ2m0kZeGfD48l6J5IPIRZt4USLRaqlakIfEbi+XLVY\n"
            "at0FJVO3YvpXAgMBAAGjJDAiMA8GA1UdEQQIMAaHBH8AAAEwDwYDVR0TAQH/BAUw\n"
            "AwEB/zANBgkqhkiG9w0BAQsFAAOCAQEABZlnuNyJ9UYTdh9CCpodDMoAzAnvSTv3\n"
            "6a6aSntURNkSMvjW/XF+NBDenbmBRctkQpMY4h2Yi+o0V4gGNXUtWBlwIbyBo42z\n"
            "GzDUjFoHlqsTBiXd1g1LFkMJcXYx6zGulXdv/7wWKx8NjPuYQj+dzxxDxZulNRW7\n"
            "ndtGp5lxHbvVXrfT8NVrjT87qjPTTPU+TcVHlpOhn49KC3ZKlh7gw6sUDx9HB64Q\n"
            "d9BPMVYysihd0AL3cbDLyRy1AUYCfTb2nPxe/Gp5OZzNqQeVTgJujKRFt+KZsvxh\n"
            "svj6A6jxPdktHDGX5DWKLEr03VSZyomm+SDjzEo7QIe4nbJsJIAwAg==\n"
            "-----END CERTIFICATE-----\n"
        )
        test_key_pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA3QCTHCimNFtzaJbsAjfuplFH7+BJlRACHf7HVy+hw1gytVIx\n"
            "+jajpDyoXittWEH/evuWupTwuNRj+nSd2qG6HSpIQlNFgdQ0nV3tm4o+hFr5/2VP\n"
            "HV4OKZin8JUl5prn6ihJ6mVmOCB5a8giRzq6wt3NSwSMpRbW0srxLHX9YAKa+cID\n"
            "k1pljfayQdISeWony1okbRX1zj3x5WOvfjrN2Bd/v2+uCEqWwbzd9DuPCFCwUmf1\n"
            "emNeYtsy9xvO1I0TBP4BlRPvLUGXqKY0RkLRczmrqhREellkNptJGXhnw+PJeieS\n"
            "DyEWbeFEi0WqpWpCHxG4vly1WGrdBSVTt2L6VwIDAQABAoIBABhjplh+sezoRMG/\n"
            "mhcalhc7tB0oWuZ86EboJZadFpSIyLvS8NoEqqWG3ivaTgxl6Cxp1HYN1s0G/2uV\n"
            "8A+/Nltena/YIb0UrqPJSF4YcRLJOXqycvsyNIzpoGsAArlC0iI4xQN9ojzCdLPs\n"
            "17+VnyO/N5c2TtEvRpDnvZrjAI3WNyQozbUCxvBgj5cweXUsj7x56OG5bHqMEB+x\n"
            "AHmpR2h5/xk/h7RcZDeV2BLTS4NE2unMJ4LPlLIyub/klZffJZ4t6FBjmXelambV\n"
            "SiYmlRyw0iijOjlMoyVSw2D6NcX6QosySIOPeltKMi1lf7j4DIPHrhPQAArYvAYm\n"
            "49mB+u0CgYEA/yN837GNCE76x+DdB4gMdnOE+rg16YBDIPtOjdWnC+/Va8u+rp9z\n"
            "69xfXAvCydBS45migZ7ek6nWejnQMxHiRHlCVDUueXNs1s40hN9gjOOPnjOm1ioF\n"
            "ZVUn4stXVmNlgwOPvSsRcmuURoYRsy0FCGkwfMZx4d2jICSFNf0njM0CgYEA3b+V\n"
            "VYN0jtkGyH8Bg7nGtxf0sBl+nS46bxbRgH7oR7ZD085cqz4BmZIPIrSD8Ygvawqs\n"
            "vELD1N8W4aujg6zWU4iwLIF45/UEV110bdDMK+qCidzQVOYOo7hgj9nwenFSoal7\n"
            "DCGq8U3MT+My+KzFhS4qXfLaWsABLAq7Vd5po7MCgYEAql4WGoFC/ZNPnnym20qb\n"
            "l9UXrRuo1F0TdkiZcdiDDVN/HdYVZCGRlKO5AYvQ7FYxo02J2Cgv1EaKs187iX6d\n"
            "qr+V7Qj+GZdbzCwxobBPloS1+BvhggzZQYsVcTn6/fKtbEjKiLTjl5YCkv0fgJfF\n"
            "TpJ/EDKrBPms3d/FHAIJkNkCgYANxkPZfwPzh6mzNKh8bULZxsQtWDgUPXXlxq4W\n"
            "5Es7gSfvdUcuX/ireHY2Oq5jh4kihhQ60Y7mn0EFnarXmBnsMHZ5HUXMatztLGH6\n"
            "HFlCdRvMwomybGQGaYKeDPSyNm3imuuI0mKTALkrUTquVdUjM73v/hDwSDMKcFQ4\n"
            "vksjnwKBgH8LPjhgMIGd9dj2Drf8N1IyoDe99vex/9OnVZ/czLzKMXBxbCTFGp3/\n"
            "oDA7n2fpm8pGtudPknvgl/KFtlXR90O+3MD87QI2piMQ1RR//z2uzgW8Qdyha5Ku\n"
            "UyCAuirLs8EqXHgByJv2n89OE2VfANzcFkhpT6VF8xGrmQ9s8iem\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        cert_file = self.root/'test-cert.pem'
        key_file = self.root/'test-key.pem'
        cert_file.write_text(test_cert_pem, encoding='utf-8')
        key_file.write_text(test_key_pem, encoding='utf-8')
        rt.commit([vless], [vless['id']])
        tls_port = rt.free_tcp_port()
        tls_cfg = rt.configure_subscription('sub.example.com', tls_port, tls_port, scheme='https',
                                            cert=str(cert_file), key=str(key_file), start_daemon=False)
        tls_server = rt.create_sub_server(self.root/'sub', bind='127.0.0.1', port=tls_port)
        t2 = threading.Thread(target=tls_server.serve_forever, daemon=True)
        t2.start()
        try:
            manifest = rt.check_sub_local(tls_cfg, port=tls_port)
            self.assertEqual(manifest['nodeCount'], 1)
        finally:
            tls_server.shutdown()
            tls_server.server_close()

    def test_rotate_token_permanently_revokes_legacy_and_editing_sub_preserves_cf_settings(self):
        legacy_tok = 'legacy_migrated_token_0123456789abcdef012345'
        (self.root/'legacy_sub_token').write_text(legacy_tok+'\n', encoding='utf-8')
        vmess = p.new_node('vmess', '节点-VMess', '203.0.113.10', rt.free_tcp_port(), 24055)
        rt.commit([vmess], [vmess['id']])
        sub_port = rt.free_tcp_port()
        initial_tok = p.new_token()
        cfg = rt.configure_subscription('203.0.113.10', sub_port, 40187, scheme='http',
                                        title='初始订阅', token=initial_tok, start_daemon=False)
        self.assertEqual(cfg['legacy_token'], legacy_tok)

        # Configure permanent CDN domain -> sets cf_mode='cdn', cf_domain='sub.example.com'
        with patch.object(rt, 'run'):
            cf_cfg = rt.enable_cf_tunnel(mode='cdn', cf_domain='sub.example.com')
        self.assertEqual(cf_cfg['cf_mode'], 'cdn')
        self.assertEqual(cf_cfg['cf_domain'], 'sub.example.com')

        # Editing subscription settings (e.g. changing title) MUST preserve cf_mode & cf_domain
        edited = rt.configure_subscription('203.0.113.10', sub_port, 40187, scheme='http',
                                           title='新标题', start_daemon=False)
        self.assertEqual(edited['cf_mode'], 'cdn')
        self.assertEqual(edited['cf_domain'], 'sub.example.com')
        self.assertIn('cf_flclash', edited['urls'])

        # Rotate token -> both initial_tok AND legacy_tok must return 404, even after subsequent syncs!
        rotated = rt.rotate_sub_token(start_daemon=False)
        rt.sync_subscription(manage_service=False)
        # If subscription service fails to start during sync_subscription(manage_service=True), error is surfaced
        with patch.object(rt, 'service_name', side_effect=RuntimeError('sub daemon down')):
            with self.assertRaisesRegex(RuntimeError, '在线订阅服务同步/启动失败'):
                rt.sync_subscription(manage_service=True)
        server = rt.create_sub_server(self.root/'sub', bind='127.0.0.1', port=sub_port)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            for bad in (initial_tok, legacy_tok):
                c = http.client.HTTPConnection('127.0.0.1', sub_port, timeout=3)
                c.request('GET', f'/s/{bad}/flclash.yaml')
                self.assertEqual(c.getresponse().status, 404)
                c.close()
            c = http.client.HTTPConnection('127.0.0.1', sub_port, timeout=3)
            c.request('GET', f"/s/{rotated['token']}/flclash.yaml")
            self.assertEqual(c.getresponse().status, 200)
            c.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_rollback_previous_revision_and_4_stage_node_status(self):
        first = p.new_node('ss2022', '第一版节点', '203.0.113.10', 29001)
        second = p.new_node('ss2022', '第二版节点', '203.0.113.10', 29002)
        rt.commit([first], [first['id']])
        stages = rt.node_status_stages(rt.load_state()['nodes'][0], core_active=True)
        self.assertTrue(stages['localSelfTestOk'])
        self.assertFalse(stages['publicClientVerified'])
        self.assertIn('待手机/电脑客户端导入验证', stages['summary'])
        rt.commit([second], [second['id']])
        self.assertEqual(rt.load_state()['nodes'][0]['name'], '第二版节点')
        restored = rt.rollback_previous()
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0]['name'], '第一版节点')
        self.assertEqual(rt.load_state()['nodes'][0]['name'], '第一版节点')


class MaintenanceAndPlatformTests(unittest.TestCase):
    """Tests for multi-arch core upgrade/rollback, systemd/OpenRC, firewall, and legacy service cleanup."""

    def test_multi_arch_detection(self):
        self.assertEqual(rt.detect_arch('x86_64'), 'amd64')
        self.assertEqual(rt.detect_arch('aarch64'), 'arm64')
        self.assertEqual(rt.detect_arch('arm64'), 'arm64')
        self.assertEqual(rt.detect_arch('armv7l'), 'armv7')
        self.assertEqual(rt.detect_arch('i686'), '386')
        with self.assertRaises(RuntimeError):
            rt.detect_arch('mips64')

    def test_core_upgrade_verifies_sha256_and_rolls_back_on_probe_failure(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            core_path = base/'opt'/'sing-box'
            core_path.parent.mkdir(parents=True)
            core_path.write_bytes(b'old-core-binary')

            buf = io.BytesIO()
            fake_new = b'new-core-binary-v1.14.4'
            with tarfile.open(fileobj=buf, mode='w:gz') as tar:
                info = tarfile.TarInfo('sing-box-1.14.4-linux-arm64/sing-box')
                info.size = len(fake_new)
                info.mode = 0o700
                tar.addfile(info, io.BytesIO(fake_new))
            archive_file = base/'core.tar.gz'
            archive_file.write_bytes(buf.getvalue())
            digest = hashlib.sha256(buf.getvalue()).hexdigest()

            with patch.object(rt, 'ROOT', base/'etc'), patch.object(rt, 'CORE', core_path), \
                 patch.object(rt, 'checked', return_value='sing-box version 1.14.4'), \
                 patch.object(rt, 'current_core_version', return_value='1.14.4'), \
                 patch.object(rt, 'service', return_value=True):
                # 1. Wrong SHA-256 is rejected before modifying existing core
                with self.assertRaisesRegex(RuntimeError, 'SHA-256'):
                    rt.upgrade_core('1.14.4', sha256='0'*64, archive_path=archive_file, arch='arm64')
                self.assertEqual(core_path.read_bytes(), b'old-core-binary')

                # 2. Successful upgrade replaces binary and creates .bak
                res = rt.upgrade_core('1.14.4', sha256=digest, archive_path=archive_file, arch='arm64')
                self.assertTrue(res['upgraded'])
                self.assertEqual(core_path.read_bytes(), fake_new)
                self.assertEqual((core_path.parent/'sing-box.bak').read_bytes(), b'old-core-binary')

                # 3. Failed self_test on active node rolls back to previous binary
                core_path.write_bytes(b'working-core')
                node = p.new_node('vless', '节点', '203.0.113.10', 20443, private_key='a'*43, public_key='b'*43)
                with patch.object(rt, 'load_state', return_value={'schema': 1, 'nodes': [node]}), \
                     patch.object(rt, 'self_test', return_value={'ok': False, 'reason': 'quic error'}), \
                     patch.object(rt.time, 'sleep'):
                    with self.assertRaisesRegex(RuntimeError, '已自动回滚'):
                        rt.upgrade_core('1.14.4', sha256=digest, archive_path=archive_file, arch='arm64')
                self.assertEqual(core_path.read_bytes(), b'working-core')

    def test_systemd_and_openrc_service_and_firewall_commands(self):
        calls = []
        def fake_run(args, **kw):
            cmd = [str(x) for x in args]
            calls.append(cmd)
            out = 'Status: active\n' if cmd[:2] == ['ufw', 'status'] else ''
            return subprocess.CompletedProcess(cmd, 0, out, '')

        with patch.object(rt, 'run', side_effect=fake_run), \
             patch.object(rt, 'init_system', return_value='systemd'), \
             patch.object(shutil, 'which', side_effect=lambda name: '/usr/sbin/ufw' if name == 'ufw' else None):
            self.assertTrue(rt.service('status', check=False))
            rt.enable_service(True)
            node = p.new_node('hysteria2', 'UDP节点', '203.0.113.10', 28443)
            msg = rt.firewall(node)
            self.assertIn('28443/udp', msg)
            self.assertIn(['systemctl', 'is-active', '--quiet', 'nodelite'], calls)
            self.assertIn(['systemctl', 'enable', 'nodelite'], calls)
            self.assertIn(['ufw', 'allow', '28443/udp'], calls)

    def test_legacy_service_inspection_backup_and_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            legacy_dir = base/'subprogress-auto'
            legacy_dir.mkdir()
            (legacy_dir/'config.json').write_text('{"inbounds":[]}', encoding='utf-8')
            third_dir = base/'usr-sing-box'
            third_dir.mkdir()
            (third_dir/'config.json').write_text('{}', encoding='utf-8')
            token_file = base/'old-token'
            tok = 'legacy_token_1234567890123456789012345678'
            token_file.write_text(tok, encoding='utf-8')

            stop_calls = []
            def track_svc(action, check=True, name=''):
                if action == 'stop':
                    stop_calls.append(name)
                return True

            with patch.object(rt, 'ROOT', base/'lite'), \
                 patch.dict(rt.LEGACY_SERVICES, {
                     'subprogress-auto': [str(legacy_dir)],
                     'subprogress-sub': [str(token_file)],
                     'sing-box': [str(third_dir)],
                 }, clear=True), \
                 patch.object(rt, 'discover_legacy_sub_token', return_value=tok), \
                 patch.object(rt, 'service_name', side_effect=track_svc), \
                 patch.object(rt, 'service_enabled_name', return_value=True), \
                 patch.object(rt, 'enable_service_name'):
                found = rt.inspect_legacy_services()
                self.assertEqual(len(found), 3)

                # 1. If backup fails, cleanup MUST abort BEFORE stopping any service
                stop_calls.clear()
                with patch.object(shutil, 'copytree', side_effect=OSError('disk full')):
                    with self.assertRaisesRegex(RuntimeError, '备份旧服务'):
                        rt.cleanup_legacy_services(backup_root=base/'backups-fail')
                self.assertEqual(stop_calls, [])

                # 2. By default, third-party 'sing-box' is skipped while SubProgress legacy services are stopped
                cleaned = rt.cleanup_legacy_services(backup_root=base/'backups')
                self.assertTrue(cleaned['recoveredSubToken'])
                self.assertIn('subprogress-auto', cleaned['stoppedServices'])
                self.assertNotIn('sing-box', cleaned['stoppedServices'])
                self.assertIn('sing-box', cleaned['skippedThirdParty'])
                self.assertTrue((Path(cleaned['backupDir'])/'manifest.json').exists())
                self.assertEqual((base/'lite'/'legacy_sub_token').read_text(encoding='utf-8').strip(), tok)


class MemoryTests(unittest.TestCase):
    def test_cgroup_does_not_count_inactive_file_cache_as_pinned_ram(self):
        files = {'/proc/meminfo': 'MemTotal: 187500 kB\nMemAvailable: 150000 kB\n',
                 '/sys/fs/cgroup/memory.max': '192000000',
                 '/sys/fs/cgroup/memory.current': '150000000',
                 '/sys/fs/cgroup/memory.stat': 'anon 31000000\ninactive_file 30000000\n'}
        with patch.object(Path, 'exists', lambda path: str(path).replace('\\', '/') in files), \
             patch.object(Path, 'read_text', lambda path: files[str(path).replace('\\', '/')]):
            memory = rt.memory_info()
        self.assertEqual(memory['MemTotal'], 183.1)
        self.assertEqual(memory['MemAvailable'], round(72000000/1048576, 1))


class PortTests(unittest.TestCase):
    def test_bound_port_is_not_silently_replaced(self):
        with socket.socket() as listener:
            listener.bind(('0.0.0.0', 0))
            listener.listen()
            n = p.new_node('ss2022', '节点', '203.0.113.10', listener.getsockname()[1])
            with self.assertRaisesRegex(RuntimeError, '不能使用'):
                rt.check_ports([n], [])

    def test_duplicate_names_ports_and_ssh_or_sub_collision(self):
        a = p.new_node('ss2022', 'same', '203.0.113.10', 29990, 40001)
        b = p.new_node('ss2022', 'same', '203.0.113.10', 29991, 40002)
        with self.assertRaises(ValueError): rt.check_ports([a, b], [])
        b['name'], b['port'] = 'other', a['port']
        with self.assertRaises(ValueError): rt.check_ports([a, b], [])
        # Duplicate public port on same transport is also rejected with actionable guidance
        b['port'], b['public_port'] = 29992, a['public_port']
        with self.assertRaisesRegex(ValueError, '节点公网端口'):
            rt.check_ports([a, b], [])
        # Colliding with SSH public port or subscription port is rejected with clear message
        with patch.object(rt, 'detect_ssh_ports', return_value={'internal': 22, 'public': 23932}), \
             patch.object(rt, 'load_sub_config', return_value={'enabled': True, 'port': 20000, 'public_port': 40187}):
            ssh_collision = p.new_node('vless', 'ssh误填', '203.0.113.10', 10086, 23932)
            with self.assertRaisesRegex(ValueError, 'SSH 公网登录端口'):
                rt.check_ports([ssh_collision], [])
            sub_collision = p.new_node('vless', '订阅冲突', '203.0.113.10', 20000, 53440)
            with self.assertRaisesRegex(ValueError, '在线订阅服务占用'):
                rt.check_ports([sub_collision], [])


class V030OptimizationTests(unittest.TestCase):
    def test_china_direct_routing_rules_in_clash_config(self):
        vless = p.new_node('vless', '日本直连', '203.0.113.10', 10086, 53440, public_key='pub_k')
        cfg = p.clash_config([vless])
        self.assertIn('dns', cfg)
        self.assertTrue(cfg['dns']['enable'])
        self.assertEqual(cfg['dns']['enhanced-mode'], 'fake-ip')
        rules = cfg['rules']
        self.assertIn('DOMAIN-SUFFIX,cn,DIRECT', rules)
        self.assertIn('DOMAIN-SUFFIX,qianwen.com,DIRECT', rules)
        self.assertIn('DOMAIN-KEYWORD,qianwen,DIRECT', rules)
        self.assertIn('DOMAIN-SUFFIX,bilibili.com,DIRECT', rules)
        self.assertIn('DOMAIN-SUFFIX,taobao.com,DIRECT', rules)
        self.assertIn('DOMAIN-SUFFIX,qq.com,DIRECT', rules)
        self.assertIn('GEOSITE,cn,DIRECT', rules)
        self.assertIn('GEOIP,CN,DIRECT', rules)
        self.assertNotIn('GEOIP,CN,DIRECT,no-resolve', rules)
        self.assertEqual(rules[-1], 'MATCH,节点选择')
        group_names = [g['name'] for g in cfg['proxy-groups']]
        self.assertIn('节点选择', group_names)
        self.assertIn('国内直连', group_names)

    def test_external_node_aggregation_and_dialer_proxy_relay_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'nodelite'
            with patch.object(rt, 'ROOT', root), \
                 patch.object(rt, 'CORE', Path(tmp)/'sing-box'), \
                 patch.object(rt, 'checked', return_value=''), \
                 patch.object(rt, 'service', return_value=True), \
                 patch.object(rt, 'service_enabled', return_value=True), \
                 patch.object(rt, 'enable_service'), \
                 patch.object(rt, 'service_name', return_value=True), \
                 patch.object(rt, 'enable_service_name'), \
                 patch.object(rt, 'install_sub_unit'):
                jp_node = p.new_node('vless', '日本入口', '104.251.231.39', rt.free_tcp_port(), 53440, public_key='jp_pbk', private_key='jp_priv')
                rt.commit([jp_node])
                sub_cfg = rt.configure_subscription('104.251.231.39', rt.free_tcp_port(), 40187, start_daemon=False)

                # Generate external node URIs from a second VPS (US) across protocols
                us_vless_orig = p.new_node('vless', '美西VLESS落地', '38.49.55.238', 10086, 37460, public_key='us_pbk')
                us_hy2_orig = p.new_node('hysteria2', '美西HY2落地', '38.49.55.238', 28443, 20381)
                us_vmess_orig = p.new_node('vmess', '美西VMess', '38.49.55.238', 23457, 20381)

                ext1 = rt.add_external_node(p.uri(us_vless_orig))
                ext2 = rt.add_external_node(p.uri(us_hy2_orig))
                ext3 = rt.add_external_node(p.uri(us_vmess_orig))
                self.assertEqual(ext1['name'], '美西VLESS落地')
                self.assertEqual(ext2['protocol'], 'hysteria2')
                self.assertEqual(ext3['protocol'], 'vmess')

                # Add a dialer-proxy relay chain: 日本入口 -> 美西VLESS落地
                chain = rt.add_relay_chain('日本入口', '美西VLESS落地', chain_name='🔗 日本中转美西')
                self.assertEqual(chain['front'], '日本入口')
                self.assertEqual(chain['exit'], '美西VLESS落地')

                # Verify the synchronized subscription YAML includes local, external, and dialer-proxy relay nodes
                yaml_data = json.loads((root/'sub'/'current'/'clash.yaml').read_text(encoding='utf-8'))
                proxies_by_name = {px['name']: px for px in yaml_data['proxies']}
                self.assertIn('日本入口', proxies_by_name)
                self.assertIn('美西VLESS落地', proxies_by_name)
                self.assertIn('美西HY2落地', proxies_by_name)
                self.assertIn('美西VMess', proxies_by_name)
                self.assertIn('🔗 日本中转美西', proxies_by_name)
                relay_px = proxies_by_name['🔗 日本中转美西']
                self.assertEqual(relay_px['dialer-proxy'], '日本入口')
                self.assertEqual(relay_px['server'], '38.49.55.238')
                self.assertEqual(relay_px['port'], 37460)

                # Removing external node also cleans up dependent relay chain
                rt.remove_external_node('美西VLESS落地')
                yaml_after = json.loads((root/'sub'/'current'/'clash.yaml').read_text(encoding='utf-8'))
                names_after = {px['name'] for px in yaml_after['proxies']}
                self.assertNotIn('美西VLESS落地', names_after)
                self.assertNotIn('🔗 日本中转美西', names_after)

    def test_reality_sni_auto_probe_picks_fastest_tls13_domain(self):
        fake_latencies = {
            'www.microsoft.com': {'sni': 'www.microsoft.com', 'ok': True, 'latency_ms': 38.5, 'tls': 'TLSv1.3'},
            'www.apple.com': {'sni': 'www.apple.com', 'ok': True, 'latency_ms': 1.4, 'tls': 'TLSv1.3'},
            'gateway.icloud.com': {'sni': 'gateway.icloud.com', 'ok': True, 'latency_ms': 2.1, 'tls': 'TLSv1.3'},
            'www.amd.com': {'sni': 'www.amd.com', 'ok': False, 'reason': 'timeout'},
        }
        res = rt.probe_reality_sni_candidates(
            candidates=list(fake_latencies.keys()),
            probe_fn=lambda d: fake_latencies[d],
        )
        self.assertEqual(res['best'], 'www.apple.com')
        self.assertEqual(res['bestLatencyMs'], 1.4)

        # Fallback when all probes fail
        fallback = rt.probe_reality_sni_candidates(
            candidates=['www.apple.com'],
            probe_fn=lambda d: {'sni': d, 'ok': False, 'reason': 'offline'},
        )
        self.assertEqual(fallback['best'], 'www.microsoft.com')

    def test_github_self_update_verifies_sha256_and_hot_updates_scripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            opt_dir = base/'opt'
            opt_dir.mkdir()
            (opt_dir/'nodelite.py').write_text("VERSION = '0.2.0'\n", encoding='utf-8')
            (opt_dir/'runtime.py').write_text("# old runtime\n", encoding='utf-8')
            (opt_dir/'protocols.py').write_text("# old protocols\n", encoding='utf-8')

            # Build a fake installer bundle with VERSION = '0.3.0'
            import io, tarfile, gzip
            buf = io.BytesIO()
            with gzip.GzipFile(filename='', mode='wb', fileobj=buf, mtime=0) as gz:
                with tarfile.open(fileobj=gz, mode='w') as tf:
                    for fname, content in [
                        ('nodelite.py', b"VERSION = '0.3.0'\n"),
                        ('runtime.py', b"# new runtime 0.3.0\n"),
                        ('protocols.py', b"# new protocols 0.3.0\n"),
                    ]:
                        info = tarfile.TarInfo(fname)
                        info.size = len(content)
                        tf.addfile(info, io.BytesIO(content))
            b64_payload = base64.b64encode(buf.getvalue()).decode('ascii')
            installer_file = base/'nodelite.run'
            installer_file.write_text(
                f"#!/bin/sh\nbase64 -d <<'PAYLOAD' | tar -xzf - -C \"$target\"\n{b64_payload}\nPAYLOAD\n",
                encoding='utf-8',
            )
            good_hash = hashlib.sha256(installer_file.read_bytes()).hexdigest()

            with patch.object(rt, 'ROOT', base/'etc'):
                # 1. Mismatched SHA-256 must abort without overwriting existing files
                with self.assertRaisesRegex(RuntimeError, 'SHA-256 校验不一致'):
                    rt.self_update_from_github(
                        installer_path=installer_file,
                        sha256_text='0'*64 + '  nodelite.run\n',
                        install_dir=opt_dir,
                    )
                self.assertIn('0.2.0', (opt_dir/'nodelite.py').read_text(encoding='utf-8'))

                # 2. Matching SHA-256 atomically updates scripts and keeps .bak backups
                res = rt.self_update_from_github(
                    installer_path=installer_file,
                    sha256_text=f'{good_hash}  nodelite.run\n',
                    install_dir=opt_dir,
                )
                self.assertTrue(res['updated'])
                self.assertEqual(res['previousVersion'], '0.2.0')
                self.assertEqual(res['currentVersion'], '0.3.0')
                self.assertIn('0.3.0', (opt_dir/'nodelite.py').read_text(encoding='utf-8'))
                self.assertTrue((opt_dir/'nodelite.py.bak').is_file())

                # 3. Verify against the real dist/nodelite.run built by build.py
                real_dist = Path(__file__).resolve().parents[2]/'dist'
                if (real_dist/'nodelite.run').is_file():
                    res_real = rt.self_update_from_github(
                        installer_path=real_dist/'nodelite.run',
                        sha256_text=(real_dist/'nodelite.run.sha256').read_text(encoding='utf-8'),
                        install_dir=opt_dir,
                    )
                    self.assertTrue(res_real['updated'])
                    self.assertEqual(res_real['currentVersion'], '0.3.0')


if __name__ == '__main__':
    unittest.main()

