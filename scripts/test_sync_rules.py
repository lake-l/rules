import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sync_rules as sync

class SyncTests(unittest.TestCase):
    def test_dns_option_migration_keeps_network_removal_guard(self):
        old = {'blocks': [{'id': 'preset-cn-ip', 'rules': [f'IP-CIDR,192.0.{i}.0/24,no-resolve' for i in range(40)]}]}
        same = [{'id': 'preset-cn-ip', 'rules': [r.replace(',no-resolve', '') for r in old['blocks'][0]['rules']]}]
        sync.check_removals(old, same)
        with self.assertRaisesRegex(ValueError, 'Too many removed'):
            sync.check_removals(old, [{'id': 'preset-cn-ip', 'rules': same[0]['rules'][:10]}])

    def test_network_exclusion_splits_broad_upstream_ranges(self):
        result = sync.exclude_networks(['IP-CIDR,47.0.0.0/8', 'IP-CIDR6,2001:db8::/32,no-resolve'], ['47.52.0.0/16'])
        blocks = [{'id': 'x', 'target': '国内网站', 'rules': result}]
        self.assertEqual(sync.route(blocks, '47.52.1.1'), '默认代理')
        self.assertEqual(sync.route(blocks, '47.53.1.1'), '国内网站')
        self.assertIn('IP-CIDR6,2001:db8::/32,no-resolve', result)

    def test_sync_reapplies_corrections_to_upstream_bodies(self):
        manifest=json.loads((sync.ROOT/'sync/sources.json').read_text(encoding='utf-8'))
        corrections=json.loads((sync.ROOT/'sync/overrides.json').read_text(encoding='utf-8'))
        snapshot=json.loads((sync.OUT/'snapshot.json').read_text(encoding='utf-8'))
        sources={name: [] for name in manifest['sources']}
        for group, block in zip(manifest['groups'], snapshot['blocks']):
            sources[group['sources'][0]]=list(block['rules'])
        # Deliberately reintroduce the offending upstream entries before building.
        sources['25-disney.list'].append('DOMAIN-SUFFIX,shanghaidisneyresort.com')
        sources['13-google.list'].append('DOMAIN-SUFFIX,265.com')
        sources['01-BanAD.list'] += ['DOMAIN-SUFFIX,lufax.com', 'DOMAIN-SUFFIX,jpush.cn', 'DOMAIN-SUFFIX,meiqia.com']
        sources['audit-geoip-cn.list']=[r+',no-resolve' for r in sources['audit-geoip-cn.list']]+['IP-CIDR,47.52.0.0/16,no-resolve']
        built=sync.build(manifest,corrections,sources)
        self.assertEqual(sync.route(built,'www.shanghaidisneyresort.com'),'国内网站')
        self.assertEqual(sync.route(built,'www.lufax.com'),'国内网站')
        self.assertEqual(sync.route(built,'api.jpush.cn'),'国内网站')
        self.assertEqual(sync.route(built,'47.52.1.1'),'默认代理')
        broken=copy.deepcopy(built)
        next(b for b in broken if b['id']=='preset-cn-ip')['rules'][0] += ',no-resolve'
        with self.assertRaisesRegex(ValueError,'must resolve'):
            sync.check_routes(broken)

    def test_domain_and_ip_semantics(self):
        self.assertEqual(sync.parse_lines('+.example.com\napi.example.com\n*.cdn.example.com\n', 'domain'), ['DOMAIN-SUFFIX,example.com', 'DOMAIN,api.example.com', 'DOMAIN-WILDCARD,*.cdn.example.com'])
        self.assertEqual(sync.parse_lines('192.0.2.0/24\n2001:db8::/32', 'ipcidr'), ['IP-CIDR,192.0.2.0/24,no-resolve', 'IP-CIDR6,2001:db8::/32,no-resolve'])
        self.assertEqual(sync.parse_lines('USER-AGENT,old,*\nDOMAIN,example.com,old-policy\nDOMAIN-SUFFIX,invalid.example/path', 'classical'), ['DOMAIN,example.com'])

    def test_invalid_or_empty_download_fails(self):
        for text, behavior in [('<html>error</html>', 'classical'), ('# empty', 'domain'), ('IP-CIDR,0.0.0.0/0', 'classical'), ('UNKNOWN,example.com', 'classical'), ('DOMAIN,bad domain', 'classical')]:
            with self.assertRaises(ValueError):
                sync.parse_lines(text, behavior)

    def test_snapshot_regressions(self):
        snapshot=json.loads((sync.OUT/'snapshot.json').read_text(encoding='utf-8'))
        sync.check_routes(snapshot['blocks'])
        broken=copy.deepcopy(snapshot['blocks'])
        broken[0]['rules'].insert(0,'DOMAIN-SUFFIX,bilibili.com')
        with self.assertRaisesRegex(ValueError,'Routing regression'):
            sync.check_routes(broken)

    def test_failed_download_keeps_existing_output_and_custom_files(self):
        with tempfile.TemporaryDirectory(dir=sync.ROOT,prefix='.sync-test-') as tmp:
            root=Path(tmp)
            self.assertEqual(root.resolve().parent,sync.ROOT.resolve())
            (root/'sync').mkdir()
            out=root/'mihomo/studio-v1'
            out.mkdir(parents=True)
            (root/'sync/sources.json').write_text(json.dumps({'sources':{'x':{}}}),encoding='utf-8')
            (root/'sync/overrides.json').write_text('{}',encoding='utf-8')
            for name in ['preset-0.yaml','snapshot.json','custom-user.yaml']:
                (out/name).write_text('keep',encoding='utf-8')
            with patch.object(sync,'ROOT',root),patch.object(sync,'OUT',out),patch.object(sync,'fetch_source',side_effect=ValueError('download failed')):
                with self.assertRaisesRegex(ValueError,'download failed'):
                    sync.run()
            self.assertTrue(all(p.read_text(encoding='utf-8')=='keep' for p in out.iterdir()))

if __name__=='__main__':
    unittest.main()
