import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sync_rules as sync

class SyncTests(unittest.TestCase):
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
