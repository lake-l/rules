import copy
import base64
import json
import io
import unittest
import publish_cloudflare as publish


class PublisherTests(unittest.TestCase):
    def layout(self):
        return {'schema': 1, 'templateId': 'a' * 64, 'slots': [
            {'slotId': 'slot-0', 'presetId': '__pinned__', 'target': 'DIRECT'},
            {'slotId': 'slot-1', 'presetId': 'preset-2', 'target': 'AI 服务'},
            {'slotId': 'slot-2', 'presetId': 'preset-cn-ip', 'target': '国内网站'},
        ]}

    def test_sources_and_rendering_preserve_target_and_no_resolve(self):
        sources = publish.load_sources()
        body, rules = publish.compile_publication(self.layout(), sources, 'a' * 40, '2026-10-20T00:00:00+00:00')
        self.assertEqual(body['templateId'], 'a' * 64)
        self.assertTrue(body['revision'].startswith('sync-'))
        self.assertTrue(any(rule.endswith(',AI 服务') for rule in rules))
        self.assertEqual(publish.fragment_rules(['IP-CIDR,192.0.2.0/24,no-resolve'], 'DIRECT'), ['IP-CIDR,192.0.2.0/24,DIRECT,no-resolve'])
        for fragment in body['fragments']:
            rows = fragment['content'].strip('\n').split('\n')
            self.assertEqual(len(rows), fragment['count'])
            for row in rows:
                self.assertIsInstance(json.loads(row[4:]), str)

    def test_destinations_cannot_forward_oidc_credentials_elsewhere(self):
        expected = 'https://subscription-studio-012345abcdef.account.workers.dev'
        self.assertEqual(publish.origin(expected + '/'), expected)
        for value in ['http://example.com', 'https://attacker.example', expected + '?token=secret', expected + '/unexpected', 'https://user:pass@subscription-studio-012345abcdef.account.workers.dev', expected + ':443']:
            with self.assertRaises(ValueError):
                publish.origin(value)

    def test_layout_cannot_select_unknown_blocks_or_change_pinned_target(self):
        sources = publish.load_sources()
        for modify in [lambda x: x['slots'][0].update(target='REJECT'), lambda x: x['slots'][1].update(presetId='unknown'), lambda x: x['slots'][1].update(target='bad\nDNS'), lambda x: x['slots'][1].update(slotId='slot-0')]:
            layout = copy.deepcopy(self.layout())
            modify(layout)
            with self.assertRaises(ValueError):
                publish.compile_publication(layout, sources, 'a' * 40, '2026-10-20T00:00:00+00:00')

    def test_destination_is_private_and_required_and_logs_exclude_service_address(self):
        address = 'https://subscription-studio-012345abcdef.private-fixture.workers.dev'
        self.assertEqual(publish.private_destination({'CLOUDFLARE_PUBLISH_ORIGIN': address}), address)
        for environment in [{}, {'CLOUDFLARE_PUBLISH_ORIGIN': ''}, {'CLOUDFLARE_PUBLISH_ORIGIN': address + '?token=forbidden'}, {'CLOUDFLARE_PUBLISH_ORIGIN': 'https://untrusted.example'}]:
            with self.assertRaises(ValueError):
                publish.private_destination(environment)
        result = publish.publish_result({'changed': True, 'revision': 'sync-test', 'url': address, 'yaml': 'private-fixture'})
        self.assertEqual(result, {'changed': True, 'revision': 'sync-test', 'status': 'published'})
        self.assertNotIn(address, json.dumps(result))
        self.assertNotIn('private-fixture', json.dumps(result))

    def test_identity_diagnostics_exclude_credentials_and_unlisted_claims(self):
        claims = {'repository': 'lake-l/rules', 'ref': 'refs/heads/main', 'jti': 'private-credential-id', 'unlisted': 'private-marker'}
        part = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
        header = base64.urlsafe_b64encode(json.dumps({'alg': 'RS256', 'kid': 'public-key'}).encode()).decode().rstrip('=')
        token = header + '.' + part + '.private-signature'
        diagnostic = json.dumps(publish.public_identity_diagnostics(token))
        self.assertTrue(publish.public_identity_diagnostics(token)['matches']['repository'])
        for private in [token, part, 'private-signature', 'private-credential-id', 'private-marker']:
            self.assertNotIn(private, diagnostic)

    def test_failure_diagnostics_keep_only_fixed_phase_and_http_status(self):
        private = 'https://private-worker.example/secret?token=private-fixture'
        for error in [ValueError(private), publish.urllib.error.URLError(private), publish.urllib.error.HTTPError(private, 403, private, {}, None)]:
            output = publish.safe_failure(error, 'layout')
            self.assertNotIn(private, json.dumps(output))
            self.assertEqual(output['stage'], 'layout')
        self.assertEqual(publish.safe_failure(ValueError('Cloudflare publication failed: HTTP 409; previous subscription retained'), 'publish')['http_status'], 409)
        self.assertEqual(publish.safe_failure(ValueError(private), private)['stage'], 'setup')
        error = publish.urllib.error.HTTPError(private, 422, private, {}, io.BytesIO(json.dumps({'error': private}).encode()))
        self.assertEqual(publish.publish_failure_code(error), {'worker_publish_check': 'unavailable'})


if __name__ == '__main__':
    unittest.main()
