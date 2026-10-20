"""Publish public rule fragments using short-lived GitHub OIDC credentials.

The workflow never receives subscription YAML, nodes, provider URLs, DNS,
personal rules, the subscription access key, or a Cloudflare API token.
"""
import argparse
import base64
import datetime as dt
import email.utils
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import sync_rules as sync

ROOT = Path(__file__).resolve().parents[1]
HOST = re.compile(r'^subscription-studio-[a-f0-9]{12}\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.workers\.dev$')
PINNED_TYPES = {'DOMAIN', 'DOMAIN-SUFFIX', 'PROCESS-NAME', 'PROCESS-PATH', 'PROCESS-NAME-REGEX', 'PROCESS-PATH-REGEX'}
PUBLISH_STAGE = 'setup'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Refusing a redirect with workflow credentials')


def origin(value):
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != 'https' or not HOST.fullmatch(parsed.hostname or '') or parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise ValueError('Unexpected Cloudflare destination')
    return 'https://' + parsed.hostname


def request_json(url, method='GET', token=None, data=None):
    headers = {'Accept': 'application/json', 'User-Agent': 'lake-l-rules-automatic-publisher/1.0'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    body = None if data is None else sync.compact(data).encode('utf-8')
    if body is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, method=method, headers=headers, data=body)
    with urllib.request.build_opener(NoRedirect()).open(req, timeout=45) as response:
        content = response.read(1024 * 1024 + 1)
    if len(content) > 1024 * 1024:
        raise ValueError('Unexpected publisher response size')
    return json.loads(content)


def oidc_token(destination):
    issuer_request = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL', '')
    parsed = urllib.parse.urlsplit(issuer_request)
    # The request URL is a trusted GitHub Actions runner variable. Do not accept
    # an arbitrary URL from a repository file or workflow input.
    if parsed.scheme != 'https' or not parsed.hostname or not (parsed.hostname.endswith('.actions.githubusercontent.com') or parsed.hostname.endswith('.actions.github.com')):
        raise ValueError('GitHub OIDC runner endpoint unavailable')
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query.append(('audience', destination + '/internal/rule-publish'))
    url = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query)))
    value = request_json(url, token=os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']).get('value')
    if not isinstance(value, str) or value.count('.') != 2:
        raise ValueError('GitHub did not issue an OIDC token')
    return value


def public_identity_diagnostics(token, destination=''):
    """Log comparison results only, never credentials or arbitrary claim values."""
    try:
        part = token.split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
        expected = {'iss': 'https://token.actions.githubusercontent.com', 'aud': destination + '/internal/rule-publish', 'repository': 'lake-l/rules', 'repository_id': '1364393721', 'repository_owner_id': '191877580', 'workflow_ref': 'lake-l/rules/.github/workflows/publish-cloudflare.yml@refs/heads/main', 'ref': 'refs/heads/main'}
        checks = {key: str(claims.get(key)) == value for key, value in expected.items()}
        checks['event_name'] = claims.get('event_name') in ('push', 'workflow_run', 'workflow_dispatch')
        checks['sub'] = claims.get('sub') in ('repo:lake-l/rules:ref:refs/heads/main', 'repo:lake-l@191877580/rules@1364393721:ref:refs/heads/main')
        header_part = token.split('.')[0]
        header = json.loads(base64.urlsafe_b64decode(header_part + '=' * (-len(header_part) % 4)))
        checks['algorithm'] = header.get('alg') == 'RS256'
        checks['critical_headers_absent'] = not header.get('crit')
        checks['kid_valid'] = isinstance(header.get('kid'), str) and len(header['kid']) <= 128
        now = int(time.time())
        deltas = {key: claims[key] - now if isinstance(claims.get(key), (int, float)) else None for key in ('iat', 'nbf', 'exp')}
        return {'matches': checks, 'seconds_from_now': deltas}
    except (ValueError, IndexError, TypeError):
        return {'metadata': 'unavailable'}


def public_key_diagnostics(token):
    try:
        part = token.split('.')[0]
        header = json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
        keys = request_json('https://token.actions.githubusercontent.com/.well-known/jwks')['keys']
        key = next((key for key in keys if key.get('kid') == header.get('kid')), None)
        signature_ok = False
        if key:
            program = "const fs=require('fs'),c=require('crypto');const x=JSON.parse(fs.readFileSync(0,'utf8'));const p=x.token.split('.');console.log(c.verify('RSA-SHA256',Buffer.from(p[0]+'.'+p[1]),c.createPublicKey({key:x.key,format:'jwk'}),Buffer.from(p[2],'base64url')));"
            signature_ok = subprocess.check_output(['node', '-e', program], input=json.dumps({'token': token, 'key': key}), text=True, timeout=15).strip() == 'true'
        return {'key_found': key is not None, 'key_count_within_limit': len(keys) <= 20, 'key_type_ok': bool(key and key.get('kty') == 'RSA' and key.get('use') == 'sig'), 'signature_valid': signature_ok}
    except Exception:
        return {'public_key_check': 'unavailable'}


def load_sources(root=ROOT):
    snapshot = json.loads((root / 'mihomo/studio-v1/snapshot.json').read_text(encoding='utf-8'))
    blocks = snapshot.get('blocks')
    if snapshot.get('schema') != 1 or not isinstance(blocks, list) or not blocks:
        raise ValueError('Invalid public rule snapshot')
    digest = hashlib.sha256(sync.compact([[b['id'], b['rules']] for b in blocks]).encode()).hexdigest()
    if snapshot.get('revision') != 'sync-' + digest:
        raise ValueError('Public rule snapshot integrity check failed')
    seen = set()
    for block in blocks:
        if block['id'] in seen or not isinstance(block['rules'], list) or not block['rules']:
            raise ValueError('Duplicate or empty public rule block')
        seen.add(block['id'])
        for rule in block['rules']:
            sync.validate_rule(rule)
    pinned = json.loads((root / 'sync/pinned-direct.json').read_text(encoding='utf-8'))
    if not isinstance(pinned, list) or not pinned or len(pinned) > 1000:
        raise ValueError('Invalid pinned direct rules')
    for rule in pinned:
        if not isinstance(rule, str) or rule.split(',', 1)[0] not in PINNED_TYPES or not rule.endswith(',DIRECT') or any(ord(c) < 32 for c in rule):
            raise ValueError('Invalid pinned direct rule')
    revision = 'sync-' + hashlib.sha256(sync.compact([[[b['id'], b['rules']] for b in blocks], pinned]).encode()).hexdigest()
    return snapshot, {b['id']: b['rules'] for b in blocks}, pinned, revision


def fragment_rules(rules, target):
    result = []
    for rule in rules:
        parts = rule.split(',')
        options = []
        while parts and parts[-1] in ('src', 'no-resolve'):
            options.insert(0, parts.pop())
        result.append(','.join(parts + [target] + options))
    return result


def compile_publication(layout, sources, source_commit, committed_at):
    snapshot, blocks, pinned, revision = sources
    if layout.get('schema') != 1 or not re.fullmatch(r'[a-f0-9]{64}', layout.get('templateId', '')) or not isinstance(layout.get('slots'), list) or not layout['slots']:
        raise ValueError('Invalid managed rule layout')
    if not re.fullmatch(r'[a-f0-9]{40}', source_commit):
        raise ValueError('Invalid source commit')
    seen, fragments, all_rules = set(), [], []
    for slot in layout['slots']:
        slot_id, preset_id, target = slot['slotId'], slot['presetId'], slot['target']
        if not re.fullmatch(r'slot-\d+', slot_id) or slot_id in seen or not isinstance(target, str) or not 0 < len(target) <= 128 or re.search(r'[,\r\n\x00]', target):
            raise ValueError('Invalid managed slot')
        seen.add(slot_id)
        if preset_id == '__pinned__':
            if target != 'DIRECT':
                raise ValueError('Pinned direct target cannot change')
            rules = pinned
        else:
            if preset_id not in blocks:
                raise ValueError('Unknown public preset')
            rules = fragment_rules(blocks[preset_id], target)
        content = ''.join('  - ' + json.dumps(rule, ensure_ascii=False) + '\n' for rule in rules)
        fragments.append({'slotId': slot_id, 'presetId': preset_id, 'target': target, 'count': len(rules), 'content': content})
        all_rules.extend(rules)
    updated = max(dt.datetime.fromisoformat(snapshot['updatedAt']), dt.datetime.fromisoformat(committed_at))
    return {'schema': 1, 'templateId': layout['templateId'], 'revision': revision, 'sourceCommit': source_commit, 'sourceUpdatedAt': updated.isoformat(), 'fragments': fragments}, all_rules


def validate_fragments(rules, layout, kernel):
    targets = sorted({slot['target'] for slot in layout['slots']} - {'DIRECT', 'REJECT'})
    config = {'mixed-port': 0, 'dns': {'enable': False}, 'proxy-groups': [{'name': target, 'type': 'select', 'proxies': ['DIRECT']} for target in targets], 'rules': rules + ['MATCH,DIRECT']}
    with tempfile.TemporaryDirectory(prefix='studio-public-rule-check-') as directory:
        file = Path(directory) / 'config.json'
        file.write_text(sync.compact(config), encoding='utf-8')
        result = subprocess.run([str(kernel), '-t', '-d', directory, '-f', str(file)], capture_output=True, text=True, timeout=45)
        if result.returncode:
            raise ValueError('Mihomo rejected public rule fragments; no subscription was published')


def private_destination(environment=None):
    value = (os.environ if environment is None else environment).get('CLOUDFLARE_PUBLISH_ORIGIN', '').strip()
    if not value:
        raise ValueError('CLOUDFLARE_PUBLISH_ORIGIN repository secret is required')
    return origin(value)


def publish_result(result):
    # A private deployment address must never be included in public logs.
    return {'revision': result.get('revision'), 'changed': result.get('changed'), 'status': 'published'}


def safe_failure(error, stage):
    phases = {'setup', 'destination', 'sources', 'commit', 'identity', 'layout', 'compile', 'validate', 'publish'}
    status = error.code if isinstance(error, urllib.error.HTTPError) else None
    if isinstance(error, ValueError):
        match = re.fullmatch(r'Cloudflare (?:layout request|publication) failed: HTTP ([1-5][0-9]{2}); previous subscription retained', str(error))
        if match:
            status = int(match[1])
    return {'status': 'failed', 'stage': stage if stage in phases else 'setup', 'http_status': status if isinstance(status, int) and 100 <= status <= 599 else None, 'previous_subscription': 'retained'}


def publish_failure_code(error):
    codes = {'Invalid rule publication': 'publication', 'Invalid managed rule fragment': 'fragment', 'Unexpected rule removal; previous subscription retained': 'rule_removal', 'Generated subscription exceeds 8 MB': 'size', 'An older or conflicting rule snapshot cannot replace the current version': 'stale', 'Subscription changed during publication; retry with the latest layout': 'concurrent_change'}
    try:
        return codes.get(json.loads(error.read(4096)).get('error'), 'unavailable')
    except (ValueError, TypeError, AttributeError):
        return 'unavailable'


def run(kernel, root=ROOT):
    global PUBLISH_STAGE
    PUBLISH_STAGE = 'destination'
    destination = private_destination()
    PUBLISH_STAGE = 'sources'
    sources = load_sources(root)
    PUBLISH_STAGE = 'commit'
    source_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    committed_at = subprocess.check_output(['git', 'show', '-s', '--format=%cI', 'HEAD'], cwd=root, text=True).strip()
    PUBLISH_STAGE = 'identity'
    token = oidc_token(destination)
    PUBLISH_STAGE = 'layout'
    try:
        layout = request_json(destination + '/internal/rule-layout', token=token)
    except urllib.error.HTTPError as error:
        if error.code == 401:
            # These fields describe this public repository and workflow;
            # neither the signed bearer credential nor private YAML is logged.
            print(sync.compact({'public_workflow_identity': public_identity_diagnostics(token, destination)}))
            print(sync.compact({'public_signing_key': public_key_diagnostics(token)}))
            try:
                response = json.loads(error.read(4096))
                expected_response = response.get('error') == 'GitHub workflow authentication required'
                worker_check = response.get('code')
                if worker_check not in ('token', 'jwt_decode', 'jwt_header', 'identity', 'identity_time', 'jwks_signal', 'jwks_fetch', 'jwks_receiver', 'jwks_timeout', 'jwks_redirect', 'jwks_type', 'jwks_http', 'jwks_document', 'signing_key', 'jwk_import', 'signature'):
                    worker_check = 'unavailable'
            except (ValueError, TypeError):
                expected_response = False
                worker_check = 'unavailable'
            try:
                server_delta = int(email.utils.parsedate_to_datetime(error.headers['Date']).timestamp() - time.time())
            except (ValueError, TypeError, KeyError):
                server_delta = None
            print(sync.compact({'worker_auth_response': expected_response, 'worker_auth_check': worker_check, 'server_clock_delta_seconds': server_delta}))
        raise ValueError(f'Cloudflare layout request failed: HTTP {error.code}; previous subscription retained') from None
    PUBLISH_STAGE = 'compile'
    publication, rules = compile_publication(layout, sources, source_commit, committed_at)
    PUBLISH_STAGE = 'validate'
    validate_fragments(rules, layout, kernel)
    PUBLISH_STAGE = 'publish'
    for attempt in range(3):
        try:
            result = request_json(destination + '/internal/rule-publish', method='POST', token=token, data=publication)
            break
        except urllib.error.HTTPError as error:
            if error.code not in (429, 502, 503, 504) or attempt == 2:
                print(json.dumps({'worker_publish_check': publish_failure_code(error)}))
                raise ValueError(f'Cloudflare publication failed: HTTP {error.code}; previous subscription retained') from None
            time.sleep(2 ** (attempt + 1))
    # Never print the OIDC token, layout, configuration or request body.
    print(json.dumps(publish_result(result), ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.mihomo)
    except Exception as error:
        # Network and parser exceptions may include private addresses. Keep the
        # public failure message fixed; do not emit a traceback or error text.
        print(json.dumps(safe_failure(error, PUBLISH_STAGE)), file=sys.stderr)
        raise SystemExit(1) from None
