"""Build public Mihomo rules. Nothing is published until every check succeeds."""
import argparse
import concurrent.futures
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'mihomo/studio-v1'
SUPPORTED = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'IP-CIDR', 'IP-CIDR6', 'PROCESS-NAME', 'PROCESS-PATH', 'DST-PORT', 'SRC-PORT'}
SKIP = {'USER-AGENT', 'URL-REGEX'}
def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))

def parse_lines(text, behavior):
    result = []
    if text.lstrip().startswith(('<', '{', '[')):
        raise ValueError('Expected a plain-text rule list')
    for raw in text.splitlines():
        raw = raw.strip().lstrip('\ufeff')
        if not raw or raw.startswith(('#', '//')):
            continue
        if behavior == 'domain':
            if raw.startswith('+.'):
                rule = 'DOMAIN-SUFFIX,' + raw[2:]
            elif '*' in raw or '?' in raw:
                rule = 'DOMAIN-WILDCARD,' + raw
            else:
                rule = 'DOMAIN,' + raw
        elif behavior == 'ipcidr':
            rule = ('IP-CIDR6,' if ':' in raw else 'IP-CIDR,') + raw + ',no-resolve'
        else:
            parts = [s.strip() for s in raw.split(',')]
            kind = parts[0].upper()
            if kind in SKIP:
                continue
            if len(parts) < 2 or kind not in SUPPORTED:
                raise ValueError('Unexpected rule type: ' + kind)
            rest = parts[2:]
            if rest and rest[0] not in ('src', 'no-resolve'):
                rest = rest[1:]  # upstream policy is replaced by our fixed group mapping
            rule = ','.join([kind, parts[1]] + rest)
        # A URL path cannot be matched as a DNS hostname (legacy upstream typo).
        if rule.startswith(('DOMAIN,', 'DOMAIN-SUFFIX,')) and '/' in rule.split(',')[1]:
            continue
        validate_rule(rule)
        result.append(rule)
    if not result:
        raise ValueError('Empty upstream rule list')
    return result

def validate_rule(rule):
    parts = rule.split(',')
    if len(parts) < 2 or parts[0] not in SUPPORTED or not parts[1] or any(p not in ('src', 'no-resolve') for p in parts[2:]):
        raise ValueError('Invalid rule: ' + rule[:100])
    kind, value = parts[:2]
    if any(ord(c) < 32 for c in value):
        raise ValueError('Control character in rule')
    if kind.startswith('DOMAIN') and (re.search(r'\s|[/<>]', value) or value in ('*', '+', '.', '+.')):
        raise ValueError('Invalid domain rule: ' + rule)
    if kind.startswith('IP-CIDR'):
        network = ipaddress.ip_network(value, strict=False)
        if network.prefixlen == 0:
            raise ValueError('Catch-all network is not allowed')

def fetch_source(item, cache):
    name, spec = item
    if cache:
        text = (cache / name).read_text(encoding='utf-8-sig')
    else:
        if not spec['url'].startswith('https://raw.githubusercontent.com/'):
            raise ValueError('Unexpected source host')
        req = urllib.request.Request(spec['url'], headers={'User-Agent': 'lake-l-rules-sync/1.0'})
        with urllib.request.urlopen(req, timeout=30) as response:
            content = response.read(8 * 1024 * 1024 + 1)
        if len(content) > 8 * 1024 * 1024:
            raise ValueError('Source is too large')
        text = content.decode('utf-8-sig')
    rules = parse_lines(text, spec['behavior'])
    if len(rules) < max(1, spec['baselineCount'] * .5) or len(rules) > max(100, spec['baselineCount'] * 2):
        raise ValueError('Unexpected source size: ' + name)
    return name, rules

def route(blocks, domain):
    for block in blocks:
        for rule in block['rules']:
            kind, value, *_ = rule.split(',')
            hit = kind == 'DOMAIN' and value == domain or kind == 'DOMAIN-SUFFIX' and (domain == value or domain.endswith('.' + value)) or kind == 'DOMAIN-KEYWORD' and value in domain
            if kind == 'DOMAIN-WILDCARD':
                hit = re.fullmatch(re.escape(value).replace(r'\*', '.*').replace(r'\?', '.'), domain) is not None
            if hit:
                return block['target']
    return '默认代理'

def check_routes(blocks):
    cases = json.loads((ROOT / 'sync/regressions.json').read_text(encoding='utf-8'))
    for domain, expected in cases.items():
        actual = route(blocks, domain)
        if actual != expected:
            raise ValueError(f'Routing regression: {domain}: {actual} != {expected}')

def build(manifest, overrides, sources):
    blocks = []
    for group in manifest['groups']:
        correction = overrides['groups'][group['id']]
        excluded = set(correction['remove'])
        rows = [r for name in group['sources'] for r in sources[name]]
        rows = [r for r in rows if r not in excluded and r.split(',')[0] not in correction.get('dropTypes', [])]
        rows = list(dict.fromkeys(correction['add'] + rows))
        for rule in rows:
            validate_rule(rule)
        if len(rows) < max(1, group['baselineCount'] * .6) or len(rows) > max(100, group['baselineCount'] * 2):
            raise ValueError('Unexpected group size: ' + group['id'])
        blocks.append({k: group[k] for k in ('id', 'name', 'target')} | {'rules': rows})
    if sum(len(b['rules']) for b in blocks) > 150000:
        raise ValueError('Too many rules')
    check_routes(blocks)
    return blocks

def run(cache=None, kernel=None):
    manifest = json.loads((ROOT / 'sync/sources.json').read_text(encoding='utf-8'))
    overrides = json.loads((ROOT / 'sync/overrides.json').read_text(encoding='utf-8'))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        sources = dict(executor.map(lambda item: fetch_source(item, cache), manifest['sources'].items()))
    blocks = build(manifest, overrides, sources)
    previous_path = OUT / 'snapshot.json'
    if previous_path.exists():
        previous = json.loads(previous_path.read_text(encoding='utf-8'))
        old = {b['id']: set(b['rules']) for b in previous['blocks']}
        for block in blocks:
            before, after = old.get(block['id'], set()), set(block['rules'])
            if before and len(before - after) > max(10, len(before) * .2):
                raise ValueError('Too many removed rules: ' + block['id'])
    revision = 'sync-' + hashlib.sha256(compact([[b['id'], b['rules']] for b in blocks]).encode()).hexdigest()
    snapshot = {'schema': 1, 'revision': revision, 'updatedAt': dt.datetime.now(dt.timezone.utc).isoformat(), 'blocks': blocks}
    if previous_path.exists() and previous.get('revision') == revision:
        snapshot['updatedAt'] = previous['updatedAt']
    files = {b['id'] + '.yaml': '# Generated by scripts/sync_rules.py; edit sync/overrides.json instead.\n# Sources and licenses: SOURCES.txt, LICENSE-META-RULES.txt\npayload:\n' + ''.join('  - ' + json.dumps(r, ensure_ascii=False) + '\n' for r in b['rules']) for b in blocks}
    files['snapshot.json'] = compact(snapshot) + '\n'
    files['sync-status.json'] = json.dumps({'revision': revision, 'updatedAt': snapshot['updatedAt'], 'sources': {k: {'url': manifest['sources'][k]['url'], 'count': len(v)} for k, v in sources.items()}, 'groups': {b['id']: len(b['rules']) for b in blocks}}, ensure_ascii=False, indent=2) + '\n'
    if all((OUT / name).is_file() and (OUT / name).read_bytes() == content.encode('utf-8') for name, content in files.items()):
        print('No effective rule changes; keeping the existing revision')
        return
    with tempfile.TemporaryDirectory(prefix='.studio-rule-check-', dir=ROOT) as tmp:
        tmp = Path(tmp)
        if tmp.resolve().parent != ROOT.resolve():
            raise ValueError('Invalid temporary directory')
        for name, content in files.items():
            (tmp / name).write_text(content, encoding='utf-8', newline='\n')
        if kernel:
            config = {'mixed-port': 0, 'dns': {'enable': False}, 'rule-providers': {b['id']: {'type': 'file', 'behavior': 'classical', 'format': 'yaml', 'path': './' + b['id'] + '.yaml'} for b in blocks}, 'rules': ['RULE-SET,' + b['id'] + ',DIRECT' for b in blocks] + ['MATCH,DIRECT']}
            (tmp / 'config.json').write_text(compact(config), encoding='utf-8')
            subprocess.run([str(kernel), '-t', '-d', str(tmp), '-f', str(tmp / 'config.json')], check=True, timeout=45)
        OUT.mkdir(parents=True, exist_ok=True)
        for name in files:
            # Only the fixed generated names are touched; custom-* and Stash files are never included.
            (OUT / name).write_bytes((tmp / name).read_bytes())
    print(json.dumps({'revision': revision, 'groups': len(blocks), 'rules': sum(len(b['rules']) for b in blocks)}, ensure_ascii=False))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--cache-dir', type=Path)
    parser.add_argument('--mihomo', type=Path)
    args = parser.parse_args()
    run(args.cache_dir, args.mihomo)
