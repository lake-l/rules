// Read-only subscription endpoint. Cloudflare management credentials never enter this Worker.
import {handleAutomaticRules} from './cloudflare-auto.mjs';
const headers = {
  'Cache-Control': 'private, no-store, max-age=0',
  'CDN-Cache-Control': 'no-store',
  'Cloudflare-CDN-Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};
const reply = (text, status, head = false) => new Response(head ? null : text, {status, headers});
export default {
  async fetch(request, env) {
    const automatic = await handleAutomaticRules(request, env);
    if (automatic) return automatic;
    const url = new URL(request.url), head = request.method === 'HEAD';
    if (url.pathname !== '/mihomo.yaml') return reply('Not found', 404, head);
    const token = url.searchParams.get('token') || '';
    if (!/^[a-f0-9]{64}$/.test(token) || !/^[a-f0-9]{64}$/.test(env.READ_TOKEN_SHA256 || '')) return reply('Unauthorized', 401, head);
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
    const actual = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
    // Both values have fixed length; compare every character.
    let mismatch = 0;
    for (let i = 0; i < actual.length; i++) mismatch |= actual.charCodeAt(i) ^ env.READ_TOKEN_SHA256.charCodeAt(i);
    if (mismatch) return reply('Unauthorized', 401, head);
    if (!['GET', 'HEAD'].includes(request.method)) return new Response('Method not allowed', {status: 405, headers: {...headers, Allow: 'GET, HEAD'}});
    try {
      const config = await env.CONFIG.get('current', 'json');
      if (!config || typeof config.yaml !== 'string' || !config.yaml.trim() || !/^[a-f0-9]{64}$/.test(config.sha256 || '')) return reply('Subscription not published yet', 503, head);
      return new Response(head ? null : config.yaml, {headers: {
        ...headers,
        'Content-Type': 'application/yaml; charset=utf-8',
        'Content-Disposition': 'inline; filename="mihomo.yaml"',
        'profile-update-interval': '6',
        'ETag': '"' + config.sha256 + '"',
        'X-Subscription-Version': config.sha256,
        'X-Subscription-Updated-At': config.updatedAt,
        ...(config.automation ? {'X-Rules-Revision': config.automation.revision} : {}),
      }});
    } catch {
      return reply('Subscription temporarily unavailable', 503, head);
    }
  },
};
