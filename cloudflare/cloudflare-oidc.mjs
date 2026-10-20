export const GITHUB_POLICY = Object.freeze({
  repository: 'lake-l/rules', repositoryId: '1364393721', ownerId: '191877580',
  workflow: 'lake-l/rules/.github/workflows/publish-cloudflare.yml@refs/heads/main',
});
const issuer = 'https://token.actions.githubusercontent.com', jwksURL = issuer + '/.well-known/jwks';
let cachedKeys, cachedAt = 0;
const bytes = text => Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - text.length % 4) % 4)), character => character.charCodeAt(0));
const decode = text => JSON.parse(new TextDecoder().decode(bytes(text)));
export const githubAudience = url => new URL(url).origin + '/internal/rule-publish';

export async function authorizeGitHub(request, {fetcher = (url, init) => globalThis.fetch(url, init), now = Date.now(), policy = GITHUB_POLICY, useCache = true, onFailure} = {}) {
  let stage = 'token';
  const deny = code => {onFailure?.(code); return false;};
  try {
    const authorization = request.headers.get('Authorization') || '';
    if (!authorization.startsWith('Bearer ') || authorization.length > 18000) return deny(stage);
    const token = authorization.slice(7), parts = token.split('.');
    if (parts.length !== 3 || parts.some(part => !/^[A-Za-z0-9_-]+$/.test(part))) return deny(stage);
    stage = 'jwt_decode';
    const header = decode(parts[0]), claims = decode(parts[1]), seconds = Math.floor(now / 1000);
    if (header.alg !== 'RS256' || header.crit || typeof header.kid !== 'string' || header.kid.length > 128) return deny('jwt_header');
    if (claims.iss !== issuer || claims.aud !== githubAudience(request.url) || claims.repository !== policy.repository || String(claims.repository_id) !== policy.repositoryId || String(claims.repository_owner_id) !== policy.ownerId || claims.workflow_ref !== policy.workflow || claims.ref !== 'refs/heads/main' || !['push', 'workflow_run', 'workflow_dispatch'].includes(claims.event_name)) return deny('identity');
    const subjects = [`repo:lake-l/rules:ref:refs/heads/main`, `repo:lake-l@${policy.ownerId}/rules@${policy.repositoryId}:ref:refs/heads/main`];
    if (!subjects.includes(claims.sub) || !Number.isFinite(claims.exp) || !Number.isFinite(claims.iat) || !Number.isFinite(claims.nbf) || claims.exp <= seconds || claims.exp > seconds + 660 || claims.iat > seconds + 30 || claims.iat < seconds - 660 || claims.nbf > seconds + 30) return deny('identity_time');
    let keys = useCache && cachedKeys && now - cachedAt < 3600000 ? cachedKeys : null;
    let key = keys?.find(value => value.kid === header.kid);
    if (!key) {
      stage = 'jwks_signal';
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10000);
      let response;
      try {
        stage = 'jwks_fetch';
        response = await fetcher(jwksURL, {redirect: 'manual', signal: controller.signal, headers: {'User-Agent': 'subscription-studio-oidc/1.7.1', Accept: 'application/json'}});
      } finally {clearTimeout(timer);}
      if (!response.ok) return deny('jwks_http');
      stage = 'jwks_document';
      keys = (await response.json()).keys;
      if (!Array.isArray(keys) || keys.length > 20) return deny(stage);
      if (useCache) {cachedKeys = keys; cachedAt = now;}
      key = keys.find(value => value.kid === header.kid);
    }
    if (!key || key.kty !== 'RSA' || key.use !== 'sig' || key.alg && key.alg !== 'RS256') return deny('signing_key');
    stage = 'jwk_import';
    const publicKey = await crypto.subtle.importKey('jwk', {kty: 'RSA', n: key.n, e: key.e, alg: 'RS256', ext: true}, {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'}, false, ['verify']);
    stage = 'signature';
    return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, bytes(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1])) || deny(stage);
  } catch (error) {
    // Fixed diagnostics only: never reflect a token, request or exception text.
    if (stage === 'jwks_fetch') {
      const message = String(error?.message || '');
      if (/illegal invocation|receiver|this.*fetch/i.test(message)) stage = 'jwks_receiver';
      else if (/abort|timed? ?out/i.test(message)) stage = 'jwks_timeout';
      else if (/redirect/i.test(message)) stage = 'jwks_redirect';
      else if (error?.name === 'TypeError') stage = 'jwks_type';
    }
    return deny(stage);
  }
}
