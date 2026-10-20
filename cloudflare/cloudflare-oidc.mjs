export const GITHUB_POLICY = Object.freeze({
  repository: 'lake-l/rules', repositoryId: '1364393721', ownerId: '191877580',
  workflow: 'lake-l/rules/.github/workflows/publish-cloudflare.yml@refs/heads/main',
});
const issuer = 'https://token.actions.githubusercontent.com', jwksURL = issuer + '/.well-known/jwks';
let cachedKeys, cachedAt = 0;
const bytes = text => Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - text.length % 4) % 4)), character => character.charCodeAt(0));
const decode = text => JSON.parse(new TextDecoder().decode(bytes(text)));
export const githubAudience = url => new URL(url).origin + '/internal/rule-publish';

export async function authorizeGitHub(request, {fetcher = fetch, now = Date.now(), policy = GITHUB_POLICY, useCache = true} = {}) {
  try {
    const authorization = request.headers.get('Authorization') || '';
    if (!authorization.startsWith('Bearer ') || authorization.length > 18000) return false;
    const token = authorization.slice(7), parts = token.split('.');
    if (parts.length !== 3 || parts.some(part => !/^[A-Za-z0-9_-]+$/.test(part))) return false;
    const header = decode(parts[0]), claims = decode(parts[1]), seconds = Math.floor(now / 1000);
    if (header.alg !== 'RS256' || header.crit || typeof header.kid !== 'string' || header.kid.length > 128) return false;
    if (claims.iss !== issuer || claims.aud !== githubAudience(request.url) || claims.repository !== policy.repository || String(claims.repository_id) !== policy.repositoryId || String(claims.repository_owner_id) !== policy.ownerId || claims.workflow_ref !== policy.workflow || claims.ref !== 'refs/heads/main' || !['push', 'workflow_run', 'workflow_dispatch'].includes(claims.event_name)) return false;
    const subjects = [`repo:lake-l/rules:ref:refs/heads/main`, `repo:lake-l@${policy.ownerId}/rules@${policy.repositoryId}:ref:refs/heads/main`];
    if (!subjects.includes(claims.sub) || !Number.isFinite(claims.exp) || !Number.isFinite(claims.iat) || !Number.isFinite(claims.nbf) || claims.exp <= seconds || claims.exp > seconds + 660 || claims.iat > seconds + 30 || claims.iat < seconds - 660 || claims.nbf > seconds + 30) return false;
    let keys = useCache && cachedKeys && now - cachedAt < 3600000 ? cachedKeys : null;
    let key = keys?.find(value => value.kid === header.kid);
    if (!key) {
      const response = await fetcher(jwksURL, {redirect: 'error', signal: AbortSignal.timeout(10000)});
      if (!response.ok) return false;
      keys = (await response.json()).keys;
      if (!Array.isArray(keys) || keys.length > 20) return false;
      if (useCache) {cachedKeys = keys; cachedAt = now;}
      key = keys.find(value => value.kid === header.kid);
    }
    if (!key || key.kty !== 'RSA' || key.use !== 'sig' || key.alg && key.alg !== 'RS256') return false;
    const publicKey = await crypto.subtle.importKey('jwk', key, {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'}, false, ['verify']);
    return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, bytes(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1]));
  } catch {return false;}
}
