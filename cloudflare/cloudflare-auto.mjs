import {authorizeGitHub} from './cloudflare-oidc.mjs';
const hash = async text => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))), byte => byte.toString(16).padStart(2, '0')).join('');
const reply = (status, data) => new Response(JSON.stringify(data), {status, headers: {'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'}});
const bad = (status, message) => reply(status, {error: message});
async function readBody(request) {
  if (Number(request.headers.get('Content-Length')) > 12 * 1024 * 1024) throw Error('Body too large');
  const reader = request.body?.getReader(); if (!reader) throw Error('Missing body');
  const chunks = []; let size = 0;
  while (true) {const value = await reader.read(); if (value.done) break; size += value.value.length; if (size > 12 * 1024 * 1024) {await reader.cancel(); throw Error('Body too large');} chunks.push(value.value);}
  const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) {bytes.set(chunk, offset); offset += chunk.length;}
  return JSON.parse(new TextDecoder().decode(bytes));
}
const validFragment = content => {
  if (typeof content !== 'string' || !content.endsWith('\n')) return false;
  const rows = content.slice(0, -1).split('\n');
  return rows.length > 0 && rows.every(row => /^  - "(?:[^"\\\r\n]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"$/.test(row));
};
export async function handleAutomaticRules(request, env, authorize = authorizeGitHub) {
  const path = new URL(request.url).pathname;
  if (!['/internal/rule-layout', '/internal/rule-publish'].includes(path)) return null;
  let failureCode = 'identity';
  if (!await authorize(request, {onFailure: code => failureCode = code})) return reply(401, {error: 'GitHub workflow authentication required', code: failureCode});
  if (path === '/internal/rule-layout' && request.method !== 'GET' || path === '/internal/rule-publish' && request.method !== 'POST') return bad(405, 'Method not allowed');
  try {
    const template = await env.CONFIG.get('automation-template', 'json');
    if (!template?.enabled || template.schema !== 1 || !Array.isArray(template.slots)) return bad(409, 'Automatic publishing has not been enabled for this subscription');
    const current = await env.CONFIG.get('current', 'json');
    if (!current?.yaml || current.sha256 !== template.baseHash && current.automation?.templateId !== template.id) return bad(409, 'Configuration changed manually; re-enable automatic publishing for the new configuration');
    if (path === '/internal/rule-layout') {
      // Return only managed rule IDs and policy labels. Private YAML, personal
      // rules, upstream URLs, nodes and DNS never leave Cloudflare for CI.
      return reply(200, {schema: 1, templateId: template.id, revision: current.automation?.revision || template.baseRevision, slots: template.slots.map(({slotId, presetId, target}) => ({slotId, presetId, target}))});
    }
    const body = await readBody(request);
    if (body.schema !== 1 || body.templateId !== template.id || !/^sync-[a-f0-9]{64}$/.test(body.revision || '') || !/^[a-f0-9]{40}$/.test(body.sourceCommit || '') || !Number.isFinite(Date.parse(body.sourceUpdatedAt)) || !Array.isArray(body.fragments) || body.fragments.length !== template.slots.length) return bad(422, 'Invalid rule publication');
    const previousAt = Date.parse(current.automation?.sourceUpdatedAt || template.sourceUpdatedAt), nextAt = Date.parse(body.sourceUpdatedAt);
    const previousRevision = current.automation?.revision || template.baseRevision;
    if (nextAt < previousAt || nextAt === previousAt && body.revision !== previousRevision) return bad(409, 'An older or conflicting rule snapshot cannot replace the current version');
    if (body.revision === previousRevision && current.automation?.templateId === template.id) return reply(200, {changed: false, sha256: current.sha256, revision: previousRevision});
    const fragments = new Map(), counts = {};
    for (const slot of template.slots) {
      const fragment = body.fragments.find(value => value.slotId === slot.slotId);
      if (!fragment || fragments.has(slot.slotId) || fragment.presetId !== slot.presetId || fragment.target !== slot.target || !Number.isInteger(fragment.count) || fragment.count < 1 || !validFragment(fragment.content)) return bad(422, 'Invalid managed rule fragment');
      const actualCount = fragment.content.match(/\n/g)?.length || 0;
      if (actualCount !== fragment.count || actualCount < Math.floor((current.automation?.counts?.[slot.slotId] || slot.baselineCount) * 0.6)) return bad(422, 'Unexpected rule removal; previous subscription retained');
      fragments.set(slot.slotId, fragment.content); counts[slot.slotId] = actualCount;
    }
    // A first activation on the same snapshot only records provenance; preserve
    // the existing file exactly until there is a real rule change.
    const yaml = body.revision === previousRevision ? current.yaml : template.prefix + template.segments.map(segment => segment.slotId ? fragments.get(segment.slotId) : segment.literal).join('') + template.suffix;
    if (new TextEncoder().encode(yaml).length > 8 * 1024 * 1024) return bad(422, 'Generated subscription exceeds 8 MB');
    const latest = await env.CONFIG.get('current', 'json');
    if (latest?.sha256 !== current.sha256 || latest?.automation?.revision !== current.automation?.revision) return bad(409, 'Subscription changed during publication; retry with the latest layout');
    const updatedAt = body.revision === previousRevision ? current.updatedAt : new Date().toISOString(), sha256 = body.revision === previousRevision ? current.sha256 : await hash(yaml);
    const result = {yaml, sha256, updatedAt, automation: {templateId: template.id, revision: body.revision, sourceUpdatedAt: body.sourceUpdatedAt, sourceCommit: body.sourceCommit, counts, publishedAt: new Date().toISOString()}};
    const payload = JSON.stringify(result); if (new TextEncoder().encode(payload).length > 25 * 1024 * 1024) return bad(422, 'Storage size limit exceeded');
    await env.CONFIG.put('current', payload);
    return reply(200, {changed: sha256 !== current.sha256, sha256, revision: body.revision, updatedAt});
  } catch {return bad(503, 'Automatic publication failed; retry without clearing the current subscription');}
}
