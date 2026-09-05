import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { request as httpsRequest } from "node:https";

const PORT = Number(process.env.PORT || 10000);
const UPSTASH_URL = (process.env.UPSTASH_REDIS_REST_URL || "").replace(/\/$/, "");
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || "";
const SYNC_KEY = process.env.SYNC_HMAC_KEY || "";
const LICENSES = parseLicenses(process.env.KAGUYA_LICENSES_JSON || "{}");
const GITHUB_TOKEN = process.env.KAGUYA_GITHUB_TOKEN || "";
const UPDATE_REPOSITORY = process.env.KAGUYA_UPDATE_REPOSITORY || "up1z/Kaguya-Mod";
const DEVICE_PEPPER = process.env.KAGUYA_DEVICE_PEPPER || "";
const ADMIN_TOKEN = process.env.KAGUYA_ADMIN_TOKEN || "";
const PROXY_TOKEN = process.env.KAGUYA_PROXY_TOKEN || "";
const PROXY_LEASE_SECONDS = 150;
const PROXY_OBSERVATION_TTL_SECONDS = 180;
const MAX_BODY = 16 * 1024;
const CLOCK_SKEW_MS = 120_000;
const STALE_SECONDS = 7 * 24 * 60 * 60;
const MAX_CLIENTS_PER_SERVER = 64;
const WORKER_TARGETS = Object.freeze({ alt3: "alt3.6b6t.org", "2b2t": "connect.2b2t.org", hvhtiers: "hvhtiers.org" });
const workerCommands = [];
const workerWaiters = new Set();
let workerStatus = { online: false, state: "unknown", target: "", updatedAt: 0 };

// One EVAL invocation performs replay protection, rate limiting, state update,
// stale-client pruning, and retrieval. Upstash bills this as one command.
const SYNC_LUA = `
local now = tonumber(ARGV[1])
local client = ARGV[2]
local payload = ARGV[3]
local cutoff = tonumber(ARGV[4])
local maximum = tonumber(ARGV[5])

if not redis.call('SET', KEYS[2], '1', 'EX', 300, 'NX') then
  return redis.error_reply('REPLAY')
end

local rate = redis.call('INCR', KEYS[3])
if rate == 1 then redis.call('EXPIRE', KEYS[3], 60) end
if rate > 10 then return redis.error_reply('RATE_LIMIT') end

redis.call('HSET', KEYS[1], client, tostring(now) .. '|' .. payload)
redis.call('EXPIRE', KEYS[1], 604800)
local entries = redis.call('HGETALL', KEYS[1])
local active = {}
local result = {}
for index = 1, #entries, 2 do
  local field = entries[index]
  local value = entries[index + 1]
  local separator = string.find(value, '|', 1, true)
  local updated = separator and tonumber(string.sub(value, 1, separator - 1)) or 0
  if updated < cutoff then
    redis.call('HDEL', KEYS[1], field)
  elseif separator then
    table.insert(active, { field, updated, string.sub(value, separator + 1) })
  end
end
table.sort(active, function(a, b) return a[2] > b[2] end)
for index, entry in ipairs(active) do
  if index <= maximum then
    table.insert(result, entry[3])
  else
    redis.call('HDEL', KEYS[1], entry[1])
  end
end
return result
`;

function json(response, status, value) {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(body)
  });
  response.end(body);
}

function validEnvironment() {
  return UPSTASH_URL.startsWith("https://") && UPSTASH_TOKEN.length >= 16 && SYNC_KEY.length >= 16;
}

function parseLicenses(value) {
  try { const parsed = JSON.parse(value); return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {}; }
  catch { return {}; }
}

function deviceIdentity(body) {
  if (!body || !/^[0-9a-f]{64}$/.test(body.hwid || "") || typeof body.license !== "string" || body.license.length < 32) return null;
  const licenseHash = createHash("sha256").update(body.license).digest("hex");
  return { licenseHash, deviceId: createHmac("sha256", DEVICE_PEPPER).update(body.hwid).digest("hex") };
}

async function authorizeDevice(body, createPending = false) {
  if (DEVICE_PEPPER.length < 32) throw Object.assign(new Error("device_auth_not_configured"), { status: 503 });
  const identity = deviceIdentity(body);
  if (!identity) return { authorized: false, deviceId: "invalid" };
  const active = await postUpstash(["HGET", "kaguya:auth:licenses", identity.licenseHash]);
  if (active.status >= 200 && active.status < 300 && typeof active.value.result === "string") {
    try { if (JSON.parse(active.value.result).deviceId === identity.deviceId) return { authorized: true, deviceId: identity.deviceId }; }
    catch { /* deny invalid records */ }
  }
  if (LICENSES[identity.licenseHash] === body.hwid) return { authorized: true, deviceId: identity.deviceId };
  if (createPending) {
    const count = await postUpstash(["HLEN", "kaguya:auth:pending"]);
    if (Number(count.value.result || 0) >= 512) throw Object.assign(new Error("pending_queue_full"), { status: 429 });
    await postUpstash(["HSET", "kaguya:auth:pending", identity.deviceId, JSON.stringify({ licenseHash: identity.licenseHash, requestedAt: Date.now() })]);
    await postUpstash(["EXPIRE", "kaguya:auth:pending", 604800]);
  }
  return { authorized: false, deviceId: identity.deviceId };
}

function adminAuthorized(request) {
  if (ADMIN_TOKEN.length < 32) return false;
  const supplied = String(request.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const a = Buffer.from(supplied), b = Buffer.from(ADMIN_TOKEN);
  return a.length === b.length && timingSafeEqual(a, b);
}

function proxyAuthorized(request) {
  if (PROXY_TOKEN.length < 32) return false;
  const supplied = String(request.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const a = Buffer.from(supplied), b = Buffer.from(PROXY_TOKEN);
  return a.length === b.length && timingSafeEqual(a, b);
}

function takeWorkerCommand() {
  return workerCommands.shift() || null;
}

function queueWorkerCommand(command) {
  if (workerCommands.length >= 16) workerCommands.shift();
  workerCommands.push(command);
  for (const wake of workerWaiters) wake();
  workerWaiters.clear();
}

async function waitForWorkerCommand(timeoutMs = 25_000) {
  const immediate = takeWorkerCommand();
  if (immediate) return immediate;
  await new Promise(resolve => {
    const timer = setTimeout(() => { workerWaiters.delete(wake); resolve(); }, timeoutMs);
    const wake = () => { clearTimeout(timer); resolve(); };
    workerWaiters.add(wake);
  });
  return takeWorkerCommand();
}

function validWorkerCommand(body) {
  if (!body || !["connect", "disconnect", "status"].includes(body.action)) return false;
  return body.action !== "connect" || Object.hasOwn(WORKER_TARGETS, body.target);
}

function sanitizeWorkerStatus(body) {
  const state = ["starting", "menu", "connecting", "connected", "disconnected", "error"].includes(body?.state)
    ? body.state : "unknown";
  const target = Object.hasOwn(WORKER_TARGETS, body?.target) ? body.target : "";
  return { online: true, state, target, detail: String(body?.detail || "").slice(0, 160), updatedAt: Date.now() };
}

function sourceIpv4(request) {
  const candidate = String(request.headers["x-forwarded-for"] || request.socket.remoteAddress || "").split(",")[0].trim().replace(/^::ffff:/, "");
  const parts = candidate.split(".");
  return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255) ? candidate : "";
}

async function renewProxyLease(request, body) {
  const authorization = await authorizeDevice(body, false);
  if (!authorization.authorized) return authorization;
  const ip = sourceIpv4(request);
  if (!ip) throw Object.assign(new Error("public_ipv4_required"), { status: 400 });
  const expiresAt = Math.floor(Date.now() / 1000) + PROXY_LEASE_SECONDS;
  await postUpstash(["HSET", "kaguya:proxy:leases", authorization.deviceId,
    JSON.stringify({ ip, expiresAt })]);
  await postUpstash(["EXPIRE", "kaguya:proxy:leases", 86400]);
  return { authorized: true, expiresAt };
}

async function activeProxyLeases() {
  const upstream = await postUpstash(["HGETALL", "kaguya:proxy:leases"]);
  const values = upstream.value.result || [], now = Math.floor(Date.now() / 1000), ips = new Set();
  for (let i = 0; i < values.length; i += 2) {
    try {
      const lease = JSON.parse(values[i + 1]);
      if (lease.expiresAt > now && sourceIpv4({ headers: { "x-forwarded-for": lease.ip }, socket: {} })) ips.add(lease.ip);
      else await postUpstash(["HDEL", "kaguya:proxy:leases", values[i]]);
    } catch { await postUpstash(["HDEL", "kaguya:proxy:leases", values[i]]); }
  }
  return [...ips];
}

function validProxyObservation(body) {
  if (!body || typeof body !== "object" || !Array.isArray(body.targets)) return false;
  if (!Number.isSafeInteger(body.measuredAt) || Math.abs(Date.now() - body.measuredAt) > 120_000) return false;
  return body.targets.length === 3 && body.targets.every(target =>
    ["alt3", "2b2t", "hvhtiers"].includes(target.id)
    && Number.isFinite(target.rttMs) && target.rttMs >= 0 && target.rttMs <= 30_000
    && Number.isFinite(target.failureRate) && target.failureRate >= 0 && target.failureRate <= 1);
}

async function storeProxyObservation(body) {
  if (!validProxyObservation(body)) throw Object.assign(new Error("invalid_proxy_observation"), { status: 400 });
  const sanitized = {
    measuredAt: body.measuredAt,
    targets: body.targets.map(target => ({
      id: target.id, rttMs: Math.round(target.rttMs),
      jitterMs: Math.max(0, Math.round(Number(target.jitterMs) || 0)),
      failureRate: Math.round(target.failureRate * 1000) / 1000,
      samples: Math.max(1, Math.min(60, Math.round(Number(target.samples) || 1)))
    }))
  };
  await postUpstash(["SET", "kaguya:proxy:observation", JSON.stringify(sanitized), "EX", PROXY_OBSERVATION_TTL_SECONDS]);
  return sanitized;
}

async function proxyObservation() {
  const upstream = await postUpstash(["GET", "kaguya:proxy:observation"]);
  if (typeof upstream.value.result !== "string") return { available: false, targets: [] };
  const stored = JSON.parse(upstream.value.result);
  return { available: Date.now() - stored.measuredAt <= PROXY_OBSERVATION_TTL_SECONDS * 1000,
    measuredAt: stored.measuredAt, targets: stored.targets || [] };
}

async function adminDevices() {
  const [active, pending] = await Promise.all([postUpstash(["HGETALL", "kaguya:auth:licenses"]), postUpstash(["HGETALL", "kaguya:auth:pending"])]);
  const decode = (values, state) => { const result=[]; for(let i=0;i<(values||[]).length;i+=2){try{const record=JSON.parse(values[i+1]);result.push({key:values[i],state,...record,deviceId:record.deviceId||values[i]})}catch{}} return result };
  return [...decode(active.value.result, "active"), ...decode(pending.value.result, "pending")];
}

async function github(path, binary = false) {
  if (!GITHUB_TOKEN) throw Object.assign(new Error("updates_not_configured"), { status: 503 });
  return new Promise((resolve, reject) => {
    const request = httpsRequest(new URL(`https://api.github.com${path}`), {
      headers: { authorization: `Bearer ${GITHUB_TOKEN}`, accept: binary ? "application/octet-stream" : "application/vnd.github+json", "user-agent": "Kaguya-Update-Relay" }
    }, response => {
      const chunks = [];
      response.on("data", chunk => chunks.push(chunk));
      response.on("end", () => {
        const data = Buffer.concat(chunks);
        if ((response.statusCode || 500) >= 300 && (response.statusCode || 500) < 400 && response.headers.location)
          return fetch(response.headers.location).then(r => r.arrayBuffer()).then(b => resolve(Buffer.from(b))).catch(reject);
        if (response.statusCode !== 200) return reject(Object.assign(new Error(`github_http_${response.statusCode}`), { status: 502 }));
        try { resolve(binary ? data : JSON.parse(data.toString("utf8"))); } catch (error) { reject(error); }
      });
    });
    request.setTimeout(30_000, () => request.destroy(new Error("github_timeout")));
    request.on("error", reject);
    request.end();
  });
}

async function latestAsset(protectedJar) {
  const releases = await github(`/repos/${UPDATE_REPOSITORY}/releases?per_page=10`);
  let latest = null;
  for (const release of releases) {
    if (release.draft) continue;
    for (const asset of release.assets || []) {
      const name = String(asset.name || "").toLowerCase();
      if (!name.endsWith(".jar") || name.includes("sources") || name.includes("protected") !== protectedJar) continue;
      const source = /\d/.test(release.tag_name || "") ? release.tag_name : release.name || release.tag_name;
      const candidate = { version: String(source).replace(/^kaguya[-_ ]*v?/i, "").replace(/^v/i, ""), size: asset.size,
        sha256: String(asset.digest || "").replace(/^sha256:/, ""), assetId: asset.id };
      if (!latest || compareVersions(candidate.version, latest.version) > 0) latest = candidate;
    }
  }
  return latest;
}

function compareVersions(a, b) {
  const left = String(a).replace(/[^0-9.]/g, "").split(".").map(Number);
  const right = String(b).replace(/[^0-9.]/g, "").split(".").map(Number);
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    const difference = (left[i] || 0) - (right[i] || 0);
    if (difference) return difference;
  }
  return 0;
}

async function readBody(request) {
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY) throw Object.assign(new Error("body_too_large"), { status: 413 });
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function canonical(body) {
  return `${body.serverHash}\n${body.clientId}\n${body.timestamp}\n${body.nonce}\n${body.payload}`;
}

function verify(body) {
  if (!body || typeof body !== "object") return false;
  if (!/^[0-9a-f]{1,16}$/.test(body.serverHash)) return false;
  if (!/^[0-9a-f]{1,16}$/.test(body.clientId)) return false;
  if (!Number.isSafeInteger(body.timestamp) || Math.abs(Date.now() - body.timestamp) > CLOCK_SKEW_MS) return false;
  if (!/^[A-Za-z0-9_-]{20,40}$/.test(body.nonce)) return false;
  if (typeof body.payload !== "string" || !body.payload.startsWith("KGSYNC2:") || body.payload.length > 4096) return false;
  if (typeof body.signature !== "string") return false;
  const expected = createHmac("sha256", SYNC_KEY).update(canonical(body)).digest();
  let supplied;
  try { supplied = Buffer.from(body.signature, "base64url"); } catch { return false; }
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

async function synchronize(body) {
  const now = Math.floor(Date.now() / 1000);
  const command = [
    "EVAL", SYNC_LUA, 3,
    `kaguya:state:${body.serverHash}`,
    `kaguya:nonce:${body.serverHash}:${body.nonce}`,
    `kaguya:rate:${body.serverHash}:${body.clientId}`,
    now, body.clientId, body.payload, now - STALE_SECONDS, MAX_CLIENTS_PER_SERVER
  ];
  const upstream = await postUpstash(command);
  const value = upstream.value;
  if (upstream.status < 200 || upstream.status >= 300 || value.error) {
    const error = new Error(value.error || `upstash_http_${upstream.status}`);
    error.status = String(value.error || "").includes("RATE_LIMIT") ? 429
      : String(value.error || "").includes("REPLAY") ? 409 : 502;
    throw error;
  }
  return Array.isArray(value.result) ? value.result : [];
}

function postUpstash(command) {
  return new Promise((resolve, reject) => {
    const encoded = Buffer.from(JSON.stringify(command));
    const request = httpsRequest(new URL(UPSTASH_URL), {
      method: "POST",
      headers: {
        authorization: `Bearer ${UPSTASH_TOKEN}`,
        "content-type": "application/json",
        "content-length": encoded.length
      }
    }, response => {
      const chunks = [];
      let size = 0;
      response.on("data", chunk => {
        size += chunk.length;
        if (size > 1024 * 1024) request.destroy(new Error("upstash_response_too_large"));
        else chunks.push(chunk);
      });
      response.on("end", () => {
        try {
          resolve({ status: response.statusCode || 500, value: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
        } catch (error) { reject(error); }
      });
    });
    request.setTimeout(25_000, () => request.destroy(new Error("upstash_timeout")));
    request.on("error", error => {
      console.error(`Upstash request failed: ${error.name}: ${error.message}; cause=${error.code || "none"}`);
      reject(error);
    });
    request.end(encoded);
  });
}

const ADMIN_HTML = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Kaguya Device Admin</title><style>body{font:14px system-ui;background:#101018;color:#eee;max-width:980px;margin:40px auto;padding:0 16px}button{background:#24243a;color:#fff;border:1px solid #666;padding:8px}table{width:100%;border-collapse:collapse;margin-top:20px}td,th{padding:9px;border-bottom:1px solid #333;text-align:left}.pending{color:#ffd166}.active{color:#71e29b}</style><h1>Kaguya Device Admin</h1><p>Only anonymous device IDs and license hashes are shown.</p><button id="reload">Reload</button><table><thead><tr><th>Status</th><th>Label</th><th>Anonymous device</th><th>Action</th></tr></thead><tbody id="rows"></tbody></table><script>let token=sessionStorage.kaguyaAdmin||prompt('Admin token')||'';sessionStorage.kaguyaAdmin=token;const call=async(path,body)=>{const r=await fetch(path,{method:body?'POST':'GET',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:body?JSON.stringify(body):undefined});if(!r.ok)throw Error((await r.json()).error||r.status);return r.json()};async function load(){const data=await call('/v1/admin/devices');const rows=document.querySelector('#rows');rows.replaceChildren();for(const d of data.devices){const tr=document.createElement('tr');for(const value of [d.state,d.label||'',d.deviceId.slice(0,16)+'…']){const td=document.createElement('td');td.textContent=value;td.className=d.state;tr.append(td)}const td=document.createElement('td'),b=document.createElement('button');b.textContent=d.state==='pending'?'Approve':'Revoke';b.onclick=async()=>{if(d.state==='pending')await call('/v1/admin/approve',{deviceId:d.deviceId,label:prompt('Device label','Kaguya device')||''});else if(confirm('Revoke '+(d.label||d.deviceId.slice(0,16))+'?'))await call('/v1/admin/revoke',{licenseHash:d.key});await load()};td.append(b);tr.append(td);rows.append(tr)} }document.querySelector('#reload').onclick=load;load().catch(e=>alert(e.message));</script>`;

const server = createServer(async (request, response) => {
  if (request.method === "GET" && request.url === "/health") {
    return json(response, validEnvironment() ? 200 : 503, { ok: validEnvironment() });
  }
  if (request.method === "GET" && request.url === "/admin") {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'", "cache-control": "no-store" });
    return response.end(ADMIN_HTML);
  }
  if (request.method === "POST" && request.url === "/v1/auth") {
    try {
      const source = String(request.headers["x-forwarded-for"] || request.socket.remoteAddress || "unknown").split(",")[0].trim();
      const sourceId = createHmac("sha256", DEVICE_PEPPER).update(source).digest("hex").slice(0,24);
      const rate = await postUpstash(["INCR", `kaguya:auth:rate:${sourceId}`]);
      if (Number(rate.value.result || 0) === 1) await postUpstash(["EXPIRE", `kaguya:auth:rate:${sourceId}`, 3600]);
      if (Number(rate.value.result || 0) > 20) return json(response, 429, { authorized:false, error:"rate_limited" });
      const body = await readBody(request);
      const result = await authorizeDevice(body, true);
      return json(response, result.authorized ? 200 : 202, result);
    } catch (error) { return json(response, Number.isInteger(error.status) ? error.status : 400, { authorized: false, error: error.message }); }
  }
  if (request.method === "POST" && request.url === "/v1/proxy/lease") {
    try {
      const result = await renewProxyLease(request, await readBody(request));
      return json(response, result.authorized ? 200 : 403, result);
    } catch (error) { return json(response, Number.isInteger(error.status) ? error.status : 400, { authorized: false, error: error.message }); }
  }
  if (request.method === "GET" && request.url === "/v1/proxy/leases") {
    if (!proxyAuthorized(request)) return json(response, 401, { error: "proxy_unauthorized" });
    try { return json(response, 200, { ips: await activeProxyLeases(), ttl: PROXY_LEASE_SECONDS }); }
    catch (error) { return json(response, 500, { error: error.message || "proxy_lease_failed" }); }
  }
  if (request.method === "POST" && request.url === "/v1/proxy/observation/report") {
    if (!proxyAuthorized(request)) return json(response, 401, { error: "proxy_unauthorized" });
    try { return json(response, 200, { ok: true, observation: await storeProxyObservation(await readBody(request)) }); }
    catch (error) { return json(response, Number.isInteger(error.status) ? error.status : 400, { error: error.message }); }
  }
  if (request.method === "POST" && request.url === "/v1/proxy/observation") {
    try {
      const authorization = await authorizeDevice(await readBody(request), false);
      if (!authorization.authorized) return json(response, 403, { error: "device_not_authorized" });
      return json(response, 200, await proxyObservation());
    } catch (error) { return json(response, Number.isInteger(error.status) ? error.status : 400, { error: error.message }); }
  }
  if (request.method === "POST" && request.url === "/v1/proxy/worker/command") {
    try {
      const body = await readBody(request);
      const authorization = await authorizeDevice(body, false);
      if (!authorization.authorized) return json(response, 403, { error: "device_not_authorized" });
      if (!validWorkerCommand(body)) return json(response, 400, { error: "invalid_worker_command" });
      const command = { id: `${Date.now()}-${authorization.deviceId.slice(0, 12)}`, action: body.action,
        target: body.action === "connect" ? body.target : "", requestedAt: Date.now() };
      queueWorkerCommand(command);
      return json(response, 202, { queued: true, id: command.id });
    } catch (error) { return json(response, Number.isInteger(error.status) ? error.status : 400, { error: error.message }); }
  }
  if (request.method === "POST" && request.url === "/v1/proxy/worker/status") {
    try {
      const authorization = await authorizeDevice(await readBody(request), false);
      if (!authorization.authorized) return json(response, 403, { error: "device_not_authorized" });
      const fresh = Date.now() - workerStatus.updatedAt <= 90_000;
      return json(response, 200, fresh ? workerStatus : { online: false, state: "offline", target: "", updatedAt: workerStatus.updatedAt });
    } catch (error) { return json(response, Number.isInteger(error.status) ? error.status : 400, { error: error.message }); }
  }
  if (request.method === "GET" && request.url === "/v1/proxy/worker/poll") {
    if (!proxyAuthorized(request)) return json(response, 401, { error: "proxy_unauthorized" });
    try { return json(response, 200, { command: await waitForWorkerCommand() }); }
    catch (error) { return json(response, 500, { error: error.message || "worker_poll_failed" }); }
  }
  if (request.method === "POST" && request.url === "/v1/proxy/worker/report") {
    if (!proxyAuthorized(request)) return json(response, 401, { error: "proxy_unauthorized" });
    try {
      workerStatus = sanitizeWorkerStatus(await readBody(request));
      return json(response, 200, { ok: true });
    } catch (error) { return json(response, 400, { error: error.message || "worker_report_failed" }); }
  }
  if (request.url?.startsWith("/v1/admin/")) {
    if (!adminAuthorized(request)) return json(response, 401, { error: "admin_unauthorized" });
    try {
      if (request.method === "GET" && request.url === "/v1/admin/devices") return json(response, 200, { devices: await adminDevices() });
      const body = await readBody(request);
      if (request.method === "POST" && request.url === "/v1/admin/approve") {
        if (!/^[0-9a-f]{64}$/.test(body.deviceId || "")) return json(response, 400, { error: "invalid_device" });
        const pending = await postUpstash(["HGET", "kaguya:auth:pending", body.deviceId]);
        if (typeof pending.value.result !== "string") return json(response, 404, { error: "pending_device_not_found" });
        const record = JSON.parse(pending.value.result);
        await postUpstash(["HSET", "kaguya:auth:licenses", record.licenseHash, JSON.stringify({ deviceId: body.deviceId, label: String(body.label || "").slice(0,80), approvedAt: Date.now() })]);
        await postUpstash(["HDEL", "kaguya:auth:pending", body.deviceId]);
        return json(response, 200, { ok: true });
      }
      if (request.method === "POST" && request.url === "/v1/admin/revoke") {
        if (!/^[0-9a-f]{64}$/.test(body.licenseHash || "")) return json(response, 400, { error: "invalid_license" });
        await postUpstash(["HDEL", "kaguya:auth:licenses", body.licenseHash]);
        return json(response, 200, { ok: true });
      }
      return json(response, 404, { error: "not_found" });
    } catch (error) { return json(response, 500, { error: error.message || "admin_failed" }); }
  }
  if (request.method === "POST" && (request.url === "/v1/update/check" || request.url === "/v1/update/download")) {
    try {
      const body = await readBody(request);
      const authorization = await authorizeDevice(body, false);
      if (!authorization.authorized) return json(response, 403, { error: "device_not_authorized", deviceId: authorization.deviceId });
      const asset = await latestAsset(Boolean(body.protected));
      if (!asset) {
        if (request.url === "/v1/update/check") {
          return json(response, 200, { update: false, reason: "update_asset_not_found" });
        }
        return json(response, 404, { error: "update_asset_not_found" });
      }
      if (request.url === "/v1/update/check") {
        const versionDifference = compareVersions(asset.version, body.version);
        const currentSha256 = String(body.currentSha256 || "").toLowerCase();
        const sameVersionReplacement = versionDifference === 0
          && /^[0-9a-f]{64}$/.test(asset.sha256)
          && /^[0-9a-f]{64}$/.test(currentSha256)
          && asset.sha256 !== currentSha256;
        return json(response, 200, {
          update: versionDifference > 0 || sameVersionReplacement,
          version: asset.version, size: asset.size, sha256: asset.sha256
        });
      }
      const jar = await github(`/repos/${UPDATE_REPOSITORY}/releases/assets/${asset.assetId}`, true);
      response.writeHead(200, { "content-type": "application/java-archive", "content-length": jar.length, "cache-control": "private, no-store" });
      return response.end(jar);
    } catch (error) { return json(response, Number.isInteger(error.status) ? error.status : 500, { error: error.message }); }
  }
  const requestUrl = new URL(request.url, "http://relay.local");
  const tunneled = request.method === "GET" && requestUrl.pathname === "/v1/sync";
  const posted = request.method === "POST" && requestUrl.pathname === "/v1/sync";
  if (!tunneled && !posted) {
    return json(response, 404, { error: "not_found" });
  }
  if (!validEnvironment()) return json(response, 503, { error: "service_not_configured" });
  try {
    const body = tunneled
      ? JSON.parse(Buffer.from(requestUrl.searchParams.get("q") || "", "base64url").toString("utf8"))
      : await readBody(request);
    if (!verify(body)) return json(response, 401, { error: "invalid_signature_or_request" });
    const states = await synchronize(body);
    return json(response, 200, { states, serverTime: Date.now() });
  } catch (error) {
    const status = Number.isInteger(error.status) ? error.status : 400;
    return json(response, status, { error: error.message || "request_failed" });
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Kaguya sync relay listening on ${PORT}`);
  const host = UPSTASH_URL ? new URL(UPSTASH_URL).hostname : "missing";
  console.log(`Upstash configuration: host=${host}, tokenLength=${UPSTASH_TOKEN.length}, keyLength=${SYNC_KEY.length}`);
});
