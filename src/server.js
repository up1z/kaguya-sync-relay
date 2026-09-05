import { createHash, createHmac, createSign, timingSafeEqual } from "node:crypto";
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
const FAILURE_WEBHOOK = process.env.KAGUYA_FAILURE_WEBHOOK || "";
const OCI_TENANCY = process.env.OCI_TENANCY_OCID || "";
const OCI_USER = process.env.OCI_USER_OCID || "";
const OCI_FINGERPRINT = process.env.OCI_FINGERPRINT || "";
const OCI_PRIVATE_KEY = (process.env.OCI_PRIVATE_KEY_PEM || "").replace(/\\n/g, "\n");
const OCI_REGION = process.env.OCI_REGION || "us-ashburn-1";
const CONFIGURED_VM_POOL = parseVmPool(process.env.KAGUYA_ORACLE_VM_POOL_JSON || "[]");
// Always Free can run as one permanently available proxy while OCI API keys are
// not configured. Explicit pool configuration replaces this fallback.
const VM_POOL = CONFIGURED_VM_POOL.length ? CONFIGURED_VM_POOL : [{
  id: "", workerId: "worker-1", name: "Kaguya Always Free", address:
    process.env.KAGUYA_ORACLE_STATIC_ADDRESS || "193.122.248.232:25568"
}];
const SESSION_IDLE_MS = 15 * 60 * 1000;
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
const workerQueues = new Map();
const workerStatuses = new Map();

function parseVmPool(value) {
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed)) return [];
    return parsed.slice(0, 4).filter(vm => typeof vm?.id === "string" && vm.id.startsWith("ocid1.instance.")
      && /^[a-zA-Z0-9_-]{1,32}$/.test(vm.workerId || "") && typeof vm.address === "string")
      .map(vm => ({ id: vm.id, workerId: vm.workerId, address: vm.address, name: String(vm.name || vm.workerId).slice(0, 40) }));
  } catch { return []; }
}

async function discordFailure(operation, vm, detail) {
  if (!FAILURE_WEBHOOK.startsWith("https://")) return;
  try {
    await fetch(FAILURE_WEBHOOK, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({
      username: "Kaguya Oracle Controller", allowed_mentions: { parse: [] }, embeds: [{
        title: `Oracle VM ${operation} failed`, description: String(detail).slice(0, 1000), color: 15026253,
        fields: [{ name: "VM", value: vm?.name || "unknown", inline: true }], timestamp: new Date().toISOString()
      }]
    }), signal: AbortSignal.timeout(10_000) });
  } catch { /* notification failure must not block cleanup */ }
}

async function oracleAction(vm, action) {
  if (!vm || !["START", "STOP"].includes(action)) throw new Error("invalid_oracle_action");
  // A static Always Free worker is already online. START/STOP means session
  // connect/disconnect; the free VM itself remains available.
  if (!vm.id) return;
  if (![OCI_TENANCY, OCI_USER, OCI_FINGERPRINT, OCI_PRIVATE_KEY].every(Boolean)) throw new Error("oracle_not_configured");
  const host = `iaas.${OCI_REGION}.oraclecloud.com`;
  const path = `/20160918/instances/${encodeURIComponent(vm.id)}?action=${action}`;
  const date = new Date().toUTCString();
  const signing = `(request-target): post ${path}\nhost: ${host}\ndate: ${date}\ncontent-length: 0\nx-content-sha256: ${createHash("sha256").update("").digest("base64")}`;
  const signer = createSign("RSA-SHA256"); signer.update(signing); signer.end();
  const signature = signer.sign(OCI_PRIVATE_KEY, "base64");
  const authorization = `Signature version="1",keyId="${OCI_TENANCY}/${OCI_USER}/${OCI_FINGERPRINT}",algorithm="rsa-sha256",headers="(request-target) host date content-length x-content-sha256",signature="${signature}"`;
  const response = await fetch(`https://${host}${path}`, { method: "POST", headers: { host, date,
    "content-length": "0", "x-content-sha256": createHash("sha256").update("").digest("base64"), authorization },
    signal: AbortSignal.timeout(30_000) });
  if (!response.ok && response.status !== 409) throw new Error(`oci_http_${response.status}`);
}

function queueFor(workerId) { if (!workerQueues.has(workerId)) workerQueues.set(workerId, []); return workerQueues.get(workerId); }
async function queueWorker(workerId, command) {
  const queue = queueFor(workerId); if (queue.length >= 16) queue.shift(); queue.push(command);
  await postUpstash(["HSET", "kaguya:proxy:worker-commands", workerId, JSON.stringify(command)]);
  for (const wake of workerWaiters) wake(); workerWaiters.clear();
}
async function waitForWorker(workerId, timeoutMs = 25_000) {
  const take = () => queueFor(workerId).shift() || null;
  let command = take();
  if (!command) {
    const stored = await postUpstash(["HGET", "kaguya:proxy:worker-commands", workerId]);
    if (typeof stored.value.result === "string") try { command = JSON.parse(stored.value.result); } catch { }
  }
  if (command) { await postUpstash(["HDEL", "kaguya:proxy:worker-commands", workerId]); return command; }
  await new Promise(resolve => { const timer = setTimeout(() => { workerWaiters.delete(wake); resolve(); }, timeoutMs);
    const wake = () => { clearTimeout(timer); resolve(); }; workerWaiters.add(wake); });
  command = take();
  if (command) await postUpstash(["HDEL", "kaguya:proxy:worker-commands", workerId]);
  return command;
}

async function readSession(deviceId) {
  const result = await postUpstash(["HGET", "kaguya:proxy:sessions", deviceId]);
  return typeof result.value.result === "string" ? JSON.parse(result.value.result) : null;
}
async function writeSession(deviceId, session) {
  await postUpstash(["HSET", "kaguya:proxy:sessions", deviceId, JSON.stringify(session)]);
}
async function allocateSession(deviceId, target) {
  let session = await readSession(deviceId);
  if (session) { session.lastSeen = Date.now(); session.target = target || session.target; await writeSession(deviceId, session); return session; }
  const all = await postUpstash(["HGETALL", "kaguya:proxy:sessions"]); const used = new Set();
  for (let index = 1; index < (all.value.result || []).length; index += 2) try { used.add(JSON.parse(all.value.result[index]).workerId); } catch { }
  const vm = VM_POOL.find(candidate => !used.has(candidate.workerId));
  if (!vm) throw Object.assign(new Error("oracle_pool_full"), { status: 503 });
  session = { workerId: vm.workerId, address: vm.address, target, state: "starting", createdAt: Date.now(), lastSeen: Date.now() };
  await writeSession(deviceId, session);
  try { await oracleAction(vm, "START"); } catch (error) { await postUpstash(["HDEL", "kaguya:proxy:sessions", deviceId]); await discordFailure("start", vm, error.message); throw error; }
  await queueWorker(vm.workerId, { id: `${Date.now()}-${deviceId.slice(0, 12)}`, action: "connect", target, requestedAt: Date.now() });
  return session;
}
async function releaseSession(deviceId, reason = "client_disconnect") {
  const session = await readSession(deviceId); if (!session) return false;
  const vm = VM_POOL.find(candidate => candidate.workerId === session.workerId);
  await queueWorker(session.workerId, { id: `${Date.now()}-${deviceId.slice(0, 12)}`, action: "disconnect", target: "", requestedAt: Date.now() });
  try { await oracleAction(vm, "STOP"); } catch (error) { await discordFailure("stop", vm, `${reason}: ${error.message}`); throw error; }
  await postUpstash(["HDEL", "kaguya:proxy:sessions", deviceId]); return true;
}

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
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch { return {}; }
}

function deviceIdentity(body) {
  if (!body || !/^[0-9a-f]{64}$/.test(body.hwid || "") || typeof body.license !== "string" || body.license.length < 32) return null;
  const licenseHash = createHash("sha256").update(body.license).digest("hex");
  const deviceId = createHmac("sha256", DEVICE_PEPPER).update(body.hwid).digest("hex");
  return { licenseHash, deviceId };
}

async function authorizeDevice(body, createPending = false) {
  if (DEVICE_PEPPER.length < 32) throw Object.assign(new Error("device_auth_not_configured"), { status: 503 });
  const identity = deviceIdentity(body);
  if (!identity) return { authorized: false, deviceId: "invalid" };
  const active = await postUpstash(["HGET", "kaguya:auth:licenses", identity.licenseHash]);
  if (active.status >= 200 && active.status < 300 && typeof active.value.result === "string") {
    try {
      const record = JSON.parse(active.value.result);
      if (record.deviceId === identity.deviceId) return { authorized: true, deviceId: identity.deviceId };
    } catch { /* invalid records are denied */ }
  }
  const legacy = LICENSES[identity.licenseHash];
  if (typeof legacy === "string" && legacy === body.hwid) return { authorized: true, deviceId: identity.deviceId };
  if (createPending) {
    const count = await postUpstash(["HLEN", "kaguya:auth:pending"]);
    if (Number(count.value.result || 0) >= 512) throw Object.assign(new Error("pending_queue_full"), { status: 429 });
    const pending = JSON.stringify({ licenseHash: identity.licenseHash, requestedAt: Date.now() });
    await postUpstash(["HSET", "kaguya:auth:pending", identity.deviceId, pending]);
    await postUpstash(["EXPIRE", "kaguya:auth:pending", 604800]);
  }
  return { authorized: false, deviceId: identity.deviceId };
}

function adminAuthorized(request) {
  if (ADMIN_TOKEN.length < 32) return false;
  const supplied = String(request.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const a = Buffer.from(supplied); const b = Buffer.from(ADMIN_TOKEN);
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
  const userCode = /^[A-Z0-9-]{4,16}$/.test(body?.userCode || "") ? body.userCode : "";
  const verificationUri = String(body?.verificationUri || "").startsWith("https://") ? String(body.verificationUri).slice(0, 200) : "";
  return { online: true, state, target, detail: String(body?.detail || "").slice(0, 160),
    userCode, verificationUri, updatedAt: Date.now() };
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
  await postUpstash(["HSET", "kaguya:proxy:leases", authorization.deviceId, JSON.stringify({ ip, expiresAt })]);
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
  const [active, pending] = await Promise.all([
    postUpstash(["HGETALL", "kaguya:auth:licenses"]), postUpstash(["HGETALL", "kaguya:auth:pending"])
  ]);
  const decode = (values, state) => {
    const result = [];
    for (let i = 0; i < (values || []).length; i += 2) {
      try {
        const record = JSON.parse(values[i + 1]);
        result.push({ key: values[i], state, ...record, deviceId: record.deviceId || values[i] });
      } catch { /* skip */ }
    }
    return result;
  };
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
      const version = String(source).replace(/^kaguya[-_ ]*v?/i, "").replace(/^v/i, "");
      const candidate = { version, size: asset.size, sha256: String(asset.digest || "").replace(/^sha256:/, ""), assetId: asset.id };
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

const ADMIN_HTML = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Kaguya Device Admin</title><style>body{font:14px system-ui;background:#101018;color:#eee;max-width:980px;margin:40px auto;padding:0 16px}button,input{background:#24243a;color:#fff;border:1px solid #666;padding:8px}table{width:100%;border-collapse:collapse;margin-top:20px}td,th{padding:9px;border-bottom:1px solid #333;text-align:left}.pending{color:#ffd166}.active{color:#71e29b}</style>
<h1>Kaguya Device Admin</h1><p>Only anonymous device IDs and license hashes are shown.</p><button id="reload">Reload</button><table><thead><tr><th>Status</th><th>Label</th><th>Anonymous device</th><th>Action</th></tr></thead><tbody id="rows"></tbody></table>
<script>let token=sessionStorage.kaguyaAdmin||prompt('Admin token')||'';sessionStorage.kaguyaAdmin=token;
const call=async(path,body)=>{const r=await fetch(path,{method:body?'POST':'GET',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:body?JSON.stringify(body):undefined});if(!r.ok)throw Error((await r.json()).error||r.status);return r.json()};
async function load(){const data=await call('/v1/admin/devices');const rows=document.querySelector('#rows');rows.replaceChildren();for(const d of data.devices){const tr=document.createElement('tr');for(const value of [d.state,d.label||'',d.deviceId.slice(0,16)+'…']){const td=document.createElement('td');td.textContent=value;td.className=d.state;tr.append(td)}const td=document.createElement('td'),b=document.createElement('button');b.textContent=d.state==='pending'?'Approve':'Revoke';b.onclick=async()=>{if(d.state==='pending')await call('/v1/admin/approve',{deviceId:d.deviceId,label:prompt('Device label','Kaguya device')||''});else if(confirm('Revoke '+(d.label||d.deviceId.slice(0,16))+'?'))await call('/v1/admin/revoke',{licenseHash:d.key});await load()};td.append(b);tr.append(td);rows.append(tr)}}document.querySelector('#reload').onclick=load;load().catch(e=>alert(e.message));</script>`;

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
      const sourceId = createHmac("sha256", DEVICE_PEPPER).update(source).digest("hex").slice(0, 24);
      const rate = await postUpstash(["INCR", `kaguya:auth:rate:${sourceId}`]);
      if (Number(rate.value.result || 0) === 1) await postUpstash(["EXPIRE", `kaguya:auth:rate:${sourceId}`, 3600]);
      if (Number(rate.value.result || 0) > 20) return json(response, 429, { authorized: false, error: "rate_limited" });
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
  if (request.method === "POST" && request.url === "/v1/proxy/session/start") {
    try {
      const body = await readBody(request); const authorization = await authorizeDevice(body, false);
      if (!authorization.authorized) return json(response, 403, { error: "device_not_authorized" });
      if (!Object.hasOwn(WORKER_TARGETS, body.target)) return json(response, 400, { error: "invalid_target" });
      const session = await allocateSession(authorization.deviceId, body.target);
      return json(response, 202, { assigned: true, ...session });
    } catch (error) { return json(response, Number.isInteger(error.status) ? error.status : 502, { error: error.message }); }
  }
  if (request.method === "POST" && request.url === "/v1/proxy/session/heartbeat") {
    try {
      const body = await readBody(request); const authorization = await authorizeDevice(body, false);
      if (!authorization.authorized) return json(response, 403, { error: "device_not_authorized" });
      const session = await readSession(authorization.deviceId);
      if (!session) return json(response, 404, { error: "session_not_found" });
      session.lastSeen = Date.now(); await writeSession(authorization.deviceId, session);
      const status = workerStatuses.get(session.workerId) || { online: false, state: "starting", target: session.target, updatedAt: 0 };
      return json(response, 200, { ...session, worker: status });
    } catch (error) { return json(response, 400, { error: error.message }); }
  }
  if (request.method === "POST" && request.url === "/v1/proxy/session/stop") {
    try {
      const body = await readBody(request); const authorization = await authorizeDevice(body, false);
      if (!authorization.authorized) return json(response, 403, { error: "device_not_authorized" });
      return json(response, 200, { stopped: await releaseSession(authorization.deviceId) });
    } catch (error) { return json(response, 502, { error: error.message }); }
  }
  if (request.method === "POST" && request.url === "/v1/proxy/worker/command") {
    try {
      const body = await readBody(request);
      const authorization = await authorizeDevice(body, false);
      if (!authorization.authorized) return json(response, 403, { error: "device_not_authorized" });
      if (!validWorkerCommand(body)) return json(response, 400, { error: "invalid_worker_command" });
      const command = { id: `${Date.now()}-${authorization.deviceId.slice(0, 12)}`, action: body.action,
        target: body.action === "connect" ? body.target : "", requestedAt: Date.now() };
      const session = await readSession(authorization.deviceId);
      if (!session) return json(response, 409, { error: "session_not_started" });
      await queueWorker(session.workerId, command);
      return json(response, 202, { queued: true, id: command.id });
    } catch (error) { return json(response, Number.isInteger(error.status) ? error.status : 400, { error: error.message }); }
  }
  if (request.method === "POST" && request.url === "/v1/proxy/worker/status") {
    try {
      const authorization = await authorizeDevice(await readBody(request), false);
      if (!authorization.authorized) return json(response, 403, { error: "device_not_authorized" });
      const session = await readSession(authorization.deviceId);
      if (!session) return json(response, 200, { online: false, state: "unassigned", target: "", updatedAt: 0 });
      const status = workerStatuses.get(session.workerId) || { online: false, state: "starting", target: session.target, updatedAt: 0 };
      const fresh = Date.now() - status.updatedAt <= 90_000;
      return json(response, 200, { ...(fresh ? status : { online: false, state: "offline", target: session.target, updatedAt: status.updatedAt }), address: session.address, workerId: session.workerId });
    } catch (error) { return json(response, Number.isInteger(error.status) ? error.status : 400, { error: error.message }); }
  }
  if (request.method === "GET" && request.url === "/v1/proxy/worker/poll") {
    if (!proxyAuthorized(request)) return json(response, 401, { error: "proxy_unauthorized" });
    const workerId = String(request.headers["x-kaguya-worker"] || "");
    if (!VM_POOL.some(vm => vm.workerId === workerId)) return json(response, 400, { error: "unknown_worker" });
    try { return json(response, 200, { command: await waitForWorker(workerId) }); }
    catch (error) { return json(response, 500, { error: error.message || "worker_poll_failed" }); }
  }
  if (request.method === "POST" && request.url === "/v1/proxy/worker/report") {
    if (!proxyAuthorized(request)) return json(response, 401, { error: "proxy_unauthorized" });
    try {
      const body = await readBody(request); const workerId = String(body.workerId || request.headers["x-kaguya-worker"] || "");
      if (!VM_POOL.some(vm => vm.workerId === workerId)) return json(response, 400, { error: "unknown_worker" });
      workerStatuses.set(workerId, sanitizeWorkerStatus(body));
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
        await postUpstash(["HSET", "kaguya:auth:licenses", record.licenseHash, JSON.stringify({ deviceId: body.deviceId, label: String(body.label || "").slice(0, 80), approvedAt: Date.now() })]);
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

let reaping = false;
setInterval(async () => {
  if (reaping || !validEnvironment()) return;
  reaping = true;
  try {
    const all = await postUpstash(["HGETALL", "kaguya:proxy:sessions"]);
    const values = all.value.result || [];
    for (let index = 0; index < values.length; index += 2) {
      try {
        const session = JSON.parse(values[index + 1]);
        if (Date.now() - Number(session.lastSeen || 0) > SESSION_IDLE_MS) await releaseSession(values[index], "15_minute_idle");
      } catch (error) { console.error(`Session reaper: ${error.message}`); }
    }
  } finally { reaping = false; }
}, 60_000).unref();
