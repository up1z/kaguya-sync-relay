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
const MAX_BODY = 16 * 1024;
const CLOCK_SKEW_MS = 120_000;
const STALE_SECONDS = 7 * 24 * 60 * 60;
const MAX_CLIENTS_PER_SERVER = 64;

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

function authorized(body) {
  if (!body || !/^[0-9a-f]{64}$/.test(body.hwid || "") || typeof body.license !== "string") return false;
  const licenseHash = createHash("sha256").update(body.license).digest("hex");
  const expected = LICENSES[licenseHash];
  return typeof expected === "string" && /^[0-9a-f]{64}$/.test(expected)
    && timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(body.hwid, "hex"));
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
  for (const release of releases) {
    if (release.draft) continue;
    for (const asset of release.assets || []) {
      const name = String(asset.name || "").toLowerCase();
      if (!name.endsWith(".jar") || name.includes("sources") || name.includes("protected") !== protectedJar) continue;
      const source = /\d/.test(release.tag_name || "") ? release.tag_name : release.name || release.tag_name;
      return { version: String(source).replace(/^kaguya[-_ ]*v?/i, "").replace(/^v/i, ""), size: asset.size,
        sha256: String(asset.digest || "").replace(/^sha256:/, ""), assetId: asset.id };
    }
  }
  return null;
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

const server = createServer(async (request, response) => {
  if (request.method === "GET" && request.url === "/health") {
    return json(response, validEnvironment() ? 200 : 503, { ok: validEnvironment() });
  }
  if (request.method === "POST" && request.url === "/v1/auth") {
    try {
      const body = await readBody(request);
      return json(response, authorized(body) ? 200 : 403, { authorized: authorized(body) });
    } catch { return json(response, 400, { authorized: false }); }
  }
  if (request.method === "POST" && (request.url === "/v1/update/check" || request.url === "/v1/update/download")) {
    try {
      const body = await readBody(request);
      if (!authorized(body)) return json(response, 403, { error: "device_not_authorized" });
      const asset = await latestAsset(Boolean(body.protected));
      if (!asset) return json(response, 404, { error: "update_asset_not_found" });
      if (request.url === "/v1/update/check") return json(response, 200, {
        update: compareVersions(asset.version, body.version) > 0, version: asset.version, size: asset.size, sha256: asset.sha256
      });
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
