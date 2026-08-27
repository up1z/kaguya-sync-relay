import { createHmac, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";

const PORT = Number(process.env.PORT || 10000);
const UPSTASH_URL = (process.env.UPSTASH_REDIS_REST_URL || "").replace(/\/$/, "");
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || "";
const SYNC_KEY = process.env.SYNC_HMAC_KEY || "";
const MAX_BODY = 16 * 1024;
const CLOCK_SKEW_MS = 120_000;
const STALE_SECONDS = 7 * 24 * 60 * 60;

// One EVAL invocation performs replay protection, rate limiting, state update,
// stale-client pruning, and retrieval. Upstash bills this as one command.
const SYNC_LUA = `
local now = tonumber(ARGV[1])
local client = ARGV[2]
local payload = ARGV[3]
local cutoff = tonumber(ARGV[4])

if not redis.call('SET', KEYS[2], '1', 'EX', 300, 'NX') then
  return redis.error_reply('REPLAY')
end

local rate = redis.call('INCR', KEYS[3])
if rate == 1 then redis.call('EXPIRE', KEYS[3], 60) end
if rate > 10 then return redis.error_reply('RATE_LIMIT') end

redis.call('HSET', KEYS[1], client, tostring(now) .. '|' .. payload)
local entries = redis.call('HGETALL', KEYS[1])
local result = {}
for index = 1, #entries, 2 do
  local field = entries[index]
  local value = entries[index + 1]
  local separator = string.find(value, '|', 1, true)
  local updated = separator and tonumber(string.sub(value, 1, separator - 1)) or 0
  if updated < cutoff then
    redis.call('HDEL', KEYS[1], field)
  elseif separator then
    table.insert(result, string.sub(value, separator + 1))
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
    now, body.clientId, body.payload, now - STALE_SECONDS
  ];
  let upstream;
  try {
    upstream = await fetch(UPSTASH_URL, {
      method: "POST",
      headers: {
        authorization: `Bearer ${UPSTASH_TOKEN}`,
        "content-type": "application/json"
      },
      body: JSON.stringify(command),
      signal: AbortSignal.timeout(25_000)
    });
  } catch (error) {
    console.error(`Upstash request failed: ${error.name}: ${error.message}; cause=${error.cause?.code || "none"}`);
    throw error;
  }
  const value = await upstream.json();
  if (!upstream.ok || value.error) {
    const error = new Error(value.error || `upstash_http_${upstream.status}`);
    error.status = String(value.error || "").includes("RATE_LIMIT") ? 429
      : String(value.error || "").includes("REPLAY") ? 409 : 502;
    throw error;
  }
  return Array.isArray(value.result) ? value.result : [];
}

const server = createServer(async (request, response) => {
  if (request.method === "GET" && request.url === "/health") {
    return json(response, validEnvironment() ? 200 : 503, { ok: validEnvironment() });
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
