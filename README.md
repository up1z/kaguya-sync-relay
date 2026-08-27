# Kaguya Sync Relay

Render-hosted relay for Kaguya's same-server learning database. Each `/v1/sync`
request maps to exactly one Upstash `EVAL` command.

## Render environment variables

- `UPSTASH_REDIS_REST_URL`: Upstash REST endpoint.
- `UPSTASH_REDIS_REST_TOKEN`: Upstash standard token. Never expose this to clients.
- `SYNC_HMAC_KEY`: At least 16 characters. Must match Kaguya's `SyncKey`.

Use the resulting `https://<service>.onrender.com` URL as Kaguya's `Endpoint`.
The relay keeps the newest state for each client and removes client records after
seven days without an update. Database credentials stay exclusively on Render.
