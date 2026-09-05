# Kaguya Sync Relay

## Oracle per-user VM pool

The relay can allocate one of up to four pre-created Oracle Ampere A1 VMs to
each authorized Kaguya device. Configure `OCI_TENANCY_OCID`, `OCI_USER_OCID`,
`OCI_FINGERPRINT`, `OCI_PRIVATE_KEY_PEM`, `OCI_REGION`,
`KAGUYA_ORACLE_VM_POOL_JSON`, and `KAGUYA_FAILURE_WEBHOOK` as Render secrets.
Sessions are persisted in Upstash and inactive VMs are stopped after 15
minutes. Give the OCI API user permission only to inspect/start/stop the listed
instances.

The pool JSON is an array of `{id, workerId, name, address}` objects. Each VM's
`KAGUYA_WORKER_ID` must match its pool entry. Never commit OCI keys, Microsoft
tokens, or Discord webhook URLs.

Render-hosted relay for Kaguya's same-server learning database. Each `/v1/sync`
request maps to exactly one Upstash `EVAL` command.

## Render environment variables

- `UPSTASH_REDIS_REST_URL`: Upstash REST endpoint.
- `UPSTASH_REDIS_REST_TOKEN`: Upstash standard token. Never expose this to clients.
- `SYNC_HMAC_KEY`: At least 16 characters. Must match Kaguya's `SyncKey`.

Use the resulting `https://<service>.onrender.com` URL as Kaguya's `Endpoint`.
The relay keeps the newest state for each client and removes client records after
seven days without an update. Database credentials stay exclusively on Render.
