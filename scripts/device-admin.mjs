const endpoint = (process.env.KAGUYA_ADMIN_ENDPOINT || "https://kaguya-sync.onrender.com").replace(/\/$/, "");
const token = process.env.KAGUYA_ADMIN_TOKEN || "";
const [command = "list", id, ...labelParts] = process.argv.slice(2);
if (token.length < 32) throw new Error("Set KAGUYA_ADMIN_TOKEN in this terminal");
const route = command === "approve" ? "/v1/admin/approve" : command === "revoke" ? "/v1/admin/revoke" : "/v1/admin/devices";
const body = command === "approve" ? { deviceId: id, label: labelParts.join(" ") }
  : command === "revoke" ? { licenseHash: id } : null;
const response = await fetch(endpoint + route, { method: body ? "POST" : "GET", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
const result = await response.json();
if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
if (command === "list") console.table(result.devices.map(device => ({ state: device.state, label: device.label || "", deviceId: device.deviceId, licenseHash: device.key })));
else console.log("OK");
