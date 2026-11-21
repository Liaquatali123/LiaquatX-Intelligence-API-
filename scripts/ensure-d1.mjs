const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
const token = process.env.CLOUDFLARE_API_TOKEN;
if (!accountId || !token) throw new Error("Missing CLOUDFLARE_ACCOUNT_ID or CLOUDFLARE_API_TOKEN");
const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
const base = `https://api.cloudflare.com/client/v4/accounts/${accountId}/d1/database`;
async function api(url, init = {}) {
  const response = await fetch(url, { ...init, headers: { ...headers, ...(init.headers || {}) } });
  const data = await response.json();
  if (!response.ok || !data.success) throw new Error(JSON.stringify(data.errors || data));
  return data.result;
}
const databases = await api(base);
let db = databases.find((item) => item.name === "liaquatx-db");
if (!db) {
  db = await api(base, { method: "POST", body: JSON.stringify({ name: "liaquatx-db" }) });
  console.log("Created D1 database:", db.name);
} else {
  console.log("Reusing D1 database:", db.name);
}
const fs = await import("node:fs/promises");
const configPath = "wrangler.toml";
let config = await fs.readFile(configPath, "utf8");
if (/database_id\s*=\s*".+"/.test(config)) {
  config = config.replace(/database_id\s*=\s*"[^"]+"/, `database_id = "${db.uuid}"`);
} else {
  throw new Error("database_id field not found in wrangler.toml");
}
await fs.writeFile(configPath, config);
console.log("Configured D1 database UUID in wrangler.toml");
