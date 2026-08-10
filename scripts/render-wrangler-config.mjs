import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const value = (name) => {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1])
    throw new Error(`${name} is required`);
  return process.argv[index + 1];
};
const inventoryPath = resolve(value("--inventory"));
const outputPath = resolve(value("--output"));
const inventory = JSON.parse(readFileSync(inventoryPath, "utf8"));
if (!["staging", "prod"].includes(inventory.environment))
  throw new Error("Inventory environment must be staging or prod");
for (const key of [
  "publicOrigin",
  "rpId",
  "emailFrom",
  "secretStoreId",
  "publicCacheId",
  "realtimeAppId",
  "cloudflareAccountId",
])
  if (!inventory[key] || String(inventory[key]).startsWith("replace-"))
    throw new Error(`Inventory ${key} is missing`);

const templateText = readFileSync(
  new URL("../apps/worker/wrangler.jsonc", import.meta.url),
  "utf8",
);
const template = JSON.parse(templateText.replace(/,\s*([}\]])/gu, "$1"));
const environment = inventory.environment;
const replaceEnvironment = (input) => {
  if (typeof input === "string")
    return input.replaceAll("cloudcord-dev", `cloudcord-${environment}`);
  if (Array.isArray(input)) return input.map(replaceEnvironment);
  if (input && typeof input === "object")
    return Object.fromEntries(
      Object.entries(input).map(([key, entry]) => [
        key,
        replaceEnvironment(entry),
      ]),
    );
  return input;
};
const config = replaceEnvironment(template);
config.name = `cloudcord-${environment}`;
config.workers_dev = false;
config.vars = {
  ...config.vars,
  ENVIRONMENT: environment,
  PUBLIC_ORIGIN: inventory.publicOrigin,
  RP_ID: inventory.rpId,
  EMAIL_FROM: inventory.emailFrom,
  REALTIME_APP_ID: inventory.realtimeAppId,
  CLOUDFLARE_ACCOUNT_ID: inventory.cloudflareAccountId,
};
for (const database of config.d1_databases) {
  const id = inventory.d1?.[database.database_name];
  if (!id)
    throw new Error(`Inventory is missing D1 ID for ${database.database_name}`);
  database.database_id = id;
}
config.kv_namespaces = [
  { binding: "PUBLIC_CACHE", id: inventory.publicCacheId },
];
config.r2_buckets = config.r2_buckets.map(({ binding, bucket_name }) => ({
  binding,
  bucket_name,
}));
config.secrets_store_secrets = [
  "JWT_SIGNING_KEY",
  "DATA_ENCRYPTION_KEY",
  "LOOKUP_HMAC_KEY",
  "TURNSTILE_SECRET",
  "ADMIN_BOOTSTRAP_TOKEN",
  "REALTIME_API_TOKEN",
  "CLOUDFLARE_BACKUP_API_TOKEN",
].map((secretName) => ({
  binding: `${secretName}_SECRET`,
  store_id: inventory.secretStoreId,
  secret_name: secretName,
}));
writeFileSync(outputPath, `${JSON.stringify(config, null, 2)}\n`, {
  encoding: "utf8",
  flag: "wx",
});
console.log(`Wrote ${outputPath}`);
