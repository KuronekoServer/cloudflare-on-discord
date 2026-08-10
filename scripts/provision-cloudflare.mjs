import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const manifest = JSON.parse(
  readFileSync(
    new URL("../infra/resource-pools.json", import.meta.url),
    "utf8",
  ),
);
const args = new Set(process.argv.slice(2));
const environmentIndex = process.argv.indexOf("--env");
const environment =
  environmentIndex >= 0 ? process.argv[environmentIndex + 1] : "dev";
if (!manifest.environments.includes(environment))
  throw new Error(`Unknown environment: ${environment}`);
const apply = args.has("--apply");
if (environment === "prod" && apply && !args.has("--confirm-production")) {
  throw new Error("Production provisioning requires --confirm-production");
}

const executable = process.platform === "win32" ? "npx.cmd" : "npx";
const wranglerScript = fileURLToPath(
  new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url),
);
const commands = [];
const add = (...command) => commands.push(command);
add(
  "wrangler",
  "secrets-store",
  "store",
  "create",
  `cloudcord-${environment}-secrets`,
);
add("wrangler", "d1", "create", `cloudcord-${environment}-identity`);
for (let index = 0; index < manifest.d1.social; index += 1)
  add(
    "wrangler",
    "d1",
    "create",
    `cloudcord-${environment}-social-${String(index).padStart(2, "0")}`,
  );
for (let index = 0; index < manifest.d1.guild; index += 1)
  add(
    "wrangler",
    "d1",
    "create",
    `cloudcord-${environment}-guild-${String(index).padStart(2, "0")}`,
  );
for (const bucket of manifest.r2)
  add(
    "wrangler",
    "r2",
    "bucket",
    "create",
    `cloudcord-${environment}-${bucket}`,
  );
for (const namespace of manifest.kv)
  add(
    "wrangler",
    "kv",
    "namespace",
    "create",
    `cloudcord-${environment}-${namespace}`,
  );
for (const queue of manifest.queues)
  add("wrangler", "queues", "create", `cloudcord-${environment}-${queue}`);

console.log(
  `# CloudCord ${environment} resource plan (${commands.length} resources)`,
);
for (const command of commands)
  console.log(`${executable} ${command.join(" ")}`);
if (!apply) {
  console.log(
    "\nPlan only. Re-run with --apply after checking the Cloudflare account and environment.",
  );
  process.exit(0);
}
for (const command of commands) {
  execFileSync(process.execPath, [wranglerScript, ...command.slice(1)], {
    stdio: "inherit",
  });
}
