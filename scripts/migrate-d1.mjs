import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const workerDirectory = fileURLToPath(
  new URL("../apps/worker/", import.meta.url),
);
const remote = process.argv.includes("--remote");
const scopeIndex = process.argv.indexOf("--scope");
const scope = scopeIndex >= 0 ? process.argv[scopeIndex + 1] : undefined;
if (scope && !["identity", "social", "guild"].includes(scope))
  throw new Error(`Unknown migration scope: ${scope}`);
const wranglerScript = fileURLToPath(
  new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url),
);
const pools = {
  identity: ["IDENTITY_DB"],
  social: Array.from(
    { length: 16 },
    (_, index) => `SOCIAL_DB_${String(index).padStart(2, "0")}`,
  ),
  guild: Array.from(
    { length: 32 },
    (_, index) => `GUILD_DB_${String(index).padStart(2, "0")}`,
  ),
};
const bindings = scope
  ? pools[scope]
  : [...pools.identity, ...pools.social, ...pools.guild];

for (const binding of bindings) {
  console.log(
    `Applying migrations to ${binding} (${remote ? "remote" : "local"})`,
  );
  const command = [
    "wrangler",
    "d1",
    "migrations",
    "apply",
    binding,
    remote ? "--remote" : "--local",
  ];
  execFileSync(process.execPath, [wranglerScript, ...command.slice(1)], {
    cwd: workerDirectory,
    stdio: "inherit",
  });
}
