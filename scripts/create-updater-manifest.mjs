import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";

const value = (name) => {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1])
    throw new Error(`${name} is required`);
  return process.argv[index + 1];
};
const bundleDir = value("--bundle-dir");
const target = value("--target");
const version = value("--version").replace(/^v/, "");
const tag = value("--tag");
const baseUrl = value("--base-url").replace(/\/$/, "");
const output = value("--output");

function files(directory) {
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry);
    return statSync(path).isDirectory() ? files(path) : [path];
  });
}

const signaturePath = files(bundleDir).find((path) => path.endsWith(".sig"));
if (!signaturePath)
  throw new Error(`No updater signature found under ${bundleDir}`);
const artifactPath = signaturePath.slice(0, -4);
const manifest = {
  version,
  notes: `CloudCord ${version}`,
  pub_date: new Date().toISOString(),
  url: `${baseUrl}/desktop/${tag}/${target}/${encodeURIComponent(basename(artifactPath))}`,
  signature: readFileSync(signaturePath, "utf8").trim(),
};
writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
