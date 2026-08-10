import type { Env } from "./env";

export type RuntimeSecretName =
  | "JWT_SIGNING_KEY"
  | "DATA_ENCRYPTION_KEY"
  | "LOOKUP_HMAC_KEY"
  | "TURNSTILE_SECRET"
  | "TURNSTILE_BYPASS_TOKEN"
  | "ADMIN_BOOTSTRAP_TOKEN"
  | "REALTIME_API_TOKEN"
  | "CLOUDFLARE_BACKUP_API_TOKEN";

const localDefaults: Partial<Record<RuntimeSecretName, string>> = {
  JWT_SIGNING_KEY: "unsafe-local-development-jwt-key",
  DATA_ENCRYPTION_KEY: "unsafe-local-development-DATA_ENCRYPTION_KEY",
  LOOKUP_HMAC_KEY: "unsafe-local-development-LOOKUP_HMAC_KEY",
};

export async function getSecret(
  env: Env,
  name: RuntimeSecretName,
): Promise<string> {
  const value = await getOptionalSecret(env, name);
  if (value) return value;
  const fallback = env.ENVIRONMENT === "dev" ? localDefaults[name] : undefined;
  if (fallback) return fallback;
  throw new Error(`${name} Secrets Store binding is unavailable`);
}

export async function getOptionalSecret(
  env: Env,
  name: RuntimeSecretName,
): Promise<string | undefined> {
  const binding = env[`${name}_SECRET` as keyof Env];
  if (binding && typeof binding === "object" && "get" in binding) {
    const value = await (binding as SecretsStoreSecret).get();
    if (value) return value;
  }
  if (env.ENVIRONMENT !== "prod") {
    const local = env[name];
    if (typeof local === "string" && local) return local;
  }
  return undefined;
}
