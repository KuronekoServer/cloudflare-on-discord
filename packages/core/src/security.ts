import { argon2id } from "@noble/hashes/argon2.js";
import * as OTPAuth from "otpauth";

const ARGON_MEMORY_KIB = 19 * 1024;
const ARGON_ITERATIONS = 2;
const ARGON_PARALLELISM = 1;

function encodeBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/=+$/, "");
}

function decodeBase64(value: string): Uint8Array {
  const padded = value.padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

export function randomToken(bytes = 32): string {
  const value = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...value))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

export async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = argon2id(password, salt, {
    m: ARGON_MEMORY_KIB,
    t: ARGON_ITERATIONS,
    p: ARGON_PARALLELISM,
    dkLen: 32,
  });
  return `$argon2id$v=19$m=${ARGON_MEMORY_KIB},t=${ARGON_ITERATIONS},p=${ARGON_PARALLELISM}$${encodeBase64(salt)}$${encodeBase64(hash)}`;
}

export async function verifyPassword(
  hash: string,
  password: string,
): Promise<boolean> {
  const match =
    /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$/.exec(hash);
  if (!match) return false;
  const memory = Number(match[1]);
  const iterations = Number(match[2]);
  const parallelism = Number(match[3]);
  if (
    memory < ARGON_MEMORY_KIB ||
    iterations < ARGON_ITERATIONS ||
    parallelism !== ARGON_PARALLELISM
  )
    return false;
  const expected = decodeBase64(match[5]!);
  const actual = argon2id(password, decodeBase64(match[4]!), {
    m: memory,
    t: iterations,
    p: parallelism,
    dkLen: expected.length,
  });
  if (actual.length !== expected.length) return false;
  let difference = 0;
  for (let index = 0; index < actual.length; index += 1) {
    difference |= actual[index]! ^ expected[index]!;
  }
  return difference === 0;
}

export function createTotpSecret(): string {
  return new OTPAuth.Secret({ size: 20 }).base32;
}

export function totpUri(
  account: string,
  issuer: string,
  secret: string,
): string {
  return new OTPAuth.TOTP({
    issuer,
    label: account,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secret),
  }).toString();
}

export function verifyTotp(
  token: string,
  account: string,
  issuer: string,
  secret: string,
): boolean {
  const totp = new OTPAuth.TOTP({
    issuer,
    label: account,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secret),
  });
  return totp.validate({ token, window: 1 }) !== null;
}
