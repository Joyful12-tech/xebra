/**
 * The shape of an API key on this side of the wire.
 *
 * A key is `xk_live_` and 32 base62 characters. Only its SHA-256 hex and the first 12 characters
 * ever reach Convex: the key itself is minted, hashed and printed on the operator's machine
 * (`scripts/api-keys.mjs`), so a Convex log or a database dump cannot give anyone a working key.
 *
 * This side hashes with Web Crypto and the operator script with `node:crypto`; both are SHA-256
 * over the UTF-8 bytes, and `keys.test.ts` holds them to the same digest.
 */

export const API_KEY_PREFIX = "xk_live_";

/** `xk_live_` and 32 base62 characters: 8 + 32. */
export const API_KEY_LENGTH = 40;

/** The characters of a key an operator is shown, to tell one from another. */
export const PREFIX_LENGTH = 12;

const KEY_SHAPE = /^xk_live_[0-9A-Za-z]{32}$/;

/** Whether `value` is the shape of a key this API issues, without asking anyone if it exists. */
export function isApiKey(value: string): boolean {
  return KEY_SHAPE.test(value);
}

/** What Convex stores for a key: its digest and enough of it to name it. Never the key. */
export interface ApiKeyRecord {
  /** `sha256(key)` as hex. */
  hash: string;
  /** The first 12 characters of the key. */
  prefix: string;
}

/** `sha256(key)` in lowercase hex. The same digest `scripts/api-keys.mjs` computes. */
export async function hashApiKey(key: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** The record to store for `key`. Everything a request with the key will be matched against. */
export async function apiKeyRecord(key: string): Promise<ApiKeyRecord> {
  return { hash: await hashApiKey(key), prefix: key.slice(0, PREFIX_LENGTH) };
}
