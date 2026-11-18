#!/usr/bin/env node
/**
 * Issue, list and revoke API keys against the Convex deployment the API reads them from.
 *
 *   CONVEX_URL=https://<deployment>.convex.cloud XEBRA_API_SECRET=... \
 *     pnpm --filter @xebra/web keys create --name "Acme" --owner you@acme.com [--integrator acme]
 *   pnpm --filter @xebra/web keys list
 *   pnpm --filter @xebra/web keys revoke <key id>
 *
 * A key is minted here and only its SHA-256 digest and first 12 characters are sent, so a key never
 * reaches Convex — not in a document, not in a function argument in the dashboard's logs. It is
 * printed once, at creation. `lib/api/keys.ts` hashes with Web Crypto for authentication; the test
 * `lib/api/keys.test.ts` holds this file's digest to the same answer.
 */
import { createHash, randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";
import { ConvexHttpClient } from "convex/browser";
import { makeFunctionReference } from "convex/server";

const API_KEY_PREFIX = "xk_live_";
const KEY_CHARS = 32;
const ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/** 62 * 4 = 248: bytes at or above it are dropped, so no character is likelier than another. */
const UNBIASED = ALPHABET.length * Math.floor(256 / ALPHABET.length);

const create = makeFunctionReference < "mutation" > "apiKeys:create";
const list = makeFunctionReference < "query" > "apiKeys:list";
const revoke = makeFunctionReference < "mutation" > "apiKeys:revoke";

/** A new key: `xk_live_` and 32 base62 characters from the OS's random source. */
export function newApiKey() {
  let key = API_KEY_PREFIX;
  while (key.length < API_KEY_PREFIX.length + KEY_CHARS) {
    for (const byte of randomBytes(KEY_CHARS * 2)) {
      if (byte >= UNBIASED) continue;
      key += ALPHABET[byte % ALPHABET.length];
      if (key.length === API_KEY_PREFIX.length + KEY_CHARS) break;
    }
  }
  return key;
}

/** What Convex stores for `key`. No key: the digest and the prefix are all it gets. */
export function apiKeyRecord(key) {
  return {
    hash: createHash("sha256").update(key, "utf8").digest("hex"),
    prefix: key.slice(0, 12),
  };
}

function parse(argv) {
  const [command, ...rest] = argv;
  const flags = {};
  const positional = [];
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }
    const name = arg.slice(2);
    const value = rest[i + 1];
    if (value === undefined || value.startsWith("--")) throw new Error(`--${name} needs a value`);
    flags[name] = value;
    i++;
  }
  return { command, flags, positional };
}

function connection() {
  const url = process.env.CONVEX_URL ?? process.env.NEXT_PUBLIC_CONVEX_URL;
  const secret = process.env.XEBRA_API_SECRET;
  if (!url || !secret) {
    throw new Error(
      "set CONVEX_URL (or NEXT_PUBLIC_CONVEX_URL) and XEBRA_API_SECRET to the deployment's values",
    );
  }
  return { convex: new ConvexHttpClient(url), secret };
}

async function main(argv) {
  const { command, flags, positional } = parse(argv);
  if (!["create", "list", "revoke"].includes(command)) {
    throw new Error("usage: api-keys.mjs <create|list|revoke> [--name … --owner …] [id]");
  }
  const { convex, secret } = connection();

  if (command === "create") {
    const { name, owner, integrator } = flags;
    if (!name || !owner) {
      throw new Error('create needs --name and --owner, e.g. --name "Acme" --owner you@acme.com');
    }
    const key = newApiKey();
    const record = apiKeyRecord(key);
    const created = await convex.mutation(create, {
      secret,
      hash: record.hash,
      prefix: record.prefix,
      name,
      owner,
      ...(integrator ? { integrator } : {}),
      nowMs: Date.now(),
    });
    console.log(`Issued ${record.prefix}… (${created.id}) to ${owner}.`);
    console.log("");
    console.log(
      "This is the only time the key is shown. Send it as `Authorization: Bearer <key>`:",
    );
    console.log("");
    console.log(`  ${key}`);
    console.log("");
    return;
  }

  if (command === "list") {
    const keys = await convex.query(list, { secret });
    if (keys.length === 0) {
      console.log("No API keys have been issued.");
      return;
    }
    for (const key of keys) {
      const state =
        key.revokedAt === null ? "active" : `revoked ${new Date(key.revokedAt).toISOString()}`;
      console.log(
        `${key.id}  ${key.prefix}…  ${key.name}  <${key.owner}>  ${new Date(key.createdAt).toISOString()}  ${state}`,
      );
    }
    return;
  }

  const id = positional[0];
  if (!id) throw new Error("revoke needs the key's id, as `keys list` prints it");
  const revoked = await convex.mutation(revoke, { secret, id, nowMs: Date.now() });
  // The API caches a key's answer for a minute, so say how long "now" really is.
  console.log(`Revoked ${revoked.prefix}…. It stops authenticating within a minute.`);
}

const isMain =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  main(process.argv.slice(2)).catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exitCode = 1;
  });
}
