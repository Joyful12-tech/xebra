import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { requireSecret } from "./auth";

/**
 * API keys, stored only as digests.
 *
 * A key is minted on the operator's machine (`apps/web/scripts/api-keys.mjs`), which computes
 * `sha256(key)` and sends only that and the first 12 characters here. Nothing in this deployment
 * — no document, no function argument in the logs — can be turned back into a working key.
 *
 * A key identifies an integrator. It never authorises moving funds: every `/v1` handler still only
 * prices, builds unsigned transactions and reads status.
 *
 * All of these are guarded by `XEBRA_API_SECRET`; see `auth.ts`.
 */

const HASH = /^[0-9a-f]{64}$/;
const PREFIX = /^xk_live_[0-9A-Za-z]{4}$/;

export const create = mutation({
  args: {
    secret: v.string(),
    hash: v.string(),
    prefix: v.string(),
    name: v.string(),
    owner: v.string(),
    integrator: v.optional(v.string()),
    nowMs: v.number(),
  },
  handler: async (ctx, { secret, hash, prefix, name, owner, integrator, nowMs }) => {
    requireSecret(secret);
    if (!HASH.test(hash)) throw new Error("hash must be sha256 hex");
    if (!PREFIX.test(prefix)) throw new Error("prefix must be the first 12 characters of a key");
    const trimmed = { name: name.trim(), owner: owner.trim() };
    if (!trimmed.name || !trimmed.owner) throw new Error("name and owner are required");

    const existing = await ctx.db
      .query("apiKeys")
      .withIndex("by_hash", (q) => q.eq("hash", hash))
      .unique();
    if (existing) throw new Error("that key already exists");

    const id = await ctx.db.insert("apiKeys", {
      hash,
      prefix,
      name: trimmed.name,
      owner: trimmed.owner,
      ...(integrator ? { integrator: integrator.trim() } : {}),
      createdAt: nowMs,
    });
    return { id, prefix };
  },
});

/** Ask what a digest belongs to. Null when no key has it, or when it was revoked. */
export const authenticate = query({
  args: { secret: v.string(), hash: v.string() },
  handler: async (ctx, { secret, hash }) => {
    requireSecret(secret);
    if (!HASH.test(hash)) return null;
    const key = await ctx.db
      .query("apiKeys")
      .withIndex("by_hash", (q) => q.eq("hash", hash))
      .unique();
    if (!key || key.revokedAt !== undefined) return null;
    return { keyId: key._id, integrator: key.integrator ?? null };
  },
});

/** Operators only: what keys exist, newest first. Returns no hash and no key. */
export const list = query({
  args: { secret: v.string(), limit: v.optional(v.number()) },
  handler: async (ctx, { secret, limit }) => {
    requireSecret(secret);
    const rows = await ctx.db
      .query("apiKeys")
      .order("desc")
      .take(Math.min(Math.max(limit ?? 50, 1), 200));
    return rows.map((row) => ({
      id: row._id,
      prefix: row.prefix,
      name: row.name,
      owner: row.owner,
      integrator: row.integrator ?? null,
      createdAt: row.createdAt,
      revokedAt: row.revokedAt ?? null,
    }));
  },
});

/** Revoked keys stop working on the API's next lookup, at most a minute later. */
export const revoke = mutation({
  args: { secret: v.string(), id: v.id("apiKeys"), nowMs: v.number() },
  handler: async (ctx, { secret, id, nowMs }) => {
    requireSecret(secret);
    const key = await ctx.db.get(id);
    if (!key) throw new Error("no such key");
    if (key.revokedAt === undefined) await ctx.db.patch(id, { revokedAt: nowMs });
    return { id, prefix: key.prefix };
  },
});
