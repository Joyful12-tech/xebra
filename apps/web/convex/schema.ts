import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

/**
 * Convex holds three things here: the counter that keeps our calls to Circle's Iris API under its
 * rate limit (`irisBudget.ts`), the API keys integrators identify themselves with (`apiKeys.ts`),
 * and the counter behind `/v1`'s per-key and per-IP limits (`rateLimit.ts`).
 *
 * There used to be relay state in this file — jobs, retry schedules, a burn-watcher cursor. The
 * relay is gone: Circle's Forwarding Service mints on the destination, and a transfer whose
 * forward fails is claimed by its owner at `/claim`. Nothing here holds funds or anyone's transfer.
 * Keys are stored only as digests, so losing this database costs rate-limit memory and makes the
 * operator issue new keys — nothing else.
 */

export default defineSchema({
  irisBudget: defineTable({
    /** A single row, addressed by name so a second budget (a different Circle host) needs no
     *  schema change. */
    key: v.string(),
    /** The whole second (`floor(ms / 1000)`) `count` belongs to. */
    second: v.number(),
    count: v.number(),
    /** Calls made in the second before `second`. */
    prevCount: v.number(),
    /** Epoch ms until which we stay off Iris after a 429; 0 when not blocked. */
    blockedUntil: v.number(),
  }).index("by_key", ["key"]),

  apiKeys: defineTable({
    /** `sha256(key)` hex. The key itself is never stored, or sent here: see `lib/api/keys.ts`. */
    hash: v.string(),
    /** The key's first 12 characters, so an operator can name a key without holding it. */
    prefix: v.string(),
    name: v.string(),
    /** Who the key belongs to, as the operator recorded it. */
    owner: v.string(),
    /** The integrator the key identifies, when that differs from the owner. */
    integrator: v.optional(v.string()),
    /** Epoch ms the key was issued. */
    createdAt: v.number(),
    /** Epoch ms it was revoked, after which it authenticates nothing. */
    revokedAt: v.optional(v.number()),
  }).index("by_hash", ["hash"]),

  rateWindows: defineTable({
    /** One row per caller: `key:<keyId>` with a key, `ip:<address>` without one. */
    bucket: v.string(),
    /** The whole minute (`floor(ms / 60000)`) `count` belongs to. */
    minute: v.number(),
    count: v.number(),
  })
    .index("by_bucket", ["bucket"])
    .index("by_minute", ["minute"]),
});
