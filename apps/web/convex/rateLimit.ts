import { v } from "convex/values";
import { internalMutation, mutation } from "./_generated/server";
import { requireSecret } from "./auth";

/**
 * The shared request counter behind `/v1`'s limits.
 *
 * One row per bucket — `key:<keyId>` for a caller that sent a key, `ip:<address>` for one that did
 * not — holding the whole minute and its count. A Convex mutation is serializable, so
 * read-increment-write is one atomic step: two instances answering at the same instant cannot both
 * be told there is room for the last request of the minute.
 *
 * The limit itself stays in the web app (`lib/api/access.ts`): this file counts, and one place
 * decides what the count may reach. There is no database per client, so the row is bounded at one
 * per bucket; `sweep` drops the buckets nobody has used for a few minutes.
 */

const MINUTE_MS = 60_000;

export const hit = mutation({
  args: { secret: v.string(), bucket: v.string(), nowMs: v.number() },
  handler: async (ctx, { secret, bucket, nowMs }) => {
    requireSecret(secret);
    const minute = Math.floor(nowMs / MINUTE_MS);
    const row = await ctx.db
      .query("rateWindows")
      .withIndex("by_bucket", (q) => q.eq("bucket", bucket))
      .unique();
    const count = row?.minute === minute ? row.count + 1 : 1;
    if (row) await ctx.db.patch(row._id, { minute, count });
    else await ctx.db.insert("rateWindows", { bucket, minute, count });
    return { count, resetMs: (minute + 1) * MINUTE_MS };
  },
});

/** Drops buckets whose last request is older than five minutes. Scheduled in `crons.ts`. */
export const sweep = internalMutation({
  args: {},
  handler: async (ctx) => {
    const cutoff = Math.floor(Date.now() / MINUTE_MS) - 5;
    const stale = await ctx.db
      .query("rateWindows")
      .withIndex("by_minute", (q) => q.lt("minute", cutoff))
      .take(500);
    for (const row of stale) await ctx.db.delete(row._id);
    return stale.length;
  },
});
