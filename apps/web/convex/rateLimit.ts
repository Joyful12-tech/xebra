import { v } from "convex/values";
import { type MutationCtx, mutation } from "./_generated/server";
import { requireSecret } from "./auth";

/**
 * The counter behind `/v1`'s per-key and per-IP limits.
 *
 * Vercel runs many short-lived instances, so an in-memory counter would see a fraction of the
 * traffic. A Convex mutation is serializable: read, increment and write are one atomic step, and
 * two instances asking at the same instant cannot both be told there is room for the last request.
 *
 * Windows are fixed minutes, because that is what `Retry-After` can explain simply. `bucket` is
 * `key:<id>` or `ip:<address>`; the web app decides which, and this file only counts.
 */

/** How many old windows to clear per hit; a bucket normally has one or two. */
const PRUNE_LIMIT = 20;

export const hit = mutation({
  args: { secret: v.string(), bucket: v.string(), minute: v.number() },
  handler: async (ctx, { secret, bucket, minute }) => {
    requireSecret(secret);
    const row = await ctx.db
      .query("rateWindows")
      .withIndex("by_key_minute", (q) => q.eq("key", bucket).eq("minute", minute))
      .unique();

    if (row) {
      await ctx.db.patch(row._id, { count: row.count + 1 });
      await prune(ctx, bucket, minute);
      return row.count + 1;
    }

    await ctx.db.insert("rateWindows", { key: bucket, minute, count: 1 });
    await prune(ctx, bucket, minute);
    return 1;
  },
});

/** Drop windows for this bucket that can no longer be asked about, so the table stays small. */
async function prune(ctx: MutationCtx, bucket: string, minute: number): Promise<void> {
  const old = await ctx.db
    .query("rateWindows")
    .withIndex("by_key_minute", (q) => q.eq("key", bucket).lt("minute", minute - 1))
    .take(PRUNE_LIMIT);
  for (const row of old) await ctx.db.delete(row._id);
}
