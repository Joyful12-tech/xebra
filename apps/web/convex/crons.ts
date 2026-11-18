import { cronJobs } from "convex/server";
import { internal } from "./_generated/api";

/**
 * One job for now: forgetting rate-limit buckets nobody has used for a few minutes, so the table
 * stays proportional to the callers we have rather than every address that ever called.
 */
const crons = cronJobs();

crons.interval("sweep spent rate windows", { minutes: 15 }, internal.rateLimit.sweep, {});

export default crons;
