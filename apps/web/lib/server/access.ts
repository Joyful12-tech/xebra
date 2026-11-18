import { ConvexHttpClient } from "convex/browser";
import { makeFunctionReference } from "convex/server";
import {
  type Caller,
  type Gate,
  type RateCount,
  type RateStore,
  createGate,
  memoryRateStore,
} from "../api/access";

/**
 * The live gate: keys and request counts in Convex, the same deployment the Iris budget uses.
 *
 * Vercel runs many short-lived instances, so a counter in one instance's memory sees a fraction of
 * a key's traffic. Convex is the shared one. Without `CONVEX_URL` and `XEBRA_API_SECRET` the app
 * still runs — it counts per instance and accepts no key, because a key cannot be checked without
 * the deployment that holds its digest. That is said once, in the log.
 */

const authenticate = makeFunctionReference<"query">("apiKeys:authenticate");
const countHit = makeFunctionReference<"mutation">("rateLimit:hit");

/** Ask Convex what a key's digest belongs to. Null when no key has it, or it was revoked. */
export function convexKeyLookup(
  convexUrl: string,
  secret: string,
): (hash: string) => Promise<Caller | null> {
  const client = new ConvexHttpClient(convexUrl);
  return async (hash) => (await client.query(authenticate, { secret, hash })) as Caller | null;
}

/** The shared per-minute counter. One Convex mutation per request, which is also its one write. */
export function convexRateStore(convexUrl: string, secret: string): RateStore {
  const client = new ConvexHttpClient(convexUrl);
  return {
    async hit(bucket, nowMs) {
      return (await client.mutation(countHit, { secret, bucket, nowMs })) as RateCount;
    },
  };
}

const SLOT = Symbol.for("xebra.api.access");

/** One gate per server instance; module state would be rebuilt on every hot reload in dev. */
function shared(): Gate {
  const g = globalThis as unknown as Record<symbol, Gate | undefined>;
  const existing = g[SLOT];
  if (existing) return existing;

  const convexUrl = process.env.CONVEX_URL ?? process.env.NEXT_PUBLIC_CONVEX_URL;
  const secret = process.env.XEBRA_API_SECRET;
  let gate: Gate;
  if (convexUrl && secret) {
    gate = createGate({
      lookup: convexKeyLookup(convexUrl, secret),
      store: convexRateStore(convexUrl, secret),
    });
  } else {
    console.warn(
      "api access: CONVEX_URL or XEBRA_API_SECRET unset, so no key can be accepted and limits are per instance",
    );
    gate = createGate({ lookup: async () => null, store: memoryRateStore() });
  }
  g[SLOT] = gate;
  return gate;
}

/** The gate in front of every live `/v1` request. */
export const liveGate: Gate = {
  identify: (req) => shared().identify(req),
  hit: (caller, req) => shared().hit(caller, req),
};
