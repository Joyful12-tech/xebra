import { ApiError } from "./errors";
import { hashApiKey, isApiKey } from "./keys";

/**
 * Who is asking, and how much they may ask.
 *
 * Keys identify an integrator; they never authorise moving funds, which is why this file is only
 * about identity and counting. A request without a key is not refused: it is counted against its
 * IP address at a lower limit, so every existing caller keeps working.
 *
 * The counter is a store rather than a field so the live wiring can put it in Convex (one counter
 * for every Vercel instance, as the Iris budget is) and tests can put it in memory.
 */

/** Requests a minute from one IP address, with no key. */
export const ANONYMOUS_LIMIT = 60;
/** Requests a minute from one key. */
export const KEYED_LIMIT = 600;
/** Limits are per whole minute, UTC, like the Iris budget's per-second window. */
export const WINDOW_MS = 60_000;
/** How long a key's answer is trusted before we ask Convex again. A revoked key stops working
 *  within this, which is what the docs promise. */
export const KEY_CACHE_MS = 60_000;

export interface Caller {
  /** The Convex document id of the key: what the rate limit is counted against. */
  keyId: string;
  /** Who the key was issued to, as the operator recorded it. */
  integrator: string | null;
}

export interface Rate {
  limit: number;
  remaining: number;
  /** Seconds until the window ends: what `RateLimit-Reset` and `Retry-After` say. */
  reset: number;
}

export interface RateCount {
  /** How many requests this bucket has made in the current minute, this one included. */
  count: number;
  /** Epoch ms when the minute ends. */
  resetMs: number;
}

/** Where requests are counted. The live one is Convex; see `lib/server/access.ts`. */
export interface RateStore {
  hit(bucket: string, nowMs: number): Promise<RateCount>;
}

export interface Gate {
  /** The key's owner, or null for a caller that sent no key. Throws `unauthorized`. */
  identify(req: Request): Promise<Caller | null>;
  /** Counts this request and throws `rate_limited` past the limit. */
  hit(caller: Caller | null, req: Request): Promise<Rate>;
}

/**
 * A counter per bucket in this instance's memory, for tests and for a deployment with no Convex.
 * Vercel runs many instances, so this sees a fraction of the traffic; the shared store is what
 * actually bounds a key.
 */
export function memoryRateStore(maxBuckets = 10_000): RateStore {
  const windows = new Map<string, { minute: number; count: number }>();
  return {
    async hit(bucket, nowMs) {
      const minute = Math.floor(nowMs / WINDOW_MS);
      const row = windows.get(bucket);
      const count = row?.minute === minute ? row.count + 1 : 1;
      if (windows.size >= maxBuckets && !windows.has(bucket)) {
        // Spent windows first; a Map iterates in insertion order.
        for (const [key, value] of windows) if (value.minute < minute) windows.delete(key);
      }
      windows.set(bucket, { minute, count });
      return { count, resetMs: (minute + 1) * WINDOW_MS };
    },
  };
}

/** The headers every answer carries, so a client can see what it has left before it is refused. */
export function rateHeaders(rate: Rate): Record<string, string> {
  return {
    "RateLimit-Limit": String(rate.limit),
    "RateLimit-Remaining": String(rate.remaining),
    "RateLimit-Reset": String(rate.reset),
  };
}

/** The key in `Authorization: Bearer <key>`, or null when the header says something else. */
function bearerToken(authorization: string): string | null {
  const match = /^Bearer[ \t]+(\S+)$/i.exec(authorization.trim());
  return match?.[1] ?? null;
}

/**
 * The bucket a request is counted in. Anonymous callers are counted per address: the first entry
 * of `X-Forwarded-For` is the client Vercel saw. A request with no forwarding header at all shares
 * the `unknown` bucket, which is the safe way to be wrong.
 */
export function rateBucket(caller: Caller | null, req: Request): string {
  if (caller) return `key:${caller.keyId}`;
  const forwarded = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return `ip:${forwarded || req.headers.get("x-real-ip")?.trim() || "unknown"}`;
}

export interface GateOptions {
  /** Ask Convex what this digest belongs to; null when no key has it, or it was revoked. */
  lookup(hash: string): Promise<Caller | null>;
  store: RateStore;
  now?: () => number;
  /** How long a key's answer is trusted. Defaults to a minute. */
  cacheMs?: number;
  limits?: { anonymous?: number; keyed?: number };
}

/**
 * The gate in front of every `/v1` handler: identify, then count.
 *
 * Only keys we found are cached. A key minted a moment ago therefore works on its first request,
 * while a revoked one keeps working for at most `cacheMs` — the trade the plan asks for, and the
 * one the docs state.
 */
export function createGate(opts: GateOptions): Gate {
  const now = opts.now ?? Date.now;
  const cacheMs = opts.cacheMs ?? KEY_CACHE_MS;
  const limits = {
    anonymous: opts.limits?.anonymous ?? ANONYMOUS_LIMIT,
    keyed: opts.limits?.keyed ?? KEYED_LIMIT,
  };
  const known = new Map<string, { at: number; caller: Caller }>();

  async function identify(req: Request): Promise<Caller | null> {
    const authorization = req.headers.get("authorization");
    if (authorization === null) return null;
    const key = bearerToken(authorization);
    if (key === null) {
      throw new ApiError(
        "unauthorized",
        "`Authorization` must be `Bearer <api key>`. To call without a key, send no Authorization header.",
      );
    }
    if (!isApiKey(key)) {
      throw new ApiError(
        "unauthorized",
        "That is not an Xebra API key: a key is `xk_live_` followed by 32 letters and digits.",
      );
    }
    const hash = await hashApiKey(key);
    const hit = known.get(hash);
    if (hit && now() - hit.at < cacheMs) return hit.caller;

    const caller = await opts.lookup(hash);
    if (!caller) {
      known.delete(hash);
      throw new ApiError(
        "unauthorized",
        "That API key is unknown or revoked. Check it, or ask Xebra for a new one.",
      );
    }
    if (known.size >= 5_000) {
      const oldest = known.keys().next().value;
      if (oldest !== undefined) known.delete(oldest);
    }
    known.set(hash, { at: now(), caller });
    return caller;
  }

  async function hit(caller: Caller | null, req: Request): Promise<Rate> {
    const limit = caller ? limits.keyed : limits.anonymous;
    const nowMs = now();
    const { count, resetMs } = await opts.store.hit(rateBucket(caller, req), nowMs);
    const reset = Math.max(1, Math.ceil((resetMs - nowMs) / 1000));
    if (count > limit) {
      const per = caller
        ? `${limit} requests a minute per API key`
        : `${limit} requests a minute per IP address without a key`;
      throw new ApiError(
        "rate_limited",
        `Too many requests: the limit is ${per}. Retry in ${reset} seconds.`,
        {},
        {
          "Retry-After": String(reset),
          ...rateHeaders({ limit, remaining: 0, reset }),
        },
      );
    }
    return { limit, remaining: Math.max(0, limit - count), reset };
  }

  return { identify, hit };
}
