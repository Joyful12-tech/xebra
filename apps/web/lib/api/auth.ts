import { ApiError } from "./errors";

/**
 * API keys and rate limits for `/v1`.
 *
 * A key identifies an integrator, so their traffic can be counted — and counted higher than
 * anonymous traffic. Requests without a key keep working at a lower limit, so nothing that works
 * today stops working. A key never authorises moving funds: the API is non-custodial and never
 * takes a private key. It only says who is asking.
 *
 * The key itself is never stored. It arrives as `Authorization: Bearer xk_live_...`, is hashed
 * with SHA-256 here, and only the hash goes to the store (`convex/apiKeys.ts`). The store lives in
 * Convex because Vercel runs many short-lived instances that must share one counter; when Convex
 * cannot be reached, `resilientKeyStore` counts per instance instead of failing requests.
 */

export const KEY_PREFIX = "xk_live_";
export const KEY_DOCS = "https://docs.xebra.exchange/guides/api-keys";
/** 32 base62 characters after the prefix. */
const KEY_PATTERN = /^xk_live_[0-9A-Za-z]{32}$/;

/** Per IP, per minute, without a key. */
export const ANONYMOUS_LIMIT = 60;
/** Per key, per minute. */
export const KEY_LIMIT = 600;
/** How long a key's record is trusted, so revocation takes effect within a minute. */
export const KEY_CACHE_MS = 60_000;

export interface ApiKeyRecord {
  id: string;
  integrator: string | null;
  /** Epoch ms, or null while the key is live. */
  revokedAt: number | null;
}

/** What `createGuard` needs from a shared store: key lookups by hash, and a counter per bucket. */
export interface KeyStore {
  find(hash: string): Promise<ApiKeyRecord | null>;
  /** Count this call in `bucket`'s window `minute`, and return the count after it. */
  hit(bucket: string, minute: number): Promise<number>;
}

/** What a guard decided about one request, and the headers that say so. */
export interface Gate {
  keyId: string | null;
  integrator: string | null;
  headers: Record<string, string>;
}

export type Guard = (req: Request) => Promise<Gate>;

/** For surfaces where another layer has already counted and identified the caller. */
export const OPEN_GUARD: Guard = async () => ({ keyId: null, integrator: null, headers: {} });

/** SHA-256 of a key, lowercase hex. The only form of the key that leaves this process. */
export async function hashKey(key: string): Promise<string> {
  // Web Crypto, available in Node 20+ and in a Worker; no dependency, and not a Node-only module.
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * A `KeyStore` in this instance's memory: for tests, for `next dev` without Convex, and as the
 * fallback when Convex is unreachable. A restart forgets every key.
 */
export interface MemoryKeyStore extends KeyStore {
  keys: Map<string, ApiKeyRecord>;
  windows: Map<string, { minute: number; count: number }>;
  calls: Array<{ hash: string }>;
}

export function createMemoryKeyStore(
  seed: Array<{ hash: string; record: ApiKeyRecord }> = [],
): MemoryKeyStore {
  const keys = new Map(seed.map(({ hash, record }) => [hash, record]));
  const windows = new Map<string, { minute: number; count: number }>();
  const calls: Array<{ hash: string }> = [];
  return {
    keys,
    windows,
    calls,
    async find(hash) {
      // Recorded so a test can assert the raw key never reaches the store.
      calls.push({ hash });
      const record = keys.get(hash);
      // A copy: the guard's cache must not see a revocation until its own TTL expires.
      return record ? { ...record } : null;
    },
    async hit(bucket, minute) {
      const window = windows.get(bucket);
      if (!window || window.minute !== minute) {
        windows.set(bucket, { minute, count: 1 });
        return 1;
      }
      window.count += 1;
      return window.count;
    },
  };
}

/**
 * The shared store, with this instance's memory behind it. A Convex outage must not take the API
 * with it: anonymous calls keep their per-instance limit, and a key we cannot check is refused
 * rather than trusted.
 */
export function resilientKeyStore(
  primary: KeyStore,
  fallback: KeyStore,
  onError?: (err: unknown) => void,
): KeyStore {
  return {
    async find(hash) {
      try {
        return await primary.find(hash);
      } catch (err) {
        onError?.(err);
        return fallback.find(hash);
      }
    },
    async hit(bucket, minute) {
      try {
        return await primary.hit(bucket, minute);
      } catch (err) {
        onError?.(err);
        return fallback.hit(bucket, minute);
      }
    },
  };
}

/** The caller's address as the proxy reports it; all unknown callers share one bucket. */
export function clientIp(req: Request): string {
  const forwarded = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return forwarded || req.headers.get("x-real-ip")?.trim() || "unknown";
}

function unauthorized(detail: string): ApiError {
  return new ApiError(
    "unauthorized",
    detail,
    {},
    {
      "WWW-Authenticate": 'Bearer realm="xebra", error="invalid_token"',
    },
  );
}

/**
 * The `/v1` gate: identify the caller, then count them. A key that is unknown or revoked is a 401
 * before it costs anything; a caller over its limit is a 429 with `Retry-After`, in the same
 * RFC 9457 shape as every other failure.
 */
export function createGuard(opts: {
  store: KeyStore;
  now?: () => number;
  anonymousLimit?: number;
  keyLimit?: number;
  cacheMs?: number;
}): Guard {
  const now = opts.now ?? Date.now;
  const anonymousLimit = opts.anonymousLimit ?? ANONYMOUS_LIMIT;
  const keyLimit = opts.keyLimit ?? KEY_LIMIT;
  const cacheMs = opts.cacheMs ?? KEY_CACHE_MS;
  const cached = new Map<string, { at: number; record: ApiKeyRecord }>();
  const MAX_CACHED = 1_000;

  async function lookup(hash: string): Promise<ApiKeyRecord | null> {
    const hit = cached.get(hash);
    if (hit && now() - hit.at < cacheMs) return hit.record;
    const record = await opts.store.find(hash);
    if (!record) return null;
    if (cached.size >= MAX_CACHED) {
      const oldest = cached.keys().next().value;
      if (oldest !== undefined) cached.delete(oldest);
    }
    // Re-inserted so the map's order stays least-recently-used first.
    cached.delete(hash);
    cached.set(hash, { at: now(), record });
    return record;
  }

  return async (req) => {
    const header = req.headers.get("authorization");
    let keyId: string | null = null;
    let integrator: string | null = null;

    if (header !== null) {
      const bearer = /^Bearer\s+(\S+)$/i.exec(header.trim())?.[1];
      if (!bearer) {
        throw unauthorized(
          `The Authorization header must be \`Authorization: Bearer ${KEY_PREFIX}...\`. See ${KEY_DOCS}.`,
        );
      }
      if (!KEY_PATTERN.test(bearer)) {
        throw unauthorized(
          `That does not look like a Xebra key: they start with ${KEY_PREFIX} and have 32 characters after it. See ${KEY_DOCS}.`,
        );
      }
      const record = await lookup(await hashKey(bearer));
      if (!record) {
        throw unauthorized(`That API key is not one we issued. See ${KEY_DOCS}.`);
      }
      if (record.revokedAt !== null) {
        throw unauthorized(`That API key was revoked. See ${KEY_DOCS}.`);
      }
      keyId = record.id;
      integrator = record.integrator;
    }

    const limit = keyId ? keyLimit : anonymousLimit;
    const bucket = keyId ? `key:${keyId}` : `ip:${clientIp(req)}`;
    const minute = Math.floor(now() / 60_000);
    const count = await opts.store.hit(bucket, minute);
    const headers: Record<string, string> = {
      "RateLimit-Limit": String(limit),
      "RateLimit-Remaining": String(Math.max(0, limit - count)),
      // Epoch seconds, as `RateLimit-Reset` is specified.
      "RateLimit-Reset": String((minute + 1) * 60),
    };

    if (count > limit) {
      const retryAfter = Math.max(1, Math.ceil(((minute + 1) * 60_000 - now()) / 1000));
      throw new ApiError(
        "rate_limited",
        keyId
          ? `Too many requests: this key is limited to ${limit} a minute. Try again in ${retryAfter} seconds.`
          : `Too many requests: ${limit} a minute without a key. Send an API key for ${keyLimit} a minute, or try again in ${retryAfter} seconds.`,
        {},
        { ...headers, "Retry-After": String(retryAfter) },
      );
    }

    return { keyId, integrator, headers };
  };
}
