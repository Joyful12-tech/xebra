import { describe, expect, it } from "vitest";
import {
  ANONYMOUS_LIMIT,
  type Caller,
  KEYED_LIMIT,
  createGate,
  memoryRateStore,
  rateBucket,
} from "./access";
import { ApiError } from "./errors";

const MINUTE = 60_000;
/** A minute boundary, so `Retry-After` is the whole window. */
const T0 = Date.UTC(2026, 10, 18, 12, 0, 0);
const KEY = `xk_live_${"a".repeat(32)}`;
const ACME: Caller = { keyId: "key-1", integrator: "acme" };

function req(opts: { key?: string; authorization?: string; ip?: string } = {}) {
  const headers = new Headers();
  const authorization = opts.authorization ?? (opts.key ? `Bearer ${opts.key}` : undefined);
  if (authorization !== undefined) headers.set("Authorization", authorization);
  // Vercel appends its own hops; the first entry is the client.
  if (opts.ip) headers.set("X-Forwarded-For", `${opts.ip}, 10.0.0.1`);
  return new Request("https://api.xebra.exchange/v1/routes", { headers });
}

describe("who is asking", () => {
  it("treats a request with no Authorization header as anonymous", async () => {
    const gate = createGate({ lookup: async () => ACME, store: memoryRateStore() });
    expect(await gate.identify(req())).toBeNull();
  });

  it("identifies a key as the integrator it was issued to", async () => {
    const gate = createGate({ lookup: async () => ACME, store: memoryRateStore() });
    expect(await gate.identify(req({ key: KEY }))).toEqual(ACME);
  });

  it("refuses a key nobody issued, as unauthorized", async () => {
    const gate = createGate({ lookup: async () => null, store: memoryRateStore() });
    const err = await gate.identify(req({ key: KEY })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ code: "unauthorized", status: 401 });
    expect((err as ApiError).headers).toEqual({});
  });

  it("refuses an Authorization header that is not a bearer key", async () => {
    const gate = createGate({ lookup: async () => ACME, store: memoryRateStore() });
    for (const authorization of ["Basic abc", "Bearer", "bearer ", "xk_live_abc"]) {
      expect(await gate.identify(req({ authorization })).catch((e: unknown) => e)).toMatchObject({
        code: "unauthorized",
      });
    }
  });

  it("refuses a key of the wrong shape without asking Convex", async () => {
    const lookups: string[] = [];
    const gate = createGate({
      lookup: async (hash) => {
        lookups.push(hash);
        return ACME;
      },
      store: memoryRateStore(),
    });
    const err = await gate
      .identify(req({ authorization: `Bearer xk_live_${"a".repeat(31)}` }))
      .catch((e: unknown) => e);
    expect(err).toMatchObject({ code: "unauthorized" });
    expect(lookups).toEqual([]);
  });

  it("stops accepting a revoked key within a minute", async () => {
    let now = T0;
    let revoked = false;
    const gate = createGate({
      lookup: async () => (revoked ? null : ACME),
      store: memoryRateStore(),
      now: () => now,
    });

    expect(await gate.identify(req({ key: KEY }))).toEqual(ACME);
    revoked = true;

    // Still cached: the answer is trusted for a minute, which is what the docs promise.
    now = T0 + 59_000;
    expect(await gate.identify(req({ key: KEY }))).toEqual(ACME);

    now = T0 + 60_001;
    expect(await gate.identify(req({ key: KEY })).catch((e: unknown) => e)).toMatchObject({
      code: "unauthorized",
    });
  });

  it("does not cache a key it could not find, so a key minted a moment ago works", async () => {
    let exists = false;
    const gate = createGate({
      lookup: async () => (exists ? ACME : null),
      store: memoryRateStore(),
    });
    expect(await gate.identify(req({ key: KEY })).catch((e: unknown) => e)).toMatchObject({
      code: "unauthorized",
    });
    exists = true;
    expect(await gate.identify(req({ key: KEY }))).toEqual(ACME);
  });
});

describe("how much they may ask", () => {
  it("allows 60 anonymous requests a minute, then 429s with Retry-After", async () => {
    const gate = createGate({ lookup: async () => null, store: memoryRateStore(), now: () => T0 });
    for (let i = 0; i < ANONYMOUS_LIMIT; i++) {
      expect((await gate.hit(null, req({ ip: "203.0.113.7" }))).remaining).toBe(
        ANONYMOUS_LIMIT - i - 1,
      );
    }
    const err = await gate.hit(null, req({ ip: "203.0.113.7" })).catch((e: unknown) => e);
    expect(err).toMatchObject({ code: "rate_limited", status: 429 });
    expect((err as ApiError).headers).toMatchObject({
      "Retry-After": "60",
      "RateLimit-Limit": String(ANONYMOUS_LIMIT),
      "RateLimit-Remaining": "0",
      "RateLimit-Reset": "60",
    });
    expect((err as ApiError).detail).toContain("60 requests a minute per IP address");
  });

  it("counts anonymous callers by the first forwarded address, not together", async () => {
    const gate = createGate({ lookup: async () => null, store: memoryRateStore(), now: () => T0 });
    for (let i = 0; i < ANONYMOUS_LIMIT; i++) await gate.hit(null, req({ ip: "203.0.113.7" }));
    expect((await gate.hit(null, req({ ip: "198.51.100.9" }))).remaining).toBe(ANONYMOUS_LIMIT - 1);
    expect(rateBucket(null, req({ ip: "198.51.100.9" }))).toBe("ip:198.51.100.9");
    expect(rateBucket(ACME, req({ ip: "198.51.100.9" }))).toBe("key:key-1");
  });

  it("puts a request with no address at all in one bucket rather than exempting it", () => {
    expect(rateBucket(null, req())).toBe("ip:unknown");
  });

  it("gives a key 600 a minute in a bucket of its own", async () => {
    const gate = createGate({ lookup: async () => ACME, store: memoryRateStore(), now: () => T0 });
    // The same IP's anonymous budget does not touch the key's.
    for (let i = 0; i < ANONYMOUS_LIMIT; i++) await gate.hit(null, req({ ip: "203.0.113.7" }));
    for (let i = 0; i < KEYED_LIMIT; i++) {
      expect((await gate.hit(ACME, req({ ip: "203.0.113.7" }))).limit).toBe(KEYED_LIMIT);
    }
    const err = await gate.hit(ACME, req({ ip: "203.0.113.7" })).catch((e: unknown) => e);
    expect(err).toMatchObject({ code: "rate_limited" });
    expect((err as ApiError).headers["Retry-After"]).toBe("60");
    expect((err as ApiError).detail).toContain("600 requests a minute per API key");
  });

  it("forgets the count when the minute rolls over", async () => {
    let now = T0;
    const gate = createGate({ lookup: async () => null, store: memoryRateStore(), now: () => now });
    for (let i = 0; i < ANONYMOUS_LIMIT; i++) await gate.hit(null, req({ ip: "203.0.113.7" }));
    expect(await gate.hit(null, req({ ip: "203.0.113.7" })).catch((e: unknown) => e)).toMatchObject(
      { code: "rate_limited" },
    );
    now = T0 + MINUTE;
    expect((await gate.hit(null, req({ ip: "203.0.113.7" }))).remaining).toBe(ANONYMOUS_LIMIT - 1);
  });

  it("reports the seconds left in the window, not the epoch second", async () => {
    const gate = createGate({
      lookup: async () => null,
      store: memoryRateStore(),
      now: () => T0 + 15_000,
    });
    expect((await gate.hit(null, req({ ip: "203.0.113.7" }))).reset).toBe(45);
  });
});
