import { describe, expect, it } from "vitest";
import { newApiKey, apiKeyRecord as scriptRecord } from "../../scripts/api-keys.mjs";
import { PREFIX_LENGTH, apiKeyRecord, hashApiKey, isApiKey } from "./keys";

describe("API keys", () => {
  it("hashes to lowercase sha256 hex", async () => {
    // The reference digest of "abc", so a change of algorithm or encoding cannot pass unnoticed.
    expect(await hashApiKey("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("agrees with the operator script's digest, so a key it mints authenticates here", async () => {
    const key = newApiKey();
    expect(await apiKeyRecord(key)).toEqual(scriptRecord(key));
  });

  it("mints a key of the shape the docs promise", () => {
    const key = newApiKey();
    expect(isApiKey(key)).toBe(true);
    expect(key).toHaveLength(40);
    expect(key.startsWith("xk_live_")).toBe(true);
    expect(new Set([newApiKey(), newApiKey()]).size).toBe(2);
  });

  it("stores only a digest and a prefix: the key itself never leaves the operator's machine", async () => {
    const key = newApiKey();
    const record = await apiKeyRecord(key);
    expect(Object.keys(record).sort()).toEqual(["hash", "prefix"]);
    expect(record.prefix).toBe(key.slice(0, PREFIX_LENGTH));
    expect(JSON.stringify(record)).not.toContain(key);
    expect(record.hash).not.toContain(key);
  });

  it("refuses the shapes it does not issue", () => {
    for (const bad of [
      "",
      "xk_live_",
      `xk_live_${"a".repeat(31)}`,
      `xk_live_${"a".repeat(33)}`,
      `sk_live_${"a".repeat(32)}`,
      `xk_live_${"a".repeat(31)}-`,
      `xk_live_${"a".repeat(31)}é`,
    ]) {
      expect(isApiKey(bad)).toBe(false);
    }
  });
});
