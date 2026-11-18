/**
 * The shared secret between the Next.js server and this deployment.
 *
 * The API key functions here are public because the web server reaches them over HTTP. They take
 * `secret` and refuse unless it is `XEBRA_API_SECRET`, set on this deployment and in the web app's
 * server environment; it never reaches a browser. An unset secret refuses everything: a missing
 * variable must not open the door.
 *
 * The comparison is constant time — the loop always touches the same number of bytes, and a length
 * difference is folded into the same accumulator — so a caller cannot learn the secret a character
 * at a time from response timings.
 */

function sameBytes(a: string, b: string): boolean {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  let diff = x.length ^ y.length;
  const length = Math.max(x.length, y.length);
  for (let i = 0; i < length; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

/** Throws unless `secret` is this deployment's `XEBRA_API_SECRET`. */
export function requireSecret(secret: string): void {
  const expected = process.env.XEBRA_API_SECRET;
  if (!expected || !sameBytes(secret, expected)) throw new Error("not authorised");
}
