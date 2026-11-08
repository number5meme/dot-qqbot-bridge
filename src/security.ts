import {
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  createHash,
  timingSafeEqual,
  createHmac,
} from "node:crypto";
import ipaddr from "ipaddr.js";

export const MAX_BODY = 64 * 1024;
export function same(a: string, b: string): boolean {
  return timingSafeEqual(
    createHash("sha256").update(a).digest(),
    createHash("sha256").update(b).digest(),
  );
}
export function qqKeys(secret: string) {
  if (!secret || Buffer.byteLength(secret) > 512)
    throw new Error("Invalid QQ secret");
  let seed = Buffer.from(secret);
  while (seed.length < 32) seed = Buffer.concat([seed, seed]);
  const key = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      seed.subarray(0, 32),
    ]),
    format: "der",
    type: "pkcs8",
  });
  return { privateKey: key, publicKey: createPublicKey(key) };
}
export function qqSign(secret: string, data: string | Uint8Array): string {
  return sign(
    null,
    typeof data === "string" ? Buffer.from(data) : data,
    qqKeys(secret).privateKey,
  ).toString("hex");
}
export function qqVerify(
  secret: string,
  body: Uint8Array,
  timestamp: string | null,
  signature: string | null,
  now = Date.now(),
): boolean {
  if (
    !timestamp ||
    !/^\d{10}$/.test(timestamp) ||
    Math.abs(now / 1000 - Number(timestamp)) > 300 ||
    !signature ||
    !/^[a-fA-F0-9]{128}$/.test(signature)
  )
    return false;
  const bytes = Buffer.from(signature, "hex");
  if ((bytes[63] & 224) !== 0) return false;
  return verify(
    null,
    Buffer.concat([Buffer.from(timestamp), Buffer.from(body)]),
    qqKeys(secret).publicKey,
    bytes,
  );
}
export function whSecret(value: unknown): Buffer {
  if (typeof value !== "string" || !/^whsec_[A-Za-z0-9+/]+={0,2}$/.test(value))
    throw new Error("Invalid webhook secret");
  const b = Buffer.from(value.slice(6), "base64");
  if (
    b.length < 24 ||
    b.length > 64 ||
    b.toString("base64").replace(/=+$/, "") !==
      value.slice(6).replace(/=+$/, "")
  )
    throw new Error("Invalid webhook secret");
  return b;
}
export function whSignature(
  secret: string,
  id: string,
  timestamp: string,
  body: string,
): string {
  return (
    "v1," +
    createHmac("sha256", whSecret(secret))
      .update(`${id}.${timestamp}.${body}`)
      .digest("base64")
  );
}
export function callbackUrl(raw: string, allowedHost: string): URL {
  const u = new URL(raw);
  if (
    !allowedHost ||
    u.protocol !== "https:" ||
    u.port ||
    u.username ||
    u.password ||
    u.hash ||
    u.hostname !== allowedHost ||
    ipaddr.isValid(u.hostname) ||
    !/^[a-z0-9.-]+$/.test(u.hostname) ||
    u.hostname.endsWith(".") ||
    u.pathname === "/"
  )
    throw new Error("Callback destination not allowed");
  return u;
}
export function publicV4(value: string): boolean {
  try {
    const a = ipaddr.parse(value);
    return a.kind() === "ipv4" && a.range() === "unicast";
  } catch {
    return false;
  }
}
export async function readBounded(
  request: Request,
  max = MAX_BODY,
): Promise<Uint8Array> {
  if (Number(request.headers.get("content-length")) > max)
    throw new Error("Body too large");
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const parts: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > max) throw new Error("Body too large");
      parts.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return Buffer.concat(parts);
}
export function canonical(x: unknown): string {
  if (Array.isArray(x)) return "[" + x.map(canonical).join(",") + "]";
  if (x && typeof x === "object")
    return (
      "{" +
      Object.keys(x)
        .sort()
        .map(
          (k) =>
            JSON.stringify(k) +
            ":" +
            canonical((x as Record<string, unknown>)[k]),
        )
        .join(",") +
      "}"
    );
  return JSON.stringify(x);
}
export function subscriptionId(
  principal: string,
  url: string,
  name: string,
  args: unknown,
): string {
  return (
    "sub_" +
    createHash("sha256")
      .update(canonical({ principal, url, name, args }))
      .digest("hex")
  );
}
export type Incoming = {
  id: string;
  user_openid: string;
  text: string;
  timestamp: string;
  received_at: number;
};
export function parseIncoming(
  payload: any,
  allowedOpenid: string,
  now = Date.now(),
): Incoming | null {
  if (payload?.op !== 0 || payload?.t !== "C2C_MESSAGE_CREATE") return null;
  const d = payload.d;
  if (!allowedOpenid || d?.author?.user_openid !== allowedOpenid) return null;
  if (
    typeof d.id !== "string" ||
    !d.id ||
    d.id.length > 256 ||
    typeof d.content !== "string" ||
    !d.content.trim() ||
    d.content.length > 8000 ||
    typeof d.timestamp !== "string" ||
    !/(Z|[+-]\d{2}:\d{2})$/.test(d.timestamp) ||
    !Number.isFinite(Date.parse(d.timestamp))
  )
    throw new Error("Incomplete C2C message");
  if (Math.abs(now - Date.parse(d.timestamp)) > 300_000)
    throw new Error("Stale C2C message");
  return {
    id: d.id,
    user_openid: allowedOpenid,
    text: d.content,
    timestamp: d.timestamp,
    received_at: now,
  };
}
