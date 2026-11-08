import { createHash, randomBytes } from "node:crypto";
import { same } from "./security.ts";

export const PAIRING_PENDING_KEY = "pairing:pending";
export const PAIRING_OWNER_KEY = "pairing:owner";
export const PAIRING_BOUND_KEY = "pairing:bound";
export const PAIRING_WINDOW_MS = 600_000;
export type PairingAuth = { principal: string; expiresAt: number };
export type PendingPairing = {
  hash: string;
  principal: string;
  createdAt: number;
  expiresAt: number;
};
export type PairedOwner = {
  principal: string;
  openid: string;
  pairedAt: number;
};
export function pairingIdentity(owner: PairedOwner): string {
  return createHash("sha256")
    .update(JSON.stringify([owner.principal, owner.openid, owner.pairedAt]))
    .digest("hex");
}
type Storage = Pick<
  DurableObjectStorage,
  "get" | "put" | "delete" | "getAlarm" | "setAlarm"
>;
const codePattern = /^QQPAIR-[A-F0-9]{32}$/;
const openidPattern = /^[A-Za-z0-9_-]{1,256}$/;
export function validPairingAuth(
  auth: unknown,
  now = Date.now(),
): auth is PairingAuth {
  const a = auth as PairingAuth | undefined;
  return (
    !!a &&
    typeof a.principal === "string" &&
    /^access_[a-f0-9]{64}$/.test(a.principal) &&
    Number.isSafeInteger(a.expiresAt) &&
    a.expiresAt > now &&
    a.expiresAt <= now + 86_460_000
  );
}
export async function pendingPairing(
  storage: Storage,
  now = Date.now(),
): Promise<PendingPairing | undefined> {
  const pending = await storage.get<PendingPairing>(PAIRING_PENDING_KEY);
  if (pending && pending.expiresAt <= now) {
    await storage.delete(PAIRING_PENDING_KEY);
    return;
  }
  return pending;
}
// Called inside the single-owner DO transaction, never via an unauthenticated HTTP route.
export async function startPairing(
  storage: Storage,
  auth: PairingAuth,
  clock: () => number = Date.now,
) {
  let now = clock();
  if (!validPairingAuth(auth, now))
    throw new Error("Verified owner authentication required");
  if (
    (await storage.get(PAIRING_OWNER_KEY)) !== undefined ||
    (await storage.get(PAIRING_BOUND_KEY)) !== undefined
  )
    throw new Error("An owner is already paired");
  const pending = await pendingPairing(storage, now);
  now = clock();
  if (!validPairingAuth(auth, now))
    throw new Error("Verified owner authentication required");
  if (pending && pending.principal !== auth.principal)
    throw new Error("Pairing unavailable for this authentication");
  if (pending && pending.expiresAt > now)
    return {
      pending: true,
      expires_at: new Date(pending.expiresAt).toISOString(),
      purpose:
        "The existing code cannot be shown again. Use the original code, or wait for its expiry and request a new code.",
    };
  now = clock();
  if (!validPairingAuth(auth, now))
    throw new Error("Verified owner authentication required");
  const code = "QQPAIR-" + randomBytes(16).toString("hex").toUpperCase();
  const expiresAt = Math.min(now + PAIRING_WINDOW_MS, auth.expiresAt);
  await storage.put<PendingPairing>(PAIRING_PENDING_KEY, {
    hash: createHash("sha256").update(code).digest("hex"),
    principal: auth.principal,
    createdAt: now,
    expiresAt,
  });
  await storage.setAlarm(
    Math.min((await storage.getAlarm()) ?? Infinity, expiresAt),
  );
  return {
    code,
    expires_at: new Date(expiresAt).toISOString(),
    purpose:
      "Send this exact code only in your private chat with the QQ bot. Pairing does not enable normal messages or replies.",
  };
}
// Intercept even stale, malformed-context or repeated codes before ordinary ingestion.
export function containsPairingCode(payload: any): boolean {
  return (
    typeof payload?.d?.content === "string" &&
    /QQPAIR-[a-fA-F0-9]{32}/.test(payload.d.content)
  );
}
export function pairingCommand(
  payload: any,
  now = Date.now(),
): { code: string; openid: string; timestamp: number } | undefined {
  if (payload?.op !== 0 || payload?.t !== "C2C_MESSAGE_CREATE") return;
  const d = payload.d;
  if (
    typeof d?.content !== "string" ||
    !codePattern.test(d.content.trim()) ||
    typeof d?.author?.user_openid !== "string" ||
    !openidPattern.test(d.author.user_openid) ||
    typeof d.timestamp !== "string" ||
    !/(Z|[+-]\d{2}:\d{2})$/.test(d.timestamp)
  )
    return;
  const timestamp = Date.parse(d.timestamp);
  if (!Number.isFinite(timestamp) || Math.abs(now - timestamp) > 300_000)
    return;
  return { code: d.content.trim(), openid: d.author.user_openid, timestamp };
}
export async function consumePairing(
  storage: Storage,
  input: unknown,
  clock: () => number = Date.now,
): Promise<PairedOwner | undefined> {
  let now = clock();
  const p = input as ReturnType<typeof pairingCommand>;
  if (
    !p ||
    typeof p.code !== "string" ||
    typeof p.openid !== "string" ||
    !codePattern.test(p.code) ||
    !openidPattern.test(p.openid) ||
    !Number.isFinite(p.timestamp) ||
    Math.abs(now - p.timestamp) > 300_000
  )
    return;
  if (
    (await storage.get(PAIRING_OWNER_KEY)) !== undefined ||
    (await storage.get(PAIRING_BOUND_KEY)) !== undefined
  )
    return;
  const pending = await pendingPairing(storage, now);
  now = clock();
  if (pending && pending.expiresAt <= now) {
    await storage.delete(PAIRING_PENDING_KEY);
    return;
  }
  if (
    !pending ||
    Math.abs(now - p.timestamp) > 300_000 ||
    p.timestamp < pending.createdAt - 1000 ||
    !same(pending.hash, createHash("sha256").update(p.code).digest("hex"))
  )
    return;
  // Store identity proof only, never the command, raw code, message ID, or ordinary message contents.
  const owner = {
    principal: pending.principal,
    openid: p.openid,
    pairedAt: now,
  };
  await storage.put<PairedOwner>(PAIRING_OWNER_KEY, owner);
  await storage.put(PAIRING_BOUND_KEY, pairingIdentity(owner));
  await storage.delete(PAIRING_PENDING_KEY);
  return owner;
}
