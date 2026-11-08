// Candidate only. Platform fetch owns DNS/TLS/public-destination enforcement.
// No DNS preflight, IP pinning claim, deployment, or production integration.
import { createHash, timingSafeEqual } from "node:crypto";
const HOST = "connectors.api.openai.com";
export const LIMIT = 65536;
// Only this closed set of locally constructed errors crosses the sender boundary.
class CallbackError extends Error {}
export type Auth = { principal: string; expiresAt: number };
export type Input = {
  url: string;
  body: string;
  auth: Auth;
  webhookId: string;
  timestamp: string;
  signature: string;
  subscriptionId: string;
};
export type Dependencies = {
  fetch: typeof fetch;
  // Must perform a REAL current authorization/revocation check. No default allow.
  authorize: (auth: Readonly<Auth>, signal: AbortSignal) => Promise<boolean>;
  now?: () => number;
  timeoutMs?: number;
};
export function destination(raw: string): URL {
  // Deliberately conservative: percent encoding is unsupported, including query.
  if (
    typeof raw !== "string" ||
    raw.length > 4096 ||
    !/^[\x21-\x7e]+$/.test(raw) ||
    /[%\\#]/.test(raw)
  )
    throw new CallbackError("Invalid destination");
  if (!/^https:\/\/connectors\.api\.openai\.com(?::443)?\//.test(raw))
    throw new CallbackError("Invalid destination");
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new CallbackError("Invalid destination");
  }
  if (
    u.protocol !== "https:" ||
    u.hostname !== HOST ||
    u.port ||
    u.username ||
    u.password ||
    u.hash ||
    u.pathname === "/"
  )
    throw new CallbackError("Invalid destination");
  // Reject dot-segment normalization rather than accepting ambiguous path spelling.
  const path = raw.slice(raw.indexOf("/", 8)).split("?")[0];
  if (path !== u.pathname || path.includes("//"))
    throw new CallbackError("Ambiguous path");
  return u;
}
function field(s: string, max: number): string {
  if (
    typeof s !== "string" ||
    !s.length ||
    s.length > max ||
    !/^[\x20-\x7e]+$/.test(s)
  )
    throw new CallbackError("Invalid header");
  return s;
}
export async function send(
  input: Input,
  deps: Dependencies,
  readResponseBody = true,
): Promise<{ status: number; body: string }> {
  const url = destination(input.url);
  if (typeof input.body !== "string" || Buffer.byteLength(input.body) > LIMIT)
    throw new CallbackError("Request too large");
  const headers = new Headers({
    "Content-Type": "application/json",
    Accept: "application/json",
    "webhook-id": field(input.webhookId, 256),
    "webhook-timestamp": field(input.timestamp, 20),
    "webhook-signature": field(input.signature, 4096),
    "X-MCP-Subscription-Id": field(input.subscriptionId, 256),
  });
  if (!/^\d{1,20}$/.test(input.timestamp))
    throw new CallbackError("Invalid timestamp");
  // Snapshot caller-owned values before any await to prevent mutation races.
  const body = input.body;
  const auth = Object.freeze({
    principal: input.auth?.principal,
    expiresAt: input.auth?.expiresAt,
  });
  const now = deps.now ?? Date.now;
  const duration = deps.timeoutMs ?? 5000;
  if (!Number.isFinite(duration) || duration <= 0 || duration > 5000)
    throw new CallbackError("Invalid timeout");
  const startedAt = now();
  if (
    !Number.isFinite(startedAt) ||
    !Number.isFinite(auth.expiresAt) ||
    auth.expiresAt <= startedAt
  )
    throw new CallbackError("Authorization expired");
  const deadline = Math.min(startedAt + duration, auth.expiresAt);
  const expiryWins = auth.expiresAt <= startedAt + duration;
  const controller = new AbortController();
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  function current() {
    if (
      controller.signal.aborted ||
      typeof auth.principal !== "string" ||
      !auth.principal ||
      !Number.isFinite(auth.expiresAt) ||
      auth.expiresAt <= now()
    )
      throw new CallbackError("Authorization expired");
    if (now() >= deadline)
      throw new CallbackError("Callback timeout; outcome uncertain");
  }
  const work = async () => {
    current();
    if ((await deps.authorize(auth, controller.signal)) !== true)
      throw new CallbackError("Authorization denied");
    current();
    const response = await deps.fetch(url.href, {
      method: "POST",
      headers,
      body,
      redirect: "manual",
      signal: controller.signal,
      credentials: "omit",
    } as RequestInit);
    if (controller.signal.aborted) {
      void response.body?.cancel().catch(() => {});
      current();
    }
    current();
    if (response.body) reader = response.body.getReader();
    if (
      (!readResponseBody && response.redirected) ||
      (readResponseBody &&
        (response.status < 200 ||
          response.status >= 300 ||
          response.redirected))
    )
      throw new CallbackError("Callback status rejected");
    // Ordinary event ACK is established by 2xx headers, not response body.
    // Cancellation in finally is fire-and-forget; a stalled body cannot undo ACK.
    if (!readResponseBody) return { status: response.status, body: "" };
    const length = response.headers.get("content-length");
    if (length !== null && (!/^\d+$/.test(length) || Number(length) > LIMIT))
      throw new CallbackError("Response too large");
    const chunks: Uint8Array[] = [];
    let size = 0;
    if (reader)
      while (true) {
        const part = await reader.read();
        current();
        if (part.done) break;
        size += part.value.byteLength;
        if (size > LIMIT) throw new CallbackError("Response too large");
        chunks.push(part.value);
      }
    current();
    return {
      status: response.status,
      body: new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(
        Buffer.concat(chunks),
      ),
    };
  };
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => {
            controller.abort();
            reject(
              new CallbackError(
                expiryWins
                  ? "Authorization expired"
                  : "Callback timeout; outcome uncertain",
              ),
            );
          },
          Math.max(0, deadline - now()),
        );
      }),
    ]);
  } catch (error) {
    if (error instanceof CallbackError) throw error;
    throw new CallbackError("Callback transport failed; outcome uncertain");
  } finally {
    if (timer) clearTimeout(timer);
    controller.abort();
    // Never let a stalled cancellation delay the deadline. Race still observes work rejection.
    if (reader) void reader.cancel().catch(() => {});
  }
}
export async function verify(
  input: Input,
  challenge: string,
  deps: Dependencies,
): Promise<void> {
  if (
    typeof challenge !== "string" ||
    !/^[A-Za-z0-9_-]{16,256}$/.test(challenge)
  )
    throw new CallbackError("Invalid challenge");
  const result = await send(
    { ...input, body: JSON.stringify({ type: "verification", challenge }) },
    deps,
  );
  let value: unknown;
  try {
    value = JSON.parse(result.body);
  } catch {
    throw new CallbackError("Challenge failed");
  }
  if (
    !value ||
    typeof value !== "object" ||
    !("challenge" in value) ||
    typeof value.challenge !== "string" ||
    value.challenge.length > 256
  )
    throw new CallbackError("Challenge failed");
  const digest = (s: string) => createHash("sha256").update(s).digest();
  if (!timingSafeEqual(digest(value.challenge), digest(challenge)))
    throw new CallbackError("Challenge failed");
}

export async function sendEvent(
  input: Input,
  deps: Dependencies,
): Promise<number> {
  return (await send(input, deps, false)).status;
}
