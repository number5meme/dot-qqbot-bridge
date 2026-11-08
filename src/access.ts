import { createHash } from "node:crypto";
import {
  createLocalJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  jwtVerify,
  type JSONWebKeySet,
  type JWTPayload,
} from "jose";

import { deploymentFromEnvironment, type DeploymentEnv } from "./deployment.ts";

export const ACCESS_LIMITS = Object.freeze({
  tokenBytes: 16_384,
  jwksBytes: 65_536,
  jwksKeys: 16,
  fetchTimeoutMs: 3_000,
  cacheMs: 300_000,
  fetchCooldownMs: 30_000,
  maxTokenAgeSeconds: 86_400,
  clockSkewSeconds: 60,
});

export interface AccessEnv extends DeploymentEnv {
  ACCESS_AUD?: string;
  ACCESS_OWNER_EMAIL?: string;
}
export interface VerifiedAccessAuth {
  /** Hash of the verified issuer, subject, and exact owner email, not the JWT. */
  principal: string;
  /** Absolute expiration in milliseconds. Do not retain auth beyond this time. */
  expiresAt: number;
  subject: string;
}
export const ACCESS_DIAGNOSTIC_REASONS = [
  "configuration_invalid",
  "host_not_allowed",
  "verification_unavailable",
  "assertion_missing",
  "assertion_encoding",
  "jwt_header",
  "claim_issuer",
  "claim_type",
  "claim_audience",
  "claim_owner_email",
  "claim_subject",
  "claim_timestamps_missing",
  "claim_expired",
  "claim_not_yet_valid",
  "claim_timestamp_order",
  "claim_age",
  "claim_issued_age",
  "claim_lifetime",
  "key_unknown",
  "signature_or_jose",
] as const;
export type AccessDiagnosticReason = (typeof ACCESS_DIAGNOSTIC_REASONS)[number];
export function isAccessDiagnosticReason(
  value: unknown,
): value is AccessDiagnosticReason {
  return (
    typeof value === "string" &&
    (ACCESS_DIAGNOSTIC_REASONS as readonly string[]).includes(value)
  );
}
type AccessErrorCode =
  | "configuration_invalid"
  | "host_not_allowed"
  | "unauthorized"
  | "verification_unavailable";
export class AccessAuthError extends Error {
  readonly code: AccessErrorCode;
  readonly status: 401 | 403 | 503;
  readonly diagnosticReason: AccessDiagnosticReason;
  constructor(
    code: AccessErrorCode,
    reason: AccessDiagnosticReason = code === "unauthorized"
      ? "signature_or_jose"
      : code,
  ) {
    // Never attach JOSE errors, token contents, headers, or network details.
    super(code);
    this.name = "AccessAuthError";
    this.code = code;
    this.diagnosticReason = reason;
    this.status =
      code === "unauthorized" ? 401 : code === "host_not_allowed" ? 403 : 503;
  }
}
function unauthorized(
  reason: AccessDiagnosticReason = "signature_or_jose",
): never {
  throw new AccessAuthError("unauthorized", reason);
}

/** Suitable for a boolean readiness field. This function returns no credentials. */
export function accessConfigured(env: AccessEnv): boolean {
  try {
    deploymentFromEnvironment(env);
  } catch {
    return false;
  }
  return (
    typeof env.ACCESS_AUD === "string" &&
    /^[a-f0-9]{64}$/.test(env.ACCESS_AUD) &&
    typeof env.ACCESS_OWNER_EMAIL === "string" &&
    env.ACCESS_OWNER_EMAIL.length <= 254 &&
    /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$/.test(
      env.ACCESS_OWNER_EMAIL,
    )
  );
}

// Deliberately require the identity-based application-token claim shape,
// including type:'app' and nbf. Global-session and service tokens are not valid
// owner credentials. See Cloudflare's authorization-cookie/application-token/.
function claimsValid(
  p: JWTPayload,
  env: AccessEnv,
  issuer: string,
  nowMs: number,
): void {
  const now = nowMs / 1000;
  const { exp, iat, nbf } = p;
  const aud = typeof p.aud === "string" ? [p.aud] : p.aud;
  if (p.iss !== issuer) unauthorized("claim_issuer");
  if (p.type !== "app") unauthorized("claim_type");
  if (
    !Array.isArray(aud) ||
    aud.length < 1 ||
    aud.length > 16 ||
    !aud.every((a) => typeof a === "string" && a.length <= 256) ||
    !aud.includes(env.ACCESS_AUD!)
  )
    unauthorized("claim_audience");
  if (p.email !== env.ACCESS_OWNER_EMAIL) unauthorized("claim_owner_email");
  if (
    typeof p.sub !== "string" ||
    p.sub.length < 1 ||
    p.sub.length > 256 ||
    /[\s\u0000-\u001f\u007f]/.test(p.sub)
  )
    unauthorized("claim_subject");
  if (
    ![exp, iat, nbf].every(
      (n) => typeof n === "number" && Number.isSafeInteger(n) && n > 0,
    )
  )
    unauthorized("claim_timestamps_missing");
  if (exp! <= now) unauthorized("claim_expired");
  if (
    exp! <= iat! ||
    exp! <= nbf! ||
    nbf! < iat! - ACCESS_LIMITS.clockSkewSeconds
  )
    unauthorized("claim_timestamp_order");
  if (
    iat! > now + ACCESS_LIMITS.clockSkewSeconds ||
    nbf! > now + ACCESS_LIMITS.clockSkewSeconds
  )
    unauthorized("claim_not_yet_valid");
  // The issuer controls exp. Do not confuse total declared lifetime with age.
  // Independently cap local acceptance to 24h from issuance, with no grace.
  if (iat! <= now - ACCESS_LIMITS.maxTokenAgeSeconds)
    unauthorized("claim_issued_age");
}

const kidPattern = /^[A-Za-z0-9_-]{1,256}$/;
function base64urlBytes(value: unknown): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value))
    throw new Error("Invalid encoding");
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value)
    throw new Error("Invalid encoding");
  return bytes;
}
function safeJwks(value: unknown): JSONWebKeySet {
  if (
    !value ||
    typeof value !== "object" ||
    !("keys" in value) ||
    !Array.isArray(value.keys) ||
    value.keys.length < 1 ||
    value.keys.length > ACCESS_LIMITS.jwksKeys
  )
    throw new Error("Invalid key set");
  const seen = new Set<string>();
  return {
    keys: value.keys.map((key) => {
      if (
        !key ||
        typeof key !== "object" ||
        typeof key.kid !== "string" ||
        !kidPattern.test(key.kid) ||
        seen.has(key.kid) ||
        key.kty !== "RSA" ||
        key.alg !== "RS256" ||
        key.use !== "sig" ||
        ["d", "p", "q", "dp", "dq", "qi", "oth", "k"].some(
          (field) => field in key,
        ) ||
        (key.key_ops !== undefined &&
          (!Array.isArray(key.key_ops) ||
            key.key_ops.length !== 1 ||
            key.key_ops[0] !== "verify"))
      )
        throw new Error("Invalid key");
      const modulus = base64urlBytes(key.n);
      // Accept 2048–8192 bit RSA keys, not undersized or padded moduli.
      if (
        modulus.length < 256 ||
        modulus.length > 1024 ||
        modulus[0] < 128 ||
        key.e !== "AQAB"
      )
        throw new Error("Invalid RSA parameters");
      seen.add(key.kid);
      // Do not pass certificate URLs or other unnecessary JWK fields to JOSE.
      return {
        kid: key.kid,
        kty: "RSA",
        alg: "RS256",
        use: "sig",
        n: key.n,
        e: key.e,
      };
    }),
  };
}

export type AccessFetch = (url: string, init: RequestInit) => Promise<Response>;
export interface AccessVerifierOptions {
  /** Test injection only. Production uses fetch to the fixed trust anchor. */
  fetch?: AccessFetch;
  now?: () => number;
  /** Tests may shorten the timeout; callers cannot increase the production cap. */
  timeoutMs?: number;
}

async function fetchJwks(
  fetcher: AccessFetch,
  timeoutMs: number,
  jwksUrl: string,
): Promise<JSONWebKeySet> {
  const abort = new AbortController();
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const work = async () => {
    const response = await fetcher(jwksUrl, {
      // workerd does not implement redirect:'error'. Manual mode never follows
      // a redirect; the exact-200 check below rejects every 3xx response.
      method: "GET",
      redirect: "manual",
      signal: abort.signal,
      headers: { accept: "application/json" },
      cache: "no-store",
    });
    if (
      response.status !== 200 ||
      response.redirected ||
      (response.url && response.url !== jwksUrl) ||
      !response.body ||
      !/^application\/(?:json|jwk-set\+json)(?:\s*;|$)/i.test(
        response.headers.get("content-type") ?? "",
      )
    ) {
      void response.body?.cancel().catch(() => {});
      throw new Error("Invalid response");
    }
    const length = response.headers.get("content-length");
    if (
      length !== null &&
      (!/^\d+$/.test(length) || Number(length) > ACCESS_LIMITS.jwksBytes)
    ) {
      void response.body.cancel().catch(() => {});
      throw new Error("Oversized response");
    }
    reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > ACCESS_LIMITS.jwksBytes) throw new Error("Oversized response");
      chunks.push(value);
    }
    return safeJwks(
      JSON.parse(
        new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(
          Buffer.concat(chunks),
        ),
      ),
    );
  };
  try {
    // A race bounds even a stalled response body or an injected fetch that
    // ignores AbortSignal. All underlying I/O is also explicitly cancelled.
    return await Promise.race([
      work(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          abort.abort();
          reject(new Error("Timeout"));
        }, timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
    abort.abort();
    void reader?.cancel().catch(() => {});
  }
}

/**
 * One instance per Worker isolate. JWKS is cached for 5 minutes, with a single
 * shared in-flight fetch and at most one fetch attempt per 30 seconds (including
 * failures). Unknown kids may trigger one cooldown-limited refresh; invalid
 * signatures never trigger refresh. Expired cache entries are never used when
 * refresh fails. No JWTs, authentication results, or attacker-keyed maps persist.
 *
 * Reference: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/
 */
export function createAccessVerifier(options: AccessVerifierOptions = {}) {
  const fetcher = options.fetch ?? ((url, init) => fetch(url, init));
  const now = options.now ?? Date.now;
  const timeoutMs = options.timeoutMs ?? ACCESS_LIMITS.fetchTimeoutMs;
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > ACCESS_LIMITS.fetchTimeoutMs
  ) {
    throw new Error("Invalid verifier timeout");
  }
  type Cache = {
    resolver: ReturnType<typeof createLocalJWKSet>;
    kids: Set<string>;
    expires: number;
  };
  let cache: Cache | undefined;
  let inFlight: Promise<Cache> | undefined;
  let lastAttempt = -Infinity;
  let pinnedTrust: string | undefined;
  async function load(jwksUrl: string): Promise<Cache> {
    if (inFlight) return inFlight;
    if (now() - lastAttempt < ACCESS_LIMITS.fetchCooldownMs)
      throw new AccessAuthError("verification_unavailable");
    lastAttempt = now();
    inFlight = (async () => {
      try {
        const jwks = await fetchJwks(fetcher, timeoutMs, jwksUrl);
        const next = {
          resolver: createLocalJWKSet(jwks),
          kids: new Set(jwks.keys.map((key) => key.kid!)),
          expires: now() + ACCESS_LIMITS.cacheMs,
        };
        cache = next;
        return next;
      } catch {
        throw new AccessAuthError("verification_unavailable");
      }
    })();
    try {
      return await inFlight;
    } finally {
      inFlight = undefined;
    }
  }
  return async function verifyAccess(
    request: Request,
    env: AccessEnv,
  ): Promise<VerifiedAccessAuth> {
    if (!accessConfigured(env))
      throw new AccessAuthError("configuration_invalid");
    const deployment = deploymentFromEnvironment(env);
    const trust = JSON.stringify([
      deployment.mcpHostname,
      deployment.accessIssuer,
      env.ACCESS_AUD,
      env.ACCESS_OWNER_EMAIL,
    ]);
    // A verifier instance may not reuse cached keys across tenants or identity settings.
    if (pinnedTrust !== undefined && pinnedTrust !== trust)
      throw new AccessAuthError("configuration_invalid");
    pinnedTrust = trust;
    const url = new URL(request.url);
    if (
      url.protocol !== "https:" ||
      url.hostname !== deployment.mcpHostname ||
      url.port ||
      url.username ||
      url.password
    ) {
      throw new AccessAuthError("host_not_allowed");
    }
    const token = request.headers.get("cf-access-jwt-assertion");
    // Neither Authorization, cookies nor an email header are an authentication
    // fallback. Reject merged duplicate assertion headers and invalid encodings.
    if (!token) unauthorized("assertion_missing");
    if (
      token.length > ACCESS_LIMITS.tokenBytes ||
      !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)
    )
      unauthorized("assertion_encoding");
    let kid: string;
    try {
      for (const part of token.split(".")) base64urlBytes(part);
      const header = decodeProtectedHeader(token);
      if (
        header.alg !== "RS256" ||
        typeof header.kid !== "string" ||
        !kidPattern.test(header.kid) ||
        (header.typ !== undefined && header.typ !== "JWT") ||
        Object.keys(header).some(
          (name) => !["alg", "kid", "typ"].includes(name),
        )
      )
        unauthorized("jwt_header");
      kid = header.kid;
      // Early rejection only. These claims are untrusted until jwtVerify below.
      claimsValid(decodeJwt(token), env, deployment.accessIssuer, now());
    } catch (error) {
      if (error instanceof AccessAuthError) throw error;
      unauthorized("assertion_encoding");
    }
    let keys = cache;
    if (!keys || keys.expires <= now())
      keys = await load(deployment.accessJwksUrl);
    else if (
      !keys.kids.has(kid) &&
      now() - lastAttempt >= ACCESS_LIMITS.fetchCooldownMs
    )
      keys = await load(deployment.accessJwksUrl);
    if (!keys.kids.has(kid)) unauthorized("key_unknown");
    try {
      const { payload } = await jwtVerify(token, keys.resolver, {
        algorithms: ["RS256"],
        issuer: deployment.accessIssuer,
        audience: env.ACCESS_AUD!,
        requiredClaims: [
          "iss",
          "aud",
          "type",
          "email",
          "sub",
          "exp",
          "iat",
          "nbf",
        ],
        currentDate: new Date(now()),
        clockTolerance: ACCESS_LIMITS.clockSkewSeconds,
        maxTokenAge: ACCESS_LIMITS.maxTokenAgeSeconds,
      });
      // No grace for expiration; recheck after network and cryptographic work.
      claimsValid(payload, env, deployment.accessIssuer, now());
      return Object.freeze({
        principal:
          "access_" +
          createHash("sha256")
            .update(
              JSON.stringify([
                deployment.accessIssuer,
                payload.sub,
                payload.email,
              ]),
            )
            .digest("hex"),
        expiresAt:
          Math.min(
            payload.exp!,
            payload.iat! + ACCESS_LIMITS.maxTokenAgeSeconds,
          ) * 1000,
        subject: payload.sub!,
      });
    } catch (error) {
      if (error instanceof AccessAuthError) throw error;
      unauthorized("signature_or_jose");
    }
  };
}

export const verifyAccess = createAccessVerifier();
