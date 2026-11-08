import test from "node:test";
import assert from "node:assert/strict";
import {
  generateKeyPair,
  exportJWK,
  SignJWT,
  CompactSign,
  type JWTPayload,
} from "jose";
import {
  AccessAuthError,
  ACCESS_LIMITS,
  accessConfigured,
  createAccessVerifier,
  type AccessEnv,
  type AccessFetch,
} from "../src/access.ts";

const ACCESS_HOSTNAME = "qq-mcp.example.com";
const ACCESS_ISSUER = "https://example-team.cloudflareaccess.com";
const ACCESS_JWKS_URL = ACCESS_ISSUER + "/cdn-cgi/access/certs";

// Ephemeral, test-only keys. Every verifier uses local fetch injection; no token
// fixtures or production credentials are stored, and no real requests are made.
const keys = await generateKeyPair("RS256");
const rotated = await generateKeyPair("RS256");
const wrongKeys = await generateKeyPair("RS256");
const jwk = {
  ...(await exportJWK(keys.publicKey)),
  kid: "test-key",
  alg: "RS256",
  use: "sig",
};
const nextJwk = {
  ...(await exportJWK(rotated.publicKey)),
  kid: "rotated-key",
  alg: "RS256",
  use: "sig",
};
const NOW = Date.UTC(2026, 10, 5, 10, 0, 0);
const seconds = NOW / 1000;
const env: AccessEnv = {
  ACCESS_HOSTNAME,
  ACCESS_TEAM_DOMAIN: "example-team.cloudflareaccess.com",
  ACCESS_AUD: "a".repeat(64),
  ACCESS_OWNER_EMAIL: "owner@example.com",
};
const defaults: JWTPayload = {
  iss: ACCESS_ISSUER,
  aud: [env.ACCESS_AUD!],
  email: env.ACCESS_OWNER_EMAIL,
  type: "app",
  sub: "test-owner-subject",
  iat: seconds - 10,
  nbf: seconds - 10,
  exp: seconds + 3600,
};
async function token(
  claims: JWTPayload = {},
  header: Record<string, unknown> = {},
) {
  return new SignJWT({ ...defaults, ...claims })
    .setProtectedHeader({
      alg: "RS256",
      kid: "test-key",
      typ: "JWT",
      ...header,
    })
    .sign(keys.privateKey);
}
function request(
  jwt?: string,
  url = `https://${ACCESS_HOSTNAME}/mcp`,
  headers: Record<string, string> = {},
) {
  return new Request(url, {
    headers: { ...(jwt ? { "cf-access-jwt-assertion": jwt } : {}), ...headers },
  });
}
function response(value: unknown = { keys: [jwk] }) {
  return Response.json(value);
}
function setup(
  options: { fetch?: AccessFetch; now?: () => number; timeoutMs?: number } = {},
) {
  let calls = 0;
  const verify = createAccessVerifier({
    now: () => NOW,
    ...options,
    fetch: async (url, init) => {
      calls++;
      assert.equal(url, ACCESS_JWKS_URL);
      assert.equal(init.method, "GET");
      assert.equal(init.redirect, "manual");
      assert.equal(init.cache, "no-store");
      assert(init.signal);
      assert.deepEqual(init.headers, { accept: "application/json" });
      return options.fetch ? options.fetch(url, init) : response();
    },
  });
  return { verify, count: () => calls };
}
function rejection(code: AccessAuthError["code"]) {
  return (error: unknown) => {
    assert(error instanceof AccessAuthError);
    assert.equal(error.code, code);
    assert.equal(error.message, code);
    assert.equal(
      error.status,
      code === "unauthorized" ? 401 : code === "host_not_allowed" ? 403 : 503,
    );
    assert.equal((error as any).cause, undefined);
    return true;
  };
}

test("valid RS256 assertion yields only stable verified identity and absolute expiry", async () => {
  const { verify, count } = setup();
  const jwt = await token();
  const auth = await verify(request(jwt), env);
  assert.match(auth.principal, /^access_[a-f0-9]{64}$/);
  assert.deepEqual(Object.keys(auth).sort(), [
    "expiresAt",
    "principal",
    "subject",
  ]);
  assert.equal(auth.expiresAt, defaults.exp! * 1000);
  assert.equal(auth.subject, defaults.sub);
  assert(Object.isFrozen(auth));
  assert(!JSON.stringify(auth).includes(jwt));
  assert(!JSON.stringify(auth).includes(env.ACCESS_OWNER_EMAIL!));
  const renewed = await verify(
    request(await token({ iat: seconds, nbf: seconds, exp: seconds + 7200 })),
    env,
  );
  assert.equal(renewed.principal, auth.principal);
  assert.notEqual(renewed.expiresAt, auth.expiresAt);
  assert.notEqual(
    (await verify(request(await token({ sub: "another-subject" })), env))
      .principal,
    auth.principal,
  );
  const anotherEmail = "another-owner@example.com";
  assert.notEqual(
    (
      await setup().verify(request(await token({ email: anotherEmail })), {
        ...env,
        ACCESS_OWNER_EMAIL: anotherEmail,
      })
    ).principal,
    auth.principal,
  );
  assert.equal(count(), 1);
});

test("string audience and extra legitimate audiences are supported", async () => {
  const { verify } = setup();
  await verify(request(await token({ aud: env.ACCESS_AUD })), env);
  await verify(
    request(await token({ aud: ["b".repeat(64), env.ACCESS_AUD!] })),
    env,
  );
});

test("invalid or missing configuration is rejected before network work", async () => {
  const { verify, count } = setup();
  const jwt = await token();
  for (const invalid of [
    {},
    { ...env, ACCESS_AUD: "" },
    { ...env, ACCESS_AUD: "abc" },
    { ...env, ACCESS_AUD: " ".repeat(64) },
    { ...env, ACCESS_AUD: "a".repeat(64) + "\n" },
    { ...env, ACCESS_OWNER_EMAIL: "" },
    { ...env, ACCESS_OWNER_EMAIL: "user@example.com " },
    { ...env, ACCESS_OWNER_EMAIL: "not-an-email" },
    { ...env, ACCESS_OWNER_EMAIL: "a".repeat(300) + "@example.com" },
  ]) {
    assert.equal(accessConfigured(invalid), false);
    await assert.rejects(
      verify(request(jwt), invalid),
      rejection("configuration_invalid"),
    );
  }
  assert.equal(accessConfigured(env), true);
  assert.equal(count(), 0);
});

test("only exact HTTPS deployment hostname is accepted before JWKS fetching", async () => {
  const { verify, count } = setup();
  const jwt = await token();
  for (const url of [
    "https://qq-dot-bridge.example.workers.dev/mcp",
    "https://qq-mcp.example.com.evil.example/mcp",
    "https://qq-mcp.example.com./mcp",
    "http://qq-mcp.example.com/mcp",
    "https://qq-mcp.example.com:444/mcp",
  ]) {
    await assert.rejects(
      verify(
        request(jwt, url, {
          host: ACCESS_HOSTNAME,
          "x-forwarded-host": ACCESS_HOSTNAME,
        }),
        env,
      ),
      rejection("host_not_allowed"),
    );
  }
  assert.equal(count(), 0);
});

test("email headers, Authorization and cookies cannot substitute for a signed assertion", async () => {
  const { verify, count } = setup();
  const jwt = await token();
  const alternatives: Record<string, string>[] = [
    { "cf-access-authenticated-user-email": env.ACCESS_OWNER_EMAIL! },
    { authorization: `Bearer ${jwt}` },
    { cookie: `CF_Authorization=${jwt}` },
  ];
  for (const headers of alternatives) {
    await assert.rejects(
      verify(request(undefined, undefined, headers), env),
      rejection("unauthorized"),
    );
  }
  assert.equal(count(), 0);
});

test("malformed, oversized, duplicate, padded and noncanonical tokens are rejected before fetching", async () => {
  const { verify, count } = setup();
  const jwt = await token();
  for (const malformed of [
    "",
    "a",
    "a.b",
    "a.b.c.d",
    "a.b.c",
    `${jwt},${jwt}`,
    jwt + "=",
    "a".repeat(ACCESS_LIMITS.tokenBytes + 1),
    jwt.replace(".", "=."),
    "____.____.____",
  ]) {
    await assert.rejects(
      verify(request(malformed), env),
      rejection("unauthorized"),
    );
  }
  assert.equal(count(), 0);
});

test("algorithm, key ID, type and unsupported key-selection headers fail before fetching", async () => {
  const { verify, count } = setup();
  const jwt = await token();
  const [, payload, signature] = jwt.split(".");
  for (const changed of [
    { alg: "none" },
    { alg: "HS256" },
    { alg: "rs256" },
    { alg: "PS256" },
    { kid: undefined },
    { kid: "" },
    { kid: "../bad-key" },
    { kid: "a".repeat(257) },
    { kid: 12 },
    { typ: "at+jwt" },
    { jku: "https://evil.example/keys" },
    { jwk },
    { x5u: "https://evil.example/cert" },
    { crit: ["custom"], custom: true },
    { b64: false },
  ]) {
    const header = Buffer.from(
      JSON.stringify({ alg: "RS256", kid: "test-key", typ: "JWT", ...changed }),
    ).toString("base64url");
    await assert.rejects(
      verify(request(`${header}.${payload}.${signature}`), env),
      rejection("unauthorized"),
    );
  }
  assert.equal(count(), 0);
});

test("issuer, audience, exact owner and nonempty subject are all mandatory", async () => {
  const { verify, count } = setup();
  for (const claims of [
    { iss: undefined },
    { iss: "https://evil.example" },
    { iss: ACCESS_ISSUER + "/" },
    { type: undefined },
    { type: "org" },
    { type: "service" },
    { aud: undefined },
    { aud: "b".repeat(64) },
    { aud: [] },
    { aud: [env.ACCESS_AUD, 3] },
    { aud: Array(17).fill(env.ACCESS_AUD) },
    { email: undefined },
    { email: "attacker@example.com" },
    { email: "Owner@example.com" },
    { email: env.ACCESS_OWNER_EMAIL + " " },
    { sub: undefined },
    { sub: "" },
    { sub: " " },
    { sub: "\u0000" },
    { sub: "a".repeat(257) },
  ]) {
    await assert.rejects(
      verify(
        request(await token(claims as JWTPayload), undefined, {
          "cf-access-authenticated-user-email": env.ACCESS_OWNER_EMAIL!,
        }),
        env,
      ),
      rejection("unauthorized"),
    );
  }
  assert.equal(count(), 0);
});

test("required numeric timestamps enforce expiry, freshness and ordering", async () => {
  const { verify, count } = setup();
  const bad: JWTPayload[] = [
    { exp: undefined },
    { iat: undefined },
    { nbf: undefined },
    { exp: seconds },
    { exp: seconds - 1 },
    { iat: seconds + 61 },
    { nbf: seconds + 61 },
    { nbf: seconds + 4000 },
    { iat: seconds - 86461 },
    { iat: seconds - 86400, nbf: seconds - 86400 },
    { exp: defaults.iat },
    { nbf: seconds - 71 },
    { exp: seconds + 0.5 },
    { iat: 0 },
    { nbf: -1 },
    { exp: Number.MAX_SAFE_INTEGER + 1 },
    ...["exp", "iat", "nbf"].flatMap((name) =>
      ["123", null, true, []].map((value) => ({ [name]: value })),
    ),
  ];
  for (const claims of bad) {
    await assert.rejects(
      verify(request(await token(claims)), env),
      rejection("unauthorized"),
    );
  }
  assert.equal(count(), 0);
  await verify(
    request(await token({ iat: seconds + 60, nbf: seconds + 60 })),
    env,
  );
  await verify(request(await token({ exp: seconds + 1 })), env);
});

test("wrong signing key, signature tampering and signed-payload tampering fail cryptographic validation", async () => {
  const { verify, count } = setup();
  const jwt = await token();
  const [header, payload, signature] = jwt.split(".");
  const bytes = Buffer.from(signature, "base64url");
  bytes[0] ^= 1;
  const forged = await new SignJWT(defaults)
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .sign(wrongKeys.privateKey);
  const changedPayload = Buffer.from(
    JSON.stringify({ ...defaults, sub: "forged-owner" }),
  ).toString("base64url");
  for (const invalid of [
    forged,
    `${header}.${payload}.${bytes.toString("base64url")}`,
    `${header}.${changedPayload}.${signature}`,
  ]) {
    await assert.rejects(
      verify(request(invalid), env),
      rejection("unauthorized"),
    );
  }
  assert.equal(count(), 1, "invalid signature must not cause refresh");
  await verify(request(jwt), env);
});

test("unsecured and symmetric-algorithm JWTs never trigger JWKS access", async () => {
  const { verify, count } = setup();
  const hmac = await new SignJWT(defaults)
    .setProtectedHeader({ alg: "HS256", kid: "test-key" })
    .sign(crypto.getRandomValues(new Uint8Array(32)));
  const unsecured = `${Buffer.from('{"alg":"none","kid":"test-key"}').toString("base64url")}.${Buffer.from(JSON.stringify(defaults)).toString("base64url")}.`;
  for (const invalid of [hmac, unsecured])
    await assert.rejects(
      verify(request(invalid), env),
      rejection("unauthorized"),
    );
  assert.equal(count(), 0);
});

test("signed malformed payloads and JWT critical headers fail closed", async () => {
  const { verify } = setup();
  for (const raw of ["[]", "null", "42", "{"]) {
    const jwt = await new CompactSign(new TextEncoder().encode(raw))
      .setProtectedHeader({ alg: "RS256", kid: "test-key" })
      .sign(keys.privateKey);
    await assert.rejects(verify(request(jwt), env), rejection("unauthorized"));
  }
});

test("JWKS cache deduplicates concurrent fetches and refreshes only after its TTL", async () => {
  let time = NOW;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const { verify, count } = setup({
    now: () => time,
    fetch: async () => {
      await gate;
      return response();
    },
  });
  const jwt = await token();
  const pending = Array.from({ length: 15 }, () => verify(request(jwt), env));
  assert.equal(count(), 1);
  release();
  await Promise.all(pending);
  time += ACCESS_LIMITS.cacheMs - 1;
  await verify(request(jwt), env);
  assert.equal(count(), 1);
  time++;
  await verify(request(jwt), env);
  assert.equal(count(), 2);
});

test("unknown kids cannot cause a fetch storm; rotated keys are accepted after bounded refresh", async () => {
  let time = NOW;
  let rotatedAvailable = false;
  const { verify, count } = setup({
    now: () => time,
    fetch: async () =>
      response({ keys: rotatedAvailable ? [jwk, nextJwk] : [jwk] }),
  });
  await verify(request(await token()), env);
  const nextToken = await new SignJWT(defaults)
    .setProtectedHeader({ alg: "RS256", kid: nextJwk.kid })
    .sign(rotated.privateKey);
  await assert.rejects(
    verify(request(nextToken), env),
    rejection("unauthorized"),
  );
  assert.equal(count(), 1);
  time += ACCESS_LIMITS.fetchCooldownMs;
  await assert.rejects(
    verify(request(nextToken), env),
    rejection("unauthorized"),
  );
  assert.equal(count(), 2);
  for (let i = 0; i < 8; i++)
    await assert.rejects(
      verify(request(await token({}, { kid: `unknown-${i}` })), env),
      rejection("unauthorized"),
    );
  assert.equal(count(), 2);
  rotatedAvailable = true;
  time += ACCESS_LIMITS.fetchCooldownMs;
  await verify(request(nextToken), env);
  assert.equal(count(), 3);
});

test("fetch failures are cooldown-limited and expired cached keys are never used", async () => {
  let time = NOW;
  let fail = false;
  const { verify, count } = setup({
    now: () => time,
    fetch: async () => {
      if (fail) throw new Error("Network failure with secret details");
      return response();
    },
  });
  const jwt = await token();
  await verify(request(jwt), env);
  time += ACCESS_LIMITS.cacheMs;
  fail = true;
  for (let i = 0; i < 4; i++)
    await assert.rejects(
      verify(request(jwt), env),
      rejection("verification_unavailable"),
    );
  assert.equal(count(), 2);
  time += ACCESS_LIMITS.fetchCooldownMs;
  fail = false;
  await verify(request(jwt), env);
  assert.equal(count(), 3);
});

test("JWKS redirects, wrong status/type and invalid response metadata are rejected", async () => {
  const jwt = await token();
  const factories = [
    () =>
      new Response(null, {
        status: 302,
        headers: { location: "https://evil.example/keys" },
      }),
    () => new Response(null, { status: 503 }),
    () =>
      new Response(JSON.stringify({ keys: [jwk] }), {
        headers: { "content-type": "text/html" },
      }),
    () =>
      new Response(null, {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    () => {
      const r = response();
      Object.defineProperty(r, "redirected", { value: true });
      return r;
    },
    () => {
      const r = response();
      Object.defineProperty(r, "url", { value: "https://evil.example/keys" });
      return r;
    },
    () => {
      const r = response();
      r.headers.set("content-length", "NaN");
      return r;
    },
    () => {
      const r = response();
      r.headers.set("content-length", String(ACCESS_LIMITS.jwksBytes + 1));
      return r;
    },
  ];
  for (const factory of factories) {
    const { verify, count } = setup({ fetch: async () => factory() });
    await assert.rejects(
      verify(request(jwt), env),
      rejection("verification_unavailable"),
    );
    assert.equal(count(), 1);
  }
});

test("JWKS reads are size bounded even with absent or dishonest Content-Length", async () => {
  const jwt = await token();
  for (const declared of [undefined, "1"]) {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(ACCESS_LIMITS.jwksBytes + 1));
      },
      cancel() {
        cancelled = true;
      },
    });
    const headers: Record<string, string> = {
      "content-type": "application/json",
    };
    if (declared) headers["content-length"] = declared;
    const { verify } = setup({
      fetch: async () => new Response(stream, { headers }),
    });
    await assert.rejects(
      verify(request(jwt), env),
      rejection("verification_unavailable"),
    );
    assert.equal(cancelled, true);
  }
});

test("fetch and stalled-body timeouts abort I/O, release concurrency and fail closed", async () => {
  const jwt = await token();
  let aborted = false;
  const { verify, count } = setup({
    timeoutMs: 15,
    fetch: async (_, init) => {
      init.signal!.addEventListener("abort", () => {
        aborted = true;
      });
      return new Promise<Response>(() => {});
    },
  });
  await assert.rejects(
    verify(request(jwt), env),
    rejection("verification_unavailable"),
  );
  assert(aborted);
  await assert.rejects(
    verify(request(jwt), env),
    rejection("verification_unavailable"),
  );
  assert.equal(count(), 1);
  let cancelled = false;
  const stalled = setup({
    timeoutMs: 15,
    fetch: async () =>
      new Response(
        new ReadableStream({
          cancel() {
            cancelled = true;
          },
        }),
        { headers: { "content-type": "application/json" } },
      ),
  });
  await assert.rejects(
    stalled.verify(request(jwt), env),
    rejection("verification_unavailable"),
  );
  assert(cancelled);
  for (const timeoutMs of [0, -1, 0.5, NaN, ACCESS_LIMITS.fetchTimeoutMs + 1])
    assert.throws(() => createAccessVerifier({ timeoutMs }));
});

test("JWKS validates public RSA keys, duplicate IDs, bounded count and valid JSON/UTF8", async () => {
  const jwt = await token();
  const invalid = [
    null,
    {},
    { keys: [] },
    { keys: Array(17).fill(jwk) },
    { keys: [jwk, jwk] },
    ...[
      { kty: "oct" },
      { alg: "HS256" },
      { use: "enc" },
      { key_ops: ["sign"] },
      { key_ops: ["verify", "sign"] },
      { d: "private" },
      { k: "secret" },
      { kid: "" },
      { kid: "../bad" },
      { n: "AQAB" },
      { n: jwk.n + "=" },
      { n: Buffer.alloc(256, 127).toString("base64url") },
      { n: Buffer.alloc(1025, 255).toString("base64url") },
      { e: "Aw" },
    ].map((change) => ({ keys: [{ ...jwk, ...change }] })),
  ];
  for (const value of invalid) {
    const { verify } = setup({ fetch: async () => response(value) });
    await assert.rejects(
      verify(request(jwt), env),
      rejection("verification_unavailable"),
    );
  }
  for (const body of ["{", new Uint8Array([0xff, 0xfe])]) {
    const { verify } = setup({
      fetch: async () =>
        new Response(body, { headers: { "content-type": "application/json" } }),
    });
    await assert.rejects(
      verify(request(jwt), env),
      rejection("verification_unavailable"),
    );
  }
});

test("token expiration is rechecked after a slow fetch", async () => {
  let time = NOW;
  const { verify } = setup({
    now: () => time,
    fetch: async () => {
      time += 2000;
      return response();
    },
  });
  await assert.rejects(
    verify(request(await token({ exp: seconds + 1 })), env),
    rejection("unauthorized"),
  );
});

test("diagnostic error categories contain no token or untrusted claim values", async () => {
  const cases: Array<[JWTPayload, string]> = [
    [{ iss: "https://untrusted.invalid" }, "claim_issuer"],
    [{ type: "other" }, "claim_type"],
    [{ aud: "wrong-audience" }, "claim_audience"],
    [{ email: "someone-else@example.test" }, "claim_owner_email"],
    [{ sub: "" }, "claim_subject"],
    [{ nbf: undefined }, "claim_timestamps_missing"],
    [{ exp: seconds - 1 }, "claim_expired"],
    [{ nbf: seconds + 61 }, "claim_not_yet_valid"],
    [{ nbf: seconds - 1000 }, "claim_timestamp_order"],
    [{ iat: seconds - 86461, nbf: seconds - 86461 }, "claim_issued_age"],
  ];
  for (const [claims, reason] of cases) {
    const { verify } = setup();
    const jwt = await token(claims);
    await assert.rejects(verify(request(jwt), env), (error: unknown) => {
      assert(error instanceof AccessAuthError);
      assert.equal(error.code, "unauthorized");
      assert.equal(error.diagnosticReason, reason);
      assert(!JSON.stringify(error).includes(jwt));
      assert(!JSON.stringify(error).includes("someone-else"));
      return true;
    });
  }
  await assert.rejects(
    setup().verify(request(), env),
    (e: any) => e.diagnosticReason === "assertion_missing",
  );
});

test("long declared lifetime requires full signature validation and caps local auth to 24h", async () => {
  const claims = { iat: seconds, nbf: seconds, exp: seconds + 30 * 86400 };
  const { verify, count } = setup();
  const auth = await verify(request(await token(claims)), env);
  assert.equal(count(), 1);
  assert.equal(auth.expiresAt, (seconds + 86400) * 1000);
  const forged = await new SignJWT({ ...defaults, ...claims })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .sign(wrongKeys.privateKey);
  await assert.rejects(verify(request(forged), env), rejection("unauthorized"));
  const signed = await token(claims);
  const [h, p, sig] = signed.split(".");
  const changed = Buffer.from(
    JSON.stringify({
      ...JSON.parse(Buffer.from(p, "base64url").toString()),
      exp: seconds + 60 * 86400,
    }),
  ).toString("base64url");
  await assert.rejects(
    verify(request([h, changed, sig].join(".")), env),
    rejection("unauthorized"),
  );
});

test("long declared lifetime never extends the local 24h age boundary", async () => {
  const claims = {
    iat: seconds - 86400,
    nbf: seconds - 86400,
    exp: seconds + 30 * 86400,
  };
  await assert.rejects(
    setup().verify(request(await token(claims)), env),
    (e: any) => e.diagnosticReason === "claim_issued_age",
  );
  const auth = await setup().verify(
    request(
      await token({ ...claims, iat: seconds - 86399, nbf: seconds - 86399 }),
    ),
    env,
  );
  assert.equal(auth.expiresAt, NOW + 1000);
});

test("long-lifetime assertions still reject expiry and wrong owner audience or type", async () => {
  for (const invalid of [
    { exp: seconds },
    { email: "other@example.test" },
    { aud: "b".repeat(64) },
    { type: "org" },
  ]) {
    await assert.rejects(
      setup().verify(
        request(await token({ exp: seconds + 30 * 86400, ...invalid })),
        env,
      ),
      rejection("unauthorized"),
    );
  }
});

test("deployment configuration cannot swap trust contexts on a cached verifier", async () => {
  const { verify, count } = setup();
  const jwt = await token();
  await verify(request(jwt), env);
  for (const changed of [
    { ...env, ACCESS_TEAM_DOMAIN: "other-team.cloudflareaccess.com" },
    { ...env, ACCESS_HOSTNAME: "other.example.com" },
    { ...env, ACCESS_AUD: "b".repeat(64) },
    { ...env, ACCESS_OWNER_EMAIL: "other@example.com" },
  ])
    await assert.rejects(
      verify(request(jwt), changed),
      rejection("configuration_invalid"),
    );
  assert.equal(count(), 1);
});
test("invalid deployment anchors fail before JWT or JWKS work", async () => {
  const { verify, count } = setup();
  for (const changed of [
    { ...env, ACCESS_TEAM_DOMAIN: undefined },
    { ...env, ACCESS_TEAM_DOMAIN: "evil.example" },
    { ...env, ACCESS_HOSTNAME: undefined },
    { ...env, ACCESS_HOSTNAME: "https://qq-mcp.example.com" },
  ])
    await assert.rejects(
      verify(request(await token()), changed),
      rejection("configuration_invalid"),
    );
  assert.equal(count(), 0);
});
