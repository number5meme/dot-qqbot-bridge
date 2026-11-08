import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { URL } from "node:url";
import { createHash } from "node:crypto";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { qqSign } from "../src/security.ts";

const host = "https://qq-mcp.example.com";
const issuer = "https://example-team.cloudflareaccess.com";
const email = "pairing@example.test";
const aud = "b".repeat(64);
const principal =
  "access_" +
  createHash("sha256")
    .update(JSON.stringify([issuer, "owner", email]))
    .digest("hex");
// NEVER DEPLOY: fixture-only access bypass, inspection, clock and mutation controls.
// Production default export remains unchanged and cannot route /fixture.
const wrapper = `import production,{BridgeStore as Impl} from './runtime.mjs';
export class BridgeStore {
 constructor(s,e){this.s=s;this.e=e;this.offset=0;this.impl=new Impl(s,e,()=>Date.now()+this.offset);}
 async alarm(){}
 async fetch(r){if(new URL(r.url).pathname==='/fixture'){
 const p=await r.json();
 if(p.op==='advance')this.offset+=p.ms;
 if(p.op==='expirePending'){const pending=await this.s.storage.get('pairing:pending');pending.expiresAt=Date.now()-1;await this.s.storage.put('pairing:pending',pending);}
 if(p.op==='delayStart'){const original=this.impl.beginPairing.bind(this.impl);this.impl.beginPairing=async(a)=>{await new Promise(r=>setTimeout(r,20));this.offset+=5001;return original(a);};}
 if(p.op==='lateFlag'){const original=this.impl.pairingStorage.bind(this.impl);let fired=false;this.impl.pairingStorage=(storage,check)=>original(new Proxy(storage,{get:(target,key)=>{const value=target[key];if(typeof value!=='function')return value;return async(...args)=>{const result=await value.apply(target,args);if(!fired&&key==='put'&&args[0]===p.key){fired=true;this.impl.env[p.name]=p.value;}return result;};}}),check);}

 if(p.op==='flag')this.impl.env[p.name]=p.value;
 if(p.op==='owner'){if(p.value===null)await this.s.storage.delete('pairing:owner');else await this.s.storage.put('pairing:owner',p.value);}
 if(p.op==='dropSnapshot')this.impl.del('pair');
 if(p.op==='orphan')this.impl.put('seen:orphan',{time:Date.now()});
 if(p.op==='removeOrphan')this.impl.del('seen:orphan');
 if(p.op==='schedule')await this.impl.schedule();
 if(p.op==='holdPairingRead'){const original=this.s.storage.transaction.bind(this.s.storage);this.storageGate=new Promise(resolve=>{this.releaseStorage=resolve;});this.s.storage.transaction=(fn)=>original(tx=>fn(new Proxy(tx,{get:(target,key)=>{const value=target[key];if(typeof value!=='function')return value;return async(...args)=>{if(key==='get'&&args[0]==='pairing:owner')await this.storageGate;return value.apply(target,args);};}})));}
 if(p.op==='releasePairingRead')this.releaseStorage();
 if(p.op==='restart')this.impl=new Impl(this.s,this.e,()=>Date.now()+this.offset);
 if(p.op==='inspect')return Response.json({kv:Object.fromEntries(await this.s.storage.list()),rows:this.impl.rows(''),timing:this.s.storage.sql.exec('SELECT * FROM message_timing_v1').toArray(),alarm:await this.s.storage.getAlarm()});
 return Response.json({ok:true});}return this.impl.fetch(r);}
}export default production;`;
async function setup(
  t: any,
  flags: Record<string, string> = { PAIRING_ENABLED: "true" },
) {
  const keys = await generateKeyPair("RS256");
  const jwk = {
    ...(await exportJWK(keys.publicKey)),
    kid: "fixture",
    alg: "RS256",
    use: "sig",
  };
  const bundle = await readFile(
    new URL("../dist/worker.js", import.meta.url),
    "utf8",
  );
  let forbiddenOutbound = 0;
  const config = convertV4MiniflareOptions({
    workers: [
      {
        name: "pairing",
        modules: [
          { type: "ESModule", path: "main.mjs", contents: wrapper },
          { type: "ESModule", path: "runtime.mjs", contents: bundle },
        ],
        compatibilityDate: "2026-11-05",
        compatibilityFlags: ["nodejs_compat"],
        durableObjects: {
          BRIDGE: { className: "BridgeStore", useSQLite: true },
        },
        bindings: {
          ACCESS_HOSTNAME: "qq-mcp.example.com",
          ACCESS_TEAM_DOMAIN: "example-team.cloudflareaccess.com",
          QQ_WEBHOOK_HOSTNAME: "qq-webhook.example.com",
          ACCESS_AUD: aud,
          ACCESS_OWNER_EMAIL: email,
          QQ_APP_ID: "fixture-app",
          QQ_APP_SECRET: "fixture-bot",
          ...flags,
        },
        outboundService: async (r) => {
          if (r.url === issuer + "/cdn-cgi/access/certs")
            return Response.json({ keys: [jwk] });
          forbiddenOutbound++;
          throw Error(
            "UNEXPECTED NETWORK: pairing cannot contact any business endpoint",
          );
        },
      },
    ],
  });
  const path = await mkdtemp(join(tmpdir(), "first-pairing-"));
  config.resourcePersistencePath = path;
  let mf = new Miniflare(config);
  let ns = await mf.getDurableObjectNamespace("BRIDGE", "pairing");
  let stub = ns.get(ns.idFromName("single-owner"));
  t.after(async () => {
    await mf.dispose();
    await rm(path, { recursive: true, force: true });
    assert.equal(forbiddenOutbound, 0);
  });
  const token = async (overrides: any = {}) =>
    new SignJWT({ email, type: "app", ...overrides })
      .setProtectedHeader({ alg: "RS256", kid: "fixture" })
      .setIssuer(issuer)
      .setAudience(aud)
      .setSubject("owner")
      .setIssuedAt()
      .setNotBefore(Math.floor(Date.now() / 1000))
      .setExpirationTime("1h")
      .sign(keys.privateKey);
  const jwt = await token();
  const direct = async (p: any) =>
    (
      await stub.fetch(host + "/fixture", {
        method: "POST",
        body: JSON.stringify(p),
      })
    ).json() as Promise<any>;
  const rpc = async (method: string, params: any = {}, assertion = jwt) => {
    const r = await stub.fetch(host + "/mcp", {
      method: "POST",
      headers: {
        "cf-access-jwt-assertion": assertion,
        "content-type": "application/json",
        accept: "application/json,text/event-stream",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    const text = await r.text();
    if (r.status !== 200) return { http: r.status };
    return JSON.parse(
      text.startsWith("event:") || text.startsWith("data:")
        ? text
            .split("\n")
            .find((l) => l.startsWith("data:"))!
            .slice(5)
        : text,
    );
  };
  const webhook = async (payload: any, options: any = {}) => {
    const body = JSON.stringify(payload),
      timestamp =
        options.signatureTimestamp ?? String(Math.floor(Date.now() / 1000));
    return stub.fetch(host + "/qq/webhook", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-bot-appid": options.app ?? "fixture-app",
        ...(options.unsigned
          ? {}
          : {
              "x-signature-timestamp": timestamp,
              "x-signature-ed25519": qqSign("fixture-bot", timestamp + body),
            }),
      },
      body,
    });
  };
  const ingress = (code: string, options: any = {}) =>
    webhook(
      {
        op: 0,
        t: options.type ?? "C2C_MESSAGE_CREATE",
        d: {
          id: options.id ?? "pair-message",
          content: code,
          timestamp: options.timestamp ?? new Date().toISOString(),
          author: { user_openid: options.openid ?? "fixture-owner" },
        },
      },
      options,
    );
  const restart = async () => {
    await mf.dispose();
    mf = new Miniflare(config);
    ns = await mf.getDurableObjectNamespace("BRIDGE", "pairing");
    stub = ns.get(ns.idFromName("single-owner"));
  };
  return {
    rpc,
    direct,
    ingress,
    webhook,
    restart,
    token,
    publicFetch: (path: string) =>
      mf.dispatchFetch(host + path, { method: "POST" }),
  };
}
function data(r: any) {
  assert(r.result && !r.result.isError, JSON.stringify(r));
  return JSON.parse(r.result.content[0].text);
}
function denied(r: any) {
  assert(r.http === 403 || r.error || r.result?.isError, JSON.stringify(r));
}
const start = (x: any) =>
  x.rpc("tools/call", { name: "start_pairing", arguments: {} });
const status = (x: any) =>
  x.rpc("tools/call", { name: "bridge_status", arguments: {} });
const snapshot = (x: any) => x.direct({ op: "inspect" });
function ownerDigest(owner: any) {
  return createHash("sha256")
    .update(JSON.stringify([owner.principal, owner.openid, owner.pairedAt]))
    .digest("hex");
}
function noSecret(state: any, code: string) {
  assert(!JSON.stringify(state).includes(code));
  assert(!state.rows.some((r: any) => /^(msg|queue|seen):/.test(r.key)));
  assert.equal(state.timing.length, 0);
}

test("empty setup, authenticated discovery and one-time private pairing keep business disabled", async (t) => {
  const x = await setup(t);
  const challenge = {
    plain_token: "synthetic_setup",
    event_ts: String(Math.floor(Date.now() / 1000)),
  };
  const response = await x.webhook(
    { op: 13, d: challenge },
    { unsigned: true },
  );
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    plain_token: challenge.plain_token,
    signature: qqSign(
      "fixture-bot",
      challenge.event_ts + challenge.plain_token,
    ),
  });
  assert(
    (
      await x.rpc("initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "fixture", version: "1" },
      })
    ).result,
  );
  assert(
    (await x.rpc("tools/list")).result.tools.some(
      (tool: any) => tool.name === "start_pairing",
    ),
  );
  assert.equal(data(await status(x)).owner_bound, false);
  assert.equal(data(await status(x)).pairing_enabled, true);
  for (const name of ["read_message", "reply_message"])
    denied(
      await x.rpc("tools/call", {
        name,
        arguments: {
          message_id: "m",
          ...(name === "reply_message" ? { text: "no" } : {}),
        },
      }),
    );
  denied(
    await x.rpc("events/subscribe", {
      name: "qq.message.created",
      arguments: { conversation: "owner_private" },
      cursor: null,
      delivery: {
        mode: "webhook",
        url: "https://connectors.api.openai.com/fixture",
        secret: "whsec_" + Buffer.alloc(32, 7).toString("base64"),
      },
    }),
  );
  const first = data(await start(x));
  assert.match(first.code, /^QQPAIR-[A-F0-9]{32}$/);
  assert.equal(typeof first.purpose, "string");
  assert(Date.parse(first.expires_at) > Date.now());
  assert(Date.parse(first.expires_at) <= Date.now() + 600000);
  const before = await snapshot(x);
  assert.equal(
    before.kv["pairing:pending"].hash,
    createHash("sha256").update(first.code).digest("hex"),
  );
  assert.equal(before.kv["pairing:pending"].principal, principal);
  noSecret(before, first.code);
  const again = data(await start(x));
  assert.equal(again.pending, true);
  assert.equal(again.code, undefined);
  assert.equal(again.expires_at, first.expires_at);
  assert.equal((await x.ingress(first.code)).status, 200);
  const after = await snapshot(x);
  assert.equal(after.kv["pairing:owner"].openid, "fixture-owner");
  assert.equal(after.kv["pairing:owner"].principal, principal);
  assert.equal(
    after.kv["pairing:bound"],
    ownerDigest(after.kv["pairing:owner"]),
  );
  assert.equal(after.kv["pairing:pending"], undefined);
  noSecret(after, first.code);
  const result = data(await status(x));
  assert.equal(result.owner_bound, true);
  assert.equal(result.enabled, false);
  assert(!JSON.stringify(result).includes("fixture-owner"));
  assert(!JSON.stringify(result).includes(first.code));
  denied(await start(x));
});

test("empty installation requires owner Access authentication without poisoning setup", async (t) => {
  const x = await setup(t);
  for (const jwt of [
    "",
    "invalid",
    await x.token({ email: "stranger@example.test" }),
  ]) {
    for (const [method, params] of [
      [
        "initialize",
        {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "fixture", version: "1" },
        },
      ],
      ["tools/list", {}],
      ["tools/call", { name: "bridge_status", arguments: {} }],
      ["tools/call", { name: "start_pairing", arguments: {} }],
    ] as const)
      assert.equal((await x.rpc(method, params, jwt)).http, 403);
  }
  assert.equal((await snapshot(x)).kv["pairing:pending"], undefined);
  assert(data(await start(x)).code);
  for (const path of [
    "/admin",
    "/pair",
    "/pairing",
    "/unpair",
    "/revoke",
    "/fixture",
  ])
    assert.equal((await x.publicFetch(path)).status, 404);
});

test("pairing defaults off and requires every business capability to remain off", async (t) => {
  const x = await setup(t, {});
  assert.equal(data(await status(x)).pairing_enabled, false);
  denied(await start(x));
  for (const value of ["false", "TRUE", "1", ""]) {
    await x.direct({ op: "flag", name: "PAIRING_ENABLED", value });
    denied(await start(x));
  }
  await x.direct({ op: "flag", name: "PAIRING_ENABLED", value: "true" });
  for (const name of [
    "BRIDGE_ENABLED",
    "EVENTS_ENABLED",
    "MCP_WRITE_ENABLED",
  ]) {
    await x.direct({ op: "flag", name, value: "true" });
    denied(await start(x));
    await x.direct({ op: "flag", name, value: "false" });
  }
  const code = data(await start(x)).code;
  for (const name of [
    "BRIDGE_ENABLED",
    "EVENTS_ENABLED",
    "MCP_WRITE_ENABLED",
  ]) {
    await x.direct({ op: "flag", name, value: "true" });
    await x.ingress(code);
    assert.equal((await snapshot(x)).kv["pairing:owner"], undefined);
    await x.direct({ op: "flag", name, value: "false" });
  }
  assert.equal((await x.ingress(code)).status, 200);
  assert((await snapshot(x)).kv["pairing:owner"]);
});

test("unsigned, wrong-app, stale, group and incorrect commands cannot consume pairing", async (t) => {
  const x = await setup(t);
  const code = data(await start(x)).code;
  for (const options of [
    { unsigned: true },
    { app: "wrong-app" },
    { signatureTimestamp: String(Math.floor(Date.now() / 1000) - 301) },
    { timestamp: new Date(Date.now() - 301000).toISOString() },
    { type: "GROUP_AT_MESSAGE_CREATE" },
    { openid: "invalid owner" },
  ]) {
    await x.ingress(code, options);
    const s = await snapshot(x);
    assert.equal(s.kv["pairing:owner"], undefined);
    assert(s.kv["pairing:pending"]);
    noSecret(s, code);
  }
  await x.ingress("QQPAIR-" + "0".repeat(32));
  assert.equal((await snapshot(x)).kv["pairing:owner"], undefined);
  assert.equal((await x.ingress(code)).status, 200);
  assert((await snapshot(x)).kv["pairing:owner"]);
});

test("expired code cannot bind and a newly issued code supersedes it", async (t) => {
  const x = await setup(t);
  const old = data(await start(x)).code;
  await x.direct({ op: "expirePending" });
  const future = new Date().toISOString(),
    signatureTimestamp = String(Math.floor(Date.now() / 1000));
  await x.ingress(old, { timestamp: future, signatureTimestamp });
  assert.equal((await snapshot(x)).kv["pairing:owner"], undefined);
  const fresh = data(await start(x)).code;
  assert.notEqual(fresh, old);
  await x.ingress(old, { timestamp: future, signatureTimestamp });
  assert.equal((await snapshot(x)).kv["pairing:owner"], undefined);
  assert.equal(
    (await x.ingress(fresh, { timestamp: future, signatureTimestamp })).status,
    200,
  );
  assert((await snapshot(x)).kv["pairing:owner"]);
});

test("concurrent starts disclose exactly one code; concurrent consumes bind exactly one owner", async (t) => {
  const x = await setup(t);
  const starts = (
    await Promise.all(Array.from({ length: 5 }, () => start(x)))
  ).map(data);
  const issued = starts.filter((r) => r.code);
  assert.equal(issued.length, 1);
  assert.equal(starts.filter((r) => r.pending === true).length, 4);
  const code = issued[0].code;
  await Promise.all([
    x.ingress(code, { openid: "owner-a" }),
    x.ingress(code, { openid: "owner-b" }),
  ]);
  const s = await snapshot(x);
  assert(["owner-a", "owner-b"].includes(s.kv["pairing:owner"].openid));
  assert.equal(s.kv["pairing:bound"], ownerDigest(s.kv["pairing:owner"]));
  assert.equal(s.kv["pairing:pending"], undefined);
  noSecret(s, code);
  await x.ingress(code, { openid: "owner-c" });
  assert.deepEqual(
    (await snapshot(x)).kv["pairing:owner"],
    s.kv["pairing:owner"],
  );
});

test("pending and bound identity persist through actual workerd restart; replays never become messages", async (t) => {
  const x = await setup(t);
  const code = data(await start(x)).code;
  await x.restart();
  assert.equal(data(await start(x)).pending, true);
  await x.ingress(code);
  const owner = (await snapshot(x)).kv["pairing:owner"];
  await x.restart();
  assert.equal(data(await status(x)).owner_bound, true);
  assert.deepEqual((await snapshot(x)).kv["pairing:owner"], owner);
  for (const name of ["BRIDGE_ENABLED", "EVENTS_ENABLED", "MCP_WRITE_ENABLED"])
    await x.direct({ op: "flag", name, value: "true" });
  for (const [i, options] of [
    {},
    { timestamp: new Date(Date.now() - 301000).toISOString() },
    { openid: "invalid owner" },
  ].entries())
    await x.ingress(code, { id: "replay-" + i, ...options });
  await x.ingress("QQPAIR-" + "F".repeat(32), { id: "unknown-code" });
  noSecret(await snapshot(x), code);
  denied(await start(x));
});

test("bound-owner deletion or mutation permanently blocks authority even after restoration and restart", async (t) => {
  for (const change of ["delete", "mutate"]) {
    const x = await setup(t);
    await x.ingress(data(await start(x)).code);
    const owner = (await snapshot(x)).kv["pairing:owner"];
    await x.direct({
      op: "owner",
      value: change === "delete" ? null : { ...owner, openid: "replacement" },
    });
    await x.restart();
    assert.equal((await status(x)).http, 403);
    denied(await start(x));
    await x.direct({ op: "owner", value: owner });
    await x.restart();
    assert.equal((await x.rpc("tools/list")).http, 403);
    denied(await start(x));
    assert((await snapshot(x)).kv["pairing:bound"]);
  }
});

test("delayed authenticated start cannot outlive its request authorization", async (t) => {
  const x = await setup(t);
  await x.direct({ op: "delayStart" });
  denied(await start(x));
  const state = await snapshot(x);
  assert.equal(state.kv["pairing:pending"], undefined);
  assert.equal(state.kv["pairing:owner"], undefined);
});

test("late flag change rolls back pending creation inside its transaction", async (t) => {
  const x = await setup(t);
  await x.direct({
    op: "lateFlag",
    key: "pairing:pending",
    name: "PAIRING_ENABLED",
    value: "false",
  });
  denied(await start(x));
  const state = await snapshot(x);
  assert.equal(state.kv["pairing:pending"], undefined);
  assert.equal(state.kv["pairing:owner"], undefined);
  assert.equal(state.kv["pairing:bound"], undefined);
});

test("late business enable rolls back owner and marker writes without spending pending code", async (t) => {
  const x = await setup(t);
  const code = data(await start(x)).code;
  await x.direct({
    op: "lateFlag",
    key: "pairing:owner",
    name: "BRIDGE_ENABLED",
    value: "true",
  });
  await x.ingress(code);
  const state = await snapshot(x);
  assert.equal(state.kv["pairing:owner"], undefined);
  assert.equal(state.kv["pairing:bound"], undefined);
  assert(state.kv["pairing:pending"]);
  noSecret(state, code);
  await x.direct({ op: "flag", name: "BRIDGE_ENABLED", value: "false" });
  assert.equal((await x.ingress(code)).status, 200);
  assert((await snapshot(x)).kv["pairing:owner"]);
});

test("atomic bound fingerprint rejects owner mutation across the pre-snapshot crash gap", async (t) => {
  const x = await setup(t);
  await x.ingress(data(await start(x)).code);
  const before = await snapshot(x);
  const owner = before.kv["pairing:owner"];
  assert.equal(before.kv["pairing:bound"], ownerDigest(owner));
  await x.direct({ op: "dropSnapshot" });
  assert(!(await snapshot(x)).rows.some((row: any) => row.key === "pair"));
  await x.direct({
    op: "owner",
    value: { ...owner, openid: "crash-gap-replacement" },
  });
  await x.restart();
  assert.equal((await status(x)).http, 403);
  denied(await start(x));
  await x.direct({ op: "owner", value: owner });
  await x.restart();
  assert.equal((await x.rpc("tools/list")).http, 403);
  denied(await start(x));
  assert.equal((await snapshot(x)).kv["pairing:bound"], ownerDigest(owner));
});

test("orphan managed state without owner proof permanently rejects first-time pairing", async (t) => {
  const x = await setup(t);
  await x.direct({ op: "orphan" });
  const before = await snapshot(x);
  assert.equal(before.kv["pairing:owner"], undefined);
  assert.equal(before.kv["pairing:bound"], undefined);
  assert(!before.rows.some((row: any) => row.key === "pair"));
  assert.equal((await status(x)).http, 403);
  denied(await start(x));
  await x.direct({ op: "removeOrphan" });
  await x.restart();
  assert.equal((await status(x)).http, 403);
  denied(await start(x));
  assert.equal((await snapshot(x)).kv["pairing:pending"], undefined);
});

test("concurrent scheduled cleanup and replacement start preserve a fresh bindable pending code", async (t) => {
  const x = await setup(t);
  const expiredCode = data(await start(x)).code;
  await x.direct({ op: "expirePending" });
  // A bounded interleaving regression, not an exhaustive scheduling proof.
  const [, replacement] = await Promise.all([
    x.direct({ op: "schedule" }),
    start(x),
  ]);
  const issued = data(replacement);
  assert.match(issued.code, /^QQPAIR-[A-F0-9]{32}$/);
  assert.notEqual(issued.code, expiredCode);
  const state = await snapshot(x);
  assert.equal(
    state.kv["pairing:pending"].hash,
    createHash("sha256").update(issued.code).digest("hex"),
  );
  assert.equal(
    state.kv["pairing:pending"].expiresAt,
    Date.parse(issued.expires_at),
  );
  assert(state.kv["pairing:pending"].expiresAt > Date.now());
  noSecret(state, issued.code);
  assert.equal((await x.ingress(issued.code)).status, 200);
  const bound = await snapshot(x);
  assert.equal(bound.kv["pairing:owner"].openid, "fixture-owner");
  assert.equal(
    bound.kv["pairing:bound"],
    ownerDigest(bound.kv["pairing:owner"]),
  );
  assert.equal(bound.kv["pairing:pending"], undefined);
});

test("suspended pairing transaction times out without late writes and permits a fresh start", async (t) => {
  const x = await setup(t);
  await x.direct({ op: "holdPairingRead" });
  const entered = Date.now();
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      start(x),
      new Promise<never>((_, reject) => {
        watchdog = setTimeout(
          () => reject(Error("Pairing response exceeded the bounded timeout")),
          8000,
        );
      }),
    ]);
    assert.equal(result.http, 504);
    const elapsed = Date.now() - entered;
    assert(elapsed >= 4500 && elapsed < 7500, `Elapsed ${elapsed} ms`);
    const beforeRelease = await snapshot(x);
    assert.equal(beforeRelease.kv["pairing:pending"], undefined);
    assert.equal(beforeRelease.kv["pairing:owner"], undefined);
    assert.equal(beforeRelease.kv["pairing:bound"], undefined);
  } finally {
    clearTimeout(watchdog);
    await x.direct({ op: "releasePairingRead" });
  }
  // This checks rejected transaction continuation, not cancellation of I/O
  // that a runtime has already accepted.
  await new Promise((resolve) => setTimeout(resolve, 100));
  const afterRelease = await snapshot(x);
  assert.equal(afterRelease.kv["pairing:pending"], undefined);
  assert.equal(afterRelease.kv["pairing:owner"], undefined);
  assert.equal(afterRelease.kv["pairing:bound"], undefined);
  const fresh = data(await start(x));
  assert.match(fresh.code, /^QQPAIR-[A-F0-9]{32}$/);
  assert.equal(
    (await snapshot(x)).kv["pairing:pending"].hash,
    createHash("sha256").update(fresh.code).digest("hex"),
  );
});
