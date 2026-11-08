import { tmpdir } from "node:os";
import { join } from "node:path";
import { URL } from "node:url";
// NEVER DEPLOY wrapper. All traffic intercepted, only synthetic keys/data.
import test from "node:test";
import assert from "node:assert/strict";
import { readFile, mkdtemp, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { qqSign, whSignature, subscriptionId } from "../src/security.ts";
const host = "https://qq-mcp.example.com",
  issuer = "https://example-team.cloudflareaccess.com",
  email = "test@example.test",
  aud = "a".repeat(64),
  secret = "whsec_" + Buffer.alloc(32, 8).toString("base64"),
  url = "https://connectors.api.openai.com/managed-fixture";
const owner = {
  principal:
    "access_" +
    createHash("sha256")
      .update(JSON.stringify([issuer, "owner", email]))
      .digest("hex"),
  openid: "fixture-owner",
  pairedAt: 1700000000000,
};
const wrapper = `import production,{BridgeStore as Impl} from './runtime.mjs';export class BridgeStore{constructor(s,e){this.s=s;this.e=e;this.offset=0;s.blockConcurrencyWhile(async()=>{if(!await s.storage.get('seeded')){await s.storage.put('pairing:owner',JSON.parse(e.OWNER));await s.storage.put('seeded',true);}this.impl=new Impl(s,e,()=>Date.now()+this.offset);});}async alarm(){if(this.e.HOLD_ALARM==='true')return;await this.impl.alarm();}async fetch(r){if(new URL(r.url).pathname==='/fixture'){const p=await r.json();if(p.op==='legacy'){await this.s.storage.put('pairing:pending',{hash:'fixture',principal:JSON.parse(this.e.OWNER).principal,createdAt:Date.now(),expiresAt:Date.now()+150});await this.s.storage.put('msg:legacy',{received_at:Date.now()-3600002});}if(p.op==='rowsOnly')return Response.json({rows:this.impl.rows('')});if(p.op==='holdScheduleStorage'){const original=this.s.storage.transaction.bind(this.s.storage);this.storageGate=new Promise(resolve=>{this.releaseStorage=resolve;});this.s.storage.transaction=(fn)=>original(tx=>fn(new Proxy(tx,{get:(target,key)=>{const value=target[key];if(typeof value!=='function')return value;return async(...args)=>{if(key==='get'&&args[0]==='pairing:pending')await this.storageGate;return value.apply(target,args);};}})));}if(p.op==='releaseScheduleStorage')this.releaseStorage();if(p.op==='bindingDelay')this.bindingDelay=p.ms;if(p.op==='stallResponse'){const original=this.impl.fetchWithin.bind(this.impl);this.impl.fetchWithin=async(...args)=>{const response=await original(...args);const raw=await response.text();return new Response(new ReadableStream({start(c){c.enqueue(new TextEncoder().encode(raw));}}),{status:response.status,headers:response.headers});};}if(p.op==='diagnostics')return Response.json(this.impl.diagnosticStatus());if(p.op==='expireDiagnostics'){this.s.storage.sql.exec('UPDATE request_diagnostics_v1 SET at=?',Date.now()-3600001);await this.impl.alarm();return Response.json(this.s.storage.sql.exec('SELECT count(*) AS n FROM request_diagnostics_v1').toArray());}if(p.op==='holdPair'){const original=this.impl.pair.bind(this.impl);this.pairGate=new Promise(r=>{this.releasePair=r;});this.impl.pair=async(...args)=>{await this.pairGate;return original(...args);};}if(p.op==='releasePair')this.releasePair();if(p.op==='holdVerifier'){const original=this.impl.verifier;this.verifierGate=new Promise(r=>{this.releaseVerifier=r;});this.impl.verifier=async(...args)=>{await this.verifierGate;return original(...args);};}if(p.op==='releaseVerifier')this.releaseVerifier();if(p.op==='flag')this.impl.env[p.name]=p.value;if(p.op==='delaySchedule'){const original=this.impl.schedule.bind(this.impl);this.impl.schedule=async(...args)=>{await original(...args);await new Promise(r=>setTimeout(r,p.ms));};}if(p.op==='tamper'){const sub=this.impl.get('sub');sub.sealed.ciphertext='invalid';this.impl.put('sub',sub);}if(p.op==='advance')this.offset+=p.ms;if(p.op==='restart')this.impl=new Impl(this.s,this.e,()=>Date.now()+this.offset);if(p.op==='pair')await this.s.storage.put('pairing:owner',p.value);if(p.op==='alarm')await this.impl.alarm();if(p.op==='inspect')return Response.json({rows:this.impl.rows(''),owner:await this.s.storage.get('pairing:owner'),alarm:await this.s.storage.getAlarm(),pending:await this.s.storage.get('pairing:pending'),legacy:await this.s.storage.get('msg:legacy')});return Response.json({ok:true});}if(this.bindingDelay)await new Promise(resolve=>setTimeout(resolve,this.bindingDelay));return this.impl.fetch(r);}}export default production;`;
async function setup(
  t: any,
  holdAlarm = true,
  flags: Record<string, string> = {},
) {
  const keys = await generateKeyPair("RS256"),
    jwk = {
      ...(await exportJWK(keys.publicKey)),
      kid: "fixture",
      alg: "RS256",
      use: "sig",
    },
    bundle = await readFile(
      new URL("../dist/worker.js", import.meta.url),
      "utf8",
    );
  let count = 0,
    replies = 0,
    tokens = 0,
    holdReply = false,
    holdToken = false,
    delayJwks = 0,
    uncertain = false,
    gate: Promise<void> | undefined,
    release: (() => void) | undefined;
  const config = convertV4MiniflareOptions({
    workers: [
      {
        name: "lease",
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
          BRIDGE_ENABLED: "true",
          EVENTS_ENABLED: "true",
          MCP_WRITE_ENABLED: "true",
          QQ_APP_ID: "fixture-app",
          ...flags,
          HOLD_ALARM: String(holdAlarm),
          ACCESS_AUD: aud,
          ACCESS_OWNER_EMAIL: email,
          OWNER: JSON.stringify(owner),
          QQ_APP_SECRET: "fixture-bot",
          CALLBACK_KEYRING: JSON.stringify({
            activeKeyId: "test",
            keys: [
              {
                id: "test",
                status: "active",
                keyBase64: Buffer.alloc(32, 4).toString("base64"),
              },
            ],
          }),
        },
        outboundService: async (r) => {
          if (r.url === issuer + "/cdn-cgi/access/certs") {
            if (delayJwks)
              await new Promise((resolve) => setTimeout(resolve, delayJwks));
            return Response.json({ keys: [jwk] });
          }
          if (r.url === url) {
            const raw = await r.text(),
              p: any = JSON.parse(raw);
            assert.equal(
              r.headers.get("webhook-signature"),
              whSignature(
                secret,
                r.headers.get("webhook-id")!,
                r.headers.get("webhook-timestamp")!,
                raw,
              ),
            );
            assert.equal(
              r.headers.get("X-MCP-Subscription-Id"),
              subscriptionId(owner.principal, url, "qq.message.created", {
                conversation: "owner_private",
              }),
            );
            if (p.type !== "verification") {
              assert.equal(p.name, "qq.message.created");
              assert.equal(p.eventId, r.headers.get("webhook-id"));
              assert.deepEqual(Object.keys(p.data).sort(), [
                "conversation",
                "message_id",
                "received_at",
                "text",
              ]);
              assert.equal(p.cursor, null);
            }
            count++;
            if (gate) await gate;
            return Response.json(
              p.type === "verification" ? { challenge: p.challenge } : {},
            );
          }
          if (r.url === "https://api.bot.qq.com/app/getAppAccessToken") {
            tokens++;
            if (holdToken && gate) await gate;
            const p: any = await r.json();
            assert.equal(p.appId, "fixture-app");
            assert.equal(p.clientSecret, "fixture-bot");
            return Response.json({
              access_token: "fixture-access-token",
              expires_in: 7200,
            });
          }
          if (
            r.url === "https://api.bot.qq.com/v2/users/fixture-owner/messages"
          ) {
            assert.equal(
              r.headers.get("authorization"),
              "QQBot fixture-access-token",
            );
            assert.equal(r.headers.get("X-Union-Appid"), "fixture-app");
            replies++;
            if (holdReply && gate) await gate;
            const p: any = await r.json();
            assert.equal(p.msg_seq, 1);
            assert.equal(p.msg_id, "m");
            return uncertain
              ? new Response("failure", { status: 500 })
              : Response.json({ id: "output" });
          }
          throw Error("UNEXPECTED NETWORK");
        },
      },
    ],
  });
  const path = await mkdtemp(join(tmpdir(), "managed-lease-sqlite-"));
  config.resourcePersistencePath = path;
  let mf = new Miniflare(config);
  t.after(async () => {
    await mf.dispose();
    await rm(path, { recursive: true, force: true });
  });
  let ns = await mf.getDurableObjectNamespace("BRIDGE", "lease"),
    stub = ns.get(ns.idFromName("single-owner"));
  const processRestart = async () => {
    await mf.dispose();
    mf = new Miniflare(config);
    ns = await mf.getDurableObjectNamespace("BRIDGE", "lease");
    stub = ns.get(ns.idFromName("single-owner"));
  };
  const jwt = await new SignJWT({ email, type: "app" })
    .setProtectedHeader({ alg: "RS256", kid: "fixture" })
    .setIssuer(issuer)
    .setAudience(aud)
    .setSubject("owner")
    .setIssuedAt()
    .setNotBefore(Math.floor(Date.now() / 1000))
    .setExpirationTime("1h")
    .sign(keys.privateKey);
  const direct = async (p: any) => {
    const r = await stub.fetch(host + "/fixture", {
      method: "POST",
      body: JSON.stringify(p),
    });
    return r.json() as any;
  };
  const rpc = async (method: string, params: any, assertion = jwt) => {
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
    return text.startsWith("event:") || text.startsWith("data:")
      ? JSON.parse(
          text
            .split("\n")
            .find((l) => l.startsWith("data:"))!
            .slice(5),
        )
      : JSON.parse(text);
  };
  const ingress = async (
    id = "m",
    content = "synthetic",
    timestampValue = new Date().toISOString(),
    openid = "fixture-owner",
  ) => {
    const body = JSON.stringify({
        op: 0,
        t: "C2C_MESSAGE_CREATE",
        d: {
          id,
          content,
          timestamp: timestampValue,
          author: { user_openid: openid },
        },
      }),
      timestamp = String(Math.floor(Date.now() / 1000));
    const r = await stub.fetch(host + "/qq/webhook", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-signature-timestamp": timestamp,
        "x-signature-ed25519": qqSign("fixture-bot", timestamp + body),
      },
      body,
    });
    await r.text();
    return r.status;
  };
  return {
    rpc,
    direct,
    ingress,
    processRestart,
    mf,
    publicRaw: (init: any) =>
      mf.dispatchFetch(host + "/mcp", {
        method: "POST",
        headers: {
          "cf-access-jwt-assertion": jwt,
          "content-type": "application/json",
          accept: "application/json,text/event-stream",
          "x-bridge-deadline": String(Date.now() + 9999999),
          "x-bridge-receipt": String(Date.now() + 9999999),
        },
        ...init,
      }),
    holdReply: () => {
      holdReply = true;
      gate = new Promise<void>((r) => {
        release = r;
      });
    },
    raw: (init: any) =>
      stub.fetch(host + "/mcp", {
        method: "POST",
        headers: {
          "cf-access-jwt-assertion": jwt,
          "content-type": "application/json",
          accept: "application/json,text/event-stream",
        },
        ...init,
      }),
    tokens: () => tokens,
    holdToken: () => {
      holdToken = true;
      gate = new Promise<void>((r) => {
        release = r;
      });
    },
    hold: () => {
      gate = new Promise<void>((r) => {
        release = r;
      });
    },
    release: () => {
      release?.();
      gate = undefined;
    },
    count: () => count,
    replies: () => replies,
    delay: (n: number) => {
      delayJwks = n;
    },
    uncertain: () => {
      uncertain = true;
    },
  };
}

const p = {
  name: "reply_message",
  arguments: { message_id: "m", text: "synthetic reply" },
};
async function bounded<T>(work: Promise<T>) {
  const started = Date.now();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(Error("test exceeded 7 seconds")),
          7000,
        );
      }),
    ]);
    assert(Date.now() - started < 6500);
    return result;
  } finally {
    clearTimeout(timer);
  }
}
for (const phase of ["Pair", "Verifier"] as const)
  test(
    "whole MCP bounds stalled " + phase + " and release cannot claim/send",
    async (t) => {
      const x = await setup(t);
      await x.ingress();
      await x.direct({ op: "hold" + phase });
      const result = await bounded(x.rpc("tools/call", p));
      assert.equal(result.http, 504);
      await x.direct({ op: "release" + phase });
      await new Promise((r) => setTimeout(r, 150));
      assert.equal(x.replies(), 0);
      assert(
        !(await x.direct({ op: "inspect" })).rows.some(
          (r: any) => r.key === "reply:m",
        ),
      );
    },
  );
test("never resolving token bounds full SDK response and late token cannot claim", async (t) => {
  const x = await setup(t);
  await x.ingress();
  x.holdToken();
  try {
    assert.equal((await bounded(x.rpc("tools/call", p))).http, 504);
  } finally {
    x.release();
  }
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(x.replies(), 0);
  assert(
    !(await x.direct({ op: "inspect" })).rows.some(
      (r: any) => r.key === "reply:m",
    ),
  );
});
test("QQ send begun before timeout retains uncertain claim and no duplicate send", async (t) => {
  const x = await setup(t);
  await x.ingress();
  x.holdReply();
  try {
    assert.equal((await bounded(x.rpc("tools/call", p))).http, 504);
  } finally {
    x.release();
  }
  await new Promise((r) => setTimeout(r, 100));
  const claim = (await x.direct({ op: "inspect" })).rows.find(
    (r: any) => r.key === "reply:m",
  );
  assert.equal(claim.value.status, "uncertain");
  await x.rpc("tools/call", p);
  assert.equal(x.replies(), 1);
});
test("SDK initialized notification preserves bodyless response", async (t) => {
  const x = await setup(t);
  const r = await x.raw({
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    }),
  });
  assert([202, 204].includes(r.status));
  await r.text();
});

test("stalled request body reaches fixed response deadline without claim", async (t) => {
  const x = await setup(t);
  await x.ingress();
  const stream = new ReadableStream({
    start(c) {
      c.enqueue(new TextEncoder().encode("{"));
    },
  });
  const r = await bounded(x.raw({ body: stream, duplex: "half" }));
  assert([403, 504].includes(r.status));
  await r.text();
  assert.equal(x.replies(), 0);
  assert(
    !(await x.direct({ op: "inspect" })).rows.some(
      (r: any) => r.key === "reply:m",
    ),
  );
});
test("JWKS network timeout closes full response before whole request budget", async (t) => {
  const x = await setup(t);
  await x.ingress();
  x.delay(6000);
  const result = await bounded(x.rpc("tools/call", p));
  assert([403, 504].includes(result.http));
  assert.equal(x.replies(), 0);
});

test("SDK response serialization stall returns 504 and records only coarse authenticated stage; alarm physically expires diagnostics", async (t) => {
  const x = await setup(t);
  await x.direct({ op: "stallResponse" });
  const result = await bounded(
    x.rpc("tools/call", { name: "bridge_status", arguments: {} }),
  );
  assert.equal(result.http, 504);
  const records = await x.direct({ op: "diagnostics" });
  assert(
    records.some(
      (r: any) => r.stage === "serialize" && r.outcome === "deadline",
    ),
  );
  const text = JSON.stringify(records);
  for (const forbidden of [
    owner.principal,
    owner.openid,
    secret,
    url,
    "fixture-access-token",
    "synthetic reply",
  ])
    assert(!text.includes(forbidden));
  assert.equal((await x.direct({ op: "expireDiagnostics" }))[0].n, 0);
});

test("public entry overwrites hostile deadline and queued binding delay does not restart budget", async (t) => {
  const x = await setup(t);
  await x.ingress();
  await x.direct({ op: "bindingDelay", ms: 2500 });
  x.holdToken();
  try {
    const r = await bounded(
      x.publicRaw({
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: p,
        }),
      }),
    );
    assert.equal(r.status, 504);
    await r.text();
  } finally {
    x.release();
  }
  await new Promise((r) => setTimeout(r, 150));
  await x.direct({ op: "bindingDelay", ms: 0 });
  assert.equal(x.replies(), 0);
  assert(
    !(await x.direct({ op: "inspect" })).rows.some(
      (r: any) => r.key === "reply:m",
    ),
  );
});

test("schedule storage stall cleans same intent at deadline and late release cannot activate; next subscribe succeeds", async (t) => {
  const x = await setup(t);
  const params = {
    name: "qq.message.created",
    arguments: { conversation: "owner_private" },
    delivery: { mode: "webhook", url, secret },
    cursor: null,
    ttlMs: null,
  };
  await x.direct({ op: "holdScheduleStorage" });
  assert.equal((await bounded(x.rpc("events/subscribe", params))).http, 504);
  let rows = (await x.direct({ op: "rowsOnly" })).rows;
  assert(!rows.some((r: any) => r.key === "intent" || r.key === "sub"));
  assert.equal(x.count(), 0);
  await x.direct({ op: "releaseScheduleStorage" });
  await new Promise((r) => setTimeout(r, 100));
  rows = (await x.direct({ op: "rowsOnly" })).rows;
  assert(!rows.some((r: any) => r.key === "intent" || r.key === "sub"));
  assert.equal(x.count(), 0);
  const result = await x.rpc("events/subscribe", params);
  assert.equal(typeof result.result?.id, "string");
  assert.equal(x.count(), 1);
});
