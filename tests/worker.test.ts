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
const wrapper = `import production,{BridgeStore as Impl} from './runtime.mjs';export class BridgeStore{constructor(s,e){this.s=s;this.e=e;this.offset=0;s.blockConcurrencyWhile(async()=>{if(!await s.storage.get('seeded')){await s.storage.put('pairing:owner',JSON.parse(e.OWNER));await s.storage.put('seeded',true);}this.impl=new Impl(s,e,()=>Date.now()+this.offset);});}async alarm(){if(this.e.HOLD_ALARM==='true')return;await this.impl.alarm();}async fetch(r){if(new URL(r.url).pathname==='/fixture'){const p=await r.json();if(p.op==='legacy'){await this.s.storage.put('pairing:pending',{hash:'fixture',principal:JSON.parse(this.e.OWNER).principal,createdAt:Date.now(),expiresAt:Date.now()+150});await this.s.storage.put('msg:legacy',{received_at:Date.now()-3600002});}if(p.op==='expireMessage'){const m=this.impl.get('msg:m');m.timestamp=new Date(Date.now()-300001).toISOString();this.impl.put('msg:m',m);}if(p.op==='flag')this.impl.env[p.name]=p.value;if(p.op==='delaySchedule'){const original=this.impl.schedule.bind(this.impl);this.impl.schedule=async(...args)=>{await original(...args);await new Promise(r=>setTimeout(r,p.ms));};}if(p.op==='tamper'){const sub=this.impl.get('sub');sub.sealed.ciphertext='invalid';this.impl.put('sub',sub);}if(p.op==='advance')this.offset+=p.ms;if(p.op==='restart')this.impl=new Impl(this.s,this.e,()=>Date.now()+this.offset);if(p.op==='pair')await this.s.storage.put('pairing:owner',p.value);if(p.op==='alarm')await this.impl.alarm();if(p.op==='inspect')return Response.json({rows:this.impl.rows(''),owner:await this.s.storage.get('pairing:owner'),alarm:await this.s.storage.getAlarm(),pending:await this.s.storage.get('pairing:pending'),legacy:await this.s.storage.get('msg:legacy')});return Response.json({ok:true});}return this.impl.fetch(r);}}export default production;`;
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
const params = (ttlMs?: number | null) => ({
  name: "qq.message.created",
  arguments: { conversation: "owner_private" },
  cursor: null,
  delivery: { mode: "webhook", url, secret },
  ...(ttlMs === undefined ? {} : { ttlMs }),
});
test("actual SDK subscribe renew unsubscribe with encrypted SQLite and handler reconstruction", async (t) => {
  const x = await setup(t);
  const initialization = await x.rpc("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "fixture", version: "1" },
  });
  assert.deepEqual(initialization.result.capabilities.events, {});
  const listing = (await x.rpc("events/list", {})).result;
  assert.equal(typeof listing.events[0].description, "string");
  assert.deepEqual(listing.events[0].payloadSchema.required, [
    "message_id",
    "text",
    "conversation",
    "received_at",
  ]);
  const first = await x.rpc("events/subscribe", params());
  assert(first.result);
  assert.equal(await x.ingress(), 200);
  const before = await x.direct({ op: "inspect" }),
    deadline = before.rows.find((r: any) => r.key === "msg:m").value.deadline;
  assert(!JSON.stringify(before).includes(secret));
  assert(!JSON.stringify(before).includes(url));
  await x.direct({ op: "advance", ms: 2000 });
  assert((await x.rpc("events/subscribe", params(9999999))).result);
  assert.equal(
    (await x.direct({ op: "inspect" })).rows.find((r: any) => r.key === "msg:m")
      .value.deadline,
    deadline,
  );
  assert.equal(x.count(), 1);
  await x.direct({ op: "restart" });
  assert(
    (
      await x.rpc("events/unsubscribe", {
        name: "qq.message.created",
        arguments: { conversation: "owner_private" },
        delivery: { mode: "webhook", url },
      })
    ).result,
  );
  await x.direct({ op: "alarm" });
  assert.equal(x.count(), 1);
  assert.deepEqual((await x.direct({ op: "inspect" })).owner, owner);
});
test("null/omitted/long TTL are finite; malformed TTL rejected by SDK", async (t) => {
  for (const ttl of [null, undefined, 999999]) {
    const x = await setup(t);
    const result = await x.rpc("events/subscribe", params(ttl));
    assert(result.result);
    assert.deepEqual(Object.keys(result.result).sort(), [
      "cursor",
      "id",
      "refreshBefore",
      "truncated",
    ]);
    assert.equal(result.result.cursor, null);
    assert.equal(result.result.truncated, false);
    assert.equal(typeof result.result.id, "string");
    assert.equal(typeof result.result.refreshBefore, "string");
    const granted = Date.parse(result.result.refreshBefore);
    assert(granted <= Date.now() + 60000 && granted > Date.now());
    assert.equal(
      granted,
      (await x.direct({ op: "inspect" })).rows.find((r: any) => r.key === "sub")
        .value.expires,
    );
  }
  const x = await setup(t);
  for (const ttl of [-1, 0, 1.5])
    assert((await x.rpc("events/subscribe", params(ttl))).error);
});
test("without renewal durable lease expires and alarm stops queued event after reconstruction", async (t) => {
  const x = await setup(t);
  assert((await x.rpc("events/subscribe", params(100))).result);
  assert.equal(await x.ingress(), 200);
  await x.direct({ op: "advance", ms: 150 });
  await x.direct({ op: "restart" });
  await x.direct({ op: "alarm" });
  assert.equal(x.count(), 1);
  const rows = (await x.direct({ op: "inspect" })).rows;
  assert(!rows.find((r: any) => r.key === "sub"));
  assert(!rows.find((r: any) => r.key === "queue:m"));
});
test("full pairing drift persists invalidation across restore and handler reconstruction", async (t) => {
  const x = await setup(t);
  await x.rpc("events/subscribe", params());
  await x.ingress();
  await x.direct({ op: "pair", value: { ...owner, openid: "other" } });
  assert.equal((await x.rpc("events/list", {})).http, 403);
  await x.direct({ op: "pair", value: owner });
  await x.direct({ op: "restart" });
  assert.equal((await x.rpc("events/list", {})).http, 403);
  await x.direct({ op: "alarm" });
  assert.equal(x.count(), 1);
});
test("synthetic QQ concurrent durable once claim survives reconstruction and uncertain result", async (t) => {
  const x = await setup(t);
  await x.rpc("events/subscribe", params());
  await x.ingress();
  x.uncertain();
  const p = {
    name: "reply_message",
    arguments: { message_id: "m", text: "reply" },
  };
  await Promise.all([x.rpc("tools/call", p), x.rpc("tools/call", p)]);
  await x.direct({ op: "restart" });
  await x.rpc("tools/call", p);
  assert.equal(x.replies(), 1);
});
test("invalid signature denied before SDK and delayed verification cannot extend requested lease", async (t) => {
  const x = await setup(t);
  assert.equal((await x.rpc("events/list", {}, "not-a-jwt")).http, 403);
  x.delay(150);
  const result = await x.rpc("events/subscribe", params(50));
  assert(result.error);
  assert.equal(x.count(), 0);
});

test("SQLite state survives actual workerd disposal/relaunch and retains reply claim", async (t) => {
  const x = await setup(t);
  await x.rpc("events/subscribe", params());
  await x.ingress();
  const p = {
    name: "reply_message",
    arguments: { message_id: "m", text: "reply" },
  };
  await x.rpc("tools/call", p);
  assert.equal(x.replies(), 1);
  await x.processRestart();
  await x.rpc("tools/call", p);
  assert.equal(x.replies(), 1);
  assert.deepEqual((await x.direct({ op: "inspect" })).owner, owner);
});

test("unsubscribe during verification prevents late challenge completion from activating a subscription", async (t) => {
  const x = await setup(t);
  x.hold();
  const pending = x.rpc("events/subscribe", params());
  const until = Date.now() + 2000;
  while (x.count() < 1 && Date.now() < until)
    await new Promise((r) => setTimeout(r, 5));
  assert.equal(x.count(), 1);
  assert(
    (
      await x.rpc("events/unsubscribe", {
        name: "qq.message.created",
        arguments: { conversation: "owner_private" },
        delivery: { mode: "webhook", url },
      })
    ).result,
  );
  x.release();
  assert((await pending).error);
  assert(
    !(await x.direct({ op: "inspect" })).rows.some((r: any) => r.key === "sub"),
  );
});
test("actual alarm expires short lease without manual alarm invocation", async (t) => {
  const x = await setup(t, false);
  assert((await x.rpc("events/subscribe", params(250))).result);
  await new Promise((r) => setTimeout(r, 500));
  assert(
    !(await x.direct({ op: "inspect" })).rows.some((r: any) => r.key === "sub"),
  );
  assert.equal(x.count(), 1);
});

test("lease scheduler preserves original pairing cleanup deadline and legacy cleanup without touching owner", async (t) => {
  const x = await setup(t, false);
  await x.direct({ op: "legacy" });
  assert((await x.rpc("events/subscribe", params())).result);
  const initial = await x.direct({ op: "inspect" });
  assert(initial.alarm <= Date.now() + 200);
  assert.equal(initial.legacy, undefined);
  await new Promise((r) => setTimeout(r, 300));
  const after = await x.direct({ op: "inspect" });
  assert.equal(after.pending, undefined);
  assert.deepEqual(after.owner, owner);
});

test("official subscription wire shape accepts cursor:null and rejects unsupported replay cursors", async (t) => {
  const x = await setup(t);
  assert(
    (
      await x.rpc("events/subscribe", {
        ...params(null),
        cursor: "unsupported",
      })
    ).error,
  );
  const r = await x.rpc("events/subscribe", params(null));
  assert.deepEqual(Object.keys(r.result).sort(), [
    "cursor",
    "id",
    "refreshBefore",
    "truncated",
  ]);
  assert.equal(
    r.result.id,
    subscriptionId(owner.principal, url, "qq.message.created", {
      conversation: "owner_private",
    }),
  );
  const unsub = await x.rpc("events/unsubscribe", {
    name: "qq.message.created",
    arguments: { conversation: "owner_private" },
    delivery: { mode: "webhook", url },
  });
  assert.deepEqual(unsub.result, {});
});

test("automatic ingress alarm delivers one signed canonical event without manual invocation", async (t) => {
  const x = await setup(t, false);
  await x.rpc("events/subscribe", params());
  await x.ingress();
  const until = Date.now() + 1500;
  while (x.count() < 2 && Date.now() < until)
    await new Promise((r) => setTimeout(r, 10));
  assert.equal(x.count(), 2);
  await x.direct({ op: "restart" });
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(x.count(), 2);
});

test("shortened event lease stops background task but fresh Access independently authorizes reply", async (t) => {
  const x = await setup(t);
  await x.rpc("events/subscribe", params());
  await x.ingress();
  const old = (await x.direct({ op: "inspect" })).rows.find(
    (r: any) => r.key === "msg:m",
  ).value.deadline;
  assert((await x.rpc("events/subscribe", params(1000))).result);
  await x.direct({ op: "advance", ms: 1100 });
  assert(old > Date.now() + 20000);
  const result = await x.rpc("tools/call", {
    name: "reply_message",
    arguments: { message_id: "m", text: "must stop" },
  });
  assert(result.result && !result.result.isError);
  assert.equal(x.replies(), 1);
  await x.direct({ op: "alarm" });
  assert.equal(x.count(), 1);
});

test("default-disabled capability admission and public route guards expose only safe status", async (t) => {
  const x = await setup(t, true, {
    BRIDGE_ENABLED: "false",
    EVENTS_ENABLED: "false",
    MCP_WRITE_ENABLED: "false",
  });
  const listing = await x.rpc("tools/list", {});
  assert.deepEqual(listing.result.tools.map((v: any) => v.name).sort(), [
    "bridge_status",
    "read_message",
    "reply_message",
    "start_pairing",
  ]);
  assert.equal(
    (await x.rpc("events/list", {})).result.events[0].name,
    "qq.message.created",
  );
  for (const name of ["read_message", "reply_message"]) {
    const r = await x.rpc("tools/call", {
      name,
      arguments: {
        message_id: "m",
        ...(name === "reply_message" ? { text: "no" } : {}),
      },
    });
    assert(r.error || r.result?.isError);
  }
  assert((await x.rpc("events/subscribe", params())).error);
  assert.equal(await x.ingress(), 503);
  const status = await x.rpc("tools/call", {
    name: "bridge_status",
    arguments: {},
  });
  const text = status.result.content[0].text;
  assert(!text.includes(owner.openid));
  assert(!text.includes(secret));
  assert.equal(JSON.parse(text).enabled, false);
  for (const path of ["/fixture", "/admin", "/token", "/revoke"])
    assert.equal(
      (await x.mf.dispatchFetch(host + path, { method: "POST" })).status,
      404,
    );
  assert.equal(
    (await x.mf.dispatchFetch("https://other.example/mcp", { method: "POST" }))
      .status,
    404,
  );
});
test("continuous bound-owner storage without callback lease; fresh reply independently authorized", async (t) => {
  const x = await setup(t);
  assert.equal(await x.ingress(), 200);
  assert.equal(x.count(), 0);
  const read = await x.rpc("tools/call", {
    name: "read_message",
    arguments: { message_id: "m" },
  });
  assert(read.result);
  const result = await x.rpc("tools/call", {
    name: "reply_message",
    arguments: { message_id: "m", text: "reply" },
  });
  assert(result.result && !result.result.isError);
  assert.equal(x.replies(), 1);
  assert.equal(
    await x.ingress(
      "stranger",
      "hidden",
      new Date().toISOString(),
      "other-owner",
    ),
    200,
  );
  assert(
    !(await x.direct({ op: "inspect" })).rows.some(
      (r: any) => r.key === "msg:stranger",
    ),
  );
});
test("rate and body limits plus timed retention/dedup cleanup prevent unbounded storage", async (t) => {
  const x = await setup(t);
  for (let i = 0; i < 10; i++) assert.equal(await x.ingress("limit-" + i), 200);
  assert.equal(await x.ingress("limit-10"), 403);
  assert.equal(await x.ingress("oversized", "x".repeat(8001)), 403);
  await x.direct({ op: "advance", ms: 3600001 });
  await x.direct({ op: "alarm" });
  let rows = (await x.direct({ op: "inspect" })).rows;
  assert(!rows.some((r: any) => r.key.startsWith("msg:")));
  assert(rows.some((r: any) => r.key.startsWith("seen:")));
  await x.direct({ op: "advance", ms: 86400001 });
  await x.direct({ op: "alarm" });
  rows = (await x.direct({ op: "inspect" })).rows;
  assert(!rows.some((r: any) => r.key.startsWith("seen:")));
  assert.equal(await x.ingress("limit-0"), 401);
});
test("fresh reply refuses expired original QQ message and invalid Access assertion", async (t) => {
  const x = await setup(t);
  await x.ingress();
  const p = {
    name: "reply_message",
    arguments: { message_id: "m", text: "reply" },
  };
  assert.equal((await x.rpc("tools/call", p, "invalid")).http, 403);
  await x.direct({ op: "expireMessage" });
  const result = await x.rpc("tools/call", p);
  assert(result.error || result.result?.isError);
  assert.equal(x.replies(), 0);
});

test("explicit unsubscribe cancels old event reply chain despite fresh authenticated request", async (t) => {
  const x = await setup(t);
  await x.rpc("events/subscribe", params());
  await x.ingress();
  await x.rpc("events/unsubscribe", {
    name: "qq.message.created",
    arguments: { conversation: "owner_private" },
    delivery: { mode: "webhook", url },
  });
  const p = {
    name: "reply_message",
    arguments: { message_id: "m", text: "reply" },
  };
  let result = await x.rpc("tools/call", p);
  assert(result.error || result.result?.isError);
  await x.rpc("events/subscribe", params());
  result = await x.rpc("tools/call", p);
  assert(result.error || result.result?.isError);
  assert.equal(x.replies(), 0);
});

test("short renewal that expires during awaited schedule cannot replace existing sealed lease", async (t) => {
  const x = await setup(t);
  await x.rpc("events/subscribe", params());
  const before = (await x.direct({ op: "inspect" })).rows.find(
    (r: any) => r.key === "sub",
  ).value;
  await x.direct({ op: "delaySchedule", ms: 100 });
  assert((await x.rpc("events/subscribe", params(50))).error);
  const after = (await x.direct({ op: "inspect" })).rows.find(
    (r: any) => r.key === "sub",
  ).value;
  assert.equal(after.expires, before.expires);
  assert.deepEqual(after.sealed, before.sealed);
});
test("callback decrypt failure stops queue and retains body cleanup alarm", async (t) => {
  const x = await setup(t);
  await x.rpc("events/subscribe", params());
  await x.ingress();
  await x.direct({ op: "tamper" });
  await x.direct({ op: "alarm" });
  const snapshot = await x.direct({ op: "inspect" });
  assert(
    !snapshot.rows.some((r: any) => r.key === "sub" || r.key === "queue:m"),
  );
  assert(snapshot.alarm > Date.now() + 500);
  assert(snapshot.rows.some((r: any) => r.key === "msg:m"));
  assert.equal(x.count(), 1);
});
test("events disable during challenge prevents late successful commit", async (t) => {
  const x = await setup(t);
  x.hold();
  const pending = x.rpc("events/subscribe", params());
  const until = Date.now() + 1500;
  while (x.count() < 1 && Date.now() < until)
    await new Promise((r) => setTimeout(r, 5));
  await x.direct({ op: "flag", name: "EVENTS_ENABLED", value: "false" });
  x.release();
  assert((await pending).error);
  assert(
    !(await x.direct({ op: "inspect" })).rows.some((r: any) => r.key === "sub"),
  );
});

test("reply flag disabled during token await blocks final QQ send and leaves claim unspent", async (t) => {
  const x = await setup(t);
  await x.ingress();
  x.holdToken();
  const pending = x.rpc("tools/call", {
    name: "reply_message",
    arguments: { message_id: "m", text: "reply" },
  });
  const until = Date.now() + 1500;
  while (x.tokens() < 1 && Date.now() < until)
    await new Promise((r) => setTimeout(r, 5));
  await x.direct({ op: "flag", name: "MCP_WRITE_ENABLED", value: "false" });
  x.release();
  const result = await pending;
  assert(result.error || result.result?.isError);
  assert.equal(x.replies(), 0);
  assert(
    !(await x.direct({ op: "inspect" })).rows.some(
      (r: any) => r.key === "reply:m",
    ),
  );
});

test("public route guards fail closed for missing deployment configuration", async (t) => {
  const x = await setup(t, true, { ACCESS_TEAM_DOMAIN: "" });
  for (const path of ["/health", "/auth-check", "/mcp", "/qq/webhook"]) {
    const r = await x.mf.dispatchFetch(host + path, {
      method: ["/health", "/auth-check"].includes(path) ? "GET" : "POST",
    });
    assert.equal(r.status, 404);
  }
  assert.equal(x.count(), 0);
});
test("configured extra webhook host never receives MCP or auth routes", async (t) => {
  const x = await setup(t);
  for (const path of ["/mcp", "/auth-check", "/health"]) {
    assert.equal(
      (
        await x.mf.dispatchFetch("https://qq-webhook.example.com" + path, {
          method: path === "/mcp" ? "POST" : "GET",
        })
      ).status,
      404,
    );
  }
  assert.equal(
    (
      await x.mf.dispatchFetch("https://qq-webhook.example.com/qq/webhook", {
        method: "POST",
      })
    ).status,
    415,
  );
  assert.equal(
    (
      await x.mf.dispatchFetch("https://unconfigured.example.com/qq/webhook", {
        method: "POST",
      })
    ).status,
    404,
  );
});
test("malformed legacy owner blocks authority and restoration cannot revive it", async (t) => {
  const x = await setup(t);
  await x.direct({ op: "pair", value: null });
  assert.equal((await x.rpc("tools/list", {})).http, 403);
  assert(
    (await x.direct({ op: "inspect" })).rows.some(
      (r: any) => r.key === "blocked" && r.value === true,
    ),
  );
  await x.direct({ op: "pair", value: owner });
  assert.equal((await x.rpc("tools/list", {})).http, 403);
  assert.equal(x.count(), 0);
});
