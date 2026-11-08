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
const wrapper = `import production,{BridgeStore as Impl} from './runtime.mjs';export class BridgeStore{constructor(s,e){this.s=s;this.e=e;this.offset=0;s.blockConcurrencyWhile(async()=>{if(!await s.storage.get('seeded')){await s.storage.put('pairing:owner',JSON.parse(e.OWNER));await s.storage.put('seeded',true);}this.impl=new Impl(s,e,()=>Date.now()+this.offset);});}async alarm(){if(this.e.HOLD_ALARM==='true')return;await this.impl.alarm();}async fetch(r){if(new URL(r.url).pathname==='/fixture'){const p=await r.json();if(p.op==='delayMark'){const original=this.impl.timing.mark.bind(this.impl.timing);this.impl.timing.mark=(trace,phase,at)=>{if(phase===p.phase)this.offset+=p.ms;return original(trace,phase,at);};}if(p.op==='attemptMetrics'){this.s.storage.sql.exec('DELETE FROM message_timing_v1');const base=Date.now()-2000,id=this.impl.timing.create({ingress_entry:base});this.impl.timing.finish(id,'reply',{marks:{reply_entry:base,reply_exit:base+50,reply_access_entry:base-10,reply_access_exit:base-2,token_entry:base+5,token_exit:base+45},token:'fetch'},'error');this.impl.timing.finish(id,'reply',{marks:{reply_entry:base+1000,reply_exit:base+1040,reply_access_entry:base+990,reply_access_exit:base+998,token_entry:base+1001,token_exit:base+1002,qq_send:base+1010,qq_ack:base+1030},token:'cache'},'success');return Response.json(this.impl.timing.summary());}if(p.op==='timings')return Response.json(this.s.storage.sql.exec('SELECT * FROM message_timing_v1').toArray());if(p.op==='expireTimings'){this.s.storage.sql.exec('UPDATE message_timing_v1 SET created=?',Date.now()-3600001);await this.impl.alarm();return Response.json(this.s.storage.sql.exec('SELECT count(*) AS n FROM message_timing_v1').toArray());}if(p.op==='seedTimings'){for(let i=0;i<110;i++)this.impl.timing.create({ingress_entry:Date.now()-1000,ingress_verified:Date.now()-900});return Response.json(this.impl.timing.summary());}if(p.op==='clockTiming'){this.s.storage.sql.exec('DELETE FROM message_timing_v1');const base=Date.now()-1000,id=this.impl.timing.create({ingress_entry:base,ingress_verified:base+100});this.impl.timing.mark(id,'queue_commit',base+150);this.impl.timing.mark(id,'alarm_entry',base+350);this.impl.timing.mark(id,'dispatch',base+400);this.impl.timing.mark(id,'callback_ack',base+600);this.impl.timing.mark(id,'qq_send',base+650);this.impl.timing.mark(id,'qq_ack',base+900);this.impl.timing.mark(id,'qq_ack',base+999);return Response.json(this.impl.timing.summary());}if(p.op==='metrics'){for(let i=0;i<1000;i++)this.impl.put('seen:'+i,{time:Date.now()});for(const key of ['msg:a','msg:雪','msg:😀','msg:'+String.fromCharCode(0),'msg:zzz'])this.impl.put(key,{});this.impl.put('msgs:other',{});const old=this.s.storage.sql.exec('SELECT key,value FROM managed_messages_v1 WHERE substr(key,1,?)=?',4,'msg:');const oldRows=old.toArray();const fresh=this.s.storage.sql.exec('SELECT key,value FROM managed_messages_v1 WHERE key>=? AND key<?','msg:','msg;');const freshRows=fresh.toArray();const count=this.s.storage.sql.exec('SELECT count(*) AS n FROM managed_messages_v1 WHERE key>=? AND key<?','msg:','msg;');const n=count.toArray()[0].n;return Response.json({oldKeys:oldRows.map(r=>r.key).sort(),newKeys:freshRows.map(r=>r.key).sort(),n,oldRowsRead:old.rowsRead,newRowsRead:fresh.rowsRead,countRowsRead:count.rowsRead,oldPlan:this.s.storage.sql.exec('EXPLAIN QUERY PLAN SELECT key,value FROM managed_messages_v1 WHERE substr(key,1,4)=?', 'msg:').toArray(),newPlan:this.s.storage.sql.exec('EXPLAIN QUERY PLAN SELECT key,value FROM managed_messages_v1 WHERE key>=? AND key<?','msg:','msg;').toArray()});}if(p.op==='breakTiming')this.s.storage.sql.exec('DROP TABLE message_timing_v1');if(p.op==='legacy'){await this.s.storage.put('pairing:pending',{hash:'fixture',principal:JSON.parse(this.e.OWNER).principal,createdAt:Date.now(),expiresAt:Date.now()+150});await this.s.storage.put('msg:legacy',{received_at:Date.now()-3600002});}if(p.op==='expireMessage'){const m=this.impl.get('msg:m');m.timestamp=new Date(Date.now()-300001).toISOString();this.impl.put('msg:m',m);}if(p.op==='flag')this.impl.env[p.name]=p.value;if(p.op==='delaySchedule'){const original=this.impl.schedule.bind(this.impl);this.impl.schedule=async(...args)=>{await original(...args);await new Promise(r=>setTimeout(r,p.ms));};}if(p.op==='tamper'){const sub=this.impl.get('sub');sub.sealed.ciphertext='invalid';this.impl.put('sub',sub);}if(p.op==='advance')this.offset+=p.ms;if(p.op==='restart')this.impl=new Impl(this.s,this.e,()=>Date.now()+this.offset);if(p.op==='pair')await this.s.storage.put('pairing:owner',p.value);if(p.op==='alarm')await this.impl.alarm();if(p.op==='inspect')return Response.json({rows:this.impl.rows(''),owner:await this.s.storage.get('pairing:owner'),alarm:await this.s.storage.getAlarm(),pending:await this.s.storage.get('pairing:pending'),legacy:await this.s.storage.get('msg:legacy')});return Response.json({ok:true});}return this.impl.fetch(r);}}export default production;`;
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

test("timing actual SDK/SQLite phases stay private and duplicate ingress keeps original trace and TTL", async (t) => {
  const x = await setup(t);
  await x.rpc("events/subscribe", params());
  await x.ingress();
  const before = await x.direct({ op: "timings" });
  assert.equal(before.length, 1);
  await x.ingress();
  assert.deepEqual(await x.direct({ op: "timings" }), before);
  await x.direct({ op: "alarm" });
  await x.rpc("tools/call", {
    name: "read_message",
    arguments: { message_id: "m" },
  });
  await x.rpc("tools/call", {
    name: "reply_message",
    arguments: { message_id: "m", text: "reply" },
  });
  const rows = await x.direct({ op: "timings" }),
    phases = JSON.parse(rows[0].phases);
  for (const key of [
    "ingress_entry",
    "ingress_verified",
    "queue_commit",
    "alarm_entry",
    "dispatch",
    "callback_ack",
    "read_entry",
    "read_exit",
    "reply_entry",
    "reply_exit",
    "read_access_entry",
    "read_access_exit",
    "reply_access_entry",
    "reply_access_exit",
    "token_entry",
    "token_exit",
    "qq_send",
    "qq_ack",
  ])
    assert.equal(typeof phases[key], "number", key);
  assert(phases.ingress_verified >= phases.ingress_entry);
  assert(phases.qq_ack >= phases.qq_send);
  assert.equal(
    rows[0].created,
    (await x.direct({ op: "inspect" })).rows.find((r: any) => r.key === "msg:m")
      .value.received_at,
  );
  const status = await x.rpc("tools/call", {
    name: "bridge_status",
    arguments: {},
  });
  const raw = JSON.stringify(status);
  for (const forbidden of [
    rows[0].trace,
    owner.principal,
    owner.openid,
    url,
    secret,
    "synthetic",
    "fixture-access-token",
  ])
    assert(!raw.includes(forbidden));
  assert.equal(x.replies(), 1);
});
test("timing capped to 100, physically alarm-expired, fixed first phase and synthetic clock aggregates", async (t) => {
  const x = await setup(t);
  const sample = await x.direct({ op: "clockTiming" });
  assert.deepEqual(sample.intervals.ingress, {
    samples: 1,
    min_ms: 100,
    max_ms: 100,
    mean_ms: 100,
  });
  assert.equal(sample.intervals.observed_end_to_end.mean_ms, 900);
  assert.equal((await x.direct({ op: "seedTimings" })).traces, 100);
  assert.equal((await x.direct({ op: "expireTimings" }))[0].n, 0);
});
test("concurrent different-message read and reply have request-local timing association", async (t) => {
  const x = await setup(t);
  await x.ingress("m");
  await x.ingress("other");
  x.holdToken();
  const reply = x.rpc("tools/call", {
    name: "reply_message",
    arguments: { message_id: "m", text: "reply" },
  });
  const limit = Date.now() + 2000;
  while (x.tokens() < 1 && Date.now() < limit)
    await new Promise((r) => setTimeout(r, 5));
  await x.rpc("tools/call", {
    name: "read_message",
    arguments: { message_id: "other" },
  });
  x.release();
  await reply;
  const messages = (await x.direct({ op: "inspect" })).rows;
  const traces = await x.direct({ op: "timings" });
  const get = (id: string) =>
    JSON.parse(
      traces.find(
        (r: any) =>
          r.trace ===
          messages.find((m: any) => m.key === "msg:" + id).value.trace,
      ).phases,
    );
  assert(get("m").reply_entry);
  assert(!get("m").read_entry);
  assert(get("other").read_entry);
  assert(!get("other").reply_entry);
});
test("timing storage failure cannot undo successful durable QQ once outcome", async (t) => {
  const x = await setup(t);
  await x.ingress();
  await x.direct({ op: "breakTiming" });
  const p = {
    name: "reply_message",
    arguments: { message_id: "m", text: "reply" },
  };
  assert((await x.rpc("tools/call", p)).result);
  await x.rpc("tools/call", p);
  assert.equal(x.replies(), 1);
  assert.equal(
    (await x.direct({ op: "inspect" })).rows.find(
      (r: any) => r.key === "reply:m",
    ).value.status,
    "sent",
  );
});
test("trusted prefix range is equivalent for unicode/NUL suffixes and uses workerd SQLite index", async (t) => {
  const x = await setup(t);
  const result = await x.direct({ op: "metrics" });
  assert.deepEqual(result.oldKeys, result.newKeys);
  assert.equal(result.n, 5);
  assert(result.oldRowsRead > result.newRowsRead);
  assert(JSON.stringify(result.oldPlan).includes("SCAN"));
  assert(JSON.stringify(result.newPlan).includes("SEARCH"));
  console.log(
    "Synthetic workerd SQLite metrics",
    JSON.stringify({
      oldRowsRead: result.oldRowsRead,
      newRowsRead: result.newRowsRead,
      countRowsRead: result.countRowsRead,
      oldPlan: result.oldPlan,
      newPlan: result.newPlan,
    }),
  );
});

test("per-request intervals never splice failed first attempt into later successful ACK; cache and fetch stay distinct", async (t) => {
  const x = await setup(t);
  const m = (await x.direct({ op: "attemptMetrics" })).intervals;
  assert.equal(m.reply_error.mean_ms, 50);
  assert.equal(m.reply_success.mean_ms, 40);
  assert.equal(m.qq_ack_success.mean_ms, 20);
  assert.equal(m.reply_access_success.mean_ms, 8);
  assert.equal(m.token_fetch_error.mean_ms, 40);
  assert.equal(m.token_cache_success.mean_ms, 1);
});
test("timing work cannot cross final authorization deadline and then send QQ or callback", async (t) => {
  const x = await setup(t);
  await x.ingress();
  await x.direct({ op: "delayMark", phase: "qq_send", ms: 6000 });
  await x.rpc("tools/call", {
    name: "reply_message",
    arguments: { message_id: "m", text: "reply" },
  });
  assert.equal(x.replies(), 0);
  assert.equal(
    (await x.direct({ op: "inspect" })).rows.find(
      (r: any) => r.key === "reply:m",
    ).value.status,
    "uncertain",
  );
  const y = await setup(t);
  await y.rpc("events/subscribe", params());
  await y.ingress();
  await y.direct({ op: "delayMark", phase: "dispatch", ms: 60001 });
  await y.direct({ op: "alarm" });
  assert.equal(y.count(), 1);
});
