import { deploymentFromEnvironment, type DeploymentEnv } from "./deployment.ts";
import { Timing, type Measurement, type Phase } from "./timing.ts";
import {
  RequestBudget,
  RequestDeadline,
  completedResponse,
  guardedStorage,
} from "./request-budget.ts";
// Managed OAuth source preparation fork; ordinary capabilities default disabled.
import { McpServer, ProtocolError } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";
import { createAccessVerifier } from "./access.ts";
import { callbackVaultFromEnvironment } from "./keyring-config.ts";
import {
  whSecret,
  whSignature,
  subscriptionId,
  qqVerify,
  qqSign,
  parseIncoming,
} from "./security.ts";
import { sendEvent, verify, destination } from "./fetch-sender.ts";
import { boundedQqResponse } from "./qq-response.ts";
import {
  pendingPairing,
  pairingIdentity,
  startPairing,
  consumePairing,
  pairingCommand,
  containsPairingCode,
  PAIRING_OWNER_KEY,
  PAIRING_BOUND_KEY,
  type PairedOwner,
} from "./pairing.ts";
import { readDiagnostics } from "./diagnostics.ts";
import { productionBody } from "./production-body.ts";
import { createHash } from "node:crypto";
const EVENT = "qq.message.created",
  VERSION = "0.3.0",
  RETENTION = 3600000,
  DEDUP = 86400000;
type Auth = {
  principal: string;
  receipt: number;
  expires: number;
  requestDeadline: number;
  budget?: RequestBudget;
  trace?: string;
  measurement?: Measurement;
};
type Sub = {
  id: string;
  revision: string;
  principal: string;
  openid: string;
  expires: number;
  sealed: any;
};
export class BridgeStore {
  timing: Timing;
  state: DurableObjectState;
  env: any;
  now: () => number;
  verifier: ReturnType<typeof createAccessVerifier>;
  vault?: ReturnType<typeof callbackVaultFromEnvironment>;
  token?: { value: string; expires: number };
  constructor(
    state: DurableObjectState,
    env: any,
    now: () => number = Date.now,
  ) {
    this.state = state;
    this.env = env;
    this.now = now;
    this.verifier = createAccessVerifier();
    try {
      this.vault = callbackVaultFromEnvironment(env);
    } catch {
      this.vault = undefined;
    }
    state.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS managed_messages_v1 (key TEXT PRIMARY KEY,value TEXT NOT NULL)",
    );
    this.timing = new Timing(state.storage.sql);
  }
  get<T = any>(key: string): T | undefined {
    return this.state.storage.sql
      .exec<{ value: string }>(
        "SELECT value FROM managed_messages_v1 WHERE key=?",
        key,
      )
      .toArray()
      .map((r) => JSON.parse(r.value))[0];
  }
  put(key: string, value: any) {
    this.state.storage.sql.exec(
      "INSERT OR REPLACE INTO managed_messages_v1 VALUES (?,?)",
      key,
      JSON.stringify(value),
    );
  }
  del(key: string) {
    this.state.storage.sql.exec(
      "DELETE FROM managed_messages_v1 WHERE key=?",
      key,
    );
  }
  prefixBounds(prefix: string) {
    if (!/^[a-z]+:$/.test(prefix)) throw Error("Invalid internal prefix");
    return [prefix, prefix.slice(0, -1) + ";"];
  }
  rows(prefix: string) {
    const cursor = prefix
      ? this.state.storage.sql.exec<{ key: string; value: string }>(
          "SELECT key,value FROM managed_messages_v1 WHERE key>=? AND key<?",
          ...this.prefixBounds(prefix),
        )
      : this.state.storage.sql.exec<{ key: string; value: string }>(
          "SELECT key,value FROM managed_messages_v1",
        );
    return cursor
      .toArray()
      .map((r) => ({ key: r.key, value: JSON.parse(r.value) }));
  }
  count(prefix: string) {
    return this.state.storage.sql
      .exec<{ n: number }>(
        "SELECT count(*) AS n FROM managed_messages_v1 WHERE key>=? AND key<?",
        ...this.prefixBounds(prefix),
      )
      .toArray()[0].n;
  }
  invalidate() {
    this.state.storage.transactionSync(() => {
      this.put("blocked", true);
      this.del("sub");
      this.del("intent");
      for (const r of this.rows("queue:")) this.del(r.key);
    });
  }
  async pair(
    budget?: RequestBudget,
    allowUnpaired = false,
  ): Promise<PairedOwner | undefined> {
    budget?.check();
    let p: any, bound: any;
    try {
      // A single snapshot avoids mistaking a concurrent first bind for owner deletion.
      const values = await this.state.storage.get([
        PAIRING_OWNER_KEY,
        PAIRING_BOUND_KEY,
      ]);
      budget?.check();
      p = values.get(PAIRING_OWNER_KEY);
      bound = values.get(PAIRING_BOUND_KEY);
    } catch {
      budget?.check();
      this.invalidate();
      throw Error("Pair unavailable");
    }
    const old = this.get("pair");
    if (
      p === undefined &&
      bound === undefined &&
      !old &&
      !this.get("blocked") &&
      this.state.storage.sql
        .exec("SELECT 1 FROM managed_messages_v1 LIMIT 1")
        .toArray().length === 0
    ) {
      if (allowUnpaired) return undefined;
      throw Error("Pair required");
    }
    if (
      !p ||
      typeof p.principal !== "string" ||
      !/^access_[a-f0-9]{64}$/.test(p.principal) ||
      typeof p.openid !== "string" ||
      !/^[A-Za-z0-9_-]{1,256}$/.test(p.openid) ||
      !Number.isSafeInteger(p.pairedAt) ||
      (bound !== undefined && bound !== pairingIdentity(p))
    ) {
      this.invalidate();
      throw Error("Pair unavailable");
    }
    if (
      this.get("blocked") ||
      (old &&
        (old.principal !== p.principal ||
          old.openid !== p.openid ||
          old.pairedAt !== p.pairedAt))
    ) {
      this.invalidate();
      throw Error("Pair changed");
    }
    if (!old) this.put("pair", p);
    return p;
  }
  authCurrent(a: Auth) {
    a.budget?.check();
    if (
      this.get("blocked") ||
      a.expires <= this.now() ||
      a.requestDeadline <= this.now()
    )
      throw Error("Request expired");
  }
  async authorize(a: Auth, allowUnpaired = false) {
    this.authCurrent(a);
    const owner = await this.pair(a.budget, allowUnpaired);
    this.authCurrent(a);
    if (owner && owner.principal !== a.principal)
      throw Error("Owner unavailable");
    return owner;
  }
  pairingEnabled() {
    return (
      this.env.PAIRING_ENABLED === "true" &&
      this.env.BRIDGE_ENABLED !== "true" &&
      this.env.EVENTS_ENABLED !== "true" &&
      this.env.MCP_WRITE_ENABLED !== "true" &&
      !!this.env.QQ_APP_ID &&
      !!this.env.QQ_APP_SECRET
    );
  }
  pairingGuard(budget?: RequestBudget, auth?: Auth) {
    budget?.check();
    if (!this.pairingEnabled() || this.get("blocked") || this.get("pair"))
      throw Error("Pairing unavailable");
    if (auth) this.authCurrent(auth);
  }
  pairingStorage<T extends object>(storage: T, check: () => void): T {
    return new Proxy(storage, {
      get(target, key) {
        const value = (target as any)[key];
        if (typeof value !== "function") return value;
        return (...args: any[]) => {
          check();
          const result = value.apply(target, args);
          return result && typeof result.then === "function"
            ? result.then((v: any) => {
                check();
                return v;
              })
            : (check(), result);
        };
      },
    });
  }
  async beginPairing(a: Auth) {
    await this.authorize(a, true);
    const check = () => this.pairingGuard(a.budget, a);
    check();
    a.budget?.mark("pairing");
    const result = await this.state.storage.transaction(async (tx) => {
      check();
      const result = await startPairing(
        this.pairingStorage(
          a.budget ? guardedStorage(tx, a.budget) : tx,
          check,
        ),
        { principal: a.principal, expiresAt: a.expires },
        this.now,
      );
      check();
      return result;
    });
    check();
    return result;
  }
  async acceptPairing(payload: any, budget?: RequestBudget) {
    // Always swallow code-bearing input; it must never become a business message.
    const command = pairingCommand(payload, this.now());
    if (!command || !this.pairingEnabled()) return;
    if (await this.pair(budget, true)) return;
    const check = () => this.pairingGuard(budget);
    check();
    const owner = await this.state.storage.transaction(async (tx) => {
      check();
      const result = await consumePairing(
        this.pairingStorage(budget ? guardedStorage(tx, budget) : tx, check),
        command,
        this.now,
      );
      check();
      return result;
    });
    budget?.check();
    // Marker + owner were committed atomically. Establish continuity before ACK.
    if (owner) await this.pair(budget);
  }
  leaseMs() {
    const ttl = Number(this.env.MANAGED_LEASE_MS ?? 60000);
    if (!Number.isSafeInteger(ttl) || ttl < 1000 || ttl > 300000)
      throw Error("Lease configuration unavailable");
    return ttl;
  }
  eventsEnabled() {
    if (
      this.env.BRIDGE_ENABLED !== "true" ||
      this.env.EVENTS_ENABLED !== "true"
    )
      throw Error("Events disabled");
  }
  current(a: Auth) {
    a.budget?.check();
    if (
      this.get("blocked") ||
      a.principal !== this.get("pair")?.principal ||
      a.expires <= this.now() ||
      a.requestDeadline <= this.now()
    )
      throw Error("Request expired");
  }
  stamp(a: Auth, phase: Phase, at = Date.now()) {
    if (a.measurement) a.measurement.marks[phase] ??= at;
    this.timing.mark(a.trace, phase, at);
  }
  ctx(s: Sub) {
    return {
      owner: s.principal,
      grant: "managed-lease",
      epoch: "managed-messages-v1",
      sub: s.id,
      incarnation: s.revision + ":" + s.expires,
    };
  }
  active(s: Sub) {
    this.eventsEnabled();
    const p = this.get("pair"),
      current = this.get<Sub>("sub");
    if (
      this.get("blocked") ||
      !p ||
      p.principal !== s.principal ||
      p.openid !== s.openid ||
      s.expires <= this.now() ||
      !current ||
      current.expires <= this.now() ||
      current.revision !== s.revision
    )
      throw Error("Lease unavailable");
  }
  task(id: string) {
    const t = this.get("msg:" + id);
    if (!t || t.deadline <= this.now()) throw Error("Task expired");
    this.active({ ...t.sub, expires: t.deadline });
    return t;
  }
  async schedule(extra?: number, budget?: RequestBudget) {
    budget?.check();
    this.prune(budget);
    const times: number[] = [];
    const timingExpiry = this.timing.nextExpiry();
    if (timingExpiry) times.push(timingExpiry);
    for (const row of this.rows("cancelled:"))
      times.push(row.value.time + DEDUP);
    for (const row of this.rows("msg:"))
      times.push(row.value.received_at + RETENTION);
    for (const row of this.rows("seen:")) times.push(row.value.time + DEDUP);
    for (const row of this.rows("outgoing:"))
      times.push(row.value.time + DEDUP);
    if (extra) times.push(extra);
    const sub = this.get<Sub>("sub"),
      intent = this.get("intent");
    if (sub) times.push(sub.expires);
    if (intent) times.push(intent.deadline);
    for (const queued of this.rows("queue:")) {
      const id = queued.key.slice(6);
      try {
        this.task(id);
        if (this.get("event:" + id)) this.del(queued.key);
        else times.push(this.now() + 1);
      } catch {
        this.del(queued.key);
      }
    }
    budget?.check();
    const cleanupBudget = budget ?? new RequestBudget();
    const pair = await this.state.storage.transaction(async (tx) => {
      cleanupBudget.check();
      const result = await pendingPairing(
        guardedStorage(tx, cleanupBudget),
        this.now(),
      );
      cleanupBudget.check();
      return result;
    });
    budget?.check();
    if (pair) times.push(pair.expiresAt);
    const diag = await readDiagnostics(
      budget ? guardedStorage(this.state.storage, budget) : this.state.storage,
      this.env.AUTH_DIAGNOSTICS_UNTIL,
    );
    budget?.check();
    if (diag) times.push(diag.expiresAt);
    for (const [key, m] of await this.state.storage.list<any>({
      prefix: "msg:",
    })) {
      budget?.check();
      if (m.received_at + 3600001 <= Date.now()) {
        await this.state.storage.delete(key);
        budget?.check();
        await this.state.storage.delete("reply:" + key.slice(4));
      } else times.push(m.received_at + 3600001);
    }
    const current = await this.state.storage.getAlarm();
    budget?.check();
    if (current && current > this.now()) times.push(current);
    if (times.length)
      await this.state.storage.setAlarm(
        Math.max(Date.now() + 1, Math.min(...times)),
      );
  }
  async subscribe(a: Auth, p: any) {
    this.eventsEnabled();
    if (!this.vault) throw Error("Callback key unavailable");
    await this.pair(a.budget);
    this.current(a);
    destination(p.delivery.url);
    whSecret(p.delivery.secret);
    const requested = p.ttlMs ?? this.leaseMs();
    const duration = Math.min(requested, this.leaseMs());
    if (!Number.isSafeInteger(requested) || requested <= 0)
      throw Error("Invalid TTL");
    const expires = Math.min(a.expires, a.receipt + duration),
      id = subscriptionId(a.principal, p.delivery.url, EVENT, {
        conversation: "owner_private",
      });
    if (expires <= this.now()) throw Error("Expired lease");
    const old = this.get<Sub>("sub");
    if (old && old.expires > this.now()) {
      this.active(old);
      const credentials = this.vault!.open(old.sealed, this.ctx(old));
      if (old.id !== id || credentials.secret !== p.delivery.secret)
        throw Error("Unsubscribe first");
      const renewed = { ...old, expires };
      await this.schedule(expires, a.budget);
      await this.pair(a.budget);
      this.current(a);
      this.eventsEnabled();
      this.active(old);
      if (expires <= this.now()) throw Error("Renewal expired");
      renewed.sealed = this.vault!.seal(credentials, this.ctx(renewed));
      this.current(a);
      this.eventsEnabled();
      if (expires <= this.now()) throw Error("Renewal expired");
      this.put("sub", renewed);
      return {
        id,
        refreshBefore: new Date(expires).toISOString(),
        cursor: null,
        truncated: false,
      };
    }
    const revision = crypto.randomUUID(),
      intent = {
        revision,
        id,
        principal: a.principal,
        deadline: Math.min(a.requestDeadline, expires),
      };
    if (this.get("intent")) throw Error("Pending");
    this.put("intent", intent);
    const clearIntent = () => {
      this.state.storage.transactionSync(() => {
        if (this.get("intent")?.revision === revision) this.del("intent");
      });
    };
    const cancelled = () => {
      try {
        clearIntent();
      } catch {}
    };
    a.budget?.controller.signal.addEventListener("abort", cancelled, {
      once: true,
    });
    try {
      await this.schedule(intent.deadline, a.budget);
      await this.pair(a.budget);
      this.current(a);
      this.eventsEnabled();
      if (
        this.get("intent")?.revision !== revision ||
        this.now() >= intent.deadline
      )
        throw Error("Cancelled");
      const owner = this.get("pair"),
        s: Sub = {
          id,
          revision,
          principal: a.principal,
          openid: owner.openid,
          expires,
          sealed: null,
        };
      const challenge = crypto.randomUUID(),
        webhookId = crypto.randomUUID(),
        timestamp = String(Math.floor(this.now() / 1000)),
        body = JSON.stringify({ type: "verification", challenge });
      await verify(
        {
          url: p.delivery.url,
          body,
          auth: { principal: a.principal, expiresAt: intent.deadline },
          webhookId,
          timestamp,
          signature: whSignature(p.delivery.secret, webhookId, timestamp, body),
          subscriptionId: id,
        },
        challenge,
        {
          now: this.now,
          authorize: async () => {
            await this.pair(a.budget);
            this.current(a);
            this.eventsEnabled();
            return this.get("intent")?.revision === revision;
          },
          fetch: (u, i) => {
            this.current(a);
            this.eventsEnabled();
            if (this.get("intent")?.revision !== revision)
              throw Error("Cancelled");
            return fetch(u, i);
          },
        },
      );
      await this.pair(a.budget);
      this.current(a);
      this.eventsEnabled();
      if (
        this.get("intent")?.revision !== revision ||
        this.now() >= intent.deadline
      )
        throw Error("Cancelled");
      s.sealed = this.vault!.seal(
        { url: p.delivery.url, secret: p.delivery.secret },
        this.ctx(s),
      );
      this.state.storage.transactionSync(() => {
        this.current(a);
        this.eventsEnabled();
        if (
          this.now() >= intent.deadline ||
          this.get("intent")?.revision !== revision
        )
          throw Error("Cancelled");
        this.put("sub", s);
        this.del("intent");
      });
      await this.schedule(undefined, a.budget);
      return {
        id,
        refreshBefore: new Date(expires).toISOString(),
        cursor: null,
        truncated: false,
      };
    } catch {
      throw new ProtocolError(-32015, "CallbackEndpointError", {
        reason: "challenge_failed",
      });
    } finally {
      a.budget?.controller.signal.removeEventListener("abort", cancelled);
      clearIntent();
    }
  }
  async unsubscribe(a: Auth, p: any) {
    await this.pair(a.budget);
    this.current(a);
    const id = subscriptionId(a.principal, p.delivery.url, EVENT, {
      conversation: "owner_private",
    });
    this.state.storage.transactionSync(() => {
      this.current(a);
      if (this.get("intent")?.id === id) this.del("intent");
      const s = this.get<Sub>("sub");
      for (const row of this.rows("msg:"))
        if (row.value.sub?.id === id && row.value.sub.principal === a.principal)
          this.put("cancelled:" + row.value.sub.revision, { time: this.now() });
      if (s?.id === id && s.principal === a.principal) {
        this.put("cancelled:" + s.revision, { time: this.now() });
        this.del("sub");
        for (const r of this.rows("queue:"))
          if (r.value.revision === s.revision) this.del(r.key);
      }
    });
    return {};
  }
  prune(budget?: RequestBudget) {
    budget?.check();
    this.timing.prune();
    try {
      this.state.storage.sql.exec(
        "DELETE FROM request_diagnostics_v1 WHERE at<=?",
        Date.now() - 3600000,
      );
    } catch {}
    const now = this.now();
    for (const row of this.rows("cancelled:"))
      if (row.value.time + DEDUP <= now) this.del(row.key);
    for (const row of this.rows("seen:"))
      if (row.value.time + DEDUP <= now) {
        this.del(row.key);
        this.del("reply:" + row.key.slice(5));
        this.del("event:" + row.key.slice(5));
      }
    for (const row of this.rows("outgoing:"))
      if (row.value.time + DEDUP <= now) this.del(row.key);
    for (const row of this.rows("msg:"))
      if (row.value.received_at + RETENTION <= now) {
        this.del(row.key);
        this.del("queue:" + row.key.slice(4));
      }
    const intent = this.get("intent");
    if (intent && intent.deadline <= now) this.del("intent");
    const sub = this.get<Sub>("sub");
    if (
      sub &&
      (sub.expires <= now ||
        this.env.BRIDGE_ENABLED !== "true" ||
        this.env.EVENTS_ENABLED !== "true")
    ) {
      this.del("sub");
      for (const q of this.rows("queue:")) this.del(q.key);
    }
  }
  ingest(m: any, clock?: { entry: number; verified: number }) {
    if (this.env.BRIDGE_ENABLED !== "true") throw Error("Messages disabled");
    this.prune();
    const pair = this.get("pair");
    if (
      m.user_openid !== pair?.openid ||
      Date.parse(m.timestamp) > this.now() + 30000 ||
      this.now() - Date.parse(m.timestamp) >= 300000
    )
      throw Error("Invalid message");
    let queuedTrace: string | undefined;
    this.state.storage.transactionSync(() => {
      if (this.get("seen:" + m.id) || this.get("outgoing:" + m.id)) return;
      const bucket = Math.floor(this.now() / 60000),
        rate = this.get("rate");
      if (rate?.bucket === bucket && rate.count >= 10)
        throw Error("Rate limit");
      if (this.count("msg:") >= 100 || this.count("seen:") >= 20000)
        throw Error("Capacity limit");
      this.put("rate", {
        bucket,
        count: rate?.bucket === bucket ? rate.count + 1 : 1,
      });
      this.put("seen:" + m.id, { time: this.now() });
      const s = this.get<Sub>("sub");
      let live = false;
      try {
        if (s) {
          this.active(s);
          live = true;
        }
      } catch {}
      const trace = this.timing.create(
        {
          ingress_entry: clock?.entry ?? Date.now(),
          ingress_verified: clock?.verified ?? Date.now(),
        },
        m.received_at,
      );
      this.put("msg:" + m.id, {
        ...m,
        trace,
        ...(live
          ? {
              sub: { ...s!, sealed: undefined },
              deadline: Math.min(s!.expires, Date.parse(m.timestamp) + 300000),
            }
          : { deadline: 0 }),
      });
      if (live) {
        this.put("queue:" + m.id, { revision: s!.revision });
        queuedTrace = trace;
      }
    });
    this.timing.mark(queuedTrace, "queue_commit");
  }
  async qqToken(a: Auth) {
    this.current(a);
    this.stamp(a, "token_entry");
    try {
      a.budget?.mark("token");
      if (this.token && this.token.expires > this.now() + 60000) {
        if (a.measurement) a.measurement.token = "cache";
        return this.token.value;
      }
      if (!this.env.QQ_APP_ID || !this.env.QQ_APP_SECRET)
        throw Error("QQ credentials unavailable");
      if (a.measurement) a.measurement.token = "fetch";
      const result = await boundedQqResponse(
        (signal) => {
          this.current(a);
          return fetch("https://api.bot.qq.com/app/getAppAccessToken", {
            method: "POST",
            redirect: "manual",
            signal,
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              appId: this.env.QQ_APP_ID,
              clientSecret: this.env.QQ_APP_SECRET,
            }),
          });
        },
        Math.min(a.expires, a.requestDeadline),
      );
      this.current(a);
      if (
        typeof result.access_token !== "string" ||
        !result.access_token ||
        !Number.isFinite(Number(result.expires_in)) ||
        Number(result.expires_in) <= 0 ||
        result.code
      )
        throw Error("QQ token unavailable");
      this.token = {
        value: result.access_token,
        expires: this.now() + Math.min(7200, Number(result.expires_in)) * 1000,
      };
      return this.token.value;
    } finally {
      this.stamp(a, "token_exit");
    }
  }
  async drain(alarmEntry?: number) {
    if (!this.vault) {
      this.del("sub");
      for (const q of this.rows("queue:")) this.del(q.key);
      return;
    }
    await this.pair();
    for (const row of this.rows("queue:")) {
      const id = row.key.slice(6);
      let t: any;
      try {
        t = this.task(id);
      } catch {
        this.del(row.key);
        continue;
      }
      this.timing.mark(t.trace, "alarm_entry", alarmEntry ?? Date.now());
      const s = this.get<Sub>("sub")!;
      let credentials;
      try {
        credentials = this.vault!.open(s.sealed, this.ctx(s));
      } catch {
        this.del("sub");
        for (const q of this.rows("queue:")) this.del(q.key);
        break;
      }
      const eventId = "qq_" + createHash("sha256").update(id).digest("hex");
      if (this.get("event:" + id)) {
        this.del(row.key);
        continue;
      }
      this.state.storage.transactionSync(() => {
        this.task(id);
        this.put("event:" + id, { status: "uncertain" });
        this.del(row.key);
      });
      const body = JSON.stringify({
          eventId,
          name: EVENT,
          timestamp: t.timestamp,
          data: {
            message_id: id,
            text: t.text,
            conversation: "owner_private",
            received_at: t.timestamp,
          },
          cursor: null,
        }),
        timestamp = String(Math.floor(this.now() / 1000));
      try {
        const status = await sendEvent(
          {
            url: credentials.url,
            body,
            auth: { principal: s.principal, expiresAt: t.deadline },
            webhookId: eventId,
            timestamp,
            signature: whSignature(
              credentials.secret,
              eventId,
              timestamp,
              body,
            ),
            subscriptionId: s.id,
          },
          {
            now: this.now,
            authorize: async () => {
              await this.pair();
              this.task(id);
              return true;
            },
            fetch: (u, i) => {
              this.task(id);
              this.timing.mark(t.trace, "dispatch");
              this.task(id);
              return fetch(u, i);
            },
          },
        );
        if (status >= 200 && status < 300) {
          this.timing.mark(t.trace, "callback_ack");
          this.put("event:" + id, { status: "sent" });
        } else if (
          [401, 403, 410].includes(status) &&
          this.get<Sub>("sub")?.revision === s.revision
        ) {
          this.del("sub");
          for (const q of this.rows("queue:"))
            if (q.value.revision === s.revision) this.del(q.key);
        }
      } catch {
      } finally {
        this.timing.mark(t.trace, "callback_end");
      }
    }
  }
  replyMessage(a: Auth, id: string) {
    if (
      this.env.BRIDGE_ENABLED !== "true" ||
      this.env.MCP_WRITE_ENABLED !== "true"
    )
      throw Error("Replies disabled");
    this.current(a);
    const m = this.get("msg:" + id);
    if (
      !m ||
      (m.sub && this.get("cancelled:" + m.sub.revision)) ||
      m.user_openid !== this.get("pair")?.openid ||
      !Number.isFinite(Date.parse(m.timestamp)) ||
      Date.parse(m.timestamp) > this.now() + 30000 ||
      Date.parse(m.timestamp) + 300000 <= this.now()
    )
      throw Error("Message unavailable");
    return m;
  }
  async reply(a: Auth, p: any) {
    a.budget?.mark("reply");
    if (
      this.env.BRIDGE_ENABLED !== "true" ||
      this.env.MCP_WRITE_ENABLED !== "true"
    )
      throw Error("Replies disabled");
    await this.pair(a.budget);
    this.current(a);
    this.replyMessage(a, p.message_id);
    const token = await this.qqToken(a);
    await this.pair(a.budget);
    this.current(a);
    this.replyMessage(a, p.message_id);
    const digest = createHash("sha256").update(p.text).digest("hex");
    a.budget?.mark("claim");
    const old = this.state.storage.transactionSync(() => {
      this.current(a);
      this.replyMessage(a, p.message_id);
      const old = this.get("reply:" + p.message_id);
      if (old) {
        if (old.digest !== digest) throw Error("Already replied");
        return old;
      }
      this.put("reply:" + p.message_id, { digest, status: "uncertain" });
    });
    if (old) return { status: old.status };
    const t = this.replyMessage(a, p.message_id);
    try {
      const result = await boundedQqResponse(
        (signal) => {
          this.current(a);
          this.replyMessage(a, p.message_id);
          a.budget?.mark("send");
          this.stamp(a, "qq_send");
          this.current(a);
          this.replyMessage(a, p.message_id);
          return fetch(
            "https://api.bot.qq.com/v2/users/" +
              encodeURIComponent(t.user_openid) +
              "/messages",
            {
              method: "POST",
              redirect: "manual",
              signal,
              headers: {
                "content-type": "application/json",
                authorization: "QQBot " + token,
                "X-Union-Appid": this.env.QQ_APP_ID,
              },
              body: JSON.stringify({
                msg_id: p.message_id,
                msg_seq: 1,
                msg_type: 0,
                content: p.text,
              }),
            },
          );
        },
        Math.min(
          Date.parse(t.timestamp) + 300000,
          a.expires,
          a.requestDeadline,
        ),
      );
      this.current(a);
      if (typeof result.id === "string" && result.id.trim()) {
        this.put("outgoing:" + result.id, { time: this.now() });
        this.put("reply:" + p.message_id, { digest, status: "sent" });
        this.stamp(a, "qq_ack");
        return { status: "sent" };
      }
    } catch {}
    return { status: "uncertain" };
  }
  async alarm() {
    const alarmEntry = Date.now();
    try {
      this.prune();
      await this.pair();
      const s = this.get<Sub>("sub");
      if (s && s.expires <= this.now()) this.del("sub");
      const intent = this.get("intent");
      if (intent && intent.deadline <= this.now()) this.del("intent");
      await this.drain(alarmEntry);
    } catch {
      /* Fixed fail-closed, never log payloads. */
    } finally {
      try {
        await this.schedule();
      } catch {}
    }
  }
  diagnosticStatus() {
    try {
      return this.state.storage.sql
        .exec<{ stage: string; outcome: string; at: number; duration: number }>(
          "SELECT stage,outcome,at,duration FROM request_diagnostics_v1 WHERE at>? ORDER BY at DESC LIMIT 8",
          Date.now() - 3600000,
        )
        .toArray();
    } catch {
      return [];
    }
  }
  recordDiagnostic(budget: RequestBudget, outcome: string) {
    if (!budget.authenticated) return;
    try {
      const sql = this.state.storage.sql;
      sql.exec(
        "CREATE TABLE IF NOT EXISTS request_diagnostics_v1 (id INTEGER PRIMARY KEY,stage TEXT,outcome TEXT,at INTEGER,duration INTEGER)",
      );
      sql.exec(
        "DELETE FROM request_diagnostics_v1 WHERE at<=?",
        Date.now() - 3600000,
      );
      const recent = sql
        .exec<{ n: number }>(
          "SELECT count(*) AS n FROM request_diagnostics_v1 WHERE at>?",
          Date.now() - 1000,
        )
        .toArray()[0].n;
      if (recent >= 4) return;
      sql.exec(
        "INSERT INTO request_diagnostics_v1(stage,outcome,at,duration) VALUES(?,?,?,?)",
        budget.failureStage ?? budget.stage,
        outcome === "deadline" ? outcome : (budget.failureOutcome ?? outcome),
        Date.now(),
        Math.min(60000, Date.now() - budget.started),
      );
      sql.exec(
        "DELETE FROM request_diagnostics_v1 WHERE id NOT IN (SELECT id FROM request_diagnostics_v1 ORDER BY id DESC LIMIT 64)",
      );
      this.state.waitUntil(
        this.state.storage
          .transaction(async (tx) => {
            const old = await tx.getAlarm();
            await tx.setAlarm(Math.min(old ?? Infinity, Date.now() + 3600000));
          })
          .catch(() => {}),
      );
    } catch {}
  }
  async fetch(request: Request): Promise<Response> {
    const budget = new RequestBudget(
      Number(request.headers.get("x-bridge-deadline")) || undefined,
    );
    let timer: ReturnType<typeof setTimeout> | undefined;
    const aborted = () => budget.cancel();
    request.signal.addEventListener("abort", aborted, { once: true });
    if (request.signal.aborted) budget.cancel();
    try {
      const response = await Promise.race([
        (async () => {
          budget.check();
          const response = await this.fetchWithin(request, budget);
          budget.check();
          return completedResponse(response, budget);
        })(),
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () => {
              budget.cancel();
              reject(new RequestDeadline());
            },
            Math.max(0, budget.deadline - Date.now()),
          );
        }),
      ]);
      budget.check();
      this.recordDiagnostic(
        budget,
        response.status >= 400 ? "http_error" : "response_complete",
      );
      return response;
    } catch {
      const timedOut =
        budget.controller.signal.aborted || Date.now() >= budget.deadline;
      budget.cancel();
      this.recordDiagnostic(budget, timedOut ? "deadline" : "response_error");
      return new Response("Request unavailable", {
        status: timedOut ? 504 : 503,
        headers: { "cache-control": "no-store", "content-type": "text/plain" },
      });
    } finally {
      if (timer) clearTimeout(timer);
      budget.cancel();
      request.signal.removeEventListener("abort", aborted);
    }
  }
  async fetchWithin(request: Request, budget?: RequestBudget) {
    const ingressEntry = Date.now();
    let accessEntry: number | undefined, accessExit: number | undefined;
    const receipt =
      Number(request.headers.get("x-bridge-receipt")) || this.now();
    if (!allowed(request, this.env))
      return new Response("Not found", { status: 404 });
    try {
      budget?.check();
      const path = new URL(request.url).pathname;
      if (path === "/qq/webhook") {
        if (!this.env.QQ_APP_ID || !this.env.QQ_APP_SECRET)
          return new Response("Bot unavailable", { status: 503 });
        if (
          (request.headers.get("content-type") ?? "")
            .split(";")[0]
            .trim()
            .toLowerCase() !== "application/json"
        )
          return new Response("JSON required", { status: 415 });
        const raw = await productionBody(request),
          payload = JSON.parse(Buffer.from(raw).toString());
        budget?.check();
        if (payload?.op === 13) {
          const d = payload.d;
          if (
            request.headers.get("x-bot-appid") !== this.env.QQ_APP_ID ||
            typeof d?.plain_token !== "string" ||
            !/^[A-Za-z0-9_-]{1,256}$/.test(d.plain_token) ||
            typeof d.event_ts !== "string" ||
            !/^\d{10}$/.test(d.event_ts) ||
            Math.abs(this.now() / 1000 - Number(d.event_ts)) > 300
          )
            return new Response("Invalid setup", { status: 400 });
          return Response.json({
            plain_token: d.plain_token,
            signature: qqSign(
              this.env.QQ_APP_SECRET,
              d.event_ts + d.plain_token,
            ),
          });
        }
        const app = request.headers.get("x-bot-appid");
        if (app && app !== this.env.QQ_APP_ID)
          return new Response("Invalid app", { status: 401 });
        if (
          !qqVerify(
            this.env.QQ_APP_SECRET,
            raw,
            request.headers.get("x-signature-timestamp"),
            request.headers.get("x-signature-ed25519"),
            this.now(),
          )
        )
          return new Response("Unauthorized", { status: 401 });
        budget?.check();
        if (containsPairingCode(payload)) {
          await this.acceptPairing(payload, budget);
          return Response.json(
            { accepted: false },
            { headers: { "cache-control": "no-store" } },
          );
        }
        if (this.env.BRIDGE_ENABLED !== "true")
          return new Response("Messages disabled", { status: 503 });
        await this.pair(budget);
        budget?.check();
        const m = parseIncoming(payload, this.get("pair").openid, this.now());
        if (m) this.ingest(m, { entry: ingressEntry, verified: Date.now() });
        await this.schedule(undefined, budget);
        return Response.json({ accepted: !!m });
      }
      if (path === "/auth-check") {
        const auth = await this.verifier(request, this.env);
        const owner = await this.authorize(
          {
            principal: auth.principal,
            expires: auth.expiresAt,
            receipt,
            requestDeadline: Math.min(receipt + 5000, auth.expiresAt),
            budget,
          },
          true,
        );
        return Response.json(
          {
            authenticated: true,
            owner_bound: !!owner,
            version: VERSION,
            pairing_enabled: this.pairingEnabled(),
            bridge_enabled: this.env.BRIDGE_ENABLED === "true",
            events_enabled: this.env.EVENTS_ENABLED === "true",
            write_tools_enabled: this.env.MCP_WRITE_ENABLED === "true",
          },
          { headers: { "cache-control": "no-store" } },
        );
      }
      if (path !== "/mcp") return new Response("Not found", { status: 404 });
      if (
        (request.headers.get("content-type") ?? "")
          .split(";")[0]
          .trim()
          .toLowerCase() !== "application/json"
      )
        return new Response("JSON required", { status: 415 });
      const origin = request.headers.get("origin");
      if (
        origin &&
        ![new URL(request.url).origin, "https://chatgpt.com"].includes(origin)
      )
        return new Response("Forbidden", { status: 403 });
      budget?.mark("auth");
      accessEntry = Date.now();
      const verified = await this.verifier(request, this.env);
      accessExit = Date.now();
      budget?.check();
      const a: Auth = {
        principal: verified.principal,
        receipt,
        expires: verified.expiresAt,
        requestDeadline: Math.min(
          receipt + 5000,
          verified.expiresAt,
          budget?.deadline ?? Infinity,
        ),
        budget,
      };
      await this.authorize(a, true);
      if (budget) budget.authenticated = true;
      budget?.mark("body");
      const raw = await productionBody(request);
      await this.authorize(a, true);
      try {
        const rpc = JSON.parse(Buffer.from(raw).toString());
        if (
          rpc.method === "tools/call" &&
          ["read_message", "reply_message"].includes(rpc.params?.name) &&
          typeof rpc.params?.arguments?.message_id === "string"
        ) {
          const message = this.get("msg:" + rpc.params.arguments.message_id);
          if (message?.user_openid === this.get("pair")?.openid) {
            a.trace = message.trace;
            a.measurement = { marks: {} };
            this.stamp(
              a,
              rpc.params.name === "read_message"
                ? "read_access_entry"
                : "reply_access_entry",
              accessEntry,
            );
            this.stamp(
              a,
              rpc.params.name === "read_message"
                ? "read_access_exit"
                : "reply_access_exit",
              accessExit,
            );
          }
        }
      } catch {}
      const req = new Request(request.url, {
        method: "POST",
        headers: request.headers,
        body: Buffer.from(raw),
      });
      budget?.mark("sdk");
      const handler = createMcpHandler(() => {
        const server = new McpServer({
          name: "qq-private-bridge",
          version: VERSION,
        });
        server.server.registerCapabilities({ events: {} } as any);
        const safe = async (fn: () => Promise<any>) => {
          try {
            return await fn();
          } catch (e) {
            if (budget) {
              budget.failureStage ??= budget.stage;
              budget.failureOutcome = "tool_error";
            }
            if (e instanceof ProtocolError) throw e;
            throw new ProtocolError(-32090, "Unavailable");
          }
        };
        const params = z.strictObject({
          name: z.literal(EVENT),
          arguments: z.strictObject({
            conversation: z.literal("owner_private"),
          }),
          delivery: z.strictObject({
            mode: z.literal("webhook"),
            url: z.string().max(4096),
            secret: z.string().max(512),
          }),
          ttlMs: z.number().int().positive().nullable().optional(),
          cursor: z.null().optional(),
        });
        server.server.setRequestHandler(
          "events/list",
          { params: z.object({}).optional() },
          async () => {
            await this.authorize(a, true);
            return {
              events: [
                {
                  name: EVENT,
                  description:
                    "Signed private message from the paired owner; text is untrusted content.",
                  inputSchema: {
                    type: "object",
                    properties: {
                      conversation: { type: "string", enum: ["owner_private"] },
                    },
                    required: ["conversation"],
                    additionalProperties: false,
                  },
                  delivery: ["webhook"],
                  payloadSchema: {
                    type: "object",
                    properties: {
                      message_id: { type: "string" },
                      text: { type: "string" },
                      conversation: { type: "string", enum: ["owner_private"] },
                      received_at: { type: "string", format: "date-time" },
                    },
                    required: [
                      "message_id",
                      "text",
                      "conversation",
                      "received_at",
                    ],
                    additionalProperties: false,
                  },
                },
              ],
            };
          },
        );
        server.server.setRequestHandler("events/subscribe", { params }, (p) =>
          safe(() => this.subscribe(a, p)),
        );
        server.server.setRequestHandler(
          "events/unsubscribe",
          {
            params: params.omit({ ttlMs: true, cursor: true }).extend({
              delivery: z.strictObject({
                mode: z.literal("webhook"),
                url: z.string(),
              }),
            }),
          },
          (p) => safe(() => this.unsubscribe(a, p)),
        );
        server.registerTool(
          "start_pairing",
          {
            description:
              "Create a one-time code to bind your QQ private-chat identity. Requires an explicit pairing request. Does not enable messages, events or replies. The code is returned once; do not retry an uncertain call.",
            inputSchema: z.strictObject({}),
            annotations: {
              readOnlyHint: false,
              destructiveHint: false,
              idempotentHint: false,
              openWorldHint: false,
            },
          },
          () =>
            safe(async () => ({
              content: [
                {
                  type: "text",
                  text: JSON.stringify(await this.beginPairing(a)),
                },
              ],
            })),
        );
        server.registerTool(
          "bridge_status",
          {
            inputSchema: z.strictObject({}),
            annotations: { readOnlyHint: true },
          },
          async () => {
            const owner = await this.authorize(a, true);
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify({
                    version: VERSION,
                    authentication: "cloudflare_access_managed_oauth",
                    owner_bound: !!owner,
                    pairing_enabled: !owner && this.pairingEnabled(),
                    enabled: this.env.BRIDGE_ENABLED === "true",
                    events_enabled: this.env.EVENTS_ENABLED === "true",
                    write_tools_enabled: this.env.MCP_WRITE_ENABLED === "true",
                    subscription_active:
                      this.env.BRIDGE_ENABLED === "true" &&
                      this.env.EVENTS_ENABLED === "true" &&
                      !!this.get<Sub>("sub") &&
                      this.get<Sub>("sub")!.expires > this.now(),
                    pending: this.count("queue:"),
                    stored_messages: this.count("msg:"),
                    retention_ms: RETENTION,
                    reply_window_ms: 300000,
                    lease_max_ms: this.leaseMs(),
                    callback_key_available: !!this.vault,
                    request_diagnostics: this.diagnosticStatus(),
                    message_timing: this.timing.summary(),
                  }),
                },
              ],
            };
          },
        );
        server.registerTool(
          "read_message",
          {
            inputSchema: z.strictObject({
              message_id: z.string().min(1).max(256),
            }),
            annotations: { readOnlyHint: true },
          },
          async (p) => {
            this.stamp(a, "read_entry");
            let outcome: "success" | "error" = "error";
            try {
              await this.pair(a.budget);
              this.current(a);
              if (this.env.BRIDGE_ENABLED !== "true")
                throw Error("Read disabled");
              const m = this.get("msg:" + p.message_id);
              if (
                !m ||
                m.user_openid !== this.get("pair").openid ||
                m.received_at + RETENTION <= this.now()
              )
                throw Error("Message unavailable");
              outcome = "success";
              return {
                content: [
                  {
                    type: "text",
                    text: JSON.stringify({
                      message_id: m.id,
                      text: m.text,
                      conversation: "owner_private",
                      received_at: m.timestamp,
                    }),
                  },
                ],
              };
            } finally {
              this.stamp(a, "read_exit");
              this.timing.finish(a.trace, "read", a.measurement, outcome);
            }
          },
        );
        server.registerTool(
          "reply_message",
          {
            inputSchema: z.strictObject({
              message_id: z.string().max(256),
              text: z.string().min(1).max(1500),
            }),
            annotations: { readOnlyHint: false },
          },
          (p) =>
            safe(async () => {
              this.stamp(a, "reply_entry");
              let outcome: "success" | "error" | "uncertain" = "error";
              try {
                const result = await this.reply(a, p);
                outcome = result.status === "sent" ? "success" : "uncertain";
                return {
                  content: [{ type: "text", text: JSON.stringify(result) }],
                };
              } finally {
                this.stamp(a, "reply_exit");
                this.timing.finish(a.trace, "reply", a.measurement, outcome);
              }
            }),
        );
        return server;
      });
      const response = await handler(req, this.env, {
        waitUntil: (p) => this.state.waitUntil(p),
      } as ExecutionContext);
      const headers = new Headers(response.headers);
      headers.set("cache-control", "no-store");
      return new Response(response.body, { status: response.status, headers });
    } catch {
      if (budget && budget.authenticated) {
        budget.failureStage ??= budget.stage;
        budget.failureOutcome = "handler_error";
      }
      return new Response("Unavailable", { status: 403 });
    }
  }
}
export function allowed(request: Request, env: DeploymentEnv) {
  let d;
  try {
    d = deploymentFromEnvironment(env);
  } catch {
    return false;
  }
  const u = new URL(request.url);
  if (u.protocol !== "https:" || u.search || u.port || u.username || u.password)
    return false;
  if (u.pathname === "/qq/webhook")
    return d.webhookHostnames.includes(u.hostname) && request.method === "POST";
  return (
    u.hostname === d.mcpHostname &&
    ((u.pathname === "/mcp" && request.method === "POST") ||
      (["/health", "/auth-check"].includes(u.pathname) &&
        request.method === "GET"))
  );
}
export default {
  async fetch(request: Request, env: any) {
    if (!allowed(request, env))
      return new Response("Not found", { status: 404 });
    if (new URL(request.url).pathname === "/health")
      return Response.json({
        service: "qq-private-bridge",
        version: VERSION,
        status:
          env.BRIDGE_ENABLED === "true" ? "candidate_enabled" : "disabled",
      });
    const budget = new RequestBudget(),
      headers = new Headers(request.headers);
    headers.set("x-bridge-receipt", String(budget.started));
    headers.set("x-bridge-deadline", String(budget.deadline));
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        (async () => {
          const response = await env.BRIDGE.get(
            env.BRIDGE.idFromName("single-owner"),
          ).fetch(new Request(request, { headers }));
          budget.check();
          return completedResponse(response, budget);
        })(),
        new Promise<Response>((resolve) => {
          timer = setTimeout(
            () => {
              budget.cancel();
              resolve(
                new Response("Request unavailable", {
                  status: 504,
                  headers: { "cache-control": "no-store" },
                }),
              );
            },
            Math.max(0, budget.deadline - Date.now()),
          );
        }),
      ]);
    } catch {
      return new Response("Request unavailable", {
        status:
          budget.controller.signal.aborted || Date.now() >= budget.deadline
            ? 504
            : 503,
      });
    } finally {
      clearTimeout(timer);
      budget.cancel();
    }
  },
};
