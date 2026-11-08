// Observability only: no authority, identifiers, payloads, or network data.
export const PHASES = [
  "ingress_entry",
  "ingress_verified",
  "queue_commit",
  "alarm_entry",
  "dispatch",
  "callback_ack",
  "callback_end",
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
] as const;
export type Phase = (typeof PHASES)[number];
export type Measurement = {
  marks: Partial<Record<Phase, number>>;
  token?: "cache" | "fetch";
};
const TTL = 3600000;
const INTERVALS = {
  ingress: ["ingress_entry", "ingress_verified"],
  queue: ["ingress_verified", "queue_commit"],
  alarm_wait: ["queue_commit", "alarm_entry"],
  dispatch_wait: ["alarm_entry", "dispatch"],
  callback: ["dispatch", "callback_ack"],
  observed_end_to_end: ["ingress_entry", "qq_ack"],
} as const;
type Metric = {
  samples: number;
  min_ms: number;
  max_ms: number;
  sum_ms: number;
};
function add(target: Record<string, Metric>, key: string, value: number) {
  if (!Number.isSafeInteger(value) || value < 0) return;
  const old = target[key];
  target[key] = old
    ? {
        samples: old.samples + 1,
        min_ms: Math.min(old.min_ms, value),
        max_ms: Math.max(old.max_ms, value),
        sum_ms: old.sum_ms + value,
      }
    : { samples: 1, min_ms: value, max_ms: value, sum_ms: value };
}
export class Timing {
  constructor(private sql: SqlStorage) {
    try {
      sql.exec(
        "CREATE TABLE IF NOT EXISTS message_timing_v1 (trace TEXT PRIMARY KEY, created INTEGER NOT NULL, phases TEXT NOT NULL, measurements TEXT NOT NULL)",
      );
      sql.exec(
        "CREATE INDEX IF NOT EXISTS message_timing_created ON message_timing_v1(created)",
      );
    } catch {}
  }
  prune(now = Date.now()) {
    try {
      this.sql.exec(
        "DELETE FROM message_timing_v1 WHERE created<=?",
        now - TTL,
      );
    } catch {}
  }
  create(phases: Partial<Record<Phase, number>>, created = Date.now()) {
    try {
      if (!Number.isSafeInteger(created)) return;
      const trace = crypto.randomUUID();
      this.prune();
      const clean: Partial<Record<Phase, number>> = {};
      for (const key of PHASES)
        if (Number.isSafeInteger(phases[key])) clean[key] = phases[key];
      this.sql.exec(
        "INSERT INTO message_timing_v1 VALUES(?,?,?,?)",
        trace,
        created,
        JSON.stringify(clean),
        "{}",
      );
      this.sql.exec(
        "DELETE FROM message_timing_v1 WHERE trace NOT IN (SELECT trace FROM message_timing_v1 ORDER BY created DESC,trace DESC LIMIT 100)",
      );
      return trace;
    } catch {
      return undefined;
    }
  }
  mark(trace: string | undefined, phase: Phase, at = Date.now()) {
    if (!trace || !PHASES.includes(phase) || !Number.isSafeInteger(at)) return;
    try {
      const row = this.sql
        .exec<{ phases: string; created: number }>(
          "SELECT phases,created FROM message_timing_v1 WHERE trace=?",
          trace,
        )
        .toArray()[0];
      if (!row || row.created + TTL <= Date.now()) return;
      const phases = JSON.parse(row.phases);
      if (phases[phase] !== undefined) return;
      phases[phase] = at;
      this.sql.exec(
        "UPDATE message_timing_v1 SET phases=? WHERE trace=?",
        JSON.stringify(phases),
        trace,
      );
    } catch {}
  }
  // Durations are paired within one request. Aggregate counters cannot mix retries.
  finish(
    trace: string | undefined,
    method: "read" | "reply",
    measurement: Measurement | undefined,
    outcome: "success" | "error" | "uncertain",
  ) {
    if (!trace || !measurement) return;
    try {
      const row = this.sql
        .exec<{ measurements: string; created: number }>(
          "SELECT measurements,created FROM message_timing_v1 WHERE trace=?",
          trace,
        )
        .toArray()[0];
      if (!row || row.created + TTL <= Date.now()) return;
      const metrics: Record<string, Metric> = JSON.parse(row.measurements),
        m = measurement.marks;
      const pairs: [string, Phase, Phase][] = [
        [method, (method + "_entry") as Phase, (method + "_exit") as Phase],
        [
          method + "_access",
          (method + "_access_entry") as Phase,
          (method + "_access_exit") as Phase,
        ],
      ];
      if (measurement.token)
        pairs.push(["token_" + measurement.token, "token_entry", "token_exit"]);
      pairs.push(["qq_ack", "qq_send", "qq_ack"]);
      for (const [name, start, end] of pairs)
        if (m[start] !== undefined && m[end] !== undefined)
          add(metrics, name + "_" + outcome, m[end]! - m[start]!);
      this.sql.exec(
        "UPDATE message_timing_v1 SET measurements=? WHERE trace=?",
        JSON.stringify(metrics),
        trace,
      );
    } catch {}
  }
  nextExpiry() {
    try {
      return (
        this.sql
          .exec<{ deadline: number | null }>(
            "SELECT min(created)+? AS deadline FROM message_timing_v1",
            TTL,
          )
          .toArray()[0]?.deadline ?? undefined
      );
    } catch {
      return undefined;
    }
  }
  summary() {
    try {
      const rows = this.sql
        .exec<{ phases: string; measurements: string }>(
          "SELECT phases,measurements FROM message_timing_v1 WHERE created>? ORDER BY created DESC LIMIT 100",
          Date.now() - TTL,
        )
        .toArray();
      const merged: Record<string, Metric> = {};
      for (const row of rows) {
        const p = JSON.parse(row.phases);
        for (const [name, [start, end]] of Object.entries(INTERVALS))
          if (Number.isSafeInteger(p[start]) && Number.isSafeInteger(p[end]))
            add(merged, name, p[end] - p[start]);
        for (const [key, value] of Object.entries(
          JSON.parse(row.measurements),
        ) as [string, Metric][]) {
          const old = merged[key];
          merged[key] = old
            ? {
                samples: old.samples + value.samples,
                min_ms: Math.min(old.min_ms, value.min_ms),
                max_ms: Math.max(old.max_ms, value.max_ms),
                sum_ms: old.sum_ms + value.sum_ms,
              }
            : value;
        }
      }
      const intervals = Object.fromEntries(
        Object.entries(merged).map(([key, m]) => [
          key,
          {
            samples: m.samples,
            min_ms: m.min_ms,
            max_ms: m.max_ms,
            mean_ms: Math.round(m.sum_ms / m.samples),
          },
        ]),
      );
      return { traces: rows.length, retention_ms: TTL, limit: 100, intervals };
    } catch {
      return { unavailable: true };
    }
  }
}
