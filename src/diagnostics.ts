import {
  isAccessDiagnosticReason,
  type AccessDiagnosticReason,
} from "./access.ts";

// Temporary, opt-in counters only. No request fields, token/claim values,
// identities, messages, URLs, or raw exceptions are accepted by this module.
export const DIAGNOSTICS_KEY = "temporary_auth_diagnostics";
export const DIAGNOSTICS_MAX_COUNT = 100;
export const DIAGNOSTICS_MAX_WINDOW_MS = 3_600_000;
type RecordData = {
  expiresAt: number;
  total: number;
  counts: Partial<Record<AccessDiagnosticReason, number>>;
};
type Storage = Pick<
  DurableObjectStorage,
  "get" | "put" | "delete" | "getAlarm" | "setAlarm"
>;
export function diagnosticsDeadline(
  value: string | undefined,
  now = Date.now(),
): number | undefined {
  if (!value || !/^\d{13}$/.test(value)) return;
  const deadline = Number(value);
  if (
    Number.isSafeInteger(deadline) &&
    deadline > now &&
    deadline <= now + DIAGNOSTICS_MAX_WINDOW_MS
  )
    return deadline;
}
export async function readDiagnostics(
  storage: Storage,
  setting: string | undefined,
  now = Date.now(),
): Promise<RecordData | undefined> {
  const deadline = diagnosticsDeadline(setting, now);
  const saved = await storage.get<RecordData>(DIAGNOSTICS_KEY);
  if (!deadline || (saved && saved.expiresAt !== deadline)) {
    if (saved) await storage.delete(DIAGNOSTICS_KEY);
    return;
  }
  return saved ?? { expiresAt: deadline, total: 0, counts: {} };
}
export async function recordDiagnostic(
  storage: Storage,
  setting: string | undefined,
  reason: unknown,
  now = Date.now(),
): Promise<void> {
  // Ignore unknown input rather than reflecting it in an error or stored key.
  if (!isAccessDiagnosticReason(reason) || reason === "host_not_allowed")
    return;
  const data = await readDiagnostics(storage, setting, now);
  if (!data || data.total >= DIAGNOSTICS_MAX_COUNT) return;
  data.counts[reason] = (data.counts[reason] ?? 0) + 1;
  data.total++;
  await storage.put(DIAGNOSTICS_KEY, data);
  await storage.setAlarm(
    Math.min((await storage.getAlarm()) ?? Infinity, data.expiresAt),
  );
}
