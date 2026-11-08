import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { CallbackVault } from "./callback-vault.ts";

export type CallbackKeyStatus = "active" | "decrypt_only";
export type CallbackKeyringSummary = Readonly<{
  activeKeyId: string;
  keys: readonly Readonly<{
    id: string;
    status: CallbackKeyStatus;
    fingerprint: string;
  }>[];
}>;
export type ConfiguredCallbackKeyring = Readonly<{
  vault: CallbackVault;
  summary: CallbackKeyringSummary;
}>;

/** A fixed, secret-free error boundary, including for malformed JSON. */
export class CallbackKeyringError extends Error {
  constructor() {
    super("Callback keyring unavailable");
    this.name = "CallbackKeyringError";
  }
}

const MAX_CONFIG_BYTES = 8192;
const fail = (): never => {
  throw new CallbackKeyringError();
};

function fields(
  value: unknown,
  expected: readonly string[],
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return fail();
  const entries = Object.keys(value);
  if (
    entries.length !== expected.length ||
    entries.some((key) => !expected.includes(key))
  )
    return fail();
  return value as Record<string, unknown>;
}

function keyId(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(value)
  )
    return fail();
  return value;
}

/** JSON.parse accepts repeated member names; configuration must not be ambiguous.
 * Called only after JSON.parse has established valid JSON grammar. Whole strings
 * are tokens, so punctuation inside either names or values is never structural.
 */
function rejectDuplicateMembers(raw: string): void {
  const stack: (Set<string> | null)[] = [];
  const tokens = /"(?:\\.|[^"\\])*"|[{}\[\]:,]/g;
  for (let match = tokens.exec(raw); match; match = tokens.exec(raw)) {
    const token = match[0];
    if (token === "{") stack.push(new Set());
    else if (token === "[") stack.push(null);
    else if (token === "}" || token === "]") stack.pop();
    else if (token.startsWith('"')) {
      let next = tokens.lastIndex;
      while (next < raw.length && /[ \t\r\n]/.test(raw[next])) next++;
      if (raw[next] !== ":") continue;
      const object = stack[stack.length - 1];
      const name: string = JSON.parse(token);
      if (!object || object.has(name)) return fail();
      object.add(name);
    }
  }
}

/**
 * Parse the secret CALLBACK_KEYRING binding, never a file or a plaintext fallback.
 * Exactly one active key seals new records. Other supplied keys only decrypt;
 * removing a key makes its records unavailable. "retired" is not an accepted
 * status: retirement means removing the key from a separately approved config.
 *
 * This validates configuration, not operational authorization. Real provisioning,
 * activation, rotation and retirement require separately authorized operations.
 * No endpoint, environment mutation, credential generation or deployment occurs.
 * The summary is for private operational comparison, not public diagnostics.
 */
export function parseCallbackKeyring(raw: unknown): ConfiguredCallbackKeyring {
  const decoded: Buffer[] = [];
  try {
    if (
      typeof raw !== "string" ||
      !raw.length ||
      Buffer.byteLength(raw, "utf8") > MAX_CONFIG_BYTES
    )
      return fail();
    const parsed: unknown = JSON.parse(raw);
    rejectDuplicateMembers(raw);
    const config = fields(parsed, ["activeKeyId", "keys"]);
    const activeKeyId = keyId(config.activeKeyId);
    if (
      !Array.isArray(config.keys) ||
      config.keys.length < 1 ||
      config.keys.length > 3
    )
      return fail();

    const keys = new Map<string, Buffer>();
    const metadata: {
      id: string;
      status: CallbackKeyStatus;
      fingerprint: string;
    }[] = [];
    let activeCount = 0;
    for (const candidate of config.keys) {
      const entry = fields(candidate, ["id", "status", "keyBase64"]);
      const id = keyId(entry.id);
      if (
        keys.has(id) ||
        (entry.status !== "active" && entry.status !== "decrypt_only")
      )
        return fail();
      if (entry.status === "active") {
        activeCount++;
        if (id !== activeKeyId) return fail();
      }
      // Standard padded base64 only. Node's permissive decoder alone is unsafe:
      // reject whitespace, URL-safe aliases, missing padding and nonzero pad bits.
      const encoded = entry.keyBase64;
      if (typeof encoded !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(encoded))
        return fail();
      const bytes: Buffer = Buffer.from(encoded, "base64");
      decoded.push(bytes);
      if (bytes.length !== 32 || bytes.toString("base64") !== encoded)
        return fail();
      if ([...keys.values()].some((prior) => prior.equals(bytes)))
        return fail();
      keys.set(id, bytes);
      metadata.push({
        id,
        status: entry.status,
        fingerprint:
          "sha256:" +
          createHash("sha256")
            .update("qq-dot-bridge.callback-keyring.fingerprint.v1\0", "utf8")
            .update(bytes)
            .digest("hex"),
      });
    }
    if (activeCount !== 1 || !keys.has(activeKeyId)) return fail();

    // The vault copies bytes into private KeyObjects before these Buffers are wiped.
    const vault = new CallbackVault({ currentKeyId: activeKeyId, keys });
    metadata.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    const summary: CallbackKeyringSummary = Object.freeze({
      activeKeyId,
      keys: Object.freeze(metadata.map((entry) => Object.freeze(entry))),
    });
    return Object.freeze({ vault, summary });
  } catch {
    // Never attach the input, decoded keys, a cause, or parser/crypto error text.
    throw new CallbackKeyringError();
  } finally {
    for (const bytes of decoded) bytes.fill(0);
  }
}

/** Validate configuration and return only private-comparison IDs/fingerprints. */
export function validateCallbackKeyring(raw: unknown): CallbackKeyringSummary {
  return parseCallbackKeyring(raw).summary;
}

/**
 * Activation must call this even if ordinary traffic switches are currently off.
 * Switches are intentionally neither accepted nor consulted as a missing-key
 * bypass. A caller that has not activated may keep its public entry point closed.
 */
export function callbackVaultFromEnvironment(
  env: Readonly<{ CALLBACK_KEYRING?: unknown }>,
): CallbackVault {
  try {
    if (env === null || typeof env !== "object") return fail();
    const binding = Object.getOwnPropertyDescriptor(env, "CALLBACK_KEYRING");
    if (!binding || !("value" in binding)) return fail();
    return parseCallbackKeyring(binding.value).vault;
  } catch {
    throw new CallbackKeyringError();
  }
}
