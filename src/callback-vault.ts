import {
  createCipheriv,
  createDecipheriv,
  createSecretKey,
  randomBytes,
  type KeyObject,
} from "node:crypto";
import { Buffer } from "node:buffer";
import { TextDecoder } from "node:util";

/** Local-only storage primitive. Key provisioning and callback destination authorization are external. */
export type CallbackContext = Readonly<{
  owner: string;
  grant: string;
  epoch: string;
  sub: string;
  incarnation: string;
}>;

export type CallbackPlaintext = Readonly<{
  url: string;
  secret: string;
  oldSecret?: string;
  rotatedAt?: number;
}>;

export type SealedCallback = Readonly<{
  version: 1;
  keyId: string;
  nonce: string;
  ciphertext: string;
  tag: string;
}>;

export type CallbackVaultOptions = Readonly<{
  currentKeyId: string;
  keys: ReadonlyMap<string, Buffer> | Readonly<Record<string, Buffer>>;
}>;

export class CallbackVaultError extends Error {
  constructor() {
    // Neither crypto/parser errors nor any supplied values escape this boundary.
    super("Callback vault unavailable");
    this.name = "CallbackVaultError";
  }
}

const MAX_CIPHERTEXT_BYTES = 16 * 1024;
const fail = (): never => {
  throw new CallbackVaultError();
};

function objectFields(
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): Record<string, unknown> {
  if (value === null || typeof value !== "object") return fail();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return fail();
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    if (
      typeof key !== "string" ||
      (!required.includes(key) && !optional.includes(key))
    )
      return fail();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
      return fail();
    result[key] = descriptor.value;
  }
  for (const key of required) if (!Object.hasOwn(result, key)) return fail();
  return result;
}

function keyId(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(value)
  )
    return fail();
  return value;
}

function contextValue(value: unknown): CallbackContext {
  const fields = objectFields(value, [
    "owner",
    "grant",
    "epoch",
    "sub",
    "incarnation",
  ]);
  for (const part of Object.values(fields)) {
    if (
      typeof part !== "string" ||
      !part.length ||
      Buffer.byteLength(part, "utf8") > 1024
    )
      return fail();
  }
  return {
    owner: fields.owner as string,
    grant: fields.grant as string,
    epoch: fields.epoch as string,
    sub: fields.sub as string,
    incarnation: fields.incarnation as string,
  };
}

function webhookSecret(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length > 94 ||
    !/^whsec_[A-Za-z0-9+/]+={0,2}$/.test(value)
  )
    return fail();
  const bytes = Buffer.from(value.slice(6), "base64");
  try {
    if (
      bytes.length < 24 ||
      bytes.length > 64 ||
      bytes.toString("base64").replace(/=+$/, "") !==
        value.slice(6).replace(/=+$/, "")
    )
      return fail();
    return value;
  } finally {
    bytes.fill(0);
  }
}

function plaintextValue(value: unknown): CallbackPlaintext {
  const fields = objectFields(
    value,
    ["url", "secret"],
    ["oldSecret", "rotatedAt"],
  );
  const url = fields.url;
  if (
    typeof url !== "string" ||
    !url.length ||
    Buffer.byteLength(url, "utf8") > 8192 ||
    url !== url.trim() ||
    /[\u0000-\u0020\u007f]/.test(url)
  )
    return fail();
  const parsed = new URL(url);
  // This is structural validation, not an SSRF policy or a grant to send to this URL.
  if (
    parsed.protocol !== "https:" ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.hash
  )
    return fail();
  const result: {
    url: string;
    secret: string;
    oldSecret?: string;
    rotatedAt?: number;
  } = { url, secret: webhookSecret(fields.secret) };
  if (Object.hasOwn(fields, "oldSecret"))
    result.oldSecret = webhookSecret(fields.oldSecret);
  if (Object.hasOwn(fields, "rotatedAt")) {
    if (
      typeof fields.rotatedAt !== "number" ||
      !Number.isSafeInteger(fields.rotatedAt) ||
      fields.rotatedAt < 0
    )
      return fail();
    result.rotatedAt = fields.rotatedAt;
  }
  return result;
}

function aad(context: CallbackContext, id: string): Buffer {
  // Fixed, sorted JSON fields preserve exact identity, including separators and Unicode.
  // Authenticate the envelope header too, including aliases that use identical key bytes.
  return Buffer.from(
    JSON.stringify({
      context: {
        epoch: context.epoch,
        grant: context.grant,
        incarnation: context.incarnation,
        owner: context.owner,
        sub: context.sub,
      },
      keyId: id,
      purpose: "qq-dot-bridge.callback-credentials",
      version: 1,
    }),
    "utf8",
  );
}

function decode(value: unknown, maxBytes: number, exactBytes?: number): Buffer {
  if (
    typeof value !== "string" ||
    !value.length ||
    value.length > Math.ceil((maxBytes * 4) / 3) ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  )
    return fail();
  const bytes = Buffer.from(value, "base64url");
  if (
    !bytes.length ||
    bytes.length > maxBytes ||
    (exactBytes !== undefined && bytes.length !== exactBytes) ||
    bytes.toString("base64url") !== value
  )
    return fail();
  return bytes;
}

/** Synchronous AEAD operations are safe to call inside a synchronous SQL transaction. */
export class CallbackVault {
  #currentKeyId: string;
  #keys: Map<string, KeyObject>;

  constructor(options: CallbackVaultOptions) {
    try {
      const supplied = objectFields(options, ["currentKeyId", "keys"]);
      this.#currentKeyId = keyId(supplied.currentKeyId);
      this.#keys = new Map();
      const keys = supplied.keys;
      let entries: [string, unknown][];
      if (keys instanceof Map) {
        entries = [...keys.entries()];
      } else {
        if (keys === null || typeof keys !== "object") return fail();
        const fields = objectFields(keys, Object.getOwnPropertyNames(keys));
        entries = Object.entries(fields);
      }
      for (const [id, bytes] of entries) {
        keyId(id);
        if (!Buffer.isBuffer(bytes)) return fail();
        // Workers' ambient Buffer declaration is `any`; retain the checked Node type.
        const keyBytes = bytes as Buffer;
        if (keyBytes.length !== 32) return fail();
        // createSecretKey copies its input. Later mutation of the constructor's map or
        // Buffers cannot silently rotate this instance's key material.
        this.#keys.set(id, createSecretKey(keyBytes));
      }
      if (!this.#keys.has(this.#currentKeyId)) return fail();
    } catch {
      throw new CallbackVaultError();
    }
  }

  seal(value: CallbackPlaintext, context: CallbackContext): SealedCallback {
    let plaintext: Buffer | undefined;
    try {
      const checkedContext = contextValue(context);
      const encoded: Buffer = Buffer.from(
        JSON.stringify(plaintextValue(value)),
        "utf8",
      );
      plaintext = encoded;
      if (encoded.length > MAX_CIPHERTEXT_BYTES) return fail();
      const nonce = randomBytes(12);
      const key = this.#keys.get(this.#currentKeyId);
      if (!key) return fail();
      const cipher = createCipheriv("aes-256-gcm", key, nonce, {
        authTagLength: 16,
      });
      cipher.setAAD(aad(checkedContext, this.#currentKeyId));
      const ciphertext = Buffer.concat([
        cipher.update(encoded),
        cipher.final(),
      ]);
      return {
        version: 1,
        keyId: this.#currentKeyId,
        nonce: nonce.toString("base64url"),
        ciphertext: ciphertext.toString("base64url"),
        tag: cipher.getAuthTag().toString("base64url"),
      };
    } catch {
      throw new CallbackVaultError();
    } finally {
      plaintext?.fill(0);
    }
  }

  open(record: SealedCallback, context: CallbackContext): CallbackPlaintext {
    let plaintext: Buffer | undefined;
    let unauthenticated: Buffer | undefined;
    try {
      const checkedContext = contextValue(context);
      const fields = objectFields(record, [
        "version",
        "keyId",
        "nonce",
        "ciphertext",
        "tag",
      ]);
      if (fields.version !== 1) return fail();
      const id = keyId(fields.keyId);
      const key = this.#keys.get(id);
      if (!key) return fail();
      const nonce = decode(fields.nonce, 12, 12);
      const ciphertext = decode(fields.ciphertext, MAX_CIPHERTEXT_BYTES);
      const tag = decode(fields.tag, 16, 16);
      const decipher = createDecipheriv("aes-256-gcm", key, nonce, {
        authTagLength: 16,
      });
      decipher.setAAD(aad(checkedContext, id));
      decipher.setAuthTag(tag);
      unauthenticated = decipher.update(ciphertext);
      plaintext = Buffer.concat([unauthenticated, decipher.final()]);
      // Decode strictly so authenticated but malformed UTF-8 is not silently repaired.
      const decoded = new TextDecoder("utf-8", { fatal: true }).decode(
        plaintext,
      );
      return plaintextValue(JSON.parse(decoded));
    } catch {
      throw new CallbackVaultError();
    } finally {
      unauthenticated?.fill(0);
      plaintext?.fill(0);
    }
  }
}
