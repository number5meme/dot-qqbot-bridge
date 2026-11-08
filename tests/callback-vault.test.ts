import test from "node:test";
import assert from "node:assert/strict";
import { createCipheriv } from "node:crypto";
import {
  CallbackVault,
  CallbackVaultError,
  type CallbackContext,
  type CallbackPlaintext,
  type CallbackVaultOptions,
  type SealedCallback,
} from "../src/callback-vault.ts";

// All material in this suite is synthetic and local. No remote service is contacted.
const KEY_OLD = Buffer.alloc(32, 41);
const KEY_NEW = Buffer.alloc(32, 42);
const context: CallbackContext = {
  owner: "fixture-owner",
  grant: "fixture-grant",
  epoch: "fixture-epoch",
  sub: "fixture-sub",
  incarnation: "fixture-incarnation",
};
const value: CallbackPlaintext = {
  url: "https://callback.fixture.invalid/private-callback?token=SYNTHETIC_CALLBACK_TOKEN",
  secret: "whsec_" + Buffer.alloc(32, 43).toString("base64"),
};
const rotated: CallbackPlaintext = {
  ...value,
  oldSecret: "whsec_" + Buffer.alloc(32, 44).toString("base64"),
  rotatedAt: 1_700_000_000_000,
};
const vault = (
  keys: CallbackVaultOptions["keys"] = new Map([["old", KEY_OLD]]),
  currentKeyId = "old",
) => new CallbackVault({ currentKeyId, keys });
const rejects = (fn: () => unknown) =>
  assert.throws(fn, (error) => {
    assert(error instanceof CallbackVaultError);
    assert.equal(error.message, "Callback vault unavailable");
    assert.equal(error.cause, undefined);
    assert(!String(error).includes(value.url));
    assert(!String(error).includes(value.secret));
    return true;
  });
const mutateBytes = (encoded: string): string => {
  const bytes = Buffer.from(encoded, "base64url");
  bytes[0] ^= 1;
  return bytes.toString("base64url");
};

test("round-trips synchronously through JSON-only database storage with no known plaintext", () => {
  const instance = vault();
  for (const plaintext of [value, rotated]) {
    const sealed = instance.seal(plaintext, context);
    assert(!(sealed instanceof Promise));
    assert.deepEqual(Object.keys(sealed).sort(), [
      "ciphertext",
      "keyId",
      "nonce",
      "tag",
      "version",
    ]);
    const serialized = JSON.stringify(sealed);
    for (const secret of [
      value.url,
      value.secret,
      rotated.oldSecret!,
      "SYNTHETIC_CALLBACK_TOKEN",
    ])
      assert(!serialized.includes(secret));
    const stored = JSON.parse(serialized);
    assert.equal(stored.version, 1);
    assert.equal(stored.keyId, "old");
    assert.equal(Buffer.from(stored.nonce, "base64url").length, 12);
    assert.equal(Buffer.from(stored.tag, "base64url").length, 16);
    assert.deepEqual(instance.open(stored, context), plaintext);
    assert.deepEqual(vault().open(stored, context), plaintext);
  }
  assert.equal(JSON.stringify(instance), "{}");
});

test("each seal gets a fresh nonce and distinct ciphertext for identical input", () => {
  const instance = vault();
  const records = Array.from({ length: 100 }, () =>
    instance.seal(value, context),
  );
  assert.equal(new Set(records.map((r) => r.nonce)).size, records.length);
  assert.equal(new Set(records.map((r) => r.ciphertext)).size, records.length);
  for (const record of records)
    assert.deepEqual(instance.open(record, context), value);
});

for (const field of [
  "owner",
  "grant",
  "epoch",
  "sub",
  "incarnation",
] as const) {
  test(`AAD prevents moving ciphertext to a different ${field}`, () => {
    const instance = vault();
    rejects(() =>
      instance.open(instance.seal(value, context), {
        ...context,
        [field]: context[field] + "-other",
      }),
    );
  });
}

test("context canonicalization is independent of object order and keeps exact Unicode identities", () => {
  const instance = vault();
  const complex = {
    owner: "界|a",
    grant: 'b:\"c',
    epoch: "restore|2",
    sub: "x\u0000y",
    incarnation: "é",
  };
  const sealed = instance.seal(value, complex);
  assert.deepEqual(
    instance.open(sealed, {
      incarnation: complex.incarnation,
      sub: complex.sub,
      epoch: complex.epoch,
      grant: complex.grant,
      owner: complex.owner,
    }),
    value,
  );
  rejects(() =>
    instance.open(sealed, { ...complex, owner: "界", grant: '|ab:\"c' }),
  );
  rejects(() => instance.open(sealed, { ...complex, incarnation: "e\u0301" }));
});

test("key rotation seals with the current key and keeps old ciphertext readable only while old key exists", () => {
  const oldRecord = vault().seal(value, context);
  const both = vault(
    new Map([
      ["old", KEY_OLD],
      ["new", KEY_NEW],
    ]),
    "new",
  );
  assert.deepEqual(both.open(oldRecord, context), value);
  const newRecord = both.seal(rotated, context);
  assert.equal(newRecord.keyId, "new");
  assert.deepEqual(both.open(newRecord, context), rotated);
  rejects(() => vault().open(newRecord, context));
  const onlyNew = vault({ new: KEY_NEW }, "new");
  assert.deepEqual(onlyNew.open(newRecord, context), rotated);
  rejects(() => onlyNew.open(oldRecord, context));
});

test("missing keys, wrong key bytes, and tampered key aliases fail without fallback", () => {
  const record = vault().seal(value, context);
  rejects(() => vault({ old: KEY_NEW }).open(record, context));
  rejects(() => vault({ new: KEY_NEW }, "new").open(record, context));
  rejects(() =>
    vault({ old: KEY_OLD, alias: KEY_OLD }).open(
      { ...record, keyId: "alias" },
      context,
    ),
  );
  rejects(() =>
    vault({ old: KEY_OLD }).open({ ...record, keyId: "missing" }, context),
  );
});

test("constructor requires an explicit valid current key and 32-byte Buffer key entries", () => {
  for (const options of [
    null,
    {},
    { currentKeyId: "old", keys: {} },
    { currentKeyId: "missing", keys: { old: KEY_OLD } },
    { currentKeyId: "", keys: { old: KEY_OLD } },
    { currentKeyId: "bad id", keys: { "bad id": KEY_OLD } },
    { currentKeyId: "old", keys: { old: Buffer.alloc(31) } },
    { currentKeyId: "old", keys: { old: Buffer.alloc(33) } },
    { currentKeyId: "old", keys: { old: new Uint8Array(32) } },
    { currentKeyId: "old", keys: { old: KEY_OLD.toString("base64") } },
    { currentKeyId: "old", keys: { old: KEY_OLD, other: Buffer.alloc(1) } },
    { currentKeyId: "old", keys: undefined },
    { currentKeyId: "old", keys: { old: KEY_OLD }, extra: "not accepted" },
  ])
    rejects(() => new CallbackVault(options as CallbackVaultOptions));
});

test("constructor isolates the keyring from later caller mutation", () => {
  const bytes = Buffer.from(KEY_OLD);
  const keys = new Map([["old", bytes]]);
  const instance = vault(keys);
  const record = instance.seal(value, context);
  bytes.fill(0);
  keys.clear();
  assert.deepEqual(instance.open(record, context), value);
  assert.deepEqual(vault().open(instance.seal(value, context), context), value);
  const objectBytes = Buffer.from(KEY_OLD);
  const objectKeys = { old: objectBytes };
  const objectInstance = vault(objectKeys);
  objectKeys.old = KEY_NEW;
  objectBytes.fill(0);
  assert.deepEqual(
    vault().open(objectInstance.seal(value, context), context),
    value,
  );
});

for (const field of ["nonce", "ciphertext", "tag"] as const) {
  test(`tampering with ${field} fails closed`, () => {
    const instance = vault();
    const record = instance.seal(value, context);
    rejects(() =>
      instance.open(
        { ...record, [field]: mutateBytes(record[field]) },
        context,
      ),
    );
  });
}

test("malformed envelopes are rejected rather than permissively decoded", () => {
  const instance = vault();
  const record = instance.seal(value, context);
  const invalid: unknown[] = [
    null,
    [],
    {},
    JSON.stringify(record),
    { ...record, version: 2 },
    { ...record, version: "1" },
    { ...record, secret: value.secret },
  ];
  for (const field of Object.keys(record)) {
    const missing: Record<string, unknown> = { ...record };
    delete missing[field];
    invalid.push(missing, { ...record, [field]: null });
  }
  for (const field of ["nonce", "ciphertext", "tag"]) {
    for (const encoded of [
      "",
      "!",
      "a",
      "AA==",
      "AA\n",
      "AA+",
      "AA/",
      "AB",
      "A".repeat(23000),
    ])
      invalid.push({ ...record, [field]: encoded });
  }
  for (const size of [0, 11, 13])
    invalid.push({
      ...record,
      nonce: Buffer.alloc(size).toString("base64url"),
    });
  for (const size of [0, 15, 17])
    invalid.push({ ...record, tag: Buffer.alloc(size).toString("base64url") });
  for (const candidate of invalid)
    rejects(() => instance.open(candidate as SealedCallback, context));
});

test("malformed or extra context fields fail at both seal and open", () => {
  const instance = vault();
  const record = instance.seal(value, context);
  const invalid: unknown[] = [
    null,
    [],
    {},
    { ...context, extra: "not part of identity" },
  ];
  for (const field of Object.keys(context)) {
    const missing: Record<string, unknown> = { ...context };
    delete missing[field];
    invalid.push(
      missing,
      { ...context, [field]: "" },
      { ...context, [field]: 1 },
      { ...context, [field]: "a".repeat(1025) },
    );
  }
  for (const candidate of invalid) {
    rejects(() => instance.seal(value, candidate as CallbackContext));
    rejects(() => instance.open(record, candidate as CallbackContext));
  }
});

test("plaintext validation rejects invalid URLs, malformed secrets, invalid rotation times, and extra fields", () => {
  const instance = vault();
  const invalid: unknown[] = [
    null,
    [],
    {},
    { ...value, extra: true },
    { url: value.url },
    { secret: value.secret },
  ];
  for (const url of [
    "",
    1,
    "not a url",
    "http://fixture.invalid/path",
    "https://user:password@fixture.invalid/path",
    "https://fixture.invalid/path#fragment",
    " https://fixture.invalid/path",
    "https://fixture.invalid/\npath",
    "https://fixture.invalid/" + "a".repeat(8192),
  ])
    invalid.push({ ...value, url });
  for (const secret of [
    "",
    null,
    undefined,
    1,
    "plain",
    "whsec_!",
    "whsec_" + Buffer.alloc(23).toString("base64"),
    "whsec_" + Buffer.alloc(65).toString("base64"),
  ])
    invalid.push({ ...value, secret }, { ...value, oldSecret: secret });
  for (const rotatedAt of [
    null,
    undefined,
    "1",
    NaN,
    Infinity,
    -1,
    1.5,
    Number.MAX_SAFE_INTEGER + 1,
  ])
    invalid.push({ ...value, rotatedAt });
  for (const candidate of invalid)
    rejects(() => instance.seal(candidate as CallbackPlaintext, context));
  assert.deepEqual(
    instance.open(instance.seal({ ...value, rotatedAt: 0 }, context), context),
    { ...value, rotatedAt: 0 },
  );
});

test("objects with accessors, prototypes, symbols, or toJSON hooks cannot alter validated payloads", () => {
  const instance = vault();
  const record = instance.seal(value, context);
  let accessed = false;
  const getter = { ...value };
  Object.defineProperty(getter, "secret", {
    get() {
      accessed = true;
      return value.secret;
    },
    enumerable: true,
  });
  rejects(() => instance.seal(getter, context));
  assert.equal(accessed, false);
  rejects(() =>
    instance.seal(
      Object.assign(Object.create({ hidden: true }), value),
      context,
    ),
  );
  rejects(() =>
    instance.seal({ ...value, [Symbol("hidden")]: "secret" }, context),
  );
  rejects(() =>
    instance.seal(
      {
        ...value,
        toJSON() {
          return value;
        },
      } as CallbackPlaintext,
      context,
    ),
  );
  rejects(() =>
    instance.open(
      {
        ...record,
        toJSON() {
          return record;
        },
      } as SealedCallback,
      context,
    ),
  );
  const nullPrototype = Object.assign(Object.create(null), value);
  assert.deepEqual(
    instance.open(instance.seal(nullPrototype, context), context),
    value,
  );
});

// Authenticate bad plaintext deliberately to prove open validates after authentication,
// not merely that GCM rejects arbitrary corruption. This helper uses synthetic keys only.
function sealRaw(raw: Buffer): SealedCallback {
  const nonce = Buffer.alloc(12, 80);
  const cipher = createCipheriv("aes-256-gcm", KEY_OLD, nonce, {
    authTagLength: 16,
  });
  cipher.setAAD(
    Buffer.from(
      JSON.stringify({
        context: {
          epoch: context.epoch,
          grant: context.grant,
          incarnation: context.incarnation,
          owner: context.owner,
          sub: context.sub,
        },
        keyId: "old",
        purpose: "qq-dot-bridge.callback-credentials",
        version: 1,
      }),
    ),
  );
  const ciphertext = Buffer.concat([cipher.update(raw), cipher.final()]);
  return {
    version: 1,
    keyId: "old",
    nonce: nonce.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
  };
}

test("open rejects authenticated malformed JSON, invalid UTF-8, and invalid plaintext schema", () => {
  const instance = vault();
  for (const raw of [
    "not JSON",
    "null",
    "[]",
    "{}",
    JSON.stringify({ ...value, secret: "invalid" }),
    JSON.stringify({ ...value, rotatedAt: -1 }),
    JSON.stringify({ ...value, extra: value.secret }),
  ])
    rejects(() => instance.open(sealRaw(Buffer.from(raw)), context));
  const invalidUtf8 = Buffer.concat([
    Buffer.from('{"url":"https://fixture.invalid/'),
    Buffer.from([0xff]),
    Buffer.from('","secret":' + JSON.stringify(value.secret) + "}"),
  ]);
  rejects(() => instance.open(sealRaw(invalidUtf8), context));
});
