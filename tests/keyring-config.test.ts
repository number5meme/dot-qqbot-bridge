import test from "node:test";
import assert from "node:assert/strict";
import { inspect } from "node:util";
import {
  CallbackVault,
  CallbackVaultError,
  type CallbackContext,
  type CallbackPlaintext,
} from "../src/callback-vault.ts";
import {
  CallbackKeyringError,
  callbackVaultFromEnvironment,
  parseCallbackKeyring,
  validateCallbackKeyring,
} from "../src/keyring-config.ts";

// Synthetic test keys only. No real credentials, provisioning or network calls.
const KEY_OLD = Buffer.alloc(32, 0xfb).toString("base64");
const KEY_NEW = Buffer.alloc(32, 42).toString("base64");
const KEY_THIRD = Buffer.alloc(32, 43).toString("base64");
const KEY_FOURTH = Buffer.alloc(32, 44).toString("base64");
const oldEntry = { id: "key-old", status: "active", keyBase64: KEY_OLD };
const newEntry = { id: "key-new", status: "active", keyBase64: KEY_NEW };
const oldConfig = { activeKeyId: oldEntry.id, keys: [oldEntry] };
const rotation = {
  activeKeyId: newEntry.id,
  keys: [newEntry, { ...oldEntry, status: "decrypt_only" }],
};
const context: CallbackContext = {
  owner: "fixture-owner",
  grant: "fixture-grant",
  epoch: "fixture-epoch",
  sub: "fixture-sub",
  incarnation: "fixture-incarnation",
};
const plaintext: CallbackPlaintext = {
  url: "https://callback.fixture.invalid/private?token=SYNTHETIC_TOKEN",
  secret: "whsec_" + Buffer.alloc(32, 45).toString("base64"),
};
const parse = (config: unknown) => parseCallbackKeyring(JSON.stringify(config));
function rejects(fn: () => unknown): void {
  assert.throws(fn, (error) => {
    assert(error instanceof CallbackKeyringError);
    assert.equal(error.name, "CallbackKeyringError");
    assert.equal(error.message, "Callback keyring unavailable");
    assert.equal(error.cause, undefined);
    const visible = [
      String(error),
      error.stack,
      JSON.stringify(error),
      inspect(error),
    ].join("\n");
    for (const secret of [
      KEY_OLD,
      KEY_NEW,
      KEY_THIRD,
      KEY_FOURTH,
      plaintext.url,
      plaintext.secret,
    ])
      assert(!visible.includes(secret));
    return true;
  });
}

test("strict configuration yields a functioning CallbackVault and only safe immutable metadata", () => {
  const configured = parse(oldConfig);
  assert(configured.vault instanceof CallbackVault);
  assert.deepEqual(
    configured.vault.open(configured.vault.seal(plaintext, context), context),
    plaintext,
  );
  assert.deepEqual(Object.keys(configured).sort(), ["summary", "vault"]);
  assert.deepEqual(Object.keys(configured.summary).sort(), [
    "activeKeyId",
    "keys",
  ]);
  assert.equal(configured.summary.activeKeyId, "key-old");
  assert.deepEqual(Object.keys(configured.summary.keys[0]).sort(), [
    "fingerprint",
    "id",
    "status",
  ]);
  assert.match(configured.summary.keys[0].fingerprint, /^sha256:[a-f0-9]{64}$/);
  assert.equal(configured.summary.keys[0].status, "active");
  assert(Object.isFrozen(configured));
  assert(Object.isFrozen(configured.summary));
  assert(Object.isFrozen(configured.summary.keys));
  assert(Object.isFrozen(configured.summary.keys[0]));
  const visible = [
    JSON.stringify(configured),
    inspect(configured),
    inspect(configured, { showHidden: true }),
  ].join("\n");
  for (const secret of [KEY_OLD, plaintext.url, plaintext.secret])
    assert(!visible.includes(secret));
  assert.equal(JSON.stringify(configured.vault), "{}");
});

test("rotation reads old ciphertext while sealing only with the active new key", () => {
  const oldVault = parse(oldConfig).vault;
  const oldRecord = oldVault.seal(plaintext, context);
  const rotated = parse(rotation);
  assert.deepEqual(rotated.vault.open(oldRecord, context), plaintext);
  for (let i = 0; i < 10; i++) {
    const newRecord = rotated.vault.seal(plaintext, context);
    assert.equal(newRecord.keyId, newEntry.id);
    assert.deepEqual(rotated.vault.open(newRecord, context), plaintext);
    assert.throws(() => oldVault.open(newRecord, context), CallbackVaultError);
  }
  assert.deepEqual(
    rotated.summary.keys.map((key) => [key.id, key.status]),
    [
      ["key-new", "active"],
      ["key-old", "decrypt_only"],
    ],
  );
});

test("removed or changed keys fail closed without trying other keys or plaintext", () => {
  const oldRecord = parse(oldConfig).vault.seal(plaintext, context);
  const both = parse(rotation).vault;
  const newRecord = both.seal(plaintext, context);
  const retired = parse({ activeKeyId: newEntry.id, keys: [newEntry] }).vault;
  assert.deepEqual(retired.open(newRecord, context), plaintext);
  assert.throws(() => retired.open(oldRecord, context), CallbackVaultError);
  assert.throws(
    () => retired.open({ ...oldRecord, keyId: newEntry.id }, context),
    CallbackVaultError,
  );
  const changed = parse({
    activeKeyId: oldEntry.id,
    keys: [{ ...oldEntry, keyBase64: KEY_NEW }],
  }).vault;
  assert.throws(() => changed.open(oldRecord, context), CallbackVaultError);
  assert.throws(
    () => retired.open(plaintext as never, context),
    CallbackVaultError,
  );
  rejects(() =>
    parse({
      ...rotation,
      keys: [newEntry, { ...oldEntry, status: "retired" }],
    }),
  );
});

test("accepts one to three unique keys and fingerprints compare independent of order or status", () => {
  const three = {
    ...rotation,
    keys: [
      ...rotation.keys,
      { id: "key-third", status: "decrypt_only", keyBase64: KEY_THIRD },
    ],
  };
  const summary = validateCallbackKeyring(JSON.stringify(three));
  assert.equal(summary.keys.length, 3);
  assert.equal(new Set(summary.keys.map((key) => key.fingerprint)).size, 3);
  assert.deepEqual(
    validateCallbackKeyring(
      JSON.stringify({ ...three, keys: [...three.keys].reverse() }),
    ),
    summary,
  );
  assert.equal(
    summary.keys.find((key) => key.id === oldEntry.id)?.fingerprint,
    parse(oldConfig).summary.keys[0].fingerprint,
  );
  const aliased = validateCallbackKeyring(
    JSON.stringify({
      activeKeyId: "different-id",
      keys: [{ ...oldEntry, id: "different-id" }],
    }),
  );
  assert.equal(
    aliased.keys[0].fingerprint,
    parse(oldConfig).summary.keys[0].fingerprint,
  );
  rejects(() =>
    parse({
      ...three,
      keys: [
        ...three.keys,
        { id: "key-fourth", status: "decrypt_only", keyBase64: KEY_FOURTH },
      ],
    }),
  );
});

test("requires a JSON string with only the exact top-level and entry fields", () => {
  for (const raw of [
    undefined,
    null,
    false,
    1,
    {},
    oldConfig,
    "",
    " ",
    "{",
    "[",
    "null",
    "true",
    "[]",
    '"plaintext"',
    JSON.stringify({ ...oldConfig, note: plaintext.secret }),
    " ".repeat(8193),
  ])
    rejects(() => parseCallbackKeyring(raw));
  const invalid = [
    {},
    { keys: [oldEntry] },
    { activeKeyId: oldEntry.id },
    { ...oldConfig, keys: null },
    { ...oldConfig, keys: {} },
    { ...oldConfig, keys: [] },
    { ...oldConfig, extra: true },
    { ...oldConfig, plaintextFallback: true },
  ];
  for (const candidate of invalid) rejects(() => parse(candidate));
  for (const candidate of [
    null,
    [],
    {},
    { id: oldEntry.id, status: "active" },
    { id: oldEntry.id, keyBase64: KEY_OLD },
    { status: "active", keyBase64: KEY_OLD },
    { ...oldEntry, extra: true },
    { ...oldEntry, key: KEY_OLD },
  ])
    rejects(() => parse({ ...oldConfig, keys: [candidate] }));
});

test("rejects ambiguous duplicate JSON members including escaped names", () => {
  const oldJson = JSON.stringify(oldConfig);
  for (const raw of [
    oldJson.replace('"activeKeyId":', '"activeKeyId":"ignored","activeKeyId":'),
    oldJson.replace(
      '"activeKeyId":',
      '"active\\u004beyId":"ignored","activeKeyId":',
    ),
    oldJson.replace('"keys":', '"keys":[],"keys":'),
    oldJson.replace('"id":', '"id":"ignored","id":'),
    oldJson.replace('"status":', '"status":"decrypt_only","status":'),
    oldJson.replace('"keyBase64":', '"keyBase64":"ignored","keyBase64":'),
    oldJson.replace('"keyBase64":', '"key\\u0042ase64":"ignored","keyBase64":'),
  ])
    rejects(() => parseCallbackKeyring(raw));
  // JSON whitespace and escaped member names remain valid when unambiguous.
  const escaped = oldJson.replace('"activeKeyId":', '"active\\u004beyId" \n :');
  assert.deepEqual(
    validateCallbackKeyring(escaped),
    validateCallbackKeyring(oldJson),
  );
});

test("requires exactly one active key matching activeKeyId and rejects duplicate IDs or material", () => {
  for (const candidate of [
    { ...oldConfig, activeKeyId: "missing" },
    { ...oldConfig, keys: [{ ...oldEntry, status: "decrypt_only" }] },
    { ...rotation, keys: [newEntry, oldEntry] },
    { ...rotation, activeKeyId: oldEntry.id },
    {
      ...rotation,
      keys: [
        newEntry,
        { ...oldEntry, id: newEntry.id, status: "decrypt_only" },
      ],
    },
    {
      ...rotation,
      keys: [
        newEntry,
        { ...oldEntry, keyBase64: KEY_NEW, status: "decrypt_only" },
      ],
    },
    { ...oldConfig, keys: [oldEntry, oldEntry] },
  ])
    rejects(() => parse(candidate));
  for (const status of ["retired", "ACTIVE", "active ", "", null, 1, true])
    rejects(() => parse({ ...oldConfig, keys: [{ ...oldEntry, status }] }));
  for (const id of [
    "",
    " bad",
    "bad id",
    "bad/id",
    "__proto__",
    "a".repeat(129),
    "秘密",
    null,
    1,
  ]) {
    rejects(() => parse({ ...oldConfig, activeKeyId: id }));
    rejects(() =>
      parse({ ...oldConfig, activeKeyId: id, keys: [{ ...oldEntry, id }] }),
    );
    rejects(() =>
      parse({
        ...oldConfig,
        keys: [oldEntry, { id, status: "decrypt_only", keyBase64: KEY_NEW }],
      }),
    );
  }
});

test("only canonical padded standard base64 encoding of exactly 32 bytes is accepted", () => {
  const noncanonicalPadBits = KEY_OLD.slice(0, -2) + "t=";
  assert.deepEqual(
    Buffer.from(noncanonicalPadBits, "base64"),
    Buffer.from(KEY_OLD, "base64"),
  );
  for (const keyBase64 of [
    null,
    1,
    {},
    "",
    "plaintext",
    KEY_OLD.slice(0, -1),
    KEY_OLD + "=",
    "\n" + KEY_OLD,
    KEY_OLD + "\n",
    KEY_OLD.slice(0, 10) + " " + KEY_OLD.slice(10),
    Buffer.from(KEY_OLD, "base64").toString("base64url"),
    KEY_OLD.replaceAll("+", "-").replaceAll("/", "_"),
    noncanonicalPadBits,
    Buffer.alloc(31).toString("base64"),
    Buffer.alloc(33).toString("base64"),
    "A".repeat(9000),
  ])
    rejects(() => parse({ ...oldConfig, keys: [{ ...oldEntry, keyBase64 }] }));
});

test("environment activation requires its own valid binding even when every ordinary switch is off", () => {
  const off = {
    BRIDGE_ENABLED: "false",
    EVENTS_ENABLED: "false",
    MCP_WRITE_ENABLED: "false",
  };
  for (const env of [
    {},
    off,
    { ...off, CALLBACK_KEYRING: undefined },
    { ...off, CALLBACK_KEYRING: "" },
    { ...off, CALLBACK_KEYRING: "{}" },
    { ...off, CALLBACK_KEY: KEY_OLD },
    { ...off, CALLBACK_PLAINTEXT: "true" },
    null,
    undefined,
  ])
    rejects(() => callbackVaultFromEnvironment(env as never));
  const valid = { ...off, CALLBACK_KEYRING: JSON.stringify(rotation) };
  const vault = callbackVaultFromEnvironment(valid);
  assert.equal(vault.seal(plaintext, context).keyId, newEntry.id);
  valid.CALLBACK_KEYRING = "";
  assert.equal(vault.seal(plaintext, context).keyId, newEntry.id);
  rejects(() =>
    callbackVaultFromEnvironment(
      Object.create({ CALLBACK_KEYRING: JSON.stringify(oldConfig) }),
    ),
  );
  let accessed = false;
  const getter = {
    get CALLBACK_KEYRING() {
      accessed = true;
      return JSON.stringify(oldConfig);
    },
  };
  rejects(() => callbackVaultFromEnvironment(getter));
  assert.equal(accessed, false);
});

test("parser and validation errors never expose malformed input or a nested error", () => {
  for (const raw of [
    KEY_OLD,
    '{"leaked-secret":"' + plaintext.secret,
    '{"leaked-url":"' + plaintext.url,
    JSON.stringify({ activeKeyId: plaintext.secret, keys: [oldEntry] }),
    JSON.stringify({
      ...oldConfig,
      keys: [{ ...oldEntry, keyBase64: plaintext.secret }],
    }),
  ]) {
    rejects(() => parseCallbackKeyring(raw));
    rejects(() => validateCallbackKeyring(raw));
    rejects(() => callbackVaultFromEnvironment({ CALLBACK_KEYRING: raw }));
  }
  let stringified = false;
  rejects(() =>
    parseCallbackKeyring({
      toString() {
        stringified = true;
        return JSON.stringify(oldConfig);
      },
    }),
  );
  assert.equal(stringified, false);
});
