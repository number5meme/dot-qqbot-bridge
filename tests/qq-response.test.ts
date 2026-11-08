import test from "node:test";
import assert from "node:assert/strict";
import { boundedQqResponse } from "../src/qq-response.ts";
test("bounded response accepts success and rejects redirect/oversize/private JSON error", async () => {
  assert.deepEqual(
    await boundedQqResponse(
      async () => Response.json({ id: "test" }),
      Date.now() + 10000,
    ),
    { id: "test" },
  );
  for (const r of [
    new Response(null, { status: 302 }),
    new Response("x".repeat(65537)),
    new Response("PRIVATE"),
  ])
    await assert.rejects(
      boundedQqResponse(async () => r, Date.now() + 10000),
      /^Error: Response unavailable$/,
    );
});
test("stalled fetch/body stop at auth expiry without retry", async () => {
  let calls = 0;
  await assert.rejects(
    boundedQqResponse(async () => {
      calls++;
      return new Promise(() => {});
    }, Date.now() + 25),
    /Response unavailable/,
  );
  assert.equal(calls, 1);
  await assert.rejects(
    boundedQqResponse(
      async () =>
        new Response(
          new ReadableStream({
            pull() {
              return new Promise(() => {});
            },
          }),
        ),
      Date.now() + 25,
    ),
    /Response unavailable/,
  );
});
test("already expired authorization never invokes transport", async () => {
  let calls = 0;
  await assert.rejects(
    boundedQqResponse(async () => {
      calls++;
      return Response.json({});
    }, Date.now() - 1),
    /Response unavailable/,
  );
  assert.equal(calls, 0);
});
