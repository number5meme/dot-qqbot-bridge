import test from "node:test";
import assert from "node:assert/strict";
import {
  RequestBudget,
  completedResponse,
  guardedStorage,
} from "../src/request-budget.ts";
test("serialization pending stream is cancelled, late chunk cannot finish response", async () => {
  const budget = new RequestBudget();
  let cancelled = false;
  const response = new Response(
    new ReadableStream({
      cancel() {
        cancelled = true;
        return new Promise(() => {});
      },
    }),
    { headers: { "content-type": "text/event-stream" } },
  );
  const work = completedResponse(response, budget);
  setTimeout(() => budget.cancel(), 20);
  await assert.rejects(work);
  assert(cancelled);
});
test("bodyless status preserves null body", async () => {
  const response = await completedResponse(
    new Response(null, { status: 204 }),
    new RequestBudget(),
  );
  assert.equal(response.status, 204);
  assert.equal(response.body, null);
});
test("guarded helper storage refuses get continuation after cancelled request", async () => {
  let release: (v: any) => void = () => {},
    writes = 0;
  const budget = new RequestBudget(),
    storage = guardedStorage(
      {
        get: () =>
          new Promise((r) => {
            release = r;
          }),
        delete: () => {
          writes++;
          return Promise.resolve(true);
        },
      } as any,
      budget,
    );
  const work = (async () => {
    await storage.get("x");
    await storage.delete("x");
  })();
  budget.cancel();
  release("late");
  await assert.rejects(work);
  assert.equal(writes, 0);
});

test("guarded transaction read rejects on abort before underlying read settles", async () => {
  const budget = new RequestBudget();
  let release: (value: unknown) => void = () => {};
  let writes = 0;
  const storage = guardedStorage(
    {
      get: () =>
        new Promise((resolve) => {
          release = resolve;
        }),
      put: async () => {
        writes++;
      },
    },
    budget,
  );
  const pending = (async () => {
    await storage.get();
    await storage.put();
  })();
  const rejection = assert.rejects(pending);
  budget.cancel();
  await rejection;
  assert.equal(writes, 0);
  release("late");
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(writes, 0);
});
test("guarded transaction read enforces absolute deadline without an external fetch timer", async () => {
  const budget = new RequestBudget(Date.now() + 30);
  const storage = guardedStorage({ get: () => new Promise(() => {}) }, budget);
  await assert.rejects(storage.get());
  assert.equal(budget.controller.signal.aborted, true);
});
