export class RequestDeadline extends Error {
  constructor() {
    super("Request deadline exceeded");
  }
}
export class RequestBudget {
  readonly started = Date.now();
  readonly deadline: number;
  readonly controller = new AbortController();
  stage = "entry";
  authenticated = false;
  failureStage?: string;
  failureOutcome?: "tool_error" | "handler_error";
  constructor(deadline?: number) {
    this.deadline = Number.isFinite(deadline)
      ? Math.min(this.started + 5000, deadline!)
      : this.started + 5000;
  }
  check() {
    if (this.controller.signal.aborted || Date.now() >= this.deadline)
      throw new RequestDeadline();
  }
  mark(stage: string) {
    this.check();
    this.stage = stage;
  }
  cancel() {
    this.controller.abort();
  }
}
// Buffers at most 128 KiB so the returned response (including SDK SSE error
// completion) is fully serialized within the request budget. No live SSE stream
// is handed to the client. This does not cancel arbitrary underlying promises.
export async function completedResponse(
  response: Response,
  budget: RequestBudget,
): Promise<Response> {
  budget.mark("serialize");
  const reader = response.body?.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  const cancel = () => {
    void reader?.cancel().catch(() => {});
  };
  budget.controller.signal.addEventListener("abort", cancel, { once: true });
  try {
    if (reader)
      while (true) {
        budget.check();
        const part = await reader.read();
        budget.check();
        if (part.done) break;
        size += part.value.byteLength;
        if (size > 131072) throw Error("Response unavailable");
        chunks.push(part.value);
      }
    budget.check();
    const headers = new Headers(response.headers);
    headers.delete("content-length");
    return new Response(
      response.body === null || [204, 205, 304].includes(response.status)
        ? null
        : Buffer.concat(chunks),
      { status: response.status, headers },
    );
  } finally {
    budget.controller.signal.removeEventListener("abort", cancel);
    void reader?.cancel().catch(() => {});
  }
}
// Guards entry and completion of each storage operation. An operation already
// accepted by the runtime cannot be rolled back by abort; later operations are
// prohibited. In particular helper get->delete continuations cannot write late.
export function guardedStorage<T extends object>(
  storage: T,
  budget: RequestBudget,
): T {
  return new Proxy(storage, {
    get(target, key) {
      const value = (target as any)[key];
      if (typeof value !== "function") return value;
      return (...args: any[]) => {
        budget.check();
        const result = value.apply(target, args);
        if (result && typeof result.then === "function") {
          // An open DO transaction gates HTTP responses. Reject its callback on
          // cancellation instead of leaving it waiting for an unbounded read.
          // This does not cancel storage I/O already accepted by the runtime.
          let timer: ReturnType<typeof setTimeout> | undefined;
          let aborted: (() => void) | undefined;
          const cancelled = new Promise<never>((_, reject) => {
            aborted = () => reject(new RequestDeadline());
            budget.controller.signal.addEventListener("abort", aborted, {
              once: true,
            });
            timer = setTimeout(
              () => budget.cancel(),
              Math.max(0, budget.deadline - Date.now()),
            );
            if (budget.controller.signal.aborted) aborted();
          });
          return Promise.race([
            Promise.resolve(result).then((v: any) => {
              budget.check();
              return v;
            }),
            cancelled,
          ]).finally(() => {
            if (timer) clearTimeout(timer);
            if (aborted)
              budget.controller.signal.removeEventListener("abort", aborted);
          });
        }
        budget.check();
        return result;
      };
    },
  });
}
