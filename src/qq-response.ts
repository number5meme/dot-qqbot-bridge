// Response-only bounded reader. Does not authorize, choose destination or retry.
export async function boundedQqResponse(
  work: (signal: AbortSignal) => Promise<Response>,
  expires: number,
): Promise<any> {
  const controller = new AbortController(),
    deadline = Math.min(Date.now() + 5000, expires);
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined,
    timer: ReturnType<typeof setTimeout> | undefined;
  const active = () => {
    if (controller.signal.aborted || Date.now() >= deadline)
      throw Error("Response unavailable");
  };
  try {
    return await Promise.race([
      (async () => {
        active();
        const r = await work(controller.signal);
        active();
        reader = r.body?.getReader();
        if (!r.ok || r.redirected) throw Error();
        const chunks: Uint8Array[] = [];
        let size = 0;
        if (reader)
          while (true) {
            const part = await reader.read();
            active();
            if (part.done) break;
            size += part.value.length;
            if (size > 65536) throw Error();
            chunks.push(part.value);
          }
        active();
        return JSON.parse(Buffer.concat(chunks).toString());
      })(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => {
            controller.abort();
            reject(Error("Response unavailable"));
          },
          Math.max(0, deadline - Date.now()),
        );
      }),
    ]);
  } catch {
    throw Error("Response unavailable");
  } finally {
    if (timer) clearTimeout(timer);
    controller.abort();
    void reader?.cancel().catch(() => {});
  }
}
