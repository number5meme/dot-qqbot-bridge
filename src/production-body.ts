export async function productionBody(
  request: Request,
  max = 65536,
): Promise<Uint8Array> {
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined,
    timer: ReturnType<typeof setTimeout> | undefined;
  let closed = false;
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    return await Promise.race([
      (async () => {
        const length = request.headers.get("content-length");
        if (length !== null && (!/^\d+$/.test(length) || Number(length) > max))
          throw Error();
        if (!request.body) return new Uint8Array();
        reader = request.body.getReader();
        while (true) {
          const part = await reader.read();
          if (closed) throw Error();
          if (part.done) break;
          size += part.value.length;
          if (size > max) throw Error();
          chunks.push(part.value);
        }
        return Buffer.concat(chunks);
      })(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          closed = true;
          void reader?.cancel().catch(() => {});
          reject(Error());
        }, 5000);
      }),
    ]);
  } catch {
    throw Error("Request body unavailable");
  } finally {
    closed = true;
    if (timer) clearTimeout(timer);
    void reader?.cancel().catch(() => {});
  }
}
