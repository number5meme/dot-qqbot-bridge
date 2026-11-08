// Offline compiler only. No CLI upload, credentials, telemetry or network APIs.
require("esbuild").buildSync({
  entryPoints: ["src/worker.ts"],
  outfile: "dist/worker.js",
  bundle: true,
  minify: true,
  format: "esm",
  platform: "neutral",
  mainFields: ["browser", "module", "main"],
  target: "es2022",
  external: ["node:*", "cloudflare:*"],
  conditions: ["workerd", "worker", "browser"],
});
