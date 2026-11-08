import { readdir, readFile, lstat } from "node:fs/promises";
import path from "node:path";
// Local, dependency-free heuristic scan. It is not a complete secret detector.
const root = process.cwd();
const skip = new Set(["node_modules", "dist", ".git", ".wrangler"]);
const findings = [];
let files = 0;
async function walk(directory) {
  for (const name of (await readdir(directory)).sort()) {
    if (skip.has(name)) continue;
    const target = path.join(directory, name);
    const relative = path.relative(root, target);
    const stat = await lstat(target);
    if (stat.isSymbolicLink()) {
      findings.push(`${relative}: unexpected symlink`);
      continue;
    }
    if (stat.isDirectory()) {
      await walk(target);
      continue;
    }
    files++;
    if (["wrangler.json", "wrangler.jsonc", "wrangler.toml"].includes(name))
      findings.push(`${relative}: private deployment configuration file`);
    if (
      /^(?:\.env|\.dev\.vars)(?:\.|$)/.test(name) &&
      !name.endsWith(".example")
    )
      findings.push(`${relative}: private configuration file`);
    if (
      /\.(?:sqlite(?:-.*)?|db(?:-.*)?|pem|key|p12|pfx|log|zip|tgz)$|\.tar\.gz$/i.test(
        name,
      )
    )
      findings.push(`${relative}: excluded artifact type`);
    if (
      ["baseline", "snapshots", "private", "secrets", "credentials"].some(
        (part) => relative.split(path.sep).includes(part),
      )
    )
      findings.push(`${relative}: excluded directory`);
    if (relative === "package-lock.json") continue; // integrity digests are intentionally high entropy
    const text = await readFile(target, "utf8");
    const checks = [
      ["private key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
      [
        "JWT literal",
        /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/,
      ],
      ["AWS access key", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
      [
        "GitHub token",
        /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b/,
      ],
      ["API key literal", /\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b/],
      ["webhook secret literal", /\bwhsec_[A-Za-z0-9+/=_-]{24,}\b/],
      ["local workspace path", /\/workspace\/(?:shared|scratch)\//],
    ];
    for (const [label, pattern] of checks)
      if (pattern.test(text)) findings.push(`${relative}: ${label}`);
    for (const match of text.matchAll(
      /[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g,
    )) {
      if (
        !/^(?:[a-z0-9-]+\.)*(?:example\.(?:com|org|net|test|invalid)|example|test|invalid)$/i.test(
          match[1],
        )
      )
        findings.push(`${relative}: non-example email address`);
    }
  }
}
await walk(root);
if (findings.length) {
  // Report file/reason only, never echo a candidate secret.
  console.error([...new Set(findings)].join("\n"));
  process.exitCode = 1;
} else
  console.log(
    `Public-source heuristic scan passed (${files} files). Manual review still required.`,
  );
