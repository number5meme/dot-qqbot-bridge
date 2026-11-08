import test from "node:test";
import assert from "node:assert/strict";
import { deploymentFromEnvironment } from "../src/deployment.ts";
const config = {
  ACCESS_HOSTNAME: "qq-mcp.example.com",
  ACCESS_TEAM_DOMAIN: "example-team.cloudflareaccess.com",
};
test("deployment anchors are exact, explicit, frozen and derived only from configuration", () => {
  const d = deploymentFromEnvironment(config);
  assert.equal(d.accessIssuer, "https://example-team.cloudflareaccess.com");
  assert.equal(
    d.accessJwksUrl,
    "https://example-team.cloudflareaccess.com/cdn-cgi/access/certs",
  );
  assert.deepEqual(d.webhookHostnames, ["qq-mcp.example.com"]);
  assert(Object.isFrozen(d));
  assert(Object.isFrozen(d.webhookHostnames));
  assert.deepEqual(
    deploymentFromEnvironment({
      ...config,
      QQ_WEBHOOK_HOSTNAME: "qq-webhook.example.com",
    }).webhookHostnames,
    ["qq-mcp.example.com", "qq-webhook.example.com"],
  );
});
test("missing, noncanonical and request-shaped trust anchors fail closed", () => {
  for (const value of [
    undefined,
    "",
    "https://qq-mcp.example.com",
    "qq-mcp.example.com/path",
    "qq-mcp.example.com:443",
    "qq-mcp.example.com.",
    "QQ-MCP.example.com",
    "*.example.com",
    "x@example.com",
    "127.0.0.1",
    "localhost",
    "a".repeat(64) + ".example.com",
    "qq-mcp.example.com\n",
    "qq-mcp.example.com?x=1",
  ]) {
    assert.throws(() =>
      deploymentFromEnvironment({ ...config, ACCESS_HOSTNAME: value }),
    );
    assert.throws(() =>
      deploymentFromEnvironment({ ...config, ACCESS_TEAM_DOMAIN: value }),
    );
    if (value !== undefined)
      assert.throws(() =>
        deploymentFromEnvironment({ ...config, QQ_WEBHOOK_HOSTNAME: value }),
      );
  }
  for (const domain of [
    "cloudflareaccess.com",
    "a.b.cloudflareaccess.com",
    "evil.example.com",
    "example-team.cloudflareaccess.com.evil.example",
    "EXAMPLE.cloudflareaccess.com",
  ]) {
    assert.throws(() =>
      deploymentFromEnvironment({ ...config, ACCESS_TEAM_DOMAIN: domain }),
    );
  }
});
