/** Deployment-owned trust anchors. Never derive these from a request or JWT. */
export interface DeploymentEnv {
  ACCESS_HOSTNAME?: string;
  ACCESS_TEAM_DOMAIN?: string;
  QQ_WEBHOOK_HOSTNAME?: string;
}
export type Deployment = Readonly<{
  mcpHostname: string;
  accessIssuer: string;
  accessJwksUrl: string;
  webhookHostnames: readonly string[];
}>;
function hostname(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length > 253 ||
    value !== value.toLowerCase() ||
    !value.includes(".") ||
    value
      .split(".")
      .some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ||
    /^\d+(?:\.\d+){3}$/.test(value)
  )
    throw Error("Deployment configuration unavailable");
  return value;
}
export function deploymentFromEnvironment(env: DeploymentEnv): Deployment {
  const mcpHostname = hostname(env.ACCESS_HOSTNAME);
  const team = hostname(env.ACCESS_TEAM_DOMAIN);
  if (
    !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/.test(team)
  ) {
    throw Error("Deployment configuration unavailable");
  }
  const webhookHostname =
    env.QQ_WEBHOOK_HOSTNAME === undefined
      ? mcpHostname
      : hostname(env.QQ_WEBHOOK_HOSTNAME);
  const accessIssuer = `https://${team}`;
  return Object.freeze({
    mcpHostname,
    accessIssuer,
    accessJwksUrl: `${accessIssuer}/cdn-cgi/access/certs`,
    webhookHostnames: Object.freeze([
      ...new Set([mcpHostname, webhookHostname]),
    ]),
  });
}
