# dot-qqbot-bridge

Connect a QQ bot's private messages to dot: receive message events, read messages, and reply through Managed OAuth MCP. It runs on Cloudflare Workers and SQLite Durable Objects, and handles only messages from the paired owner.

- Tools: `bridge_status`, `start_pairing`, `read_message`, `reply_message`.
- Events: `qq.message.created`, private messages from the paired owner only.
- Event subscribe, renew, and unsubscribe; the callback destination is limited to `https://connectors.api.openai.com`.

## Deployment prerequisites

- A Cloudflare Workers account and SQLite Durable Objects.
- A QQ bot application that supports C2C private-message events, and a Cloudflare Access application that allows only the owner's identity.
- A client/connector that supports Managed OAuth and this project's MCP event extensions. OAuth, Access policies, and connector registration must be configured separately; ordinary MCP clients do not necessarily support event subscriptions.
- **An HTTPS callback domain reachable from the China mainland network, and actually reachable by Tencent's QQ platform servers.** Configure public DNS, a valid TLS certificate, and Worker hostname routes. The template has `workers.dev` disabled; neither `workers.dev` nor a custom domain is assumed reachable from the mainland until tested.

In the QQ console, enter the full callback URL, for example `https://qq-webhook.example.com/qq/webhook`, substituting your own domain. This project accepts only POST `/qq/webhook` on HTTPS default port 443. Query parameters, a trailing slash, or any other path are rejected.

The callback path must not require an interactive Access login, captcha, or browser challenge; `/mcp` and `/auth-check` must keep their identity protection. After deployment, check DNS/TLS from a mainland network, then complete address verification through the QQ platform. A browser open, a successful GET/HEAD, or a successful `/health` check is not callback verification.

ICP filing depends on hosting region, access service, and platform configuration; it is not required for every webhook. See [Deployment network verification](docs/SETUP.md#deployment-network-verification-before-pairing) and the [official QQ event documentation](https://bot.q.qq.com/wiki/develop/api-v2/dev-prepare/interface-framework/event-emit.html).

## Quick start

Requires Node.js 24.11+ (24.x) and npm 11.x.

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run check
cp wrangler.example.jsonc wrangler.jsonc
cp .dev.vars.example .dev.vars
```

`check` runs typechecking, a local build, tests, a secret-pattern scan, and a format check. Private configuration is Git-ignored; `.dev.vars` does not become live Worker secrets automatically.

## Configuration

Fill in the following, then follow the [setup guide](docs/SETUP.md) to add the account, hostname routes, `BRIDGE` binding, and SQLite migrations for a fresh Worker:

- `ACCESS_HOSTNAME`: MCP hostname, without scheme, port, or path.
- `ACCESS_TEAM_DOMAIN`: your `<team>.cloudflareaccess.com`.
- `ACCESS_AUD`, `ACCESS_OWNER_EMAIL`: Access application audience and the sole allowed owner email (case-sensitive).
- `QQ_WEBHOOK_HOSTNAME`: optional separate callback hostname; defaults to the MCP hostname. The separate host serves only POST `/qq/webhook`.
- `QQ_APP_ID`, `QQ_APP_SECRET`: QQ bot application credentials.
- `CALLBACK_KEYRING`: callback encryption key configuration. See the [example](.dev.vars.example) and [Security and privacy boundaries](docs/SECURITY.md). Example keys are invalid; replace them before deployment.
- `PAIRING_ENABLED`, `BRIDGE_ENABLED`, `EVENTS_ENABLED`, `MCP_WRITE_ENABLED`: all default-off; only the exact string `"true"` enables a switch.

Put credentials only in private configuration or secret bindings. Existing deployments must keep their own Worker, namespace, migration history, and owner data; do not apply the fresh-install migration to them.

## First-time pairing

1. Complete QQ callback address verification. Keep the three business switches off, and enable only `PAIRING_ENABLED`.
2. Authenticate as the owner through Access, call `start_pairing` with `{}`, and receive a pairing code shown once and valid for at most 10 minutes.
3. Send the code exactly as issued in a private chat with your own QQ bot. Do not publish it or give it to anyone else; the account that holds the code can complete the binding.
4. Call `bridge_status` and confirm `owner_bound: true`. Pairing does not automatically reply to the QQ message.
5. Turn off `PAIRING_ENABLED`, enable receive, event, and reply capabilities as needed, and have the client establish an event subscription.

If issuance times out or the response is lost, check status first. If the original code was never received, wait for it to expire and start again. A bound identity cannot be rebound. Owner disappearance, change, or fingerprint mismatch blocks authority permanently; restoring the old value does not unlock it. There is no unbind or reset API. Full steps: [First-time installation and pairing](docs/SETUP.md).

## Operation and security

- Message bodies are retained for 1 hour, up to 100 messages, at most 10 received per minute. Bodies have no application-layer encryption. Callback URLs and secrets use AES-256-GCM.
- Historical events are not backfilled without an active subscription. Event and QQ reply sends are not retried automatically when the result is uncertain; events or replies may be lost.
- The reply window is 5 minutes after the source message, at most 1500 UTF-16 code units (project limits).
- The 5-second request budget cannot recall already-accepted writes or network requests, and does not guarantee end-to-end latency.
- Do not commit credentials, pairing codes, or databases. Do not deploy test wrappers that contain synthetic identities or administrative entry points.

See [Security and privacy boundaries](docs/SECURITY.md) and the [pairing security review](docs/PAIRING-REVIEW.md).

## Validation status

Local clean install, build, and 123 tests have passed, including workerd/SQLite pairing, authentication, concurrency, replay, rollback, and restart tests. **Live QQ/Managed OAuth end-to-end verification, and China-mainland reachability of a deployment domain, have not been verified.**

## License

[MIT](LICENSE). Dependencies use their own licenses.

## Related projects

- [grokbot-qqbot-bridge](https://github.com/number5meme/grokbot-qqbot-bridge): QQ to a generic HTTP webhook.
- [grokbot-wechatclaw-bridge](https://github.com/number5meme/grokbot-wechatclaw-bridge): WeChat ClawBot bridge.
- [grokbot-larkbot-bridge](https://github.com/number5meme/grokbot-larkbot-bridge): Lark bot bridge.
