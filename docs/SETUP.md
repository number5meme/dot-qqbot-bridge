# First-time installation and pairing

This version already implements first-time pairing and has real local workerd/SQLite integration tests. The sections below distinguish what the code already provides, the external services the operator must configure, and the live end-to-end verification that has not yet been completed. This work only changed the local preparation project; it did not deploy, create credentials, or send messages to QQ.

## 1. External prerequisites

You need your own Cloudflare Workers account and an environment that supports SQLite Durable Objects; an HTTPS domain you control that is reachable from the China mainland network; a QQ bot application with C2C private-message event / test-user permissions; and a Cloudflare Access application that allows only the owner's email identity. **Tencent's QQ platform servers must be able to actually reach the full webhook URL; a successful overseas probe cannot replace this verification.** Application, review, and permissions on the QQ platform are decided by the platform.

You also need a client/connector that can complete Managed OAuth and that supports this project's MCP event interface. The project does not provide an OAuth server, client registration, Access policies, or ChatGPT connector registration. An ordinary MCP connection does not guarantee support for event subscriptions. This external integration flow still has to be verified in the target account; do not treat the local code steps below as automatically completing platform configuration.

## 2. Local checks and private configuration

Run the README's `npm ci --ignore-scripts --no-audit --no-fund` and `npm run check`. Copy the example configuration into Git-ignored private files, and fill in your hostname, Access tenant/audience, QQ app ID, owner email, QQ secret, and callback encryption keyring.

`.dev.vars` is for local tooling only and does not automatically become live Worker secrets. Secret bindings for a real deployment must be configured separately by the operator through their authorized secure workflow. Do not put secrets in source code, public configuration, command history, or chat.

Keep all four switches off initially: `PAIRING_ENABLED`, `BRIDGE_ENABLED`, `EVENTS_ENABLED`, `MCP_WRITE_ENABLED`.

## 3. Fresh isolated deployment configuration

The template has no account ID, hostname routes, or migrations; the operator must fill these in. A new deployment needs the `BRIDGE` binding pointed at `BridgeStore` and a SQLite class created. For a **fresh Worker and namespace**, the corresponding Wrangler migration shape is:

```json
"migrations": [{ "tag": "v1", "new_sqlite_classes": ["BridgeStore"] }]
```

Do not apply this new-install migration to an existing production Worker. Existing installations must keep their own Worker identity, DO namespace, migration history, and owner data. This project is not a drop-in production replacement that can be applied without review.

Configure and verify hostname routes you own:

- MCP hostname: POST `/mcp`, GET `/auth-check`, GET `/health`.
- Extra QQ webhook hostname: POST `/qq/webhook` only. The MCP hostname also allows this webhook path.
- Other paths, methods, hostnames, and query parameters are rejected.

MCP/auth-check must use the correct Access identity chain. The project verifies QQ signatures on ordinary events.

On the QQ platform, configure the corresponding `/qq/webhook` URL and complete the setup challenge. The implementation accepts a constrained, fresh op13 challenge, checks the app ID, and returns the required signature; this step can be done before pairing. It does not bind an owner and does not enable ordinary messages.

### Deployment network verification (before pairing)

1. **Domain and routes must match.** Enter the full URL in the QQ console, for example `https://qq-webhook.example.com/qq/webhook`. That hostname must match `QQ_WEBHOOK_HOSTNAME` or `ACCESS_HOSTNAME`, and must already be routed to the target Worker. The current template has `workers.dev` disabled; do not fill in only the default domain without configuring a deployment entry point.
2. **Check from a China mainland network.** Check DNS resolution, an HTTPS connection on default port 443, the certificate hostname/validity/complete trust chain, and possible IPv4/IPv6 path differences. Test at least on the mainland network you will actually use; one successful overseas check or a single carrier's success does not mean every path or Tencent callback will succeed. Do not treat default `workers.dev` as a guarantee of mainland reachability; custom domains must still be tested. Cloudflare documents latency and reliability on cross-border paths; see the [China Network overview](https://developers.cloudflare.com/china-network/).
3. **Check the exact URL and authentication boundary.** This project allows only POST `/qq/webhook`, with no trailing slash or query parameters, and only HTTPS default port 443. QQ's official docs list a wider set of configurable ports than this project accepts; do not enter 8080/8443 for this project on that basis. The callback path must not redirect to an Access login, captcha, or browser challenge, and must not return a static web page in place of the protocol response. Adjust only the correct callback scope; do not turn off authentication on `/mcp` and `/auth-check`.
4. **Interpret probe results correctly.** A GET or HEAD request to `/qq/webhook` being rejected by routing is expected behavior. `/health` on the MCP hostname only checks basic service availability; it does not mean authentication or pairing succeeded. An extra QQ webhook hostname does not provide `/health`. These results cannot prove that the op13 handshake or ordinary events have succeeded.
5. **Use real QQ platform verification.** Save/verify the callback configuration on the QQ platform, confirm that the op13 request reaches the correct path, and that the platform successfully verifies `plain_token` and the signature in the response. Then, after obtaining test authorization, confirm with an owner private message that real signed events are reachable. When troubleshooting, record only necessary status codes / fixed error stages; do not disclose pairing codes, message bodies, credentials, or complete private payloads.
6. **Check the scope of filing requirements.** Do not treat "mainland reachability" as meaning every webhook must have an ICP filing. Check against the actual hosting region, access service, platform configuration, and current rules. For example, using [Cloudflare China Network](https://developers.cloudflare.com/china-network/) has its own ICP prerequisites, and QQ's official [message URL allowlist notes](https://github.com/tencent-connect/bot-docs/blob/main/docs/README.md) are a separate configuration for link domains inside messages; they cannot directly substitute for event-webhook requirements.

Protocol basis: [QQ official event subscription and notification](https://bot.q.qq.com/wiki/develop/api-v2/dev-prepare/interface-framework/event-emit.html) explicitly describes HTTPS callbacks, platform address verification, and signature checks. The exact hostname/path/method and default-port restrictions come from `allowed()` in this project's `src/worker.ts`, and are additional limits of this implementation. Network reachability must be judged by tests of the target domain against the real platform; this document does not claim that China-mainland connectivity has been verified for any deployment.

## 4. Start first-time pairing through authenticated MCP

1. Confirm the deployment is a fresh install or an empty store with no historical owner data. Do not manually delete records to fabricate an empty store.
2. The operator turns on `PAIRING_ENABLED="true"`. The other three business switches must stay off. The QQ app ID and secret must already be configured.
3. The owner authenticates through Access. `/auth-check` or `bridge_status` should show authentication and `owner_bound: false`. Unknown users, expired assertions, or a wrong issuer/audience/email cannot issue a code.
4. From a client that supports this service, explicitly call the MCP tool `start_pairing` with an empty object `{}`. It returns `code`, `expires_at`, and a usage description. The code shape is `QQPAIR-` plus 32 hexadecimal characters, valid for at most 10 minutes, and also capped by the Access assertion expiry at issuance time.
5. The issuance response sets `Cache-Control: no-store`; the server keeps only a hash of the code. Further calls during the same pending period return only `pending: true` and the expiry time; they do not redisplay or reissue the original code. Do not screen-record it, copy it publicly, or send the code to anyone else.

If the response is lost or times out, check status first. If the original code was never received, wait for the old code to expire and start again explicitly; do not blindly retry and assume the first attempt never happened. A transaction that has already committed cannot be automatically undone because the response timed out.

## 5. Complete binding in your own QQ private chat

1. The owner sends the **pairing code exactly as issued** in a private chat with their own bot. Do not send it to a group chat or have another account send it on their behalf.
2. The Worker verifies the QQ signature, freshness, and C2C format, matches the pending hash, and then in one transaction writes the owner, writes the bound identity fingerprint, and deletes pending state.
3. Confirm `owner_bound: true` through an owner-authenticated `bridge_status`. Pairing does not send an automatic QQ reply, so success cannot be judged by whether a bot reply was received.
4. Turn off `PAIRING_ENABLED`. Even if it is left on, a bound installation cannot issue a new code or rebind.

Anyone who holds the pairing code and can send a real QQ private message can complete that binding; the project cannot externally verify that the QQ account and the Access email belong to the same person. If the code leaks or an incorrect binding is discovered, immediately turn off the pairing/business switches and handle the incident manually. There is no automatic unbind, reset, seed-owner, or administrative API.

Concurrent issuance produces only one valid pending code. Concurrent consumption binds only one owner. Expired, incorrect, replayed, group, and unsigned commands cannot rebind. Content that matches the pairing-code shape is intercepted before ordinary message storage, including replays after binding; it is not forwarded as an event and does not enter body or timing records.

## 6. Enable business capabilities and live verification

When pairing succeeds, all business switches are still off. Only after the owner has explicitly agreed to the corresponding data sharing/operations may the operator enable receive, event, and reply capabilities, and have the client establish a real event subscription.

Live verification should be done in an isolated environment and should at least include: the owner sending a test message, a stranger being ignored, a read, one reply, a callback challenge, renewal, explicit cancellation, and reply blocking after the old event chain is cancelled. Do not blindly retry an `uncertain` send result.

Completing the first-time pairing code is not the same as passing live QQ/Managed OAuth verification, and it does not guarantee that event features will work on a particular client.

## Identity continuity and recovery boundaries

Access to a fresh empty store, unsigned input, or unpaired business requests will not automatically lock permanently just because "there is no owner." However, if historical business data, a legacy SQL owner, a bound fingerprint, or any malformed owner record is present, it is not treated as a fresh install.

The fingerprint for a new binding is committed in the same transaction as the owner, so later owner changes are still detected even if the process crashes before the SQL continuity snapshot is written. Deleting/changing an existing owner or a fingerprint mismatch persistently blocks authority; restoring the old value does not automatically unlock it. Legacy installations without the new fingerprint keep the original SQL owner continuity check.

Do not copy someone else's database, invent OpenIDs by hand, deploy a test wrapper, or delete security markers to bypass these limits.
