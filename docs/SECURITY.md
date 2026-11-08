# Security and privacy boundaries

This is a single-owner bridge, not a public multi-user relay. Incoming QQ text is untrusted data, even when the sender is the paired owner. Receiving a message or event does not itself authorize unrelated actions by a downstream assistant.

## Trust boundaries

- Hostname and Access tenant are operator-owned environment bindings. They are syntax-checked, not obtained from token claims or request headers. JWKS uses the exact configured Cloudflare Access tenant, no redirects, bounded response sizes and timeout.
- Access requires a valid RS256 application assertion, expected issuer and audience, exact owner email, subject, and time claims. Cookies, bearer headers and plain email headers are not substitutes.
- Every tool request must also match the stored single owner. Owner disappearance or drift blocks authority persistently.
- QQ ingress uses signature verification and a narrow C2C schema. Reply destinations, original QQ message ID, and sequence are selected by the server, not arbitrary tool arguments.
- The OpenAI callback hostname is intentionally fixed. Configuring a different Access tenant does not expand callback destinations.
- `BRIDGE_ENABLED`, `EVENTS_ENABLED`, `MCP_WRITE_ENABLED` are all default-off, exact-string checks. Discovery is not permission to execute.

## Storage and transmission

- Messages and their linked QQ identifiers are stored privately for up to one hour, subject to cleanup alarms. Message bodies are not application-encrypted; cloud-provider protections and access control still matter.
- Callback URLs and secrets are context-bound AES-256-GCM ciphertext. Removing decryption keys can make outstanding subscriptions unusable. Automatic webhook-secret replacement during an active subscription is not implemented.
- Timing records use random internal traces and bounded phase/duration fields, retained at most one hour and 100 traces. They do not store text, QQ IDs, URLs or credentials. Existing message rows link to those traces.
- Callback events carry the owner's message text and message ID to the permitted OpenAI callback service. Replies send text and the stored target/message identifiers to QQ. Enabling the bridge is a data-sharing decision, not merely a local switch.
- No raw request/token logging is implemented in the project. Independently review provider logs, observability, backups and retention when deploying.

## Delivery and revocation limits

The event sender and reply sender use durable once-only claims, not exactly-once delivery. A timeout, non-success response or runtime failure can lose work. Do not automatically retry a claimed uncertain result. A request already accepted by a remote service cannot be recalled.

Subscriptions have finite local leases. They cannot prove immediate remote OAuth revocation propagation. A fresh authenticated request can authorize a reply after natural lease expiry within the message window. Explicit unsubscribe cancels the old chain. Active secret rotation and live cancellation behavior require further validation.

## Public-source hygiene

Do not commit `.dev.vars`, `.env`, real Wrangler configs, tokens, Access assertions, OpenIDs, callback URLs/secrets, pairing records, databases, snapshots, operational transcripts or logs. Generated binaries and dependency trees are excluded from source release packages.

`npm run scan` is a local heuristic check for common secret formats, non-example emails, local workspace paths, unexpected symlinks and excluded artifact types. It intentionally skips dependency trees, build output and lockfile text patterns; those require separate inspection. It is not a comprehensive security audit, dependency vulnerability scan, legal review or assurance that no secrets exist.

Before sharing a real repository, also review full Git history, remote refs, issue/PR artifacts and all release contents. This preparation directory has no imported Git history. Do not paste a possible real credential into an issue or public report. If exposure is suspected, use a private channel and rotate through the service's authorized workflow.

## First-time pairing

Pairing is separately default-off (`PAIRING_ENABLED`) and requires all three business capabilities to remain off. A fresh valid owner Access request may call `start_pairing`; ordinary tools/events still require a bound owner. The returned 128-bit random code is a short-lived bearer proof, disclosed once with no-store response headers. It does not externally prove that a QQ account and Access email belong to the same human; the owner must keep the code private and send it personally to the intended bot.

Only signature-verified QQ C2C messages can consume a code. One transaction writes the owner and SHA-256 identity fingerprint and removes pending state. New code creation and consumption are checked before/after awaited transaction operations for current flags and request authorization. Concurrent/late failures roll back the transaction; a previously committed transaction cannot be undone after response timeout.

The fingerprint closes the gap between first binding and the later SQL snapshot. Missing/changed previously bound owners remain permanently blocked; there is no public rebind/reset path. Legacy owner records without a new fingerprint continue to rely on the original SQL continuity snapshot. Pending expiry cleanup is transactional so it cannot delete a concurrently replaced code. Any code-shaped incoming text is intercepted before ordinary storage, including stale or replayed commands.

A pending code is capped by the original verified assertion expiry and ten minutes. Immediate remote OAuth revocation is not independently observed during QQ consumption. Turning off pairing prevents consumption; no claim of instantaneous remote revocation is made.
