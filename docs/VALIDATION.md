# Local validation

Date: 2026-11-08. Environment: Linux x86_64, Node.js 24.22.1, npm 11.9.0.
Source baseline: `0.3.0-managed-timing.1`; preparation fork: `0.3.0-public-prep.2`.
The baseline came from the source snapshot associated with an existing deployment record; this preparation did not re-query or change the live service.

## Results

- **Clean installation passed.** Copied the allowlisted source files to an independent temporary directory with no `node_modules`, used a separate initially empty npm cache, and ran `npm ci --ignore-scripts --no-audit --no-fund`. Installed 130 packages from the lockfile. No dependency-directory symlink or preexisting production installation was used.
- **Typecheck passed.** `tsc --noEmit`.
- **Offline build passed.** `node scripts/build-local.cjs`, producing the same `dist/worker.js` SHA-256 in the working project and the independent clean installation: `d8264b6492f612706b38f6023556657f8f5a8daa0686d716b826185fc6d8b084`.
- **Tests passed: 123 / 123.** No failures, cancellations or skips. The full clean-install suite completed in approximately 51 seconds.
- **Privacy/secret heuristic scan passed.** Scanned the source/docs/config package with `npm run scan`; no matches remained. Separate manual inspection checked literal domains/emails, known source-specific identifiers, deployment IDs, high-entropy string candidates, private registry URLs and excluded files. Fixtures use reserved example identities; private keys are generated only during tests, not saved in source.
- **Formatting check passed.** All matched source, tests, scripts, docs and configuration files follow the pinned Prettier version.
- **Independent read-only review completed.** Reviewed trust-anchor handling and first-time pairing admission, transactions, replay protection, owner continuity and timeout behavior. Three review/regression findings were fixed and re-reviewed; see PAIRING-REVIEW.md. No remaining source-review blocker was identified.

The archive is assembled from explicit source-file and source-directory allowlists. `SOURCE-MANIFEST.sha256` covers all included files except the manifest itself. Generated `dist/`, `node_modules/`, private configuration, snapshots, logs, databases and Git history are not part of the archive. Final archive extraction and manifest verification are performed separately from tests.

## Coverage

The inherited 99 tests cover Access verification, callback vault/keyring validation, SDK/SQLite event leases, delivery/reply claims, cancellation, request budgets and timing. Seven added tests cover deployment configuration validation/pinning, hostname isolation, missing configuration and malformed-owner blocking. Fifteen dedicated tests cover first-time pairing, and two additional tests cover abort/deadline behavior of guarded transaction storage. Test temporary directories use the operating system's temporary directory API.

Runtime tests run real local workerd/SQLite with synthetic keys. Business fixtures use pre-seeded synthetic owners, while first-time pairing fixtures start with empty storage and bind only through the implemented authenticated/signed flow. Outbound service requests are intercepted. Tests include process restart/persistence, alarms, late continuation and uncertain-response behavior; they are not live QQ or Managed OAuth integration tests.

## Not validated or not completed

- First-time pairing is **implemented and locally tested**. Verification on an empty live deployment: **not run**.
- Live QQ callback setup, real owner pairing, QQ reply, Managed OAuth provisioning, renewal and explicit cancellation for this fork: **not run**.
- Load/quota testing at maximum retention occupancy: **not run**.
- Automatic active webhook-secret rotation: **not implemented**.
- MIT license selection and project metadata are complete. Current dependency advisory audit and full legal/provenance review: **not performed**. The lockfile is reproducible input, not a security guarantee.
- Other operating systems/CPU architectures: **not tested**.
- Comprehensive secret detection or formal security audit: **not claimed**. The bundled scanner is heuristic; dependency and build trees are excluded from its source scan.

During local validation, no credentials were created/uploaded, no event subscriptions were changed, no QQ messages were sent, and no production configuration or code was modified.

## MIT metadata revision

The project license was changed to MIT with project-contributor attribution.
The application source and dependency versions did not change. The full
`npm run check` was rerun successfully: 123 tests passed, with typecheck, build,
source scanning and formatting also passing. The application bundle retains the
SHA-256 recorded above. License text, README, package metadata and lockfile root
metadata were checked for agreement; npm publication remains disabled.

## Domain prerequisite documentation correction

The README and setup guide now require a China-mainland-accessible HTTPS callback
domain and separate verification that Tencent's callback servers can reach the
exact URL. QQ's official event documentation and the implementation's route
checks were reviewed. The guide distinguishes QQ's platform rules from this
Worker's stricter default-port/path rules, explains workers.dev reachability
uncertainty, and avoids treating ICP filing as a universal webhook requirement.
No live domain, Mainland China network probe or Tencent callback test was run for
this documentation correction. Application source and dependency versions did
not change.
