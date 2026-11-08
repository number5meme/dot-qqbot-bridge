# Public release checklist

## Prepared locally

- [x] Copy only maintained source, tests and build inputs into a separate project.
- [x] Exclude production snapshots, state, deployment transcripts, personal identifiers and original Git history.
- [x] Replace personal domains/tenant with explicit validated deployment bindings.
- [x] Use example-only test identities and sample configuration.
- [x] Declare build/test dependencies directly, including esbuild and Miniflare.
- [x] Provide ignore rules and default-off capability settings.
- [x] Document message retention, trust boundaries, delivery limits and onboarding gaps.
- [x] Add the MIT License and synchronize package metadata; keep npm publication disabled.

See VALIDATION.md for actual install/build/test/scan results. A checked source-preparation item does not imply a live deployment or legal license grant.

## Required before claiming a usable fresh-install release

- [x] Select MIT and include the license text and project-contributor attribution.
- [ ] Confirm authorship and third-party obligations for the intended distribution.
- [x] Implement and independently review an authenticated first-time pairing flow. Do not seed records manually.
- [x] Add empty-state, replay, concurrent binding, transaction rollback and restart pairing tests.
- [ ] Verify China-mainland DNS/TLS reachability and actual Tencent callback access to the exact HTTPS webhook URL; do not rely on overseas probes or workers.dev assumptions.
- [ ] Verify the new flow in an isolated live environment.
- [ ] Document and verify the current Managed OAuth/Access/client provisioning workflow with real supported interfaces.
- [ ] Verify real callback challenge, lease renewal, explicit cancellation and fresh reply boundaries.
- [ ] Address or clearly accept active webhook-secret rotation and uncertain/lost delivery behavior.
- [ ] Evaluate provider quota/load behavior at retention limits.
- [ ] Check current dependency advisories and license obligations.
- [x] Re-run privacy/secret scanning over the exact proposed source archive. Scan any future Git history before publishing further changes.
- [x] Obtain publication approval for `number5meme/dot-qqbot-bridge`, public, MIT.

Source publication does not deploy or update the production service.
