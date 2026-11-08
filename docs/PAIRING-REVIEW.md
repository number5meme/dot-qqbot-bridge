# First-time pairing security review

Scope: the local `0.3.0-public-prep.2` implementation. This is an independent source review plus local regression testing, not a formal audit, live-platform certification or deployment approval.

## Reviewed boundaries

- Only the configured owner's verified Cloudflare Access application assertion may initiate pairing.
- Pairing is separately default-off, requires QQ credentials, and is prohibited while any business capability is enabled.
- QQ setup challenge is available before binding but cannot create an owner. Ordinary pairing ingress requires a valid QQ signature, fresh timestamps and a C2C private-message command.
- Pairing codes contain 128 bits of randomness, are disclosed once, stored as hashes, expire within ten minutes and no later than the issuing assertion, and are atomically consumed.
- Paired owner identity cannot be changed through a public tool or route. Empty fresh state is distinguished from malformed, orphaned or previously bound state.
- Code-shaped input is intercepted before message/event/timing storage, including replays after business activation.
- Transaction operations recheck request deadlines, flags and authorization around awaits. MCP responses containing codes use no-store caching.

## Issues found and fixed

1. **Crash gap before SQL continuity snapshot.** A boolean bound marker recorded only existence, so it could not detect owner replacement between the first KV commit and later SQL snapshot. The marker now stores a SHA-256 fingerprint of the exact principal, OpenID and paired timestamp, atomically committed with owner and pending deletion. Every owner check validates the fingerprint. A regression removes the SQL snapshot, changes owner, performs a real workerd restart, and confirms irreversible blocking even after restoring the original owner.
2. **Expired pending-code cleanup race.** Nontransactional read/delete could remove a concurrently replaced code. Cleanup now uses a storage transaction. A bounded concurrent cleanup/new-start regression verifies that the replacement survives and can bind; it is not an exhaustive scheduling proof.

3. **Suspended transaction delaying timeout responses.** A stalled transaction read could keep workerd's output gate open after the outer HTTP budget expired. Guarded storage now rejects awaited operations on abort or the fixed absolute deadline, letting transaction callbacks reject/roll back. Alarm cleanup uses one bounded budget across transaction retries. Late underlying results are handled and cannot resume helper writes. This bounds callback waiting, not cancellation of I/O already accepted by the runtime.

The reviewer re-read all three fixes and identified no remaining blocker in the reviewed source changes.

## Test coverage

Fifteen dedicated workerd/SQLite tests cover empty setup, owner authentication, default-off admission, signed/unsigned/stale/group/wrong-app commands, expiry, concurrent issuance and consumption, code secrecy, actual restart persistence, owner disappearance/mutation, late authorization and flag changes, transactional rollback, the pre-snapshot crash gap, orphan-state detection, concurrent cleanup/replacement and a stalled pairing transaction. Two additional unit tests cover prompt abort before raw storage settlement and deadline enforcement without an external fetch timer.

The broader suite continues to cover business authorization, callback encryption, event leases, cancellation, reply claims, timing and request budgets. A legacy timeout-injection fixture was updated to stall the new transaction read rather than the former nontransactional read. Runtime persistence fixtures now use the supported resource persistence setting; pairing tests assert actual pending and owner continuity across workerd process replacement.

## Remaining caveats

- A code is a bearer proof. The service cannot independently match QQ account identity to Access email; leaking the code can lead to an incorrect binding.
- New guards prevent subsequent operations but cannot undo a transaction already committed when its HTTP response later times out. An uncertain start may leave a pending code that cannot be redisplayed.
- Remote OAuth revocation is not queried during QQ code consumption. Local expiry and the pairing switch bound permission; instant remote revocation is not promised.
- Legacy owner records without the new fingerprint retain the existing SQL continuity mechanism. The project does not silently migrate or reset a running deployment.
- Cloud-provider administrators can alter storage; the application marker is not protection against an administrator changing all continuity evidence.
- Real QQ callback/Managed OAuth interoperability, isolated deployment, load limits and dependency advisories remain separate verification work.
