# Scenario 2: Alice's temporary access expires

Alice grants Bob time-limited access. Bob writes while it's valid.
The grant expires. Bob's next write is rejected.

---

## Setup (local — both nodes independently)

Same as [Scenario 1](01-happy-path-write-sync.md) Steps 1-4, except
Alice's delegation to Bob includes an expiry timestamp:

```rust
Delegation::builder()
    .issuer(alice)
    .audience(bob)
    .subject(namespace_did)
    .command(Command::new(vec!["willow", "write"]))
    .policy(vec![])
    .expiration(Timestamp::from_unix(1_700_000_000)) // expires at this time
    .try_build()
```

The `expiration` field is part of the UCAN delegation payload —
it constrains when the capability is valid, independent of which
entries it covers (that's the `wil_time_*` predicates).

## Bob writes while valid (local — Bob's node builds the invocation)

Same as Scenario 1 Step 2. Bob's node builds a write invocation
locally. The write succeeds because `now < exp`.

Expiry is checked inside `validate_common()` (`src/uwill/invocation.rs:99`),
which is the shared entry point for ALL invocations. When Bob builds a
write invocation and it goes through `validate_write(entry)`, the call
chain is:

1. `validate_common()` (line 283):
   - Invocation signature
   - Chain integrity via `from_chain()`
   - `check_expiry(&chain)` (line 109)
2. `run_syntatic_checks()` — delegated authority
3. Write-specific checks (namespace, area containment)

`check_expiry` (`src/uwill/invocation.rs:394`) calls:

```rust
chain.is_expired(now_secs) -> false  // not expired yet
chain.is_not_yet_valid(now_secs) -> false  // not in the future
```

> `src/uwill/chain.rs:421` `is_expired()`:

- Iterates delegations
- For each with `exp`: checks `now > exp + CLOCK_TOLERANCE_SECS`
- `CLOCK_TOLERANCE_SECS` = 60 seconds (`src/uwill/chain.rs:139`)
- `now < exp` > not expired > continues

## The grant expires

Wall clock advances past `exp + 60s` (the tolerance window).

## Bob tries to write again — rejected (local — Bob's node)

Bob's node builds a write invocation locally (same as before — the
invocation itself is structurally fine). But `validate_write()` on
Bob's node rejects it because `validate_common()` detects the expiry:

```
validate_common() -> check_expiry() -> chain.is_expired(now_secs) -> true
```

> `src/uwill/chain.rs:426-428`:

```rust
if now_secs > exp_secs.saturating_add(tolerance) {
    return true; // expired
}
```

`validate_write()` returns `Err(InvocationError::Expired)`. The entry
is not ingested.

The `is_authorised_write` trait impl (`src/uwill/invocation.rs:418`)
calls `self.validate_write(entry).is_ok()` — which returns `false`
since `validate_write` failed. This is the defense-in-depth path;
the primary security boundary for untrusted entries (from peers) is
`static_tokens.rs` where `token.validate_write(&entry)?` is called
explicitly and the error propagated.

## PAI also filters out expired read caps (local — our own node only)

Before entering the PAI protocol, each node filters its own read
capabilities locally. Expired caps never produce PAI fragments, so
the peer never sees them — not even as blinded group elements.

In `PaiFinder::submit_authorisation()` (`src/session/pai_finder.rs:167`):

```rust
let now_secs = SystemTime::now()...;
if read_cap.is_expired(now_secs) || read_cap.is_not_yet_valid(now_secs) {
    tracing::warn!("skipping expired/not-yet-valid read cap in PAI");
    return;
}
```

This is a local filter on our own caps — no peer data is involved.
An expired read capability will never generate PAI fragments,
preventing the peer from discovering shared namespaces through expired
grants.

## Receiving node also rejects expired caps during sync (local — validating received data)

When a node receives a read capability invocation from a peer (via
`SetupBindReadCapability`, sent over the wire after PAI finds overlap),
the receiving node validates it locally.

`validate_read_proof()` (`src/uwill/invocation.rs:302`) and
`validate_enumerate_proof()` (`src/uwill/invocation.rs:320`) both
call `validate_common()` as their first step, which runs `check_expiry()`
on the chain. If the chain is expired, `InvocationError::Expired` is
returned and the capability is rejected.

This catches the case where a peer sends an expired read/enumerate
capability invocation over the wire. The local PAI filter (above)
prevents our own expired caps from entering PAI, but this check
protects against expired caps received from the peer.

## Not-before (nbf)

The same mechanism works for `nbf` — a delegation with `nbf` in the
future is not yet valid:

> `src/uwill/chain.rs:434` `is_not_yet_valid()`:

```rust
if now_secs + tolerance < nbf_secs {
    return true; // not yet valid
}
```

A delegation with both `nbf` and `exp` defines a validity window
`[nbf - 60s, exp + 60s]` (with clock tolerance).

## What about the chain itself?

The chain validation in `from_chain()` (`src/uwill/chain.rs:148`)
does NOT check expiry — chains with expired delegations are accepted
structurally. Expiry is checked at usage time, at different points
depending on whether the operation is local or involves received data:

1. `validate_write()` — for write entries (local on the writing node,
   or local on the receiving node when validating received entries)
2. `validate_read_proof()` — for read cap exchange during sync
   (local on the receiving node, validating data from the peer)
3. `validate_enumerate_proof()` — for enumerate cap exchange
   (local on the receiving node, validating data from the peer)
4. `validate_revoke()` — for revocation invocations (local)
5. PAI `submit_authorisation` — local filter on our own caps before
   fragments are generated (direct `is_expired()` check, not via
   `validate_common`)

This allows importing and storing expired chains for historical purposes.

---

**Test coverage:** `uwill::tests::expired_delegation_rejects_write`,
`uwill::tests::not_yet_valid_delegation_rejects_write`,
`uwill::tests::valid_time_window_accepts_write`
