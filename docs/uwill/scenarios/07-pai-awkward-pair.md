# Scenario 7: Alice and Bob have an awkward overlap

Alice has full-area access (Any subspace). Bob has access restricted to
his subspace with path "chess/". Their interests overlap, but neither
can safely reveal their capability first. The enumerate chain breaks
the standoff.

---

## Setup

Alice is the namespace owner with full-area read access:
- `subspace: Any, path: empty` — `FragmentKit::Complete`

Bob has delegated read access restricted to his subspace + path "chess/":
- `subspace: Id(bob), path: "chess/"` — `FragmentKit::Selective`

Same as [Scenario 1](01-happy-path-write-sync.md) Steps 1-4 for the
capability setup, with the area restriction on Bob's delegation.

## Why this is "awkward"

Per the Willow spec, two interests are **awkward** when:
- One has `Any` subspace with a path `p`
- The other has a specific subspace with a path that is a strict prefix of `p`

Alice: `(namespace X, Any subspace, empty path)`
Bob: `(namespace X, Id(bob), "chess/")`

They overlap (Bob's entries at "chess/" are covered by both), but:
- Alice can't reveal her full-area cap first (it contains no subspace —
  Bob might not have access to all subspaces)
- Bob can't reveal his specific subspace first (it contains `bob` —
  Alice might not know Bob is in this namespace)

Neither can safely go first without potentially leaking information.

## PAI fragment generation (local — each node independently)

Each node generates its PAI fragments locally. No data crosses the
wire in this step.

### Alice's fragments (Complete)

> `src/proto/pai.rs:77` — `AreaSubspace::Any` — `FragmentKit::Complete`

> `src/proto/pai.rs:136-141` `into_fragment_set()`:
Generates pairs `(namespace, prefix)` for each path prefix.
Alice has empty path — one pair: `(namespace, "")`.

All sent as **Primary** fragments.

### Bob's fragments (Selective)

> `src/proto/pai.rs:78-79` — `AreaSubspace::Id(bob)` — `FragmentKit::Selective`

> `src/proto/pai.rs:143-153`:
- **Primary** triples: `(namespace, bob, "")`, `(namespace, bob, "chess/")`
- **Secondary** pairs: `(namespace, "")`, `(namespace, "chess/")`

Secondary fragments are the "relaxation" — they drop the subspace,
used to detect awkward overlaps.

## Fragment exchange (over the wire — blinded, no capability details visible)

Same as [Scenario 1](01-happy-path-write-sync.md) Step 5b. Fragments
are hashed into Ristretto255 group elements, blinded with each node's
random scalar (local), then the blinded points are exchanged over the
wire. Only blinded group elements are sent — no namespace IDs, no
subspace IDs, no paths, no capability details are visible to either
peer.

## Intersection detection — awkward pair found (local — each node independently)

Each node locally compares its doubly-blinded values. Bob's
**secondary** pair `(namespace, "")` hashes to the same value as
Alice's **primary** pair `(namespace, "")`. After double-blinding,
they match:

> `src/session/pai_finder.rs:480` `completes_with()` — the secondary
(Bob's) matches the primary (Alice's).

The `OnIntersection` for a secondary + most specific match:

> `src/session/pai_finder.rs:507`:
```rust
(FragmentKind::Secondary, true) => OnIntersection::RequestSubspaceCap
```

-> Alice's PAI finder sends `PaiRequestSubspaceCapability` over the
wire to Bob, asking him to prove namespace membership. This message
itself carries no capability details — just a handle reference.

## Bob responds with enumerate invocation (local build, then sent over wire)

Bob's `ReadAuthorisation` includes an enumerate chain created during
delegation. It uses command `willow/enumerate` — proves namespace
membership without granting data access.

> `src/session/pai_finder.rs:360` `received_subspace_cap_request`:
```rust
if let Some(cap) = fragment_info.authorisation.subspace_cap() {
    self.out(Output::SignAndSendSubspaceCap(handle, cap.clone())).await;
}
```

Bob's node builds the response locally as a UCAN invocation:

> `src/session/capabilities.rs:151` `build_enumerate_cap_invocation`:
```rust
let invocation = build_enumerate_invocation(&challenge, &cap, &user_secret)?;
Ok(PaiReplySubspaceCapability {
    handle,
    invocation: SerdeUWillInvocation(invocation),
})
```

The invocation (`willow/enumerate`) carries:
- The enumerate delegation chain as resolved proofs
- The session challenge nonce in `args["challenge"]`
- Capability area fields (`wil_subspace`, `wil_path`, etc.) in args

-> Bob's enumerate invocation is sent over the wire as
`PaiReplySubspaceCapability { handle, invocation }`. This is the
first time capability details become visible to Alice's node — the
PAI phase up to this point only exchanged blinded group elements.

## Alice verifies and completes intersection (local — validating received data)

<- Alice's node receives the enumerate invocation from Bob over the
wire and validates it locally.

> `src/session/capabilities.rs:116` `validate_enumerate_cap_invocation`:

Validates the invocation via `validate_enumerate_proof(&their_challenge)`
(`src/uwill/invocation.rs:320`):

1. **`validate_common()`** (line 324) — shared stateless checks
   (local): invocation signature, chain integrity via `from_chain()`,
   and expiry. No revocation (stateful, checked at boundaries).
2. **`run_syntatic_checks()`** (line 325) — UCAN-level validation
   (local): subject match, issuer chain alignment, command hierarchy
   (`willow/enumerate`), area predicate evaluation.
3. **Challenge nonce match** (line 326) — proves Bob signed this for
   *this* session, not a replay.
4. **`proves_enumerate()`** (line 328) — chain's command proves
   enumerate access.

After `validate_enumerate_proof` returns the validated chain,
revocation is checked against Alice's local revocation store:

> `src/session/run.rs:500`:
```rust
if store.revocations().chain_is_revoked(&cap) {
    return Err(Error::ChainRevoked);
}
```

Revocation is NOT inside the validation methods — it's stateful and
checked at each boundary (`run.rs` for enumerate/read caps,
`static_tokens.rs` for write entries, `data.rs`/`reconciler.rs` for
reconciliation). All revocation checks are local, against the
receiving node's own store.

> `src/session/pai_finder.rs:342` `received_verified_subspace_cap_reply`:
The intersection is now complete. Both peers know they share
namespace X. The `NewIntersection` output is yielded.

Reconciliation proceeds as in Scenario 1 Step 6.

## Why the enumerate chain is NOT a read capability

The enumerate chain has `cmd = willow/enumerate`. It proves "Bob has
been granted access to this namespace" without revealing what data
Bob can read or write.

If Mallory extracted this chain and tried to use it for data access:
- `proves_read()` — `false` (`src/uwill/command.rs:59`)
- `proves_write()` — `false` (`src/uwill/command.rs:63`)
- `validate_write()` — `InvocationError::WrongCommand`

See [Scenario 4c](04-rejection-identity-mismatch.md#4c-mallory-uses-the-enumerate-chain-for-data-access)
for the full rejection trace.

---

**Test coverage:** `session::pai_finder::tests::pai_subspace`,
`uwill::tests::enumerate_chain_cannot_authorize_writes`,
`uwill::tests::enumerate_chain_is_not_read_cap`
