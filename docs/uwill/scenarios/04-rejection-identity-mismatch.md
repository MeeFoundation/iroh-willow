# Scenario 4: Mallory tries to forge access

Three attack scenarios where identity checks prevent unauthorized
access.

---

## 4a: Mallory signs with the wrong key

**Story:** Alice delegates write access to Bob. Mallory obtains Alice's
delegation chain (it's not secret — it's sent over the wire during
sync). Mallory tries to write an entry using Alice's chain but signing
with her own key.

### Setup

Same as [Scenario 1](01-happy-path-write-sync.md) Steps 1-3. The
delegation chain grants write access to Bob (aud = Bob's DID).

### Mallory builds an invocation (local — Mallory's node)

Mallory calls `build_write_invocation(entry, alice_chain, &mallory_secret)`.
The invocation is built and signed locally — the builder doesn't check
who's signing.

### Validation rejects (local — on the receiving node)

When Mallory sends this entry over the wire to another peer, that
peer's node runs `validate_write(entry)` locally
(`src/uwill/invocation.rs:282`):

First, `validate_common()` (line 283) runs the shared stateless
checks — invocation signature, chain integrity via `from_chain()`,
and expiry. These all pass (the signature is valid for Mallory's key,
and the chain itself is intact).

Then `run_syntatic_checks()` (line 284) calls the UCAN crate's
`syntatic_checks()` which validates the issuer chain integrity. The
invocation's issuer is Mallory's DID, but the chain's receiver (final
`aud`) is Bob's DID. The issuer chain check fails because the
invocation issuer does not match the proof chain's audience:

```rust
self.run_syntatic_checks()?;
// -> InvocationError::SyntaticCheck("InvalidProofIssuerChain ...")
```

The `syntatic_checks()` function from the `ucan` crate validates that
the invocation's issuer matches the last delegation's audience, that
each delegation's audience matches the next delegation's issuer, and
that the subject is consistent. All of these are checked in a single
pass — there is no separate `IssuerMismatch` error variant.

**Test:** `uwill::tests::wrong_signer_rejected`

---

## 4b: Mallory uses a capability from the wrong namespace

**Story:** Mallory has write access to namespace A (her own). She tries
to use that capability to write an entry in namespace B (Alice's).

### Setup

Mallory has `UWillChain` for namespace A. She builds a write invocation
targeting an entry in namespace B (local — Mallory's node).

### Validation rejects (local — on the receiving node)

When the entry is sent over the wire to another peer, that peer's
node runs `validate_write(entry)` locally
(`src/uwill/invocation.rs:282`):

`validate_common()` and `run_syntatic_checks()` pass (the chain and
invocation are internally consistent). Then at line 291:

```rust
if chain.granted_namespace() != *entry.namespace_id() {
    return Err(InvocationError::NamespaceMismatch);
}
```

The chain's namespace (A) doesn't match the entry's namespace (B).
> `NamespaceMismatch` error.

**Test:** `uwill::tests::cross_namespace_write_rejected`

---

## 4c: Mallory uses the enumerate chain for data access

**Story:** Bob has a `ReadAuthorisation` with a read chain + enumerate
chain. Mallory (or Bob himself) extracts the enumerate chain and tries
to use it as a write capability.

### Background

The enumerate chain is bundled alongside the read capability for PAI
awkward pair resolution (see [Scenario 7](07-pai-awkward-pair.md)).
The enumerate chain is only ever sent over the wire during PAI awkward
pair resolution (as `PaiReplySubspaceCapability`). It uses command
`willow/enumerate` — a namespace membership proof that does NOT grant
data access.

### Mallory extracts the enumerate chain (local)

```rust
let enumerate = auth.subspace_cap().unwrap(); // UWillChain with cmd=enumerate
```

### Validation rejects (local — on the receiving node)

When the entry is sent over the wire, the receiving node runs
`validate_write(entry)` locally (`src/uwill/invocation.rs:282`):

`validate_common()` passes (chain and signature are valid).
`run_syntatic_checks()` passes (internal consistency holds). Then at
line 286:

```rust
if !chain.proves_write() {
    return Err(InvocationError::WrongCommand(...));
}
```

`WillowCommand::Enumerate.proves_write()` returns `false`
(`src/uwill/command.rs:63`). > rejected.

The enumerate chain also fails `proves_read()`:

```rust
pub fn proves_read(&self) -> bool {
    matches!(self, Self::Full | Self::Read) // Enumerate not included
}
```

> `src/uwill/command.rs:59`

The enumerate chain ONLY serves as a namespace membership proof in
PAI. It cannot authorize any data access.

**Test:** `uwill::tests::enumerate_chain_cannot_authorize_writes`,
`uwill::tests::enumerate_chain_is_not_read_cap`

---

## Also: forged delegation chains

If Mallory tampers with the serialized bytes of a delegation chain
(e.g., changing the audience DID to her own) before sending it over
the wire, the receiving node's `UWillChain::from_chain()` (local)
rejects it at the signature verification step:

> `src/uwill/chain.rs:184`:

```rust
d.verify().map_err(|_| ChainError::InvalidSignature { step: i })?;
```

The delegation's signature was made over the original payload. Any
tampering produces a different DAG-CBOR encoding, and the Ed25519
signature verification fails.

Additionally, `from_chain()` now validates:

- **Root issuer check** (line 157-162): the root delegation's issuer
  must match its subject (namespace DID). A chain where the root is
  signed by someone other than the namespace owner is rejected with
  `ChainError::RootIssuerMismatch`.
- **Subject consistency** (line 166-176): all delegations in the chain
  must have the same subject. A chain with mixed subjects is rejected
  with `ChainError::SubjectMismatch`.

**Test:** `uwill::tests::forged_chain_rejected`
