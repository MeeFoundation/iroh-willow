# Scenario 3: Alice revokes Bob's access

Alice shares with Bob (Scenario 1). Alice decides to revoke. Bob's
future imports are rejected.

---

## Setup

Same as [Scenario 1](01-happy-path-write-sync.md) Steps 1-4. Alice
has delegated read+write access to Bob. Bob has imported the caps
and can sync.

## Alice builds a revocation invocation (local — Alice's node only)

Alice decides to revoke Bob's access. She builds a UCAN Invocation
with command `ucan/revoke` on her own node:

```
build_revoke_invocation(delegation_cid, chain, &alice_secret)
```

> `src/uwill/invocation.rs:241`

The invocation contains:

- `iss` = Alice's DID (the revoker)
- `sub` = namespace DID
- `cmd` = `ucan/revoke`
- `arg` = `{ revoke: <CID bytes of the delegation being revoked> }`
- `prf` = CIDs of the chain proving Alice's authority
- Signed by Alice

The revoked CID is computed from the delegation:
`delegation.to_cid()` > DAG-CBOR serialize + SHA-256 hash.

## Alice's node validates and applies the revocation (local — Alice's node only)

Alice's node validates and stores the revocation locally. The
revocation is applied to Alice's store — Bob's node does not learn
about the revocation until it tries to sync.

```
Auth::apply_revocation(&invocation)
```

> `src/store/auth.rs:50`

Validation goes through `invocation.validate_revoke()`
(`src/uwill/invocation.rs:347`), which starts with `validate_common()`
— the same shared entry point used by ALL invocation types:

1. **`validate_common()`** (`src/uwill/invocation.rs:99`):
   - Invocation signature (`invocation.verify()`)
   - Chain integrity via `from_chain()` (delegation signatures, root
     issuer, subject consistency, area narrowing, principals)
   - Expiry / not-before via `check_expiry()`

2. **Command check** (line 352): `cmd.segments() == ["ucan", "revoke"]`
   — this is NOT done via `syntatic_checks()`. Revocations use
   inherent authority (positional in the delegation chain), not
   delegated authority (command hierarchy). Per the UCAN spec, the
   authority to revoke comes from being an issuer in the chain, not
   from holding a `ucan/revoke` delegation. `run_syntatic_checks()`
   is only used for `willow/*` invocations.

3. **CID extraction** (line 358-363): reads `args["revoke"]` as bytes,
   parses as CID

4. **Inherent authority** (line 367-380): walks the proof chain, checks
   Alice's DID appears as `iss` in some delegation at or above the
   revoked one. If Alice issued the delegation, she can revoke it.
   If she's higher in the chain, she can revoke anything derived from
   her delegation.

**Revoker's chain revocation check** — before storing, `apply_revocation`
also checks that the revoker's own chain hasn't been revoked
(`src/store/auth.rs:53`):

```rust
if self.is_chain_revoked(&invocation.capability()) {
    return Err(AuthError::Revoked);
}
```

On success, the revoked CID is stored:

```
RevocationStorage::apply(&invocation)
```

> memory backend (`src/store/memory.rs:67`): calls `validate_revoke()`
again, extracts CID, calls `store.revoke(cid)`

> persistent backend (`src/store/persistent.rs:629`): same + writes
CID to redb `REVOCATIONS` table

## Bob tries to import new capabilities — rejected (local — Bob's node)

Bob receives updated capabilities (e.g., from a re-sync attempt).
Bob's node checks against its own local revocation store. If Bob's
node has received the revocation (e.g., via a prior sync with Alice),
the import fails.

```
Auth::import_caps(caps)
```

> `src/store/auth.rs:89`

At line 102:

```rust
if self.is_chain_revoked(chain) {
    return Err(AuthError::Revoked);
}
```

`is_chain_revoked` (`src/store/auth.rs:61`) delegates to
`RevocationStorage::chain_is_revoked()` which checks each delegation
CID in the chain against Bob's local revoked set.

The revoked delegation's CID matches > `AuthError::Revoked` returned.

## What about already-synced data?

Revocation is enforced at explicit security boundaries — every point
where untrusted data enters the system from a peer. Validation is
stateless (signature, chain integrity, expiry), revocation is stateful
(requires the local revocation store). This clean separation means
validation methods like `validate_write()` take no revocation parameter.

The revocation checks happen AFTER stateless validation succeeds, at
each security boundary. In every case, the check runs locally on the
receiving node against its own revocation store:

### Entry reception during sync (`data.rs` and `reconciler.rs`)

When an entry arrives from a peer (<- received over wire), the
receiving node runs `static_tokens.rs:authorise_entry_eventually`
which calls `validate_write(&entry)` for stateless checks (local),
then wraps via `new_unchecked()`. The caller then checks revocation
(local) before ingesting:

**`data.rs:on_send_entry`** (`src/session/data.rs:160`):

```rust
let authorised_entry = self.static_tokens
    .authorise_entry_eventually(entry, handle, dynamic_token).await?;
if self.store.revocations().chain_is_revoked(
    &authorised_entry.token().capability(),
) {
    return Err(Error::ChainRevoked);
}
self.store.entries().ingest_entry(&authorised_entry, ...)?;
```

**`reconciler.rs`** (`src/session/reconciler.rs:165`) — same pattern:

```rust
let authorised_entry = self.shared.static_tokens
    .authorise_entry_eventually(...).await?;
if self.shared.store.revocations().chain_is_revoked(
    &authorised_entry.token().capability(),
) {
    return Err(Error::ChainRevoked);
}
self.shared.store.entries().ingest_entry(&authorised_entry, ...)?;
```

### Read capability exchange (`run.rs:caps_recv_loop`)

When a peer sends a read capability invocation (<- received over
wire via `SetupBindReadCapability`), the receiving node validates
and checks revocation locally:

**`run.rs:321-324`**:

```rust
let chain = caps.validate_and_bind_read_invocation(message.invocation.0)?;
if store.revocations().chain_is_revoked(&chain) {
    return Err(Error::ChainRevoked);
}
```

### Enumerate capability exchange (`run.rs:control_loop`)

When a peer replies with an enumerate capability (<- received over
wire via `PaiReplySubspaceCapability`, PAI awkward pair), the
receiving node validates and checks revocation locally:

**`run.rs:499-501`**:

```rust
let cap = caps.validate_enumerate_cap_invocation(&msg.invocation.0)?;
if store.revocations().chain_is_revoked(&cap) {
    return Err(Error::ChainRevoked);
}
```

### Revocation application (`auth.rs:apply_revocation`)

When applying a revocation locally, the revoker's own chain is checked:

**`src/store/auth.rs:53`**:

```rust
if self.is_chain_revoked(&invocation.capability()) {
    return Err(AuthError::Revoked);
}
```

### What `is_authorised_write` does NOT check

`is_authorised_write` (`src/uwill/invocation.rs:418`) calls
`self.validate_write(entry).is_ok()` — no revocation check. It is
defense-in-depth for internal DB reads and trusted paths. The real
security boundary for untrusted entries is the pipeline above:
`static_tokens.rs` (stateless validation) + `data.rs` / `reconciler.rs`
(revocation check).

## Cascading revocation

If Alice revokes her delegation to Bob (Alice>Bob), and Bob had
further delegated to Carol (Bob>Carol), Carol's chain is ALSO
revoked — it contains the Alice>Bob delegation CID.

> tested in `uwill::tests::revocation_cascades_through_chain`

## Out-of-order revocation

The UCAN spec recommends accepting revocations for delegations not
yet seen. The revocation store holds CIDs regardless of whether the
delegation has been imported. If Bob's chain arrives after the
revocation, it's still rejected.

> tested in `uwill::tests::revoke_before_seeing_delegation`

---

**Test coverage:** `uwill::tests::revoked_chain_detected`,
`uwill::tests::revocation_cascades_through_chain`,
`uwill::tests::revoke_before_seeing_delegation`,
`uwill::tests::double_revocation_idempotent`,
`uwill::revocation::tests::revocation_authority_check`
