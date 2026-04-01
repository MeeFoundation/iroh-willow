# Scenario 1: Alice shares a document with Bob

Alice creates a personal namespace, writes a document, grants Bob
read+write access. Bob's node discovers Alice, they sync, Bob sees
Alice's document and writes a reply.

---

## Step 1: Alice creates her namespace (local — Alice's node only)

Alice's node generates a namespace keypair and creates a personal
namespace. Full read+write capabilities are created for Alice.
Everything here is local to Alice's node — no data crosses the wire.

```
Auth::create_full_caps(namespace_id, alice_user_id)
```

> `src/store/auth.rs:165` — creates read + write `CapabilityPack`

Internally:

- `ReadAuthorisation::new_owned(&ns_secret, alice_id)` (`src/proto/meadowcap.rs:101`)
  - Creates a `/willow/read` chain via `UWillChain::new_owned()` (`src/uwill/chain.rs:266`)
  - Creates a `/willow/enumerate` chain via `UWillChain::new_enumerate()` (`src/uwill/chain.rs:283`)
  - Bundles both in `ReadAuthorisation`
- `UWillChain::new_owned(..., Write)` for the write capability

Each chain is a UCAN Delegation signed by the namespace secret key:

- `iss` = namespace DID
- `aud` = Alice's DID
- `sub` = namespace DID
- `cmd` = `willow/read` or `willow/write`
- `pol` = empty (full area)

Built via `build_root_delegation()` (`src/uwill/chain.rs:239`) which
calls `Delegation::builder().try_build()`.

**Chain validation** (local) happens in `UWillChain::from_chain()`
(`src/uwill/chain.rs:148`):

- Root issuer check: root delegation's issuer must match its subject (namespace owner) (line 157-162)
- Subject consistency: all delegations must have the same subject (line 166-176)
- Signature verification: `d.verify()` (line 184)
- Command hierarchy check (line 190-197)
- Area extraction + narrowing (line 199-204)
- Principal alignment (line 206-214)
- CID precomputation (line 224)
- Receiver public key decompression (line 225-226)

## Step 2: Alice writes a document (local — Alice's node only)

Alice writes an entry at path `messages/hello` with payload "Hi Bob!".
This is entirely local — Alice's node builds the invocation and stores
the entry. Nothing is sent over the wire yet.

```
Store::insert_entry(entry, auth)
```

> `src/store.rs:81` — looks up write capability, builds invocation

Internally:

- Finds a matching write capability via `Auth::get_write_cap(&selector)` (`src/store/auth.rs:64`)
- Retrieves Alice's secret key
- Builds a UCAN write invocation (local):

```
build_write_invocation(&entry, &capability, &secret_key)
```

> `src/uwill/invocation.rs:148`

The invocation is an `Invocation<Ed25519Did>` with:

- `iss` = Alice's DID
- `aud` = Alice's DID (self-addressed)
- `sub` = namespace DID
- `cmd` = `willow/write`
- `arg` = capability area fields (`wil_subspace`, `wil_path`, `wil_time_start`, `wil_time_end` from the chain's granted area)
- `prf` = CIDs of the delegation chain
- Signed by Alice

The args describe the capability's area, NOT the specific entry.
Entry containment is validated separately via `area.includes_entry()`.

The entry is wrapped in `AuthorisedEntry::new_unchecked(entry, invocation)` (line 113).

Individual delegations from the chain are stored in `DelegationStorage` (line 110 in `import_caps`, similarly in `insert_caps_unchecked`).

## Step 3: Alice delegates access to Bob (local — Alice's node only)

Alice grants Bob read+write access to her namespace. This builds the
delegation chains locally on Alice's node.

```
Auth::delegate_full_caps(from, AccessMode::Write, to, store=true)
```

> `src/store/auth.rs:212` — delegates both read and write

Internally:

- `delegate_read_cap()` (line 233): takes Alice's read chain, calls
  `chain.delegate(&alice_secret, &bob_id, &area)` (`src/uwill/chain.rs:311`)
  - Creates a new UCAN Delegation appended to the chain
  - `iss` = Alice's DID (the current holder)
  - `aud` = Bob's DID
  - Same `sub`, narrowed `pol` predicates for the restricted area
  - Validates monotonic narrowing in `from_chain()`
- `delegate_write_cap()` (line 254): same for write
- Stores delegated caps and individual delegations

Bob receives these capabilities out-of-band (e.g., via invite) —
this is the first time capability data leaves Alice's node.

## Step 4: Bob imports capabilities (local — Bob's node only)

Bob's node receives Alice's delegated caps (delivered out-of-band)
and imports them. All validation here is local to Bob's node.

```
Auth::import_caps(caps)
```

> `src/store/auth.rs:89`

Validation on import (local):

1. `cap.validate()` (line 95) — checks access mode consistency
2. **Revocation check** (line 102): `self.is_chain_revoked(chain)`
   > `RevocationStorage::chain_is_revoked()` checks each delegation
   CID against Bob's local revocation store
3. User secret check (line 107) — Bob must have the secret key
   matching the chain's receiver
4. Capability stored in `CapsStorage` (line 110)

## Step 5: PAI — discovering overlapping interests

Alice and Bob's nodes connect (via mDNS, relay, or gossip). They run
the Private Area Intersection (PAI) protocol to discover which
namespaces they have in common — without revealing namespaces they
DON'T share.

### 5a: Submit authorisations to PAI finder (local — each node independently)

Each peer submits their own `ReadAuthorisation` objects to their local
PAI finder. No data crosses the wire in this step.

```
PaiFinder::submit_authorisation(auth)
```

> `src/session/pai_finder.rs:167`

Before fragment generation, a **local expiry filter** rejects expired
or not-yet-valid read capabilities from our own store:

```rust
let now_secs = SystemTime::now()...;
if read_cap.is_expired(now_secs) || read_cap.is_not_yet_valid(now_secs) {
    tracing::warn!("skipping expired/not-yet-valid read cap in PAI");
    return;
}
```

> `src/session/pai_finder.rs:172-181`

This is a local filter on our own caps — the peer never sees expired
capabilities because they never produce PAI fragments.

The PAI finder then extracts the read capability and generates
fragments (local):

```
PaiScheme::get_fragment_kit(read_cap)
```

> `src/proto/pai.rs:71`

- If subspace is `Any` > `FragmentKit::Complete(namespace, path)` — generates pairs
- If subspace is `Id(specific)` > `FragmentKit::Selective(namespace, subspace, path)` — generates triples (primary) + pairs (secondary)

Fragments are all prefixes of the path. E.g., path `messages/hello`
generates fragments for `""`, `"messages"`, `"messages/hello"`.

### 5b: Fragment exchange (over the wire — blinded, no capability details visible)

Each fragment is hashed into a Ristretto255 group element and multiplied
by the peer's random scalar. Only blinded group elements cross the wire —
no namespace IDs, no paths, no capability details are visible to the
peer.

```
submit_fragment(auth, fragment, kind, is_most_specific)
```

> `src/session/pai_finder.rs:225`

- `hash_into_group(fragment)` > Ristretto255 point (local, line 232)
- `scalar_mult(point, self.scalar)` > blinded point (local, line 233)
- Blinded point sent as `PaiBindFragment` message (-> sent over wire, line 239)

The receiver multiplies the received point by THEIR scalar and replies:

```
receive_bind(message)
```

> `src/session/pai_finder.rs:243`

- `scalar_mult(received_point, self.scalar)` > doubly-blinded (local, line 249)
- Replies with `PaiReplyFragment` (-> sent over wire, line 252-256)

### 5c: Intersection detection (local — each node independently)

After exchange, both peers have `s_a * s_b * H` for each fragment.
If two fragments produce the same doubly-blinded value, the interests
overlap. This comparison is done locally on each node.

```
check_for_intersection(handle, scope)
```

> `src/session/pai_finder.rs:274`

- Compares group values via `completes_with()` (line 296)
- On match: determines action based on fragment kind (line 307-318):
  - Primary + most specific > `BindReadCap` > yields `NewIntersection`
  - Secondary + most specific > `RequestSubspaceCap` > awkward pair (see scenario 7)

### 5d: Capability binding via UCAN invocations (over the wire)

After PAI finds overlap, peers exchange their actual read capabilities
as UCAN invocations. This is the first time capability details become
visible to the peer — PAI only exchanged blinded group elements up to
this point.

**Sending** (local: build invocation, then send over wire):

```
Capabilities::build_read_cap_invocation(secret_store, handle, capability)
```

> `src/session/capabilities.rs:61`

- Retrieves the session challenge nonce (local)
- Calls `build_read_invocation(&challenge, &capability, &user_secret)`
  (`src/uwill/invocation.rs:164`) (local)
- The invocation (`willow/read`) carries:
  - The read cap chain as resolved proofs
  - The session challenge nonce in `args["challenge"]`
  - Capability area fields in `args` (`wil_subspace`, `wil_path`, etc.)
- -> Sent over wire as `SetupBindReadCapability { invocation: SerdeUWillInvocation, handle }`

**Receiving** (local: validate data received from peer):

```
Capabilities::validate_and_bind_read_invocation(invocation)
```

> `src/session/capabilities.rs:87`

- <- Received from peer: the read invocation
- Calls `invocation.validate_read_proof(&their_challenge)` which runs:
  1. `validate_common()` — signature, chain integrity via `from_chain()`,
     expiry / not-before
  2. `run_syntatic_checks()` — delegated authority validation (invocation-to-chain
     link, area predicates, command hierarchy)
  3. Challenge nonce check
  4. Chain must prove read access
- On success, binds the validated chain

**Revocation is checked by the caller** (local, against our
revocation store) — after `validate_and_bind_read_invocation` returns,
`run.rs:322` checks `store.revocations().chain_is_revoked(&chain)`.
This is the stateful check that cannot live inside the stateless
validation methods.

For **enumerate capabilities** (PAI awkward pair), the same pattern
applies:

- `build_enumerate_cap_invocation()` (`src/session/capabilities.rs:151`)
  -> sends `PaiReplySubspaceCapability { handle, invocation: SerdeUWillInvocation }` over wire
- `validate_enumerate_cap_invocation()` (`src/session/capabilities.rs:116`)
  <- receives invocation from peer, calls
  `invocation.validate_enumerate_proof(&their_challenge)` (same
  `validate_common()` + `run_syntatic_checks()` pipeline, local)
- Revocation checked by caller at `run.rs:500` (local)

## Step 6: Reconciliation — Alice's entry syncs to Bob

After PAI completes, the reconciliation protocol exchanges entries
within the overlapping areas.

### 6a: Alice's node decomposes the entry (local, then sent over wire)

```
DataHandler::send_entry(authorised_entry)
```

> `src/session/data.rs:87`

Alice's node decomposes the `UWillInvocation` for the wire (local):

- **StaticToken** = proof delegations (line 89): `token.capability().into()`
  > bound once by handle via `static_tokens.bind_and_send_ours()`
- **DynamicToken** = serialized invocation (line 90): `token.invocation().clone().into()`
  > sent per entry in `DataSendEntry`

The StaticToken goes through the DAG-CBOR bytes adapter
(`src/proto/meadowcap.rs` serde_encoding) to wrap UCAN types for
postcard wire format.

-> Both tokens are sent over the wire to Bob's node along with the
entry data.

### 6b: Bob's node reconstructs and validates (local — validating received data)

```
StaticTokens::authorise_entry_eventually(entry, handle, dynamic_token)
```

> `src/session/static_tokens.rs:49`

Bob's node receives the entry + tokens from Alice and validates them
locally:

- Resolves the StaticToken (proof chain) by handle (line 56-61)
- Extracts the invocation from the DynamicToken (line 64)
- Reconstructs: `UWillInvocation::from_parts(invocation, chain.delegations())` (line 65)
- Calls `token.validate_write(&entry)` (line 66) which runs the full
  stateless validation pipeline (local):
  1. `validate_common()` — invocation signature, chain integrity via
     `from_chain()`, expiry / not-before
  2. `run_syntatic_checks()` — delegated authority (area predicates,
     command hierarchy, invocation-to-chain link)
  3. Chain must prove write access
  4. Namespace match
  5. `chain.granted_area().includes_entry(entry)` — Willow-native
     containment check
- On success, wraps via `AuthorisedEntry::new_unchecked(entry, token)` (line 68)

### 6c: Revocation check at the security boundary (local — Bob's node)

The caller of `authorise_entry_eventually` — **not** the validation
method itself — checks revocation against Bob's local revocation
store. This is the stateful/stateless separation: validation is pure,
revocation requires the store.

In `data.rs:on_send_entry` (`src/session/data.rs:160`):

```rust
if self.store.revocations().chain_is_revoked(
    &authorised_entry.token().capability(),
) {
    return Err(Error::ChainRevoked);
}
```

The same pattern applies in the reconciler (`src/session/reconciler.rs:165`).

Only after both stateless validation AND the revocation check pass
does the entry proceed to ingestion.

### 6d: Entry ingested (local — Bob's node)

```
EntryStorage::ingest_entry(&authorised_entry, EntryOrigin::Remote(session_id))
```

> `src/session/data.rs:163` — stores the entry in Bob's Willow store

### 6e: Defense-in-depth — `is_authorised_write` (local)

The `AuthorisationToken` trait impl (`src/uwill/invocation.rs:418`)
provides `is_authorised_write(entry)` which calls
`self.validate_write(entry).is_ok()`. This is defense-in-depth for
internal DB reads and trusted paths — it does NOT check revocation.
The real security boundary for untrusted entries is the
`static_tokens.rs` + `data.rs` / `reconciler.rs` pipeline described
above.

## Step 7: Bob writes a reply

Same as Steps 2 + 6, but in reverse direction:

1. Bob's node builds a write invocation (local) at path
   `messages/reply`, referencing Bob's delegated write chain
2. -> Bob's node sends the entry + tokens over the wire to Alice
3. <- Alice's node receives and validates them (local — same pipeline
   as 6b-6c: stateless validation + revocation check against Alice's
   local store)
4. Alice's node ingests the entry (local)

---

**Test coverage:** `tests/basic.rs:owned_namespace_subspace_write_sync`,
`tests/spaces.rs:prop_sync_simulation_matches_model`
