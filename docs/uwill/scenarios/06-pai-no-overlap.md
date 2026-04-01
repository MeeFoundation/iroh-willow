# Scenario 6: Alice and Carol have nothing in common

Alice's node serves namespace A. Carol's node serves namespace B.
They connect, run PAI, discover no overlapping interests. No data
is exchanged.

---

## Setup (local — each node independently)

Alice and Carol each have their own namespace with full read+write
capabilities. Same as [Scenario 1](01-happy-path-write-sync.md) Step 1,
done independently by each. No data exchanged yet.

## Nodes connect (over the wire)

Alice and Carol discover each other (via mDNS, relay, or gossip) and
establish a QUIC connection. The Willow sync protocol begins.

## PAI runs — same as Scenario 1 Step 5a-5b

### Fragment generation (local — each node independently)

Each peer submits their own `ReadAuthorisation` to their local PAI
finder and generates fragments. No data crosses the wire in this step.

> `src/session/pai_finder.rs:167` `submit_authorisation`
> `src/proto/pai.rs:71` `get_fragment_kit`

Before fragment generation, each node runs a local expiry filter on
its own read caps: if a read capability is expired or not yet valid,
it is silently skipped. The peer never sees expired caps.

> `src/session/pai_finder.rs:173-180`

Alice generates fragments for namespace A. Carol generates fragments
for namespace B.

### Fragment exchange (over the wire — blinded, no capability details visible)

The fragments are hashed into Ristretto255 group elements, blinded
with random scalars, and exchanged over the wire. Only blinded group
elements are sent — no namespace IDs, paths, or capability details
are visible to either peer.

> `src/session/pai_finder.rs:225` `submit_fragment` (local blinding, then -> sent over wire)
> `src/session/pai_finder.rs:243` `receive_bind` (<- received from peer, local double-blinding, then -> reply sent over wire)

## Intersection check — no match (local — each node independently)

After exchanging and double-blinding, each peer locally checks for
matching group values:

> `src/session/pai_finder.rs:274` `check_for_intersection`

Alice's fragments hash to different Ristretto points than Carol's
(different namespace IDs produce different hashes). The doubly-blinded
values don't match for any pair.

`completes_with()` (line 480) returns `false` for every combination.

No `NewIntersection` output is yielded. No capability binding occurs.

## Session completes — nothing synced

The reconciliation phase has no areas of interest to reconcile. The
session completes with `Completion::Complete` (all interests
satisfied — vacuously, since there are none).

No entries are exchanged. No data leaks. Neither peer learns what
namespaces the other serves — only that they share no common ones.
The PAI protocol only exchanged blinded group elements, so no
namespace or capability information was revealed.

Note: if either peer had tried to bind a read capability, it would
be sent over the wire as a UCAN invocation (`SetupBindReadCapability`
carries a `SerdeUWillInvocation` with the read chain + challenge
nonce). The receiving node would validate it locally via
`validate_common()` + `run_syntatic_checks()` + challenge check +
`proves_read()`. But since no intersection is found, this never
happens — no capability details are ever exchanged.

---

**Test coverage:** `session::pai_finder::tests::pai_different_namespaces`
