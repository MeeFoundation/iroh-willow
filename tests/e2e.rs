//! End-to-end tests for UWill capability system.
//!
//! These tests exercise complete user stories through the public API
//! only (Engine / Client / Space). No internal component access.

#![allow(clippy::indexing_slicing)]

use std::{sync::Arc, time::Duration};

use anyhow::Result;
use iroh::{address_lookup::memory::MemoryLookup, Endpoint, EndpointAddr, SecretKey};
use iroh_willow::{
    engine::AcceptOpts,
    interest::{CapSelector, DelegateTo, RestrictArea},
    proto::{
        data_model::{Path, PathExt},
        grouping::Area,
        keys::NamespaceKind,
        meadowcap::AccessMode,
    },
    rpc::client::{Client, EntryForm, Space},
    session::{intents::Completion, SessionMode},
    Engine,
};
use testresult::TestResult;
use willow_data_model::grouping::{AreaSubspace, Range, RangeEnd};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

type BoxedClient = Client<quic_rpc::client::BoxedConnector<iroh_willow::rpc::proto::RpcService>>;
type BoxedSpace = Space<quic_rpc::client::BoxedConnector<iroh_willow::rpc::proto::RpcService>>;

struct TestNode {
    client: BoxedClient,
    blobs: iroh_blobs::store::mem::MemStore,
    addr: EndpointAddr,
    _router: iroh::protocol::Router,
}

impl TestNode {
    async fn spawn(lookup: MemoryLookup) -> Self {
        let blobs_store = iroh_blobs::store::mem::MemStore::default();
        let secret_key = SecretKey::from(rand::random::<[u8; 32]>());
        let endpoint = Endpoint::empty_builder()
            .secret_key(secret_key)
            .alpns(vec![iroh_willow::ALPN.to_vec()])
            .address_lookup(lookup)
            .clear_ip_transports()
            .bind_addr((std::net::Ipv4Addr::LOCALHOST, 0u16))
            .unwrap()
            .bind()
            .await
            .unwrap();

        let store = blobs_store.clone();
        let engine = Engine::spawn(
            endpoint.clone(),
            move || iroh_willow::store::memory::Store::new(store),
            AcceptOpts::default(),
        );

        let client = engine.client().clone().boxed();
        let addr = endpoint.addr();

        let router = iroh::protocol::Router::builder(endpoint)
            .accept(iroh_willow::ALPN, Arc::new(engine))
            .spawn();

        Self {
            client,
            blobs: blobs_store,
            addr,
            _router: router,
        }
    }

    fn client(&self) -> &BoxedClient {
        &self.client
    }
}

async fn spawn_pair() -> (TestNode, TestNode) {
    let lookup = MemoryLookup::new();
    let alice = TestNode::spawn(lookup.clone()).await;
    let bob = TestNode::spawn(lookup.clone()).await;
    lookup.add_endpoint_info(alice.addr.clone());
    lookup.add_endpoint_info(bob.addr.clone());
    (alice, bob)
}

/// Wait for an entry to appear at the given path, polling with timeout.
async fn wait_for_entry(
    space: &BoxedSpace,
    subspace: iroh_willow::proto::data_model::SubspaceId,
    path: &Path,
    timeout: Duration,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if space.get_one(subspace, path.clone()).await?.is_some() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("timeout waiting for entry at {path:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Sync once between two nodes and wait for completion.
async fn sync_once(space: &BoxedSpace, peer_addr: &EndpointAddr) -> Result<()> {
    let mut sync = space
        .sync_once(
            peer_addr.id,
            iroh_willow::interest::AreaOfInterestSelector::Widest,
        )
        .await?;
    let completion = tokio::time::timeout(Duration::from_secs(10), sync.complete()).await??;
    assert_eq!(completion, Completion::Complete);
    Ok(())
}

// ---------------------------------------------------------------------------
// E2E scenarios
// ---------------------------------------------------------------------------

/// Alice creates a namespace, writes an entry, shares with Bob.
/// Bob syncs and reads the entry.
#[tokio::test]
async fn e2e_write_sync() -> TestResult {
    iroh_test::logging::setup_multithreaded();
    let (alice, bob) = spawn_pair().await;

    let user_alice = alice.client().create_user().await?;
    let user_bob = bob.client().create_user().await?;

    // Alice creates namespace + writes
    let space_alice = alice
        .client()
        .create(NamespaceKind::Owned, user_alice)
        .await?;
    let path = Path::from_bytes(&[b"hello"])?;
    space_alice
        .insert_bytes(
            &alice.blobs,
            EntryForm::new(user_alice, path.clone()),
            b"world".to_vec(),
        )
        .await?;

    // Alice shares with Bob
    let ticket = space_alice
        .share(user_bob, AccessMode::Write, RestrictArea::None)
        .await?;

    // Bob imports and syncs
    let (space_bob, syncs) = bob
        .client()
        .import_and_sync(ticket, SessionMode::ReconcileOnce)
        .await?;
    let mut completions = syncs.complete_all().await;
    let completion = completions.remove(&alice.addr.id).unwrap()?;
    assert_eq!(completion, Completion::Complete);

    // Bob reads the entry
    let entry = space_bob.get_one(user_alice.into(), path).await?;
    assert!(entry.is_some(), "Bob should see Alice's entry");

    Ok(())
}

/// Both peers write entries, sync, both see all entries.
#[tokio::test]
async fn e2e_bidirectional_sync() -> TestResult {
    iroh_test::logging::setup_multithreaded();
    let (alice, bob) = spawn_pair().await;

    let user_alice = alice.client().create_user().await?;
    let user_bob = bob.client().create_user().await?;

    // Alice creates namespace
    let space_alice = alice
        .client()
        .create(NamespaceKind::Owned, user_alice)
        .await?;

    // Share with Bob (write access)
    let ticket = space_alice
        .share(user_bob, AccessMode::Write, RestrictArea::None)
        .await?;
    let (space_bob, syncs) = bob
        .client()
        .import_and_sync(ticket, SessionMode::ReconcileOnce)
        .await?;
    syncs.complete_all().await;

    // Both write entries
    let path_alice = Path::from_bytes(&[b"from_alice"])?;
    let path_bob = Path::from_bytes(&[b"from_bob"])?;
    space_alice
        .insert_bytes(
            &alice.blobs,
            EntryForm::new(user_alice, path_alice.clone()),
            b"hi from alice".to_vec(),
        )
        .await?;
    space_bob
        .insert_bytes(
            &bob.blobs,
            EntryForm::new(user_bob, path_bob.clone()),
            b"hi from bob".to_vec(),
        )
        .await?;

    // Sync from Alice's side
    sync_once(&space_alice, &bob.addr).await?;
    // Sync from Bob's side
    sync_once(&space_bob, &alice.addr).await?;

    // Both should see both entries
    assert!(
        space_alice
            .get_one(user_bob.into(), path_bob)
            .await?
            .is_some(),
        "Alice should see Bob's entry"
    );
    assert!(
        space_bob
            .get_one(user_alice.into(), path_alice)
            .await?
            .is_some(),
        "Bob should see Alice's entry"
    );

    Ok(())
}

/// Alice delegates restricted access to Bob. Bob syncs via ticket and
/// sees only the data in his granted area.
#[tokio::test]
async fn e2e_capability_delegation() -> TestResult {
    iroh_test::logging::setup_multithreaded();
    let (alice, bob) = spawn_pair().await;

    let user_alice = alice.client().create_user().await?;
    let user_bob = bob.client().create_user().await?;

    // Alice creates namespace
    let space_alice = alice
        .client()
        .create(NamespaceKind::Owned, user_alice)
        .await?;
    let ns = space_alice.namespace_id();

    // Alice writes entries in different areas
    let docs_path = Path::from_bytes(&[b"docs", b"readme"])?;
    let secret_path = Path::from_bytes(&[b"secrets", b"key"])?;
    space_alice
        .insert_bytes(
            &alice.blobs,
            EntryForm::new(user_alice, docs_path.clone()),
            b"hello docs".to_vec(),
        )
        .await?;
    space_alice
        .insert_bytes(
            &alice.blobs,
            EntryForm::new(user_alice, secret_path.clone()),
            b"top secret".to_vec(),
        )
        .await?;

    // Share with Bob via ticket (restricted to "docs/" path)
    let restricted_area = Area::new(
        AreaSubspace::Any,
        Path::from_bytes(&[b"docs"])?,
        Range::new(0, RangeEnd::Open),
    );
    let ticket = space_alice
        .share(
            user_bob,
            AccessMode::Write,
            RestrictArea::Restrict(restricted_area),
        )
        .await?;

    // Bob imports ticket and syncs
    let (space_bob, syncs) = bob
        .client()
        .import_and_sync(ticket, SessionMode::ReconcileOnce)
        .await?;
    let mut completions = syncs.complete_all().await;
    let completion = completions.remove(&alice.addr.id).unwrap()?;
    assert_eq!(completion, Completion::Complete);

    // Bob should see docs/readme
    assert!(
        space_bob
            .get_one(user_alice.into(), docs_path)
            .await?
            .is_some(),
        "Bob should see docs/readme"
    );

    // Bob should NOT see secrets/key (outside his granted area)
    assert!(
        space_bob
            .get_one(user_alice.into(), secret_path)
            .await?
            .is_none(),
        "Bob should NOT see secrets/key"
    );

    Ok(())
}

/// Two unrelated namespaces. Peers connect, sync, neither sees the other's data.
#[tokio::test]
async fn e2e_no_overlap_no_sync() -> TestResult {
    iroh_test::logging::setup_multithreaded();
    let (alice, bob) = spawn_pair().await;

    let user_alice = alice.client().create_user().await?;
    let user_bob = bob.client().create_user().await?;

    // Each creates their own namespace
    let space_alice = alice
        .client()
        .create(NamespaceKind::Owned, user_alice)
        .await?;
    let space_bob = bob
        .client()
        .create(NamespaceKind::Owned, user_bob)
        .await?;

    // Each writes to their own namespace
    space_alice
        .insert_bytes(
            &alice.blobs,
            EntryForm::new(user_alice, Path::from_bytes(&[b"secret"])?),
            b"alice-only".to_vec(),
        )
        .await?;
    space_bob
        .insert_bytes(
            &bob.blobs,
            EntryForm::new(user_bob, Path::from_bytes(&[b"secret"])?),
            b"bob-only".to_vec(),
        )
        .await?;

    // They connect and try to sync — no shared namespaces.
    // PAI finds no overlap; nothing should be exchanged.
    let init = iroh_willow::session::SessionInit::new(
        iroh_willow::interest::Interests::All,
        SessionMode::ReconcileOnce,
    );
    let _intent = alice.client().sync_with_peer(bob.addr.id, init).await?;

    // Give the session time to run PAI and (not) exchange data.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Neither should see the other's data
    assert!(
        space_alice
            .get_one(user_bob.into(), Path::from_bytes(&[b"secret"])?)
            .await?
            .is_none(),
        "Alice should NOT see Bob's entry"
    );
    assert!(
        space_bob
            .get_one(user_alice.into(), Path::from_bytes(&[b"secret"])?)
            .await?
            .is_none(),
        "Bob should NOT see Alice's entry"
    );

    Ok(())
}

/// Continuous sync: Alice inserts after session starts, Bob receives it.
#[tokio::test]
async fn e2e_continuous_sync() -> TestResult {
    iroh_test::logging::setup_multithreaded();
    let (alice, bob) = spawn_pair().await;

    let user_alice = alice.client().create_user().await?;
    let user_bob = bob.client().create_user().await?;

    let space_alice = alice
        .client()
        .create(NamespaceKind::Owned, user_alice)
        .await?;

    // Share with Bob
    let ticket = space_alice
        .share(user_bob, AccessMode::Write, RestrictArea::None)
        .await?;
    let (space_bob, _syncs) = bob
        .client()
        .import_and_sync(ticket, SessionMode::Continuous)
        .await?;

    // Start continuous sync from Alice's side
    let _sync = space_alice
        .sync_continuously(
            bob.addr.id,
            iroh_willow::interest::AreaOfInterestSelector::Widest,
        )
        .await?;

    // Alice inserts AFTER sync starts
    tokio::time::sleep(Duration::from_millis(200)).await;
    let path = Path::from_bytes(&[b"live_data"])?;
    space_alice
        .insert_bytes(
            &alice.blobs,
            EntryForm::new(user_alice, path.clone()),
            b"live!".to_vec(),
        )
        .await?;

    // Bob should receive it via the open session
    wait_for_entry(&space_bob, user_alice.into(), &path, Duration::from_secs(5)).await?;

    Ok(())
}

/// Share via SpaceTicket: Alice shares, Bob imports and syncs.
#[tokio::test]
async fn e2e_ticket_sharing() -> TestResult {
    iroh_test::logging::setup_multithreaded();
    let (alice, bob) = spawn_pair().await;

    let user_alice = alice.client().create_user().await?;
    let user_bob = bob.client().create_user().await?;

    let space_alice = alice
        .client()
        .create(NamespaceKind::Owned, user_alice)
        .await?;

    // Write some data
    let path = Path::from_bytes(&[b"file"])?;
    space_alice
        .insert_bytes(
            &alice.blobs,
            EntryForm::new(user_alice, path.clone()),
            b"content".to_vec(),
        )
        .await?;

    // Create ticket (read-only)
    let ticket = space_alice
        .share(user_bob, AccessMode::Read, RestrictArea::None)
        .await?;

    // Bob imports ticket and syncs
    let (space_bob, syncs) = bob
        .client()
        .import_and_sync(ticket, SessionMode::ReconcileOnce)
        .await?;
    let mut completions = syncs.complete_all().await;
    let completion = completions.remove(&alice.addr.id).unwrap()?;
    assert_eq!(completion, Completion::Complete);

    // Bob should see the data
    let entry = space_bob.get_one(user_alice.into(), path).await?;
    assert!(entry.is_some(), "Bob should see Alice's file via ticket");

    Ok(())
}
