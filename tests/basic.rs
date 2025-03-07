use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use futures_concurrency::future::TryJoin;
use futures_lite::StreamExt;
use iroh_base::SecretKey;
use iroh_blobs::store::{Map, MapEntry};
use iroh_io::AsyncSliceReaderExt;
use iroh_willow::{
    form::EntryForm,
    interest::{
        AreaSelector, CapSelector, DelegateTo, Interests, IntoAreaOfInterest, RestrictArea,
        UserSelector,
    },
    proto::{
        data_model::{NamespaceId, Path, PathExt},
        grouping::{Area, AreaExt, Range3d},
        keys::{NamespaceKind, UserId},
    },
    session::{
        intents::{Completion, EventKind},
        SessionInit, SessionMode,
    },
};
use meadowcap::AccessMode;
use tokio::time::sleep;
use util::spawn_three;

use self::util::{create_rng, insert, setup_and_delegate, spawn_two, Peer};

#[tokio::test(flavor = "multi_thread")]
async fn peer_manager_two_intents() -> Result<()> {
    iroh_test::logging::setup_multithreaded();
    let mut rng = create_rng("peer_manager_two_intents");

    let [alfie, betty] = spawn_two(&mut rng).await?;
    let (namespace, _alfie_user, betty_user) = setup_and_delegate(&alfie, &betty).await?;
    let betty_node_id = betty.node_id();

    insert(&betty, namespace, betty_user, &[b"foo", b"1"], "foo 1").await?;
    insert(&betty, namespace, betty_user, &[b"bar", b"2"], "bar 2").await?;
    insert(&betty, namespace, betty_user, &[b"bar", b"3"], "bar 3").await?;

    let task_foo_path = tokio::task::spawn({
        let alfie = alfie.clone();
        async move {
            let path = Path::from_bytes(&[b"foo"]).unwrap();

            let init = SessionInit::new(
                Interests::builder().add_area(namespace, [Area::new_path(path.clone())]),
                SessionMode::ReconcileOnce,
            );
            let mut intent = alfie.sync_with_peer(betty_node_id, init).await.unwrap();

            assert_eq!(
                intent.next().await.unwrap(),
                EventKind::CapabilityIntersection {
                    namespace,
                    area: Area::new_full(),
                }
            );

            assert_eq!(
                intent.next().await.unwrap(),
                EventKind::InterestIntersection {
                    namespace,
                    area: Area::new_path(path.clone()).into_area_of_interest()
                }
            );

            assert_eq!(
                intent.next().await.unwrap(),
                EventKind::Reconciled {
                    namespace,
                    area: Area::new_path(path.clone()).into_area_of_interest()
                }
            );

            assert_eq!(intent.next().await.unwrap(), EventKind::ReconciledAll);

            assert!(intent.next().await.is_none());
        }
    });

    let task_bar_path = tokio::task::spawn({
        let alfie = alfie.clone();
        async move {
            let path = Path::from_bytes(&[b"bar"]).unwrap();

            let interests =
                Interests::builder().add_area(namespace, [Area::new_path(path.clone())]);
            let init = SessionInit::new(interests, SessionMode::ReconcileOnce);

            let mut intent = alfie.sync_with_peer(betty_node_id, init).await.unwrap();

            assert_eq!(
                intent.next().await.unwrap(),
                EventKind::CapabilityIntersection {
                    namespace,
                    area: Area::new_full(),
                }
            );

            assert_eq!(
                intent.next().await.unwrap(),
                EventKind::InterestIntersection {
                    namespace,
                    area: Area::new_path(path.clone()).into_area_of_interest()
                }
            );

            assert_eq!(
                intent.next().await.unwrap(),
                EventKind::Reconciled {
                    namespace,
                    area: Area::new_path(path.clone()).into_area_of_interest()
                }
            );

            assert_eq!(intent.next().await.unwrap(), EventKind::ReconciledAll);

            assert!(intent.next().await.is_none());
        }
    });

    task_foo_path.await.unwrap();
    task_bar_path.await.unwrap();

    // tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    [alfie, betty].map(Peer::shutdown).try_join().await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_manager_update_intent() -> Result<()> {
    iroh_test::logging::setup_multithreaded();
    let mut rng = create_rng("peer_manager_update_intent");

    let [alfie, betty] = spawn_two(&mut rng).await?;
    let (namespace, _alfie_user, betty_user) = setup_and_delegate(&alfie, &betty).await?;
    let betty_node_id = betty.node_id();

    insert(&betty, namespace, betty_user, &[b"foo"], "foo 1").await?;
    insert(&betty, namespace, betty_user, &[b"bar"], "bar 1").await?;

    let path = Path::from_bytes(&[b"foo"]).unwrap();
    let interests = Interests::builder().add_area(namespace, [Area::new_path(path.clone())]);
    let init = SessionInit::new(interests, SessionMode::Continuous);
    let mut intent = alfie.sync_with_peer(betty_node_id, init).await.unwrap();

    assert_eq!(
        intent.next().await.unwrap(),
        EventKind::CapabilityIntersection {
            namespace,
            area: Area::new_full(),
        }
    );
    assert_eq!(
        intent.next().await.unwrap(),
        EventKind::InterestIntersection {
            namespace,
            area: Area::new_path(path.clone()).into_area_of_interest()
        }
    );
    assert_eq!(
        intent.next().await.unwrap(),
        EventKind::Reconciled {
            namespace,
            area: Area::new_path(path.clone()).into_area_of_interest()
        }
    );
    assert_eq!(intent.next().await.unwrap(), EventKind::ReconciledAll);

    let path = Path::from_bytes(&[b"bar"]).unwrap();
    let interests = Interests::builder().add_area(namespace, [Area::new_path(path.clone())]);
    intent.add_interests(interests).await?;

    assert_eq!(
        intent.next().await.unwrap(),
        EventKind::InterestIntersection {
            namespace,
            area: Area::new_path(path.clone()).into_area_of_interest()
        }
    );
    assert_eq!(
        intent.next().await.unwrap(),
        EventKind::Reconciled {
            namespace,
            area: Area::new_path(path.clone()).into_area_of_interest()
        }
    );

    assert_eq!(intent.next().await.unwrap(), EventKind::ReconciledAll);

    intent.close().await;

    assert!(intent.next().await.is_none());

    [alfie, betty].map(Peer::shutdown).try_join().await?;
    Ok(())
}

/// Test immediate shutdown.
// TODO: This does not really test much. Used it for log reading of graceful connection termination.
// Not sure where we should expose whether connections closed gracefully or not?
#[tokio::test(flavor = "multi_thread")]
async fn peer_manager_shutdown_immediate() -> Result<()> {
    iroh_test::logging::setup_multithreaded();
    let mut rng = create_rng("peer_manager_shutdown_immediate");

    let [alfie, betty] = spawn_two(&mut rng).await?;
    let (_namespace, _alfie_user, _betty_user) = setup_and_delegate(&alfie, &betty).await?;
    let betty_node_id = betty.node_id();
    let mut intent = alfie
        .sync_with_peer(betty_node_id, SessionInit::reconcile_once(Interests::all()))
        .await?;
    let completion = intent.complete().await?;
    assert_eq!(completion, Completion::Complete);
    [alfie, betty].map(Peer::shutdown).try_join().await?;
    Ok(())
}

/// Test shutdown after a timeout.
// TODO: This does not really test much. Used it for log reading of graceful connection termination.
// Not sure where we should expose whether connections closed gracefully or not?
#[tokio::test(flavor = "multi_thread")]
async fn peer_manager_shutdown_timeout() -> Result<()> {
    iroh_test::logging::setup_multithreaded();
    let mut rng = create_rng("peer_manager_shutdown_timeout");

    let [alfie, betty] = spawn_two(&mut rng).await?;
    let (_namespace, _alfie_user, _betty_user) = setup_and_delegate(&alfie, &betty).await?;
    let betty_node_id = betty.node_id();
    let mut intent = alfie
        .sync_with_peer(betty_node_id, SessionInit::reconcile_once(Interests::all()))
        .await?;
    let completion = intent.complete().await?;
    assert_eq!(completion, Completion::Complete);
    tokio::time::sleep(Duration::from_secs(1)).await;
    [alfie, betty].map(Peer::shutdown).try_join().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_manager_twoway_loop() -> Result<()> {
    iroh_test::logging::setup_multithreaded();
    let mut rng = create_rng("peer_manager_twoway_loop");

    let [alfie, betty] = spawn_two(&mut rng).await?;
    let (namespace, alfie_user, betty_user) = setup_and_delegate(&alfie, &betty).await?;
    insert(&alfie, namespace, alfie_user, &[b"foo"], "foo 1").await?;
    insert(&betty, namespace, betty_user, &[b"bar"], "bar 1").await?;
    let alfie_node_id = alfie.node_id();
    let betty_node_id = betty.node_id();
    let rounds = 20;
    for i in 0..rounds {
        println!("\n\nROUND {i} of {rounds}\n\n");
        let alfie = alfie.clone();
        let betty = betty.clone();
        let task_alfie = tokio::task::spawn(async move {
            let mut intent = alfie
                .sync_with_peer(betty_node_id, SessionInit::reconcile_once(Interests::all()))
                .await
                .unwrap();
            let completion = intent.complete().await.expect("failed to complete intent");
            assert_eq!(completion, Completion::Complete);
        });

        let task_betty = tokio::task::spawn(async move {
            let mut intent = betty
                .sync_with_peer(alfie_node_id, SessionInit::reconcile_once(Interests::all()))
                .await
                .unwrap();
            let completion = intent.complete().await.expect("failed to complete intent");
            assert_eq!(completion, Completion::Complete);
        });
        task_alfie.await.unwrap();
        task_betty.await.unwrap();
    }
    [alfie, betty].map(Peer::shutdown).try_join().await?;
    Ok(())
}

/// Regression test. Used to fail due to redb's slices being unaligned,
/// and previously timestamps being represented as u64, thus failing to
/// zerocopy-deserialize.
#[tokio::test(flavor = "multi_thread")]
async fn read_back_write() -> Result<()> {
    iroh_test::logging::setup_multithreaded();
    let mut rng = create_rng("read_back_write");

    let alfie = Peer::spawn(SecretKey::generate(&mut rng), Default::default()).await?;

    let user_alfie = alfie.create_user().await?;
    let namespace_id = alfie
        .create_namespace(NamespaceKind::Owned, user_alfie)
        .await?;

    for i in 0u64..2 {
        let path = Path::from_bytes(&[b"foo", &i.to_le_bytes()])?;
        let entry = EntryForm::new_bytes(namespace_id, path, "foo");
        alfie.insert_entry(entry, user_alfie).await?;
    }

    let entries: Vec<_> = alfie
        .get_entries(namespace_id, Range3d::new_full())
        .await?
        .try_collect()
        .await?;

    println!("{entries:#?}");

    assert_eq!(entries.len(), 2);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn owned_namespace_subspace_write_sync() -> Result<()> {
    iroh_test::logging::setup_multithreaded();
    let mut rng = create_rng("owned_namespace_subspace_write_sync");

    let [alfie, betty] = spawn_two(&mut rng).await?;

    let user_alfie = alfie.create_user().await?;
    let user_betty = betty.create_user().await?;

    let namespace_id = alfie
        .create_namespace(NamespaceKind::Owned, user_alfie)
        .await?;

    let restriction = RestrictArea::Restrict(Area::new_subspace(user_betty));

    let cap_for_betty = alfie
        .delegate_caps(
            CapSelector::any(namespace_id),
            AccessMode::Write,
            DelegateTo::new(user_betty, restriction),
        )
        .await?;

    betty.import_caps(cap_for_betty).await?;

    // Insert an entry into our subspace.
    let path = Path::from_bytes(&[b"foo"])?;
    let entry = EntryForm::new_bytes(namespace_id, path, "foo");
    betty.insert_entry(entry, user_betty).await?;

    // Make sure we cannot write into alfie's subspace.
    let path = Path::from_bytes(&[b"foo"])?;
    let entry = EntryForm::new_bytes(namespace_id, path, "foo").subspace(user_alfie);
    assert!(betty.insert_entry(entry, user_betty).await.is_err());

    // Make sure sync runs correctl.y
    let init = SessionInit::new(
        Interests::builder().add_full_cap(namespace_id),
        SessionMode::ReconcileOnce,
    );
    let mut intent = alfie.sync_with_peer(betty.node_id(), init).await.unwrap();
    let completion = intent.complete().await.expect("failed to complete intent");
    assert_eq!(completion, Completion::Partial);
    let entries: Vec<_> = alfie
        .get_entries(namespace_id, Range3d::new_full())
        .await?
        .try_collect()
        .await?;
    assert_eq!(entries.len(), 1);

    Ok(())
}

mod util {
    use std::sync::{Arc, Mutex};

    use anyhow::Result;
    use bytes::Bytes;
    use futures_concurrency::future::TryJoin;
    use iroh::{Endpoint, NodeId};
    use iroh_willow::{
        engine::{AcceptOpts, Engine},
        form::EntryForm,
        interest::{CapSelector, DelegateTo, RestrictArea},
        proto::{
            data_model::{Path, PathExt},
            keys::{NamespaceId, NamespaceKind, UserId},
            meadowcap::AccessMode,
        },
        ALPN,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use rand_core::CryptoRngCore;
    use tokio::task::JoinHandle;

    pub fn create_rng(seed: &str) -> ChaCha12Rng {
        let seed = iroh_blobs::Hash::new(seed);
        ChaCha12Rng::from_seed(*(seed.as_bytes()))
    }

    #[derive(Debug, Clone)]
    pub struct Peer {
        pub blobs: iroh_blobs::store::mem::Store,
        endpoint: Endpoint,
        engine: Engine,
        accept_task: Arc<Mutex<Option<JoinHandle<Result<()>>>>>,
    }

    impl Peer {
        pub async fn spawn(secret_key: iroh::SecretKey, accept_opts: AcceptOpts) -> Result<Self> {
            let endpoint = Endpoint::builder()
                .secret_key(secret_key)
                .relay_mode(iroh::RelayMode::Disabled)
                .alpns(vec![ALPN.to_vec()])
                .bind()
                .await?;
            let blobs = iroh_blobs::store::mem::Store::default();
            let payloads = blobs.clone();
            let create_store = move || iroh_willow::store::memory::Store::new(payloads);
            let engine = Engine::spawn(endpoint.clone(), create_store, accept_opts);
            let accept_task = tokio::task::spawn({
                let engine = engine.clone();
                let endpoint = endpoint.clone();
                async move {
                    while let Some(incoming) = endpoint.accept().await {
                        let Ok(mut connecting) = incoming.accept() else {
                            continue;
                        };
                        let Ok(alpn) = connecting.alpn().await else {
                            continue;
                        };
                        if alpn != ALPN {
                            continue;
                        }
                        let Ok(conn) = connecting.await else {
                            continue;
                        };
                        engine.handle_connection(conn).await?;
                    }
                    Result::Ok(())
                }
            });
            Ok(Self {
                blobs,
                endpoint,
                engine,
                accept_task: Arc::new(Mutex::new(Some(accept_task))),
            })
        }

        pub async fn shutdown(self) -> Result<()> {
            let accept_task = self.accept_task.lock().unwrap().take();
            if let Some(accept_task) = accept_task {
                accept_task.abort();
                match accept_task.await {
                    Err(err) if err.is_cancelled() => {}
                    Ok(Ok(())) => {}
                    Err(err) => Err(err)?,
                    Ok(Err(err)) => Err(err)?,
                }
            }
            self.engine.shutdown().await?;
            self.endpoint.close().await?;
            Ok(())
        }

        pub fn node_id(&self) -> NodeId {
            self.endpoint.node_id()
        }
    }

    impl std::ops::Deref for Peer {
        type Target = Engine;
        fn deref(&self) -> &Self::Target {
            &self.engine
        }
    }

    pub async fn spawn_two(mut rng: &mut impl CryptoRngCore) -> Result<[Peer; 2]> {
        let peers = [
            iroh::SecretKey::generate(&mut rng),
            iroh::SecretKey::generate(&mut rng),
        ]
        .map(|secret_key| Peer::spawn(secret_key, Default::default()))
        .try_join()
        .await?;

        peers[0]
            .endpoint
            .add_node_addr(peers[1].endpoint.node_addr().await?)?;

        peers[1]
            .endpoint
            .add_node_addr(peers[0].endpoint.node_addr().await?)?;

        Ok(peers)
    }

    pub async fn spawn_three(rng: &mut impl CryptoRngCore) -> Result<[Peer; 3]> {
        let peers = [
            iroh_base::SecretKey::generate(&mut *rng),
            iroh_base::SecretKey::generate(&mut *rng),
            iroh_base::SecretKey::generate(&mut *rng),
        ]
        .map(|secret_key| Peer::spawn(secret_key, Default::default()))
        .try_join()
        .await?;

        peers[0]
            .endpoint
            .add_node_addr(peers[1].endpoint.node_addr().await?)?;

        peers[0]
            .endpoint
            .add_node_addr(peers[2].endpoint.node_addr().await?)?;

        peers[1]
            .endpoint
            .add_node_addr(peers[0].endpoint.node_addr().await?)?;

        peers[1]
            .endpoint
            .add_node_addr(peers[2].endpoint.node_addr().await?)?;

        peers[2]
            .endpoint
            .add_node_addr(peers[0].endpoint.node_addr().await?)?;

        peers[2]
            .endpoint
            .add_node_addr(peers[1].endpoint.node_addr().await?)?;

        Ok(peers)
    }

    pub async fn setup_and_delegate(
        alfie: &Engine,
        betty: &Engine,
    ) -> Result<(NamespaceId, UserId, UserId)> {
        let user_alfie = alfie.create_user().await?;
        let user_betty = betty.create_user().await?;

        let namespace_id = alfie
            .create_namespace(NamespaceKind::Owned, user_alfie)
            .await?;

        let cap_for_betty = alfie
            .delegate_caps(
                CapSelector::any(namespace_id),
                AccessMode::Write,
                DelegateTo::new(user_betty, RestrictArea::None),
            )
            .await?;

        betty.import_caps(cap_for_betty).await?;
        Ok((namespace_id, user_alfie, user_betty))
    }

    pub async fn insert(
        handle: &Engine,
        namespace_id: NamespaceId,
        user: UserId,
        path: &[&[u8]],
        bytes: impl Into<Bytes>,
    ) -> Result<()> {
        let path = Path::from_bytes(path)?;
        let entry = EntryForm::new_bytes(namespace_id, path, bytes);
        handle.insert_entry(entry, user).await?;
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_manager_empty_payload() -> Result<()> {
    iroh_test::logging::setup_multithreaded();
    let mut rng = create_rng("peer_manager_empty_payload");

    let [alfie, betty] = spawn_two(&mut rng).await?;
    let (namespace, _alfie_user, betty_user) = setup_and_delegate(&alfie, &betty).await?;
    let betty_node_id = betty.node_id();

    insert(&betty, namespace, betty_user, &[b"foo"], "").await?;

    let init = SessionInit::new(Interests::all(), SessionMode::ReconcileOnce);
    let mut intent = alfie.sync_with_peer(betty_node_id, init).await.unwrap();

    assert_eq!(
        intent.next().await.unwrap(),
        EventKind::CapabilityIntersection {
            namespace,
            area: Area::new_full(),
        }
    );

    assert_eq!(
        intent.next().await.unwrap(),
        EventKind::InterestIntersection {
            namespace,
            area: Area::new_full().into_area_of_interest()
        }
    );

    assert_eq!(
        intent.next().await.unwrap(),
        EventKind::Reconciled {
            namespace,
            area: Area::new_full().into_area_of_interest()
        }
    );

    assert_eq!(intent.next().await.unwrap(), EventKind::ReconciledAll);

    assert!(intent.next().await.is_none());

    [alfie, betty].map(Peer::shutdown).try_join().await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_manager_big_payload() -> Result<()> {
    iroh_test::logging::setup_multithreaded();
    let mut rng = create_rng("peer_manager_empty_payload");

    let [alfie, betty] = spawn_two(&mut rng).await?;
    let (namespace, _alfie_user, betty_user) = setup_and_delegate(&alfie, &betty).await?;
    let betty_node_id = betty.node_id();

    let payload = Bytes::from(vec![2u8; 1024 * 128]);
    insert(&betty, namespace, betty_user, &[b"foo"], payload.clone()).await?;

    let init = SessionInit::new(Interests::all(), SessionMode::ReconcileOnce);
    let mut intent = alfie.sync_with_peer(betty_node_id, init).await.unwrap();

    intent.complete().await?;

    let entries = alfie.get_entries(namespace, Range3d::new_full()).await?;
    let entries: Vec<_> = entries.try_collect().await?;
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    let hash: iroh_blobs::Hash = (*entry.entry().payload_digest()).into();
    let blob = alfie.blobs.get(&hash).await?.expect("missing blob");
    let actual = blob.data_reader().await?.read_to_end().await?;
    assert_eq!(actual.len(), payload.len());
    assert!(actual == payload);

    [alfie, betty].map(Peer::shutdown).try_join().await?;

    Ok(())
}

async fn delegate_path(
    path: Path,
    alfie: Peer,
    betty: Peer,
    user_alfie: UserId,
    user_betty: UserId,
    namespace_id: NamespaceId,
    session_mode: SessionMode,
) {
    let restricted_area = Area::new_path(path.clone());

    let cap_for_betty = alfie
        .delegate_caps(
            CapSelector::any(namespace_id),
            AccessMode::Read,
            DelegateTo::new(user_betty, RestrictArea::Restrict(restricted_area.clone())),
        )
        .await
        .unwrap();

    betty.import_caps(cap_for_betty).await.unwrap();

    let entry = EntryForm::new_bytes(namespace_id, path.clone(), "foo");

    alfie.insert_entry(entry, user_alfie).await.unwrap();

    let cap_selector = CapSelector::new(
        namespace_id,
        UserSelector::Any,
        AreaSelector::ContainsArea(restricted_area.clone()),
    );

    let interest = Interests::builder()
        .add_area(cap_selector.clone(), vec![restricted_area])
        .build();

    let init = SessionInit::new(interest, session_mode);

    let mut intent = betty.sync_with_peer(alfie.node_id(), init).await.unwrap();

    intent.complete().await.unwrap();

    intent.close().await;
}

#[ignore = "failing test - potential bug in the willow implementation"]
#[tokio::test(flavor = "multi_thread")]
async fn subsequent_cap_delegations() {
    iroh_test::logging::setup_multithreaded();
    let mut rng = create_rng("subsequent_cap_delegations");

    let [alfie, betty] = spawn_two(&mut rng).await.unwrap();

    let user_alfie = alfie.create_user().await.unwrap();
    let user_betty = betty.create_user().await.unwrap();

    let namespace_id = alfie
        .create_namespace(NamespaceKind::Owned, user_alfie)
        .await
        .unwrap();

    let shared_path1 = Path::from_bytes(&[b"1"]).unwrap();
    let shared_path2 = Path::from_bytes(&[b"2"]).unwrap();

    tokio::spawn({
        let alfie = alfie.clone();
        let betty = betty.clone();

        async move {
            delegate_path(
                shared_path1,
                alfie,
                betty,
                user_alfie,
                user_betty,
                namespace_id,
                SessionMode::Continuous,
            )
            .await;
        }
    });

    loop {
        let entries: Vec<_> = betty
            .get_entries(namespace_id, Range3d::new_full())
            .await
            .unwrap()
            .try_collect()
            .await
            .unwrap();

        tracing::info!("len should be 1, actual: {}", entries.len());

        if entries.len() == 1 {
            break;
        }

        sleep(Duration::from_secs(1)).await;
    }

    tokio::spawn({
        let alfie = alfie.clone();
        let betty = betty.clone();

        async move {
            delegate_path(
                shared_path2,
                alfie,
                betty,
                user_alfie,
                user_betty,
                namespace_id,
                SessionMode::Continuous,
            )
            .await;
        }
    });

    loop {
        let entries: Vec<_> = betty
            .get_entries(namespace_id, Range3d::new_full())
            .await
            .unwrap()
            .try_collect()
            .await
            .unwrap();

        tracing::info!("len should be 2, actual: {}", entries.len());

        if entries.len() == 2 {
            break;
        }

        sleep(Duration::from_secs(1)).await;
    }
}

#[ignore = "failing test - potential bug in the willow implementation"]
#[tokio::test(flavor = "multi_thread")]
async fn mutual_cap_delegations() {
    iroh_test::logging::setup_multithreaded();
    let mut rng = create_rng("mutual_cap_delegations");

    let [alfie, betty] = spawn_two(&mut rng).await.unwrap();

    let user_alfie = alfie.create_user().await.unwrap();
    let user_betty = betty.create_user().await.unwrap();

    let namespace_id = alfie
        .create_namespace(NamespaceKind::Owned, user_alfie)
        .await
        .unwrap();

    let alfie_path = Path::from_bytes(&[b"a"]).unwrap();
    let betty_path = Path::from_bytes(&[b"b"]).unwrap();

    tokio::spawn({
        let alfie = alfie.clone();
        let betty = betty.clone();
        let alfie_path = alfie_path.clone();

        async move {
            delegate_path(
                alfie_path,
                alfie,
                betty,
                user_alfie,
                user_betty,
                namespace_id,
                SessionMode::Continuous,
            )
            .await;
        }
    });

    loop {
        let entries: Vec<_> = betty
            .get_entries(namespace_id, Range3d::new_full())
            .await
            .unwrap()
            .try_collect()
            .await
            .unwrap();

        tracing::info!("alfie path delegated to betty: {:?}", entries);

        if entries.iter().any(|e| e.entry().path() == &alfie_path) {
            break;
        }

        sleep(Duration::from_secs(1)).await;
    }

    tokio::spawn({
        let alfie = alfie.clone();
        let betty = betty.clone();
        let betty_path = betty_path.clone();

        async move {
            delegate_path(
                betty_path,
                betty,
                alfie,
                user_betty,
                user_alfie,
                namespace_id,
                SessionMode::Continuous,
            )
            .await;
        }
    });

    loop {
        let entries: Vec<_> = alfie
            .get_entries(namespace_id, Range3d::new_full())
            .await
            .unwrap()
            .try_collect()
            .await
            .unwrap();

        tracing::info!("Betty path delegated to Alfie: {:?}", entries);

        if entries.iter().any(|e| e.entry().path() == &betty_path) {
            break;
        }

        sleep(Duration::from_secs(1)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn transitive_sync() -> Result<()> {
    iroh_test::logging::setup_multithreaded();
    let mut rng = create_rng("transitive_sync");

    let [alfie, betty, catty] = spawn_three(&mut rng).await?;

    let user_alfie = alfie.create_user().await?;
    let user_betty = betty.create_user().await?;
    let user_catty = catty.create_user().await?;

    let namespace_id = alfie
        .create_namespace(NamespaceKind::Owned, user_alfie)
        .await?;

    let a_path = Path::from_bytes(&[b"a"])?;
    let b_path = Path::from_bytes(&[b"b"])?;

    // issue read cap from aflie to betty

    let cap_for_betty = alfie
        .delegate_caps(
            CapSelector::any(namespace_id),
            AccessMode::Read,
            DelegateTo::new(user_betty, RestrictArea::None),
        )
        .await?;

    betty.import_caps(cap_for_betty).await?;

    let entry = EntryForm::new_bytes(namespace_id, a_path.clone(), "a_path");

    alfie.insert_entry(entry, user_alfie).await?;

    // sync alfie with betty

    let cap_selector = CapSelector::new(namespace_id, UserSelector::Any, AreaSelector::Widest);

    let interest = Interests::builder()
        .add_area(cap_selector.clone(), vec![Area::new_full()])
        .build();

    let init = SessionInit::new(interest.clone(), SessionMode::ReconcileOnce);

    let mut intent = betty.sync_with_peer(alfie.node_id(), init).await.unwrap();

    intent.complete().await.unwrap();

    // issue read cap from betty to catty

    let cap_for_catty = betty
        .delegate_caps(
            CapSelector::any(namespace_id),
            AccessMode::Read,
            DelegateTo::new(user_catty, RestrictArea::None),
        )
        .await?;

    catty.import_caps(cap_for_catty).await?;

    // update alfie's data

    let entry = EntryForm::new_bytes(namespace_id, b_path.clone(), "b_path");

    alfie.insert_entry(entry, user_alfie).await?;

    // close betty app

    betty.shutdown().await?;

    //sync catty with alfie

    let init = SessionInit::new(interest.clone(), SessionMode::ReconcileOnce);

    let mut intent = catty.sync_with_peer(alfie.node_id(), init).await.unwrap();

    intent.complete().await.unwrap();

    //check catty's entries

    let entries: Vec<_> = catty
        .get_entries(namespace_id, Range3d::new_full())
        .await?
        .try_collect()
        .await?;

    tracing::warn!("Catty after sync: {:#?}", entries);

    let caps: Vec<_> = catty.list_read_caps().await?;

    tracing::warn!("Catty's caps: {:#?}", caps);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_with_replica() -> Result<()> {
    iroh_test::logging::setup_multithreaded();
    let mut rng = create_rng("sync_with_replica");

    let [alfie, betty, catty] = spawn_three(&mut rng).await?;

    let user_alfie = alfie.create_user().await?;
    let user_betty = betty.create_user().await?;
    let user_catty = catty.create_user().await?;

    let namespace_id = alfie
        .create_namespace(NamespaceKind::Owned, user_alfie)
        .await?;

    let a_path = Path::from_bytes(&[b"a"])?;
    let b_path = Path::from_bytes(&[b"b"])?;

    // issue read cap from aflie to betty

    let cap_for_betty = alfie
        .delegate_caps(
            CapSelector::any(namespace_id),
            AccessMode::Write,
            DelegateTo::new(user_betty, RestrictArea::None),
        )
        .await?;

    let cap_for_catty = alfie
        .delegate_caps(
            CapSelector::any(namespace_id),
            AccessMode::Read,
            DelegateTo::new(user_catty, RestrictArea::None),
        )
        .await?;

    betty.import_caps(cap_for_betty).await?;
    catty.import_caps(cap_for_catty).await?;

    let entry = EntryForm::new_bytes(namespace_id, a_path.clone(), "a_path");

    alfie.insert_entry(entry, user_alfie).await?;

    // sync alfie with betty

    let cap_selector = CapSelector::new(namespace_id, UserSelector::Any, AreaSelector::Widest);

    let interest = Interests::builder()
        .add_area(cap_selector.clone(), vec![Area::new_full()])
        .build();

    let init = SessionInit::new(interest.clone(), SessionMode::ReconcileOnce);

    let mut intent = betty.sync_with_peer(alfie.node_id(), init).await.unwrap();

    intent.complete().await.unwrap();

    // issue read cap from betty to catty

    let cap_for_catty = betty
        .delegate_caps(
            CapSelector::any(namespace_id),
            AccessMode::Read,
            DelegateTo::new(user_catty, RestrictArea::None),
        )
        .await?;

    catty.import_caps(cap_for_catty).await?;

    // update alfie's data via betty node

    let entry = EntryForm::new_bytes(namespace_id, b_path.clone(), "b_path");

    betty.insert_entry(entry, user_betty).await?;

    // close alfie app

    alfie.shutdown().await?;

    //sync catty with alfie

    let init = SessionInit::new(interest.clone(), SessionMode::ReconcileOnce);

    let mut intent = catty.sync_with_peer(betty.node_id(), init).await.unwrap();

    intent.complete().await.unwrap();

    //check catty's entries

    let entries: Vec<_> = catty
        .get_entries(namespace_id, Range3d::new_full())
        .await?
        .try_collect()
        .await?;

    tracing::warn!("Catty after sync: {:#?}", entries);

    let caps: Vec<_> = catty.list_read_caps().await?;

    tracing::warn!("Catty's caps: {:#?}", caps);

    Ok(())
}
