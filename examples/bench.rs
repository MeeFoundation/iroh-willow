use std::time::Instant;

use anyhow::Result;
use futures_lite::StreamExt;
use iroh_willow::{
    interest::Interests,
    proto::grouping::Range3d,
    session::{intents::Completion, SessionInit, SessionMode},
};
use tracing::info;

use self::util::{create_rng, insert, parse_env_var, setup_and_delegate, spawn_two};

#[tokio::main]
async fn main() -> Result<()> {
    let t = Instant::now();
    tracing_subscriber::fmt::init();
    let n_betty: usize = parse_env_var("N_BETTY", 100);
    let n_alfie: usize = parse_env_var("N_ALFIE", 100);
    let mut rng = create_rng("peer_manager_two_intents");

    let start = Instant::now();
    let [alfie, betty] = spawn_two(&mut rng).await?;
    let (namespace, alfie_user, betty_user) = setup_and_delegate(&alfie, &betty).await?;
    info!(t=?t.elapsed(), d=?start.elapsed(), "setup done");

    let start = Instant::now();
    for i in 0..n_alfie {
        let x = format!("{i}");
        insert(
            &alfie,
            namespace,
            alfie_user,
            &[b"alfie", x.as_bytes()],
            "foo",
        )
        .await?;
    }
    for i in 0..n_betty {
        let x = format!("{i}");
        insert(
            &betty,
            namespace,
            betty_user,
            &[b"betty", x.as_bytes()],
            "foo",
        )
        .await?;
    }
    info!(t=?t.elapsed(), d=?start.elapsed(), "insert done");

    let start = Instant::now();
    let init = SessionInit::new(Interests::all(), SessionMode::ReconcileOnce);
    let mut intent_alfie = alfie
        .sync_with_peer(betty.id(), init.clone())
        .await
        .unwrap();
    let mut intent_betty = betty.sync_with_peer(alfie.id(), init).await.unwrap();
    let completion_alfie = intent_alfie.complete().await?;
    // info!(t=?t.elapsed(), d=?start.elapsed(), "alfie done");
    // let start = Instant::now();
    let completion_betty = intent_betty.complete().await?;
    info!(t=?t.elapsed(), d=?start.elapsed(), "sync done");

    let time = start.elapsed();
    let total = n_alfie + n_betty;
    let per_entry = time.as_micros() / total as u128;
    let entries_per_second = (total as f32 / time.as_secs_f32()).round();
    info!(time=?time, ms_per_entry=per_entry, entries_per_second, "sync done");

    assert_eq!(completion_alfie, Completion::Complete);
    assert_eq!(completion_betty, Completion::Complete);
    let start = Instant::now();
    let alfie_count = alfie
        .get_entries(namespace, Range3d::new_full())
        .await?
        .count()
        .await;
    let betty_count = betty
        .get_entries(namespace, Range3d::new_full())
        .await?
        .count()
        .await;
    info!(t=?t.elapsed(), d=?start.elapsed(), "get done");
    info!("alfie has now {} entries", alfie_count);
    info!("betty has now {} entries", betty_count);
    assert_eq!(alfie_count, n_alfie + n_betty);
    assert_eq!(betty_count, n_alfie + n_betty);
    alfie.shutdown().await?;
    betty.shutdown().await?;

    Ok(())
}

mod util {
    use std::sync::{Arc, Mutex};

    use anyhow::Result;
    use bytes::Bytes;
    use futures_concurrency::future::TryJoin;
    use iroh::{address_lookup::memory::MemoryLookup, Endpoint, EndpointId};
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
        endpoint: Endpoint,
        engine: Engine,
        accept_task: Arc<Mutex<Option<JoinHandle<Result<()>>>>>,
    }

    impl Peer {
        pub async fn spawn(
            secret_key: iroh::SecretKey,
            accept_opts: AcceptOpts,
            lookup: MemoryLookup,
        ) -> Result<Self> {
            let endpoint = Endpoint::empty_builder(iroh::RelayMode::Disabled)
                .secret_key(secret_key)
                .alpns(vec![ALPN.to_vec()])
                .address_lookup(lookup)
                .clear_ip_transports()
                .bind_addr((std::net::Ipv4Addr::LOCALHOST, 0u16))?
                .bind()
                .await?;
            let blobs = iroh_blobs::store::mem::MemStore::default();
            let create_store = move || iroh_willow::store::memory::Store::new(blobs);
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
            self.endpoint.close().await;
            Ok(())
        }

        pub fn id(&self) -> EndpointId {
            self.endpoint.id()
        }
    }

    impl std::ops::Deref for Peer {
        type Target = Engine;
        fn deref(&self) -> &Self::Target {
            &self.engine
        }
    }

    pub async fn spawn_two(rng: &mut (impl CryptoRngCore + rand::Rng)) -> Result<[Peer; 2]> {
        let lookup = MemoryLookup::new();
        let peers = [
            iroh::SecretKey::from(rng.gen::<[u8; 32]>()),
            iroh::SecretKey::from(rng.gen::<[u8; 32]>()),
        ]
        .map(|secret_key| Peer::spawn(secret_key, Default::default(), lookup.clone()))
        .try_join()
        .await?;

        for peer in &peers {
            lookup.add_endpoint_info(peer.endpoint.addr());
        }

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

    pub fn parse_env_var<T>(var: &str, default: T) -> T
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Debug,
    {
        match std::env::var(var).as_deref() {
            Ok(val) => val
                .parse()
                .unwrap_or_else(|_| panic!("failed to parse environment variable {var}")),
            Err(_) => default,
        }
    }
}
