use std::path::PathBuf;

use bytes::Bytes;
use futures_lite::StreamExt as _;
use iroh::Endpoint;
use iroh_blobs::{api, BlobFormat};
use tempfile::tempdir;

// Exercise PayloadForm::{File,Stream,Reader} via submit against a MemStore.
#[tokio::test(flavor = "multi_thread")]
async fn payload_form_variants_submit() -> anyhow::Result<()> {
    // MemStore client handle
    let store = iroh_blobs::store::mem::MemStore::new();
    let blobs = store.as_ref();

    // 1) File variant
    let tmp = tempdir()?;
    let path = tmp.path().join("data.bin");
    let content_file = b"hello-file".to_vec();
    std::fs::write(&path, &content_file)?;
    let (hash_f, len_f) = iroh_willow::form::PayloadForm::File(
        PathBuf::from(&path),
        iroh_blobs::api::blobs::ImportMode::Copy,
    )
    .submit(blobs)
    .await?;
    assert_eq!(len_f as usize, content_file.len());
    assert!(blobs.blobs().has(hash_f).await?);
    let roundtrip = blobs.blobs().get_bytes(hash_f).await?;
    assert_eq!(roundtrip, Bytes::from(content_file.clone()));

    // 2) Stream variant
    let chunks = vec![
        Ok(Bytes::from_static(b"stream-")),
        Ok(Bytes::from_static(b"content")),
    ];
    let stream = futures_lite::stream::iter(chunks);
    let (hash_s, len_s) = iroh_willow::form::PayloadForm::Stream(Box::new(stream))
        .submit(blobs)
        .await?;
    assert_eq!(len_s as usize, b"stream-content".len());
    let data_s = blobs.blobs().get_bytes(hash_s).await?;
    assert_eq!(data_s, Bytes::from_static(b"stream-content"));

    // 3) Reader variant
    let reader_data = Bytes::from_static(b"reader-content");
    let (mut tx, rx) = tokio::io::duplex(64);
    let writer_task = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt as _;
        tx.write_all(&reader_data).await.ok();
    });
    let (hash_r, len_r) = iroh_willow::form::PayloadForm::Reader(Box::new(rx))
        .submit(blobs)
        .await?;
    writer_task.await.ok();
    assert_eq!(len_r as usize, b"reader-content".len());
    let data_r = blobs.blobs().get_bytes(hash_r).await?;
    assert_eq!(data_r, Bytes::from_static(b"reader-content"));

    Ok(())
}

// Check add_* progress events and final tag/hash for add_bytes.
#[tokio::test(flavor = "multi_thread")]
async fn blobs_add_bytes_progress_and_result() -> anyhow::Result<()> {
    let store = iroh_blobs::store::mem::MemStore::new();
    let blobs: &api::Store = store.as_ref();

    let progress1 = blobs
        .blobs()
        .add_bytes_with_opts((Bytes::from_static(b"progress-bytes"), BlobFormat::Raw));
    let mut saw_size = false;
    let mut stream = progress1.stream().await;
    while let Some(item) = stream.next().await {
        use iroh_blobs::api::blobs::AddProgressItem as I;
        match item {
            I::Size(_) => saw_size = true,
            I::Done(_) => break,
            I::CopyProgress(_) | I::CopyDone | I::OutboardProgress(_) => {}
            I::Error(e) => return Err(e.into()),
        }
    }
    assert!(saw_size, "expected Size event");

    // Also validate final tag/hash
    let info = blobs
        .blobs()
        .add_bytes_with_opts((Bytes::from_static(b"progress-bytes"), BlobFormat::Raw))
        .with_tag()
        .await?;
    assert!(blobs.blobs().has(info.hash).await?);

    Ok(())
}

// Exercise RPC client methods: node_addr and insert_bytes.
#[tokio::test(flavor = "multi_thread")]
async fn rpc_client_addr_and_insert_bytes() -> anyhow::Result<()> {
    let secret_a = iroh::SecretKey::from(rand::random::<[u8; 32]>());

    let ep_a = Endpoint::empty_builder(iroh::RelayMode::Disabled)
        .secret_key(secret_a)
        .alpns(vec![iroh_willow::ALPN.to_vec()])
        .clear_ip_transports()
        .bind_addr((std::net::Ipv4Addr::LOCALHOST, 0u16))?
        .bind()
        .await?;

    // payload store
    let blobs_a = iroh_blobs::store::mem::MemStore::new();

    // engine
    let eng_a = iroh_willow::engine::Engine::spawn(
        ep_a.clone(),
        {
            let payloads = blobs_a.clone();
            move || iroh_willow::store::memory::Store::new(payloads.clone())
        },
        Default::default(),
    );

    // Client for A
    let client_a = eng_a.client().clone();
    // EndpointAddr via RPC should match endpoint addr
    let addr_a_rpc = client_a.node_addr().await?;
    let addr_a_local = ep_a.addr();
    assert_eq!(addr_a_rpc.id, addr_a_local.id);

    // Exercise insert_bytes via client
    let user_a = client_a.create_user().await?;
    let space = client_a
        .create(iroh_willow::proto::keys::NamespaceKind::Owned, user_a)
        .await?;
    use iroh_willow::proto::data_model::PathExt;
    let path = iroh_willow::proto::data_model::Path::from_bytes(&[b"rpc", b"insert"])?;
    let entry = iroh_willow::rpc::client::EntryForm::new(user_a, path);
    let payload = Bytes::from_static(b"rpc-insert-bytes");
    space
        .insert_bytes(blobs_a.as_ref(), entry, payload.clone())
        .await?;

    // Verify content exists in A's store
    let hashes = blobs_a.blobs().list().hashes().await?;
    assert!(!hashes.is_empty());

    // Cleanup
    eng_a.shutdown().await?;
    ep_a.close().await;
    Ok(())
}
