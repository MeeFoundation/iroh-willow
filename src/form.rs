//! Structs that allow constructing entries and other structs where some fields may be
//! automatically filled.

use std::{io, path::PathBuf};

use bytes::Bytes;
use futures_lite::{Stream, StreamExt};
use iroh_blobs::api::blobs::ImportMode;
use iroh_blobs::{api, BlobFormat, Hash};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncRead;

use crate::proto::{
    data_model::{Entry, NamespaceId, Path, SubspaceId, Timestamp},
    keys::UserId,
    meadowcap::{self, WriteCapability},
};

/// Sources where payload data can come from.
#[derive(derive_more::Debug)]
pub enum PayloadForm {
    /// Set the payload hash directly. The blob must exist in the node's blob store, this will fail
    /// otherwise.
    Hash(Hash),
    /// Set the payload hash directly. The blob must exist in the node's blob store, this will fail
    /// otherwise.
    HashUnchecked(Hash, u64),
    /// Import data from the provided bytes and set as payload.
    #[debug("Bytes({})", _0.len())]
    Bytes(Bytes),
    /// Import data from a file on the node's local file system and set as payload.
    File(PathBuf, ImportMode),
    #[debug("Stream")]
    /// Import data from a [`Stream`] of bytes and set as payload.
    Stream(Box<dyn Stream<Item = io::Result<Bytes>> + Send + Sync + Unpin>),
    /// Import data from a [`AsyncRead`] and set as payload.
    #[debug("Reader")]
    Reader(Box<dyn AsyncRead + Send + Sync + Unpin>),
}

impl PayloadForm {
    pub async fn submit(self, store: &api::Store) -> anyhow::Result<(Hash, u64)> {
        let (hash, len) = match self {
            PayloadForm::Hash(digest) => {
                // Query blob status to retrieve size
                match store.blobs().status(digest).await? {
                    iroh_blobs::api::blobs::BlobStatus::Complete { size } => (digest, size),
                    iroh_blobs::api::blobs::BlobStatus::Partial { .. } => {
                        anyhow::bail!("hash found but not complete")
                    }
                    iroh_blobs::api::blobs::BlobStatus::NotFound => {
                        anyhow::bail!("hash not found")
                    }
                }
            }
            PayloadForm::HashUnchecked(digest, len) => (digest, len),
            PayloadForm::Bytes(bytes) => {
                let len = bytes.len();
                let tag_info = store
                    .blobs()
                    .add_bytes_with_opts((bytes, BlobFormat::Raw))
                    .with_tag()
                    .await?;
                (tag_info.hash, len as u64)
            }
            PayloadForm::File(path, mode) => {
                let mut size: Option<u64> = None;
                let mut stream = store
                    .blobs()
                    .add_path_with_opts(api::blobs::AddPathOptions {
                        path,
                        mode,
                        format: BlobFormat::Raw,
                    })
                    .stream()
                    .await;
                let mut hash: Option<Hash> = None;
                while let Some(item) = stream.next().await {
                    use iroh_blobs::api::blobs::AddProgressItem as I;
                    match item {
                        I::Size(s) => size = Some(s),
                        I::Done(tt) => {
                            hash = Some(tt.hash());
                            break;
                        }
                        I::Error(e) => return Err(e.into()),
                        _ => {}
                    }
                }
                let hash = hash.ok_or_else(|| anyhow::anyhow!("import did not complete"))?;
                let len = size.ok_or_else(|| anyhow::anyhow!("size not reported"))?;
                (hash, len)
            }
            PayloadForm::Stream(stream) => {
                let mut size: Option<u64> = None;
                let mut stream = store.blobs().add_stream(stream).await.stream().await;
                let mut hash: Option<Hash> = None;
                while let Some(item) = stream.next().await {
                    use iroh_blobs::api::blobs::AddProgressItem as I;
                    match item {
                        I::Size(s) => size = Some(s),
                        I::Done(tt) => {
                            hash = Some(tt.hash());
                            break;
                        }
                        I::Error(e) => return Err(e.into()),
                        _ => {}
                    }
                }
                let hash = hash.ok_or_else(|| anyhow::anyhow!("import did not complete"))?;
                let len = size.ok_or_else(|| anyhow::anyhow!("size not reported"))?;
                (hash, len)
            }
            PayloadForm::Reader(reader) => {
                // Convert reader into a stream of Bytes and reuse the stream path
                use tokio_util::io::ReaderStream;
                let bytes_stream = ReaderStream::new(reader);
                let mut size: Option<u64> = None;
                let mut stream = store
                    .blobs()
                    .add_stream(Box::pin(bytes_stream))
                    .await
                    .stream()
                    .await;
                let mut hash: Option<Hash> = None;
                while let Some(item) = stream.next().await {
                    use iroh_blobs::api::blobs::AddProgressItem as I;
                    match item {
                        I::Size(s) => size = Some(s),
                        I::Done(tt) => {
                            hash = Some(tt.hash());
                            break;
                        }
                        I::Error(e) => return Err(e.into()),
                        _ => {}
                    }
                }
                let hash = hash.ok_or_else(|| anyhow::anyhow!("import did not complete"))?;
                let len = size.ok_or_else(|| anyhow::anyhow!("size not reported"))?;
                (hash, len)
            }
        };
        Ok((hash, len))
    }
}

/// Either a [`Entry`] or a [`EntryForm`].
#[derive(Debug, derive_more::From)]
pub enum EntryOrForm {
    Entry(Entry),
    Form(EntryForm),
}

/// Creates an entry while setting some fields automatically.
#[derive(Debug)]
pub struct EntryForm {
    pub namespace_id: NamespaceId,
    pub subspace_id: SubspaceForm,
    pub path: Path,
    pub timestamp: TimestampForm,
    pub payload: PayloadForm,
}

impl EntryForm {
    /// Creates a new [`EntryForm`] where the subspace is set to the user authenticating the entry,
    /// the timestamp is the current system time, and the payload is set to the provided [`Bytes`].
    pub fn new_bytes(namespace_id: NamespaceId, path: Path, payload: impl Into<Bytes>) -> Self {
        EntryForm {
            namespace_id,
            subspace_id: SubspaceForm::User,
            path,
            timestamp: TimestampForm::Now,
            payload: PayloadForm::Bytes(payload.into()),
        }
    }

    /// Sets the subspace for the entry.
    pub fn subspace(mut self, subspace: SubspaceId) -> Self {
        self.subspace_id = SubspaceForm::Exact(subspace);
        self
    }
}

/// Select which capability to use for authenticating a new entry.
#[derive(Debug, Clone, Serialize, Deserialize, derive_more::From)]
pub enum AuthForm {
    /// Use any available capability which covers the entry and whose receiver is the provided
    /// user.
    Any(UserId),
    /// Use the provided [`WriteCapability`].
    Exact(#[serde(with = "meadowcap::serde_encoding::mc_capability")] WriteCapability),
}

impl AuthForm {
    /// Get the user id of the user who is the receiver of the capability selected by this
    /// [`AuthForm`].
    pub fn user_id(&self) -> UserId {
        match self {
            AuthForm::Any(user) => *user,
            AuthForm::Exact(cap) => *cap.receiver(),
        }
    }
}

/// Set the subspace either to a provided [`SubspaceId`], or use the user authenticating the entry
/// as subspace.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum SubspaceForm {
    /// Set the subspace to the [`UserId`] of the user authenticating the entry.
    #[default]
    User,
    /// Set the subspace to the provided [`SubspaceId`].
    Exact(SubspaceId),
}

/// Set the timestamp either to the provided [`Timestamp`] or to the current system time.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum TimestampForm {
    /// Set the timestamp to the current system time.
    #[default]
    Now,
    /// Set the timestamp to the provided value.
    Exact(Timestamp),
}
