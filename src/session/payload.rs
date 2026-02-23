use bytes::Bytes;
use futures_lite::StreamExt;
use bao_tree::{ChunkNum, ChunkRanges};
use iroh_blobs::{api, Hash};

use super::Error;
use crate::{
    proto::{data_model::PayloadDigest, wgps::Message},
    session::channels::ChannelSenders,
};

/// Send a payload in chunks.
///
/// Returns `true` if the payload was sent.
/// Returns `false` if blob is not found in `payload_store`.
/// Returns an error if the store or sending on the `senders` return an error.
// TODO: Include outboards.
pub async fn send_payload_chunked(
    digest: PayloadDigest,
    payload_store: &api::Store,
    senders: &ChannelSenders,
    offset: u64,
    map: impl Fn(Bytes) -> Message,
) -> Result<bool, Error> {
    let hash: Hash = digest.into();
    // Check if we have the blob
    if !payload_store
        .blobs()
        .has(hash)
        .await
        .map_err(|e| Error::PayloadStore(std::io::Error::other(e)))?
    {
        return Ok(false);
    }
    // Determine ranges from offset to end
    let base = ChunkNum::full_chunks(offset);
    let ranges: ChunkRanges = (base..).into();
    let mut stream = payload_store
        .blobs()
        .export_bao(hash, ranges)
        .into_byte_stream();
    while let Some(bytes) = stream.next().await {
        let bytes = bytes.map_err(|e| Error::PayloadStore(std::io::Error::other(e)))?;
        let msg = map(bytes);
        senders.send(msg).await?;
    }
    Ok(true)
}

#[derive(Debug, Default)]
pub struct CurrentPayload(Option<CurrentPayloadInner>);

#[derive(Debug)]
struct CurrentPayloadInner {
    payload_digest: PayloadDigest,
    expected_length: u64,
    received_length: u64,
    _total_length: u64,
    offset: u64,
    writer: Option<PayloadWriter>,
}

#[derive(derive_more::Debug)]
struct PayloadWriter {
    chunks: Vec<Bytes>,
}

impl CurrentPayload {
    /// Set the payload to be received.
    pub fn set(
        &mut self,
        payload_digest: PayloadDigest,
        total_length: u64,
        available_length: Option<u64>,
        offset: Option<u64>,
    ) -> Result<(), Error> {
        if self.0.is_some() {
            return Err(Error::InvalidMessageInCurrentState);
        }
        let offset = offset.unwrap_or(0);
        let available_length = available_length.unwrap_or(total_length);
        let expected_length = available_length - offset;
        self.0 = Some(CurrentPayloadInner {
            payload_digest,
            writer: None,
            expected_length,
            _total_length: total_length,
            offset,
            received_length: 0,
        });
        Ok(())
    }

    pub async fn recv_chunk(&mut self, _store: &api::Store, chunk: Bytes) -> anyhow::Result<()> {
        let state = self.0.as_mut().ok_or(Error::InvalidMessageInCurrentState)?;
        let len = chunk.len();
        let writer = state
            .writer
            .get_or_insert(PayloadWriter { chunks: Vec::new() });
        writer.chunks.push(chunk);
        state.received_length += len as u64;
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        let Some(state) = self.0.as_ref() else {
            return false;
        };
        state.received_length >= state.expected_length
    }

    pub async fn finalize(&mut self, store: &api::Store) -> Result<(), Error> {
        let state = self.0.take().ok_or(Error::InvalidMessageInCurrentState)?;
        // The writer is only set if we received at least one payload chunk.
        if let Some(writer) = state.writer {
            let hash: Hash = state.payload_digest.into();
            // Concatenate chunks into a single buffer and import via bao
            let data = {
                if writer.chunks.len() == 1 {
                    writer.chunks[0].clone()
                } else {
                    let mut buf = Vec::with_capacity(writer.chunks.iter().map(|b| b.len()).sum());
                    for b in writer.chunks {
                        buf.extend_from_slice(&b);
                    }
                    buf.into()
                }
            };
            let base = ChunkNum::full_chunks(state.offset);
            let ranges: ChunkRanges = (base..).into();
            // Verify and import BAO stream
            store
                .blobs()
                .import_bao_bytes(hash, ranges, data)
                .await
                .map_err(|e| Error::PayloadStore(std::io::Error::other(e)))?;
        }
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.0.as_ref().map(|s| s.writer.is_some()).unwrap_or(false)
    }

    pub fn ensure_none(&self) -> Result<(), Error> {
        if self.is_active() {
            Err(Error::InvalidMessageInCurrentState)
        } else {
            Ok(())
        }
    }
}
