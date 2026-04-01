use std::time::Instant;

use anyhow::Result;
use redb::{
    MultimapTable, MultimapTableDefinition, ReadOnlyMultimapTable, ReadOnlyTable, ReadTransaction,
    Table, TableDefinition, WriteTransaction,
};

use crate::proto::meadowcap::{serde_encoding::SerdeReadAuthorisation, McCapability, ReadAuthorisation};

// These consts are here so we don't accidentally break the schema!
pub type NamespaceId = [u8; 32];
pub type UserId = [u8; 32];

pub const NAMESPACE_NODES: TableDefinition<NamespaceId, willow_store::NodeId> =
    TableDefinition::new("namespace-nodes-0");

pub const AUTH_TOKENS: TableDefinition<[u8; 64], StoredInvocation> =
    TableDefinition::new("auth-tokens-1");
pub const AUTH_TOKEN_REFCOUNT: TableDefinition<[u8; 64], u64> =
    TableDefinition::new("auth-token-refcounts-1");

pub const USER_SECRETS: TableDefinition<UserId, [u8; 32]> = TableDefinition::new("user-secrets-0");
pub const NAMESPACE_SECRETS: TableDefinition<NamespaceId, [u8; 32]> =
    TableDefinition::new("namespaces-secrets-0");

pub const READ_CAPS: MultimapTableDefinition<NamespaceId, ReadCap> =
    MultimapTableDefinition::new("read-caps-0");
pub const WRITE_CAPS: MultimapTableDefinition<NamespaceId, WriteCap> =
    MultimapTableDefinition::new("write-caps-0");

/// Revoked delegation CIDs. Value is `()` — it's just a set.
pub const REVOCATIONS: TableDefinition<&[u8], ()> = TableDefinition::new("revocations-0");

self_cell::self_cell! {
    struct OpenWriteInner {
        owner: WriteTransaction,
        #[covariant]
        dependent: Tables,
    }
}

#[derive(derive_more::Debug)]
pub struct OpenWrite {
    #[debug("OpenWriteInner")]
    inner: OpenWriteInner,
    pub since: Instant,
}

impl OpenWrite {
    pub fn new(tx: WriteTransaction) -> Result<Self> {
        Ok(Self {
            inner: OpenWriteInner::try_new(tx, |tx| Tables::new(tx))?,
            since: Instant::now(),
        })
    }

    pub fn read(&self) -> &Tables<'_> {
        self.inner.borrow_dependent()
    }

    pub fn modify<T>(&mut self, f: impl FnOnce(&mut Tables) -> Result<T>) -> Result<T> {
        self.inner.with_dependent_mut(|_, t| f(t))
    }

    pub fn commit(self) -> Result<()> {
        self.inner
            .into_owner()
            .commit()
            .map_err(anyhow::Error::from)
    }
}

pub struct Tables<'tx> {
    pub namespace_nodes: Table<'tx, NamespaceId, willow_store::NodeId>,
    pub auth_tokens: Table<'tx, [u8; 64], StoredInvocation>,
    pub auth_token_refcount: Table<'tx, [u8; 64], u64>,
    pub user_secrets: Table<'tx, UserId, [u8; 32]>,
    pub namespace_secrets: Table<'tx, NamespaceId, [u8; 32]>,
    pub read_caps: MultimapTable<'tx, NamespaceId, ReadCap>,
    pub write_caps: MultimapTable<'tx, NamespaceId, WriteCap>,
    pub revocations: Table<'tx, &'static [u8], ()>,
    pub node_store: willow_store::Tables<'tx>,
}

impl<'tx> Tables<'tx> {
    pub fn new(tx: &'tx WriteTransaction) -> Result<Self> {
        Ok(Self {
            namespace_nodes: tx.open_table(NAMESPACE_NODES)?,
            auth_tokens: tx.open_table(AUTH_TOKENS)?,
            auth_token_refcount: tx.open_table(AUTH_TOKEN_REFCOUNT)?,
            user_secrets: tx.open_table(USER_SECRETS)?,
            namespace_secrets: tx.open_table(NAMESPACE_SECRETS)?,
            read_caps: tx.open_multimap_table(READ_CAPS)?,
            write_caps: tx.open_multimap_table(WRITE_CAPS)?,
            revocations: tx.open_table(REVOCATIONS)?,
            node_store: willow_store::Tables::open(tx)?,
        })
    }
}

pub struct OpenRead {
    pub namespace_nodes: ReadOnlyTable<NamespaceId, willow_store::NodeId>,
    pub auth_tokens: ReadOnlyTable<[u8; 64], StoredInvocation>,
    pub read_caps: ReadOnlyMultimapTable<NamespaceId, ReadCap>,
    pub write_caps: ReadOnlyMultimapTable<NamespaceId, WriteCap>,
    pub revocations: ReadOnlyTable<&'static [u8], ()>,
    pub node_store: willow_store::Snapshot,
}

impl OpenRead {
    pub fn new(tx: &ReadTransaction) -> Result<Self> {
        Ok(Self {
            namespace_nodes: tx.open_table(NAMESPACE_NODES)?,
            auth_tokens: tx.open_table(AUTH_TOKENS)?,
            read_caps: tx.open_multimap_table(READ_CAPS)?,
            write_caps: tx.open_multimap_table(WRITE_CAPS)?,
            revocations: tx.open_table(REVOCATIONS)?,
            node_store: willow_store::Snapshot::open(tx)?,
        })
    }
}

#[derive(Debug)]
pub struct WriteCap(pub McCapability);

impl redb::Key for WriteCap {
    fn compare(data1: &[u8], data2: &[u8]) -> std::cmp::Ordering {
        data1.cmp(data2)
    }
}

impl redb::Value for WriteCap {
    type SelfType<'a>
        = Self
    where
        Self: 'a;

    type AsBytes<'a>
        = Vec<u8>
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        let raw: crate::uwill::UWillChainRaw =
            serde_ipld_dagcbor::from_slice(data).expect("invalid WriteCap in database");
        let validated = crate::uwill::UWillChain::from_chain(raw)
            .expect("invalid WriteCap chain in database");
        WriteCap(validated)
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        serde_ipld_dagcbor::to_vec(value.0.chain()).expect("WriteCap serialization failed")
    }

    fn type_name() -> redb::TypeName {
        redb::TypeName::new("WriteCap")
    }
}

/// Stored UCAN invocation (write authorization token).
#[derive(Debug)]
pub struct StoredInvocation(pub crate::uwill::UWillInvocation);

impl redb::Value for StoredInvocation {
    type SelfType<'a> = Self;
    type AsBytes<'a> = Vec<u8>;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        let inv: crate::uwill::UWillInvocation =
            serde_ipld_dagcbor::from_slice(data).expect("invalid StoredInvocation in database");
        StoredInvocation(inv)
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        serde_ipld_dagcbor::to_vec(&value.0).expect("StoredInvocation serialization failed")
    }

    fn type_name() -> redb::TypeName {
        redb::TypeName::new("StoredInvocation")
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct ReadCap(pub ReadAuthorisation);

impl redb::Key for ReadCap {
    fn compare(data1: &[u8], data2: &[u8]) -> std::cmp::Ordering {
        data1.cmp(data2)
    }
}

impl redb::Value for ReadCap {
    type SelfType<'a>
        = Self
    where
        Self: 'a;

    type AsBytes<'a>
        = Vec<u8>
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        let capability: SerdeReadAuthorisation = postcard::from_bytes(data).unwrap();
        ReadCap(capability.0)
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        // TODO(matheus23): Fewer clones.
        postcard::to_stdvec(&SerdeReadAuthorisation(value.0.clone())).unwrap()
    }

    fn type_name() -> redb::TypeName {
        redb::TypeName::new("ReadCap")
    }
}
