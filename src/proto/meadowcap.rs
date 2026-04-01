//! Capability system for Willow, backed by UWill (UCAN delegation chains).

use serde::{Deserialize, Serialize};

use super::{
    grouping::Area,
    keys::{self, UserSecretKey},
};

use crate::uwill::{self, UWillChain, UWillChainRaw};

pub type UserPublicKey = keys::UserPublicKey;
pub type NamespacePublicKey = keys::NamespacePublicKey;
pub type UserId = keys::UserId;
pub type NamespaceId = keys::NamespaceId;
pub type UserSignature = keys::UserSignature;
pub type NamespaceSignature = keys::NamespaceSignature;

// -- AccessMode (now owned, not imported from meadowcap) ---------------------

/// Access mode for capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessMode {
    Read,
    Write,
}

// -- IsCommunal --------------------------------------------------------------

/// Trait for checking if a namespace is communal.
///
/// A communal namespace allows any user to create capabilities.
/// An owned namespace requires the namespace secret holder to grant access.
/// Convention: the last byte of the namespace public key determines the kind.
pub trait IsCommunal {
    fn is_communal(&self) -> bool;
}

// -- Secret keys -------------------------------------------------------------

#[derive(Debug, derive_more::From, Serialize, Deserialize)]
pub enum SecretKey {
    User(keys::UserSecretKey),
    Namespace(keys::NamespaceSecretKey),
}

// -- Capability types (backed by UWill) ---------------------------------

pub type McCapability = UWillChain;
pub type ReadCapability = UWillChain;
pub type WriteCapability = UWillChain;
pub type McAuthorisationToken = crate::uwill::UWillInvocation;
pub type SubspaceCapability = UWillChain;

// -- ReadAuthorisation -------------------------------------------------------

/// Represents authorisation to read an area of data in a namespace.
///
/// In Meadowcap this bundled an McCapability + optional McSubspaceCapability.
/// In UWill, a single chain can express both — the enumeration
/// capability is a separate chain when needed for awkward pairs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadAuthorisation {
    /// The read capability chain.
    read_chain: UWillChain,
    /// Optional enumeration capability for PAI awkward pair resolution.
    enumerate_chain: Option<UWillChain>,
}

// Manual impls needed because UWillChain contains types that
// don't derive Hash/Eq. We hash by granted_namespace + granted_area.
impl std::hash::Hash for ReadAuthorisation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Delegate to UWillChain's Hash (includes receiver)
        self.read_chain.hash(state);
    }
}

impl PartialEq for ReadAuthorisation {
    fn eq(&self, other: &Self) -> bool {
        self.read_chain == other.read_chain
    }
}

impl Eq for ReadAuthorisation {}

impl ReadAuthorisation {
    /// Create from a read chain and optional enumeration chain.
    pub fn new(read_chain: UWillChain, enumerate_chain: Option<UWillChain>) -> Self {
        Self {
            read_chain,
            enumerate_chain,
        }
    }

    /// Create a root read authorization from a namespace secret.
    ///
    /// Creates a UCAN delegation signed by the namespace owner granting
    /// read access to `user_key`. Optionally creates an enumerate chain
    /// for PAI awkward pair resolution.
    pub fn new_owned(
        namespace_secret: &keys::NamespaceSecretKey,
        user_key: UserId,
    ) -> anyhow::Result<Self> {
        let ns_id = namespace_secret.id();
        let read_chain = UWillChain::new_owned(
            ns_id,
            namespace_secret,
            user_key,
            AccessMode::Read,
        ).map_err(anyhow::Error::from)?;

        // Create enumerate chain for PAI awkward pair resolution.
        // Uses /willow/enumerate — proves namespace membership without
        // granting read access to data.
        let enumerate_chain = UWillChain::new_enumerate(
            ns_id,
            namespace_secret,
            user_key,
        ).map_err(anyhow::Error::from)?;

        Ok(Self::new(read_chain, Some(enumerate_chain)))
    }

    /// Create from a single read chain (no enumeration capability).
    pub fn from_read_chain(chain: UWillChain) -> Self {
        Self {
            read_chain: chain,
            enumerate_chain: None,
        }
    }

    /// The read capability chain.
    pub fn read_cap(&self) -> &UWillChain {
        &self.read_chain
    }

    /// The enumerate capability chain (for PAI awkward pair resolution).
    pub fn subspace_cap(&self) -> Option<&UWillChain> {
        self.enumerate_chain.as_ref()
    }

    /// The namespace this authorisation covers.
    pub fn namespace(&self) -> NamespaceId {
        self.read_chain.granted_namespace()
    }

    /// Delegate this read authorisation to a new user with a restricted area.
    ///
    /// Propagates the enumerate chain when the new area has `Any` subspace
    /// and a non-empty path (the condition where PAI awkward pairs can arise).
    /// The enumerate chain is re-delegated to the new user but NOT area-
    /// restricted — it proves namespace membership, not area access.
    pub fn delegate(
        &self,
        user_secret: &UserSecretKey,
        new_user: UserId,
        new_area: Area,
    ) -> anyhow::Result<Self> {
        let new_chain = self.read_chain.delegate(user_secret, &new_user, &new_area)
            .map_err(anyhow::Error::from)?;

        // Propagate enumerate chain only when awkward pairs are possible:
        // subspace is Any AND path is non-empty.
        // Re-delegate with full area (enumerate proves namespace membership).
        let enumerate = match self.enumerate_chain {
            Some(ref enum_chain) if new_area.subspace().is_any() && !new_area.path().is_empty() => {
                let full_area = Area::new_full();
                Some(enum_chain.delegate(user_secret, &new_user, &full_area)
                    .map_err(anyhow::Error::from)?)
            }
            _ => None,
        };

        Ok(Self::new(new_chain, enumerate))
    }
}

// -- Helpers -----------------------------------------------------------------

/// Check if entry write is authorised by this token.
///
/// Delegates to the `AuthorisationToken` trait impl which verifies
/// command, expiry, area inclusion, and entry signature.
pub fn is_authorised_write(
    entry: &super::data_model::Entry,
    token: &McAuthorisationToken,
) -> bool {
    use willow_data_model::AuthorisationToken as _;
    token.is_authorised_write(entry)
}

/// Returns `true` if `a` covers a larger area than `b`,
/// or covers the same area with fewer delegations.
pub fn is_wider_than(a: &McCapability, b: &McCapability) -> bool {
    a.granted_area().includes_area(b.granted_area())
        || (a.granted_area() == b.granted_area()
            && a.delegations().len() < b.delegations().len())
}

// -- Error types -------------------------------------------------------------

/// Error from capability delegation.
#[derive(Debug, thiserror::Error)]
pub enum FailedDelegationError {
    #[error("chain error: {0}")]
    Chain(#[from] uwill::chain::ChainError),
    #[error("area extraction error: {0}")]
    AreaExtract(#[from] uwill::area_extract::AreaExtractError),
}

// -- Serde encoding ----------------------------------------------------------

/// Serde helpers for capability types.
///
/// UWill types contain IPLD values that postcard cannot serialize.
/// These modules encode capabilities to DAG-CBOR bytes first, then
/// serialize the bytes — making them compatible with any outer format.
///
/// TODO(uwill/confidential-sync): This encoding sends the full
/// UCAN chain in cleartext, including namespace DID (`sub`), receiver
/// DID (`aud`), and all `wil_*` policy predicates (subspace, path).
/// An intermediary node relaying a sync session can see exactly who has
/// access to what. Meadowcap avoided this by encoding capabilities
/// *relative to* the PAI PrivateInterest — stripping fields both peers
/// already know and making the wire form useless to eavesdroppers.
///
/// To restore confidentiality: implement a relative encoding that omits
/// `sub`, leaf `aud`, `wil_subspace`, and `wil_path` from the wire,
/// reconstructing them from PAI context on the receiver side. This
/// requires enforcing canonical predicate ordering in `area_to_predicates()`
/// (already done) so that reconstruction produces byte-identical DAG-CBOR
/// for signature verification.
pub mod serde_encoding {
    use serde::{de, Deserialize, Deserializer, Serialize};

    use super::*;

    /// Serialize a UWill type as opaque DAG-CBOR bytes.
    fn to_dagcbor_bytes<T: Serialize>(value: &T) -> Vec<u8> {
        serde_ipld_dagcbor::to_vec(value)
            .expect("DAG-CBOR serialization of UWill type failed")
    }

    /// Deserialize a UWill type from opaque DAG-CBOR bytes.
    fn from_dagcbor_bytes<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<T, String> {
        serde_ipld_dagcbor::from_slice(bytes)
            .map_err(|e| format!("DAG-CBOR deserialization failed: {e}"))
    }

    pub mod read_authorisation {
        use super::*;
        pub fn serialize<S: serde::Serializer>(
            value: &ReadAuthorisation,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let bytes = to_dagcbor_bytes(value);
            bytes.serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<ReadAuthorisation, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            from_dagcbor_bytes(&bytes).map_err(de::Error::custom)
        }
    }

    #[derive(
        Debug,
        Clone,
        derive_more::From,
        derive_more::Into,
        derive_more::Deref,
        Serialize,
        Deserialize,
    )]
    pub struct SerdeReadAuthorisation(
        #[serde(with = "read_authorisation")] pub ReadAuthorisation,
    );

    // Hash/Eq needed because InterestMap uses ReadAuthorisation as key
    impl std::hash::Hash for SerdeReadAuthorisation {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.0.hash(state);
        }
    }
    impl PartialEq for SerdeReadAuthorisation {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0
        }
    }
    impl Eq for SerdeReadAuthorisation {}

    pub mod mc_capability {
        use super::*;
        pub fn serialize<S: serde::Serializer>(
            value: &UWillChain,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let bytes = to_dagcbor_bytes(value.chain());
            bytes.serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<UWillChain, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            let raw: UWillChainRaw = from_dagcbor_bytes(&bytes).map_err(de::Error::custom)?;
            UWillChain::from_chain(raw).map_err(de::Error::custom)
        }
    }

    #[derive(
        Debug,
        Clone,
        derive_more::From,
        derive_more::Into,
        derive_more::Deref,
        Serialize,
        Deserialize,
    )]
    pub struct SerdeMcCapability(#[serde(with = "mc_capability")] pub McCapability);

    // Hash/Eq delegate to UWillChain (includes receiver)
    impl std::hash::Hash for SerdeMcCapability {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.0.hash(state);
        }
    }
    impl PartialEq for SerdeMcCapability {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0
        }
    }
    impl Eq for SerdeMcCapability {}

    // SerdeMcSubspaceCapability reuses mc_capability — both types are UWillChain.
    #[derive(
        Debug,
        Clone,
        derive_more::From,
        derive_more::Into,
        derive_more::Deref,
        Serialize,
        Deserialize,
    )]
    pub struct SerdeMcSubspaceCapability(
        #[serde(with = "mc_capability")] pub SubspaceCapability,
    );

    /// DAG-CBOR serde wrapper for UCAN Invocations (used as DynamicToken).
    pub mod invocation_serde {
        use super::*;
        pub fn serialize<S: serde::Serializer>(
            value: &ucan::invocation::Invocation<ucan::did::Ed25519Did>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let bytes = to_dagcbor_bytes(value);
            bytes.serialize(serializer)
        }

        pub fn deserialize<'de, D>(
            deserializer: D,
        ) -> Result<ucan::invocation::Invocation<ucan::did::Ed25519Did>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            from_dagcbor_bytes(&bytes).map_err(de::Error::custom)
        }
    }

    #[derive(Debug, Clone, derive_more::From, derive_more::Into, Serialize, Deserialize)]
    pub struct SerdeInvocation(
        #[serde(with = "invocation_serde")]
        pub ucan::invocation::Invocation<ucan::did::Ed25519Did>,
    );

    /// DAG-CBOR serde wrapper for a full UWillInvocation
    /// (invocation + resolved proof delegations).
    pub mod uwill_invocation_serde {
        use super::*;
        use crate::uwill::UWillInvocation;

        pub fn serialize<S: serde::Serializer>(
            value: &UWillInvocation,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let bytes = to_dagcbor_bytes(value);
            bytes.serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<UWillInvocation, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            from_dagcbor_bytes(&bytes).map_err(de::Error::custom)
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SerdeUWillInvocation(
        #[serde(with = "uwill_invocation_serde")]
        pub crate::uwill::UWillInvocation,
    );

    pub mod access_mode {
        use super::*;
        pub fn serialize<S: serde::Serializer>(
            value: &AccessMode,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match value {
                AccessMode::Read => 0u8.serialize(serializer),
                AccessMode::Write => 1u8.serialize(serializer),
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<AccessMode, D::Error>
        where
            D: Deserializer<'de>,
        {
            let value: u8 = Deserialize::deserialize(deserializer)?;
            match value {
                0 => Ok(AccessMode::Read),
                1 => Ok(AccessMode::Write),
                _ => Err(de::Error::custom("Invalid access mode")),
            }
        }
    }
}
