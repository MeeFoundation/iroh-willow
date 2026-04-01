//! UWill delegation chain.
//!
//! Two types:
//! - `UWillChainRaw` — raw serializable data (just the UCAN delegations)
//! - `UWillChain` — validated wrapper with cached derived state

use serde::{Deserialize, Serialize};
use ucan::{
    delegation::{subject::DelegatedSubject, Delegation},
    did::{Ed25519Did, Ed25519Signer},
};

use crate::proto::{
    grouping::Area,
    keys::{NamespaceId, NamespaceSecretKey, UserPublicKey, UserSecretKey, UserId},
    meadowcap::AccessMode,
};

use super::{
    area_extract::{self, AreaExtractError},
    command::WillowCommand,
};

// ---------------------------------------------------------------------------
// UWillChainRaw — raw serializable data
// ---------------------------------------------------------------------------

/// Raw UCAN delegation chain. Just the delegations — no derived state.
///
/// This is what goes over the wire and into storage. Use
/// `UWillChain::from_chain()` to validate and prepare for use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UWillChainRaw(Vec<Delegation<Ed25519Did>>);

impl UWillChainRaw {
    /// Create from a vec of delegations.
    pub fn from_delegations(delegations: Vec<Delegation<Ed25519Did>>) -> Self {
        Self(delegations)
    }

    /// The raw delegations.
    pub fn delegations(&self) -> &[Delegation<Ed25519Did>] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// UWillChain — validated + cached wrapper
// ---------------------------------------------------------------------------

/// A validated UWill chain with precomputed derived state.
///
/// All validation (command narrowing, area narrowing, principal alignment)
/// and all cache computation (CIDs, public key decompression) happen in
/// `from_chain()`. Protocol code works exclusively with this type.
///
/// Serialize delegates to the inner `UWillChainRaw`. Deserialize deserializes
/// `UWillChainRaw` then validates via `from_chain()`.
#[derive(Debug, Clone)]
pub struct UWillChain {
    inner: UWillChainRaw,
    area: Area,
    command: WillowCommand,
    cids: Vec<ipld_core::cid::Cid>,
    receiver_pk: Option<UserPublicKey>,
}

impl std::hash::Hash for UWillChain {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.granted_namespace().hash(state);
        self.receiver().hash(state);
        self.area.hash(state);
        self.command.hash(state);
    }
}

impl Serialize for UWillChain {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.inner.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UWillChain {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = UWillChainRaw::deserialize(deserializer)?;
        Self::from_chain(raw).map_err(serde::de::Error::custom)
    }
}

impl PartialEq for UWillChain {
    fn eq(&self, other: &Self) -> bool {
        self.granted_namespace() == other.granted_namespace()
            && self.receiver() == other.receiver()
            && self.area == other.area
            && self.command == other.command
    }
}

impl Eq for UWillChain {}

/// Errors constructing or validating a UWill chain.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("empty delegation chain")]
    Empty,
    #[error("no Willow command found in delegation")]
    NoWillowCommand,
    #[error("area extraction failed: {0}")]
    AreaExtract(#[from] AreaExtractError),
    #[error("area widening detected at delegation step {step}")]
    AreaWidening { step: usize },
    #[error("command widening: child command {child} does not start with parent {parent}")]
    CommandWidening { parent: String, child: String },
    #[error("principal misalignment: aud of step {step} does not match iss of step {next}")]
    PrincipalMismatch { step: usize, next: usize },
    #[error("chain expired")]
    Expired,
    #[error("chain not yet valid")]
    NotYetValid,
    #[error("communal namespaces not supported in UWill")]
    CommunalNotSupported,
    #[error("not a write capability")]
    NotWriteCapability,
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("delegation build failed: {0}")]
    DelegationBuild(String),
    #[error("invalid delegation signature at step {step}")]
    InvalidSignature { step: usize },
    #[error("root delegation issuer does not match subject (namespace owner must sign root)")]
    RootIssuerMismatch,
    #[error("subject mismatch at delegation step {step}")]
    SubjectMismatch { step: usize },
    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),
}

/// Clock drift tolerance for UCAN expiry/nbf checks (seconds).
const CLOCK_TOLERANCE_SECS: u64 = 60;

impl UWillChain {
    // -- Validation + construction -------------------------------------------

    /// Validate a raw chain and compute derived state.
    ///
    /// This is the single entry point from raw data to validated state.
    /// All validation and cache computation happens here.
    pub fn from_chain(chain: UWillChainRaw) -> Result<Self, ChainError> {
        use ucan::delegation::subject::DelegatedSubject;

        let delegations = &chain.0;
        if delegations.is_empty() {
            return Err(ChainError::Empty);
        }

        // Root issuer must match subject (namespace owner signs the root).
        let root = &delegations[0];
        if let DelegatedSubject::Specific(subject_did) = root.subject() {
            if root.issuer() != subject_did {
                return Err(ChainError::RootIssuerMismatch);
            }
        }

        // Subject consistency: all delegations must refer to the same
        // specific subject, or use Any (which allows anything).
        let specific_subject = delegations.iter().find_map(|d| match d.subject() {
            DelegatedSubject::Specific(s) => Some(*s),
            DelegatedSubject::Any => None,
        });
        if let Some(ref expected_did) = specific_subject {
            for (i, d) in delegations.iter().enumerate() {
                if !d.subject().allows(expected_did) {
                    return Err(ChainError::SubjectMismatch { step: i });
                }
            }
        }

        // Validate command hierarchy, area narrowing, and signatures
        let mut prev_area: Option<Area> = None;
        let mut prev_command: Option<ucan::command::Command> = None;

        for (i, d) in delegations.iter().enumerate() {
            // Verify delegation signature against issuer's public key
            d.verify().map_err(|_| ChainError::InvalidSignature { step: i })?;

            if WillowCommand::from_ucan_command(d.command()).is_none() {
                return Err(ChainError::NoWillowCommand);
            }

            if let Some(ref parent) = prev_command {
                if !d.command().starts_with(parent) {
                    return Err(ChainError::CommandWidening {
                        parent: parent.to_string(),
                        child: d.command().to_string(),
                    });
                }
            }

            let area = area_extract::extract_willow_area(d.policy())?;
            if let Some(ref prev) = prev_area {
                if !prev.includes_area(&area) {
                    return Err(ChainError::AreaWidening { step: i });
                }
            }

            if i + 1 < delegations.len() {
                let next = &delegations[i + 1];
                if d.audience() != next.issuer() {
                    return Err(ChainError::PrincipalMismatch {
                        step: i,
                        next: i + 1,
                    });
                }
            }

            prev_area = Some(area);
            prev_command = Some(d.command().clone());
        }

        let area = prev_area.expect("non-empty checked above");
        let leaf = delegations.last().expect("non-empty checked above");
        let command = WillowCommand::from_ucan_command(leaf.command())
            .expect("validated above");
        let cids = delegations.iter().map(|d| d.to_cid()).collect();
        let receiver_id = ed25519_did_to_user_id(leaf.audience());
        let receiver_pk = receiver_id.into_public_key().ok();

        Ok(Self { inner: chain, area, command, cids, receiver_pk })
    }

    /// Validate a single delegation.
    pub fn from_single(delegation: Delegation<Ed25519Did>) -> Result<Self, ChainError> {
        Self::from_chain(UWillChainRaw(vec![delegation]))
    }

    // -- Capability creation -------------------------------------------------

    /// Create a root delegation signed by the namespace owner.
    fn build_root_delegation(
        namespace_id: NamespaceId,
        namespace_secret: &NamespaceSecretKey,
        user_id: UserId,
        command: WillowCommand,
    ) -> Result<Self, ChainError> {
        let issuer_key = ed25519_dalek::SigningKey::from_bytes(&namespace_secret.to_bytes());
        let issuer = Ed25519Signer::new(issuer_key);

        let audience = user_id_to_ed25519_did(&user_id)
            .map_err(|e| ChainError::InvalidKey(e.to_string()))?;

        let namespace_did = namespace_id_to_ed25519_did(&namespace_id)
            .map_err(|e| ChainError::InvalidKey(e.to_string()))?;

        let delegation = Delegation::<Ed25519Did>::builder()
            .issuer(issuer)
            .audience(audience)
            .subject(DelegatedSubject::Specific(namespace_did))
            .command(command.to_ucan_command())
            .policy(vec![])
            .try_build()
            .map_err(|e| ChainError::DelegationBuild(format!("{e}")))?;

        Self::from_single(delegation)
    }

    pub fn new_owned(
        namespace_id: NamespaceId,
        namespace_secret: &NamespaceSecretKey,
        user_id: UserId,
        access_mode: AccessMode,
    ) -> Result<Self, ChainError> {
        let command = match access_mode {
            AccessMode::Read => WillowCommand::Read,
            AccessMode::Write => WillowCommand::Write,
        };
        Self::build_root_delegation(namespace_id, namespace_secret, user_id, command)
    }

    /// Create a namespace membership proof for PAI awkward pair resolution.
    ///
    /// Uses `/willow/enumerate` — proves namespace membership without
    /// granting read or write access to data.
    pub fn new_enumerate(
        namespace_id: NamespaceId,
        namespace_secret: &NamespaceSecretKey,
        user_id: UserId,
    ) -> Result<Self, ChainError> {
        Self::build_root_delegation(namespace_id, namespace_secret, user_id, WillowCommand::Enumerate)
    }

    /// Test helper: build a root delegation with any command.
    #[cfg(test)]
    pub fn build_root_delegation_for_test(
        namespace_id: NamespaceId,
        namespace_secret: &NamespaceSecretKey,
        user_id: UserId,
        command: WillowCommand,
    ) -> Result<Self, ChainError> {
        Self::build_root_delegation(namespace_id, namespace_secret, user_id, command)
    }

    pub fn new_communal(
        _namespace_id: NamespaceId,
        _user_id: UserId,
        _access_mode: AccessMode,
    ) -> Result<Self, ChainError> {
        Err(ChainError::CommunalNotSupported)
    }

    /// Delegate this capability to a new user with a restricted area.
    pub fn delegate(
        &self,
        user_secret: &UserSecretKey,
        new_user: &UserId,
        new_area: &Area,
    ) -> Result<Self, ChainError> {
        let issuer_key = ed25519_dalek::SigningKey::from_bytes(&user_secret.to_bytes());
        let issuer = Ed25519Signer::new(issuer_key);

        let audience = user_id_to_ed25519_did(new_user)
            .map_err(|e| ChainError::InvalidKey(e.to_string()))?;

        let root = self.inner.0.first().expect("non-empty");
        let subject = root.subject().clone();
        let command = self.command;
        let policy = area_extract::area_to_predicates(new_area);

        let delegation = Delegation::<Ed25519Did>::builder()
            .issuer(issuer)
            .audience(audience)
            .subject(subject)
            .command(command.to_ucan_command())
            .policy(policy)
            .try_build()
            .map_err(|e| ChainError::DelegationBuild(format!("{e}")))?;

        let mut new_delegations = self.inner.0.clone();
        new_delegations.push(delegation);

        Self::from_chain(UWillChainRaw(new_delegations))
    }

    /// Create a write authorization invocation for an entry.
    pub fn authorisation_token(
        &self,
        entry: &crate::proto::data_model::Entry,
        user_secret: &UserSecretKey,
    ) -> Result<super::UWillInvocation, ChainError> {
        if !self.proves_write() {
            return Err(ChainError::NotWriteCapability);
        }

        super::invocation::build_write_invocation(entry, self, user_secret)
            .map_err(|e| ChainError::DelegationBuild(format!("{e}")))
    }

    // -- Accessors -----------------------------------------------------------

    /// The raw chain (for serialization).
    pub fn chain(&self) -> &UWillChainRaw {
        &self.inner
    }

    /// Consume, returning the raw chain.
    pub fn into_chain(self) -> UWillChainRaw {
        self.inner
    }

    /// The raw delegations.
    pub fn delegations(&self) -> &[Delegation<Ed25519Did>] {
        self.inner.delegations()
    }

    pub fn receiver(&self) -> UserId {
        let leaf = self.delegations().last().expect("non-empty");
        ed25519_did_to_user_id(leaf.audience())
    }

    pub fn receiver_public_key(&self) -> Option<&UserPublicKey> {
        self.receiver_pk.as_ref()
    }

    pub fn granted_namespace(&self) -> NamespaceId {
        let root = self.delegations().first().expect("non-empty");
        match root.subject() {
            DelegatedSubject::Specific(did) => ed25519_did_to_namespace_id(did),
            DelegatedSubject::Any => NamespaceId::from([0u8; 32]),
        }
    }

    pub fn granted_area(&self) -> &Area {
        &self.area
    }

    pub fn access_mode(&self) -> AccessMode {
        self.command.access_mode()
    }

    pub fn command(&self) -> WillowCommand {
        self.command
    }

    pub fn proves_read(&self) -> bool {
        self.command.proves_read()
    }

    pub fn proves_write(&self) -> bool {
        self.command.proves_write()
    }

    pub fn proves_enumerate(&self) -> bool {
        self.command.proves_enumerate()
    }

    pub fn delegation_cids(&self) -> &[ipld_core::cid::Cid] {
        &self.cids
    }

    // -- Expiry / validity ---------------------------------------------------

    pub fn is_expired(&self, now_secs: u64) -> bool {
        let tolerance = CLOCK_TOLERANCE_SECS;
        for d in self.delegations() {
            if let Some(exp) = d.expiration() {
                let exp_secs = exp.to_unix();
                if now_secs > exp_secs.saturating_add(tolerance) {
                    return true;
                }
            }
        }
        false
    }

    pub fn is_not_yet_valid(&self, now_secs: u64) -> bool {
        let tolerance = CLOCK_TOLERANCE_SECS;
        for d in self.delegations() {
            if let Some(nbf) = d.not_before() {
                let nbf_secs = nbf.to_unix();
                if now_secs + tolerance < nbf_secs {
                    return true;
                }
            }
        }
        false
    }
}

// -- DID ↔ Willow key conversions -------------------------------------------

/// Convert an Ed25519Did to a Willow UserId.
///
/// Both are 32-byte Ed25519 public keys under the hood.
pub fn ed25519_did_to_user_id(did: &Ed25519Did) -> UserId {
    UserId::from(*did.0.as_bytes())
}

/// Convert an Ed25519Did to a Willow NamespaceId.
pub fn ed25519_did_to_namespace_id(did: &Ed25519Did) -> NamespaceId {
    NamespaceId::from(*did.0.as_bytes())
}

/// Convert a Willow UserId to an Ed25519Did.
pub fn user_id_to_ed25519_did(id: &UserId) -> Result<Ed25519Did, ed25519_dalek::SignatureError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(id.as_bytes())?;
    Ok(Ed25519Did::from(vk))
}

/// Convert a Willow NamespaceId to an Ed25519Did.
pub fn namespace_id_to_ed25519_did(
    id: &NamespaceId,
) -> Result<Ed25519Did, ed25519_dalek::SignatureError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(id.as_bytes())?;
    Ok(Ed25519Did::from(vk))
}

#[cfg(test)]
mod tests {
    use rand_core::CryptoRngCore;
    use willow_data_model::grouping::{AreaSubspace, Range, RangeEnd};

    use super::*;
    use crate::proto::keys::{NamespaceKind, NamespaceSecretKey, UserSecretKey};

    fn keypair<R: CryptoRngCore + ?Sized>(rng: &mut R) -> (UserSecretKey, UserId) {
        let secret = UserSecretKey::generate(rng);
        let public = secret.public_key();
        (secret, public.id())
    }

    fn rng() -> rand_chacha::ChaCha12Rng {
        use rand_core::SeedableRng;
        rand_chacha::ChaCha12Rng::seed_from_u64(42)
    }

    // -- new_owned -----------------------------------------------------------

    #[test]
    fn new_owned_read_cap() {
        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (_, user_id) = keypair(&mut rng);

        let chain = UWillChain::new_owned(ns_id, &ns_secret, user_id, AccessMode::Read)
            .expect("new_owned failed");

        assert_eq!(chain.granted_namespace(), ns_id);
        assert_eq!(chain.receiver(), user_id);
        assert_eq!(chain.access_mode(), AccessMode::Read);
        assert!(chain.proves_read());
        assert!(!chain.proves_write());
        assert_eq!(chain.command(), WillowCommand::Read);
        // Full area (empty policy)
        assert!(chain.granted_area().subspace().is_any());
        assert!(chain.granted_area().path().is_empty());
        assert_eq!(chain.delegations().len(), 1);
    }

    #[test]
    fn new_owned_write_cap() {
        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (_, user_id) = keypair(&mut rng);

        let chain = UWillChain::new_owned(ns_id, &ns_secret, user_id, AccessMode::Write)
            .expect("new_owned failed");

        assert_eq!(chain.granted_namespace(), ns_id);
        assert_eq!(chain.receiver(), user_id);
        assert_eq!(chain.access_mode(), AccessMode::Write);
        assert!(!chain.proves_read());
        assert!(chain.proves_write());
    }

    #[test]
    fn new_communal_rejected() {
        let mut rng = rng();
        let (_, user_id) = keypair(&mut rng);
        let ns_id = NamespaceId::from([0u8; 32]);

        let result = UWillChain::new_communal(ns_id, user_id, AccessMode::Read);
        assert!(matches!(result, Err(ChainError::CommunalNotSupported)));
    }

    // -- namespace/user ID roundtrip -----------------------------------------

    #[test]
    fn namespace_id_roundtrips_through_did() {
        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (_, user_id) = keypair(&mut rng);

        let chain = UWillChain::new_owned(ns_id, &ns_secret, user_id, AccessMode::Read)
            .unwrap();

        // granted_namespace extracts from sub DID — must match original
        assert_eq!(chain.granted_namespace(), ns_id);
        assert_eq!(chain.granted_namespace().as_bytes(), ns_id.as_bytes());
    }

    #[test]
    fn user_id_roundtrips_through_did() {
        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (_, user_id) = keypair(&mut rng);

        let chain = UWillChain::new_owned(ns_id, &ns_secret, user_id, AccessMode::Read)
            .unwrap();

        assert_eq!(chain.receiver(), user_id);
        assert_eq!(chain.receiver().as_bytes(), user_id.as_bytes());
    }

    // -- delegate ------------------------------------------------------------

    #[test]
    fn delegate_narrows_area() {
        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (owner_secret, owner_id) = keypair(&mut rng);
        let (_, delegate_id) = keypair(&mut rng);

        let root = UWillChain::new_owned(ns_id, &ns_secret, owner_id, AccessMode::Read)
            .unwrap();

        let restricted_area = Area::new(
            AreaSubspace::Id(delegate_id),
            crate::proto::data_model::Path::new_empty(),
            Range::new(0, RangeEnd::Open),
        );

        let delegated = root.delegate(&owner_secret, &delegate_id, &restricted_area)
            .expect("delegate failed");

        assert_eq!(delegated.granted_namespace(), ns_id);
        assert_eq!(delegated.receiver(), delegate_id);
        assert_eq!(delegated.granted_area().subspace(), restricted_area.subspace());
        assert_eq!(delegated.delegations().len(), 2);
        assert_eq!(delegated.command(), WillowCommand::Read);
    }

    #[test]
    fn delegate_preserves_namespace() {
        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();

        let bob_secret = UserSecretKey::generate(&mut rng);
        let bob_id = bob_secret.public_key().id();
        let (_, carol_id) = keypair(&mut rng);

        // namespace owner → bob → carol: namespace stays the same
        let to_bob = UWillChain::new_owned(
            ns_id, &ns_secret, bob_id, AccessMode::Write,
        ).unwrap();
        let to_carol = to_bob.delegate(&bob_secret, &carol_id, &Area::new_full()).unwrap();

        assert_eq!(to_bob.granted_namespace(), ns_id);
        assert_eq!(to_carol.granted_namespace(), ns_id);
        assert_eq!(to_carol.delegations().len(), 2);
    }

    #[test]
    fn delegate_chain_three_levels() {
        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();

        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();
        let bob_secret = UserSecretKey::generate(&mut rng);
        let bob_id = bob_secret.public_key().id();
        let carol_secret = UserSecretKey::generate(&mut rng);
        let carol_id = carol_secret.public_key().id();

        // namespace owner → alice (full area)
        let to_alice = UWillChain::new_owned(
            ns_id, &ns_secret, alice_id, AccessMode::Read,
        ).unwrap();

        // alice → bob (restricted to bob's subspace)
        let bob_area = Area::new(
            AreaSubspace::Id(bob_id),
            crate::proto::data_model::Path::new_empty(),
            Range::new(0, RangeEnd::Open),
        );
        let to_bob = to_alice.delegate(&alice_secret, &bob_id, &bob_area).unwrap();

        // bob → carol (same area, further delegation)
        let to_carol = to_bob.delegate(&bob_secret, &carol_id, &bob_area).unwrap();

        assert_eq!(to_carol.granted_namespace(), ns_id);
        assert_eq!(to_carol.receiver(), carol_id);
        assert_eq!(to_carol.delegations().len(), 3);
        assert_eq!(to_carol.granted_area().subspace(), &AreaSubspace::Id(bob_id));
    }

    // -- area narrowing validation -------------------------------------------

    #[test]
    fn delegate_rejects_area_widening() {
        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();

        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();
        let bob_secret = UserSecretKey::generate(&mut rng);
        let bob_id = bob_secret.public_key().id();
        let (_, carol_id) = keypair(&mut rng);

        // namespace owner → alice (full area)
        let to_alice = UWillChain::new_owned(
            ns_id, &ns_secret, alice_id, AccessMode::Read,
        ).unwrap();

        // alice → bob (restricted to bob's subspace)
        let bob_area = Area::new(
            AreaSubspace::Id(bob_id),
            crate::proto::data_model::Path::new_empty(),
            Range::new(0, RangeEnd::Open),
        );
        let to_bob = to_alice.delegate(&alice_secret, &bob_id, &bob_area).unwrap();

        // bob → carol (full area) — should fail, can't widen
        let result = to_bob.delegate(&bob_secret, &carol_id, &Area::new_full());
        assert!(matches!(result, Err(ChainError::AreaWidening { .. })));
    }

    // -- expiry --------------------------------------------------------------

    #[test]
    fn expiry_check() {
        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (_, user_id) = keypair(&mut rng);

        let chain = UWillChain::new_owned(ns_id, &ns_secret, user_id, AccessMode::Read)
            .unwrap();

        // No expiry set — never expired
        assert!(!chain.is_expired(u64::MAX));
        assert!(!chain.is_not_yet_valid(0));
    }

    // -- authorisation_token -------------------------------------------------

    #[test]
    fn authorisation_token_requires_write() {
        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (user_secret, user_id) = keypair(&mut rng);

        let read_chain = UWillChain::new_owned(
            ns_id, &ns_secret, user_id, AccessMode::Read,
        ).unwrap();

        // Create a dummy entry
        let entry = crate::proto::data_model::Entry::new(
            ns_id,
            user_id,
            crate::proto::data_model::Path::new_empty(),
            0,
            0,
            crate::proto::data_model::PayloadDigest::default(),
        );

        let result = read_chain.authorisation_token(&entry, &user_secret);
        assert!(matches!(result, Err(ChainError::NotWriteCapability)));
    }

    #[test]
    fn authorisation_token_for_write_cap() {
        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (user_secret, user_id) = keypair(&mut rng);

        let write_chain = UWillChain::new_owned(
            ns_id, &ns_secret, user_id, AccessMode::Write,
        ).unwrap();

        let entry = crate::proto::data_model::Entry::new(
            ns_id,
            user_id,
            crate::proto::data_model::Path::new_empty(),
            0,
            0,
            crate::proto::data_model::PayloadDigest::default(),
        );

        let token = write_chain.authorisation_token(&entry, &user_secret)
            .expect("authorisation_token failed");

        assert!(token.verify_signature());
        assert_eq!(token.capability().granted_namespace(), ns_id);
    }

    // -- serde roundtrip -----------------------------------------------------

    #[test]
    fn dagcbor_serde_roundtrip() {
        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (_, user_id) = keypair(&mut rng);

        let chain = UWillChain::new_owned(ns_id, &ns_secret, user_id, AccessMode::Read)
            .unwrap();

        let bytes = serde_ipld_dagcbor::to_vec(&chain).expect("serialize failed");
        let decoded: UWillChain =
            serde_ipld_dagcbor::from_slice(&bytes).expect("deserialize failed");

        assert_eq!(decoded.granted_namespace(), chain.granted_namespace());
        assert_eq!(decoded.receiver(), chain.receiver());
        assert_eq!(decoded.command(), chain.command());
        assert_eq!(decoded.granted_area(), chain.granted_area());
    }

    // -- is_authorised_write -------------------------------------------------

    #[test]
    fn is_authorised_write_verifies_signature() {
        use willow_data_model::AuthorisationToken as _;

        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (user_secret, user_id) = keypair(&mut rng);

        let write_chain = UWillChain::new_owned(
            ns_id, &ns_secret, user_id, AccessMode::Write,
        ).unwrap();

        let entry = crate::proto::data_model::Entry::new(
            ns_id,
            user_id,
            crate::proto::data_model::Path::new_empty(),
            0,
            0,
            crate::proto::data_model::PayloadDigest::default(),
        );

        let token = write_chain.authorisation_token(&entry, &user_secret).unwrap();

        // Verification should pass
        assert!(token.is_authorised_write(&entry));
    }

    #[test]
    fn is_authorised_write_after_dagcbor_roundtrip() {
        use willow_data_model::AuthorisationToken as _;

        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (user_secret, user_id) = keypair(&mut rng);

        let write_chain = UWillChain::new_owned(
            ns_id, &ns_secret, user_id, AccessMode::Write,
        ).unwrap();

        let entry = crate::proto::data_model::Entry::new(
            ns_id,
            user_id,
            crate::proto::data_model::Path::new_empty(),
            0,
            0,
            crate::proto::data_model::PayloadDigest::default(),
        );

        let token = write_chain.authorisation_token(&entry, &user_secret).unwrap();

        // Roundtrip through DAG-CBOR
        let bytes = serde_ipld_dagcbor::to_vec(&token).expect("serialize");
        let decoded: super::super::UWillInvocation =
            serde_ipld_dagcbor::from_slice(&bytes).expect("deserialize");

        assert!(decoded.is_authorised_write(&entry));
    }

    #[test]
    fn is_authorised_write_after_wire_roundtrip() {
        // Simulates the wire path: StaticToken (proofs, bound once) +
        // DynamicToken (invocation, per entry).
        use willow_data_model::AuthorisationToken as _;

        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (user_secret, user_id) = keypair(&mut rng);

        let write_chain = UWillChain::new_owned(
            ns_id, &ns_secret, user_id, AccessMode::Write,
        ).unwrap();

        let entry = crate::proto::data_model::Entry::new(
            ns_id,
            user_id,
            crate::proto::data_model::Path::new_empty(),
            0,
            0,
            crate::proto::data_model::PayloadDigest::default(),
        );

        let token = write_chain.authorisation_token(&entry, &user_secret).unwrap();

        // Sender decomposes: StaticToken (chain) + DynamicToken (invocation)
        use crate::proto::meadowcap::serde_encoding::{SerdeMcCapability, SerdeInvocation};
        let static_token = SerdeMcCapability::from(token.capability());
        let dynamic_token = SerdeInvocation::from(token.invocation().clone());

        // Wire roundtrip via postcard
        let static_bytes = postcard::to_allocvec(&static_token).expect("static serialize");
        let dynamic_bytes = postcard::to_allocvec(&dynamic_token).expect("dynamic serialize");

        let decoded_static: SerdeMcCapability =
            postcard::from_bytes(&static_bytes).expect("static deserialize");
        let decoded_dynamic: SerdeInvocation =
            postcard::from_bytes(&dynamic_bytes).expect("dynamic deserialize");

        // Receiver reconstructs
        let reconstructed = super::super::UWillInvocation::from_parts(
            decoded_dynamic.0,
            decoded_static.0.delegations().to_vec(),
        );

        assert!(reconstructed.is_authorised_write(&entry));
    }

    #[test]
    fn is_authorised_write_rejects_wrong_subspace() {
        use willow_data_model::AuthorisationToken as _;

        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (alice_secret, alice_id) = keypair(&mut rng);
        let (_, bob_id) = keypair(&mut rng);

        // Restricted to alice's subspace
        let root = UWillChain::new_owned(
            ns_id, &ns_secret, alice_id, AccessMode::Write,
        ).unwrap();
        let restricted = root.delegate(
            &alice_secret,
            &alice_id,
            &Area::new(AreaSubspace::Id(alice_id), crate::proto::data_model::Path::new_empty(), Range::new(0, RangeEnd::Open)),
        ).unwrap();

        let entry = crate::proto::data_model::Entry::new(
            ns_id,
            alice_id,
            crate::proto::data_model::Path::new_empty(),
            0,
            0,
            crate::proto::data_model::PayloadDigest::default(),
        );

        let token = restricted.authorisation_token(&entry, &alice_secret).unwrap();

        // Entry in bob's subspace — should be rejected
        let other_entry = crate::proto::data_model::Entry::new(
            ns_id,
            bob_id,
            crate::proto::data_model::Path::new_empty(),
            0,
            0,
            crate::proto::data_model::PayloadDigest::default(),
        );

        assert!(token.is_authorised_write(&entry));
        assert!(!token.is_authorised_write(&other_entry));
    }

    // -- root issuer + subject consistency -----------------------------------

    #[test]
    fn from_chain_rejects_wrong_root_issuer() {
        // Build a delegation where issuer != subject (someone other than the
        // namespace owner signs the root). This should be rejected.
        use ucan::delegation::subject::DelegatedSubject;

        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (alice_secret, alice_id) = keypair(&mut rng);

        // Alice (not the namespace owner) signs a root delegation claiming
        // namespace ns_id as subject.
        let alice_key = ed25519_dalek::SigningKey::from_bytes(&alice_secret.to_bytes());
        let issuer = ucan::did::Ed25519Signer::new(alice_key);
        let ns_did = namespace_id_to_ed25519_did(&ns_id).unwrap();
        let alice_did = user_id_to_ed25519_did(&alice_id).unwrap();

        let delegation = ucan::delegation::Delegation::<ucan::did::Ed25519Did>::builder()
            .issuer(issuer)
            .audience(alice_did)
            .subject(DelegatedSubject::Specific(ns_did))
            .command(WillowCommand::Read.to_ucan_command())
            .policy(vec![])
            .try_build()
            .unwrap();

        let result = UWillChain::from_chain(UWillChainRaw::from_delegations(vec![delegation]));
        assert!(
            matches!(result, Err(ChainError::RootIssuerMismatch)),
            "expected RootIssuerMismatch, got {result:?}"
        );
    }

    #[test]
    fn from_chain_rejects_subject_mismatch() {
        // Build a two-delegation chain where the second delegation has a
        // different specific subject than the first.
        use ucan::delegation::subject::DelegatedSubject;

        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (alice_secret, alice_id) = keypair(&mut rng);

        // Valid root: namespace owner → Alice
        let root_chain = UWillChain::new_owned(
            ns_id, &ns_secret, alice_id, AccessMode::Read,
        ).unwrap();

        // Alice builds a delegation with a DIFFERENT namespace as subject
        let other_ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let other_ns_did = namespace_id_to_ed25519_did(&other_ns_secret.id()).unwrap();
        let (_, bob_id) = keypair(&mut rng);
        let bob_did = user_id_to_ed25519_did(&bob_id).unwrap();

        let alice_key = ed25519_dalek::SigningKey::from_bytes(&alice_secret.to_bytes());
        let issuer = ucan::did::Ed25519Signer::new(alice_key);

        let bad_delegation = ucan::delegation::Delegation::<ucan::did::Ed25519Did>::builder()
            .issuer(issuer)
            .audience(bob_did)
            .subject(DelegatedSubject::Specific(other_ns_did))
            .command(WillowCommand::Read.to_ucan_command())
            .policy(vec![])
            .try_build()
            .unwrap();

        let mut delegations = root_chain.delegations().to_vec();
        delegations.push(bad_delegation);

        let result = UWillChain::from_chain(UWillChainRaw::from_delegations(delegations));
        assert!(
            matches!(result, Err(ChainError::SubjectMismatch { .. })),
            "expected SubjectMismatch, got {result:?}"
        );
    }
}
