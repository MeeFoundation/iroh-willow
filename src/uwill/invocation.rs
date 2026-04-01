//! UCAN Invocation integration for Willow.
//!
//! All actions (write, read-prove, enumerate-prove, revoke) are modeled
//! as UCAN Invocations. Every invocation runs through `syntatic_checks()`
//! from the `ucan` crate, which validates subject, issuer chain, command
//! hierarchy, and area predicates. For writes, Willow-native
//! `area.includes_entry()` additionally validates the specific entry.

use std::collections::BTreeMap;

use ipld_core::cid::Cid;
use serde::{Deserialize, Serialize};
use ucan::{
    delegation::Delegation,
    did::{Ed25519Did, Ed25519Signer},
    invocation::Invocation,
    promise::Promised,
};

use crate::proto::{
    data_model::Entry,
    keys::UserSecretKey,
};

use super::{
    area_extract,
    chain::{namespace_id_to_ed25519_did, user_id_to_ed25519_did, UWillChain},
};

// ---------------------------------------------------------------------------
// UWillInvocation — unified invocation type
// ---------------------------------------------------------------------------

/// A UCAN Invocation with resolved proof delegations.
///
/// Used for all authorization: write (`willow/write`), read-prove
/// (`willow/read`), enumerate-prove (`willow/enumerate`), and
/// revocation (`ucan/revoke`). Self-contained: carries the signed
/// envelope plus resolved delegations for validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UWillInvocation {
    /// The signed UCAN invocation. Always present.
    invocation: Invocation<Ed25519Did>,
    /// Resolved proof delegations. Always bundled — never assume the
    /// receiver has them.
    resolved_proofs: Vec<Delegation<Ed25519Did>>,
}

impl UWillInvocation {
    /// The inner UCAN invocation.
    pub fn invocation(&self) -> &Invocation<Ed25519Did> {
        &self.invocation
    }

    /// The resolved proof delegations.
    pub fn resolved_proofs(&self) -> &[Delegation<Ed25519Did>] {
        &self.resolved_proofs
    }

    /// Verify the invocation's signature.
    pub fn verify_signature(&self) -> bool {
        self.invocation.verify().is_ok()
    }

    /// Extract the write capability chain from resolved proofs.
    ///
    /// Returns a `UWillChain` for compatibility with existing code
    /// that needs the capability (PAI, static tokens, etc.).
    pub fn to_capability_chain(&self) -> Result<UWillChain, InvocationError> {
        UWillChain::from_chain(super::chain::UWillChainRaw::from_delegations(
            self.resolved_proofs.clone(),
        ))
        .map_err(|e| InvocationError::ChainValidation(format!("{e}")))
    }

    /// Reconstruct from an invocation + resolved proofs.
    pub fn from_parts(
        invocation: Invocation<Ed25519Did>,
        resolved_proofs: Vec<Delegation<Ed25519Did>>,
    ) -> Self {
        Self {
            invocation,
            resolved_proofs,
        }
    }

    /// Common stateless validation for ALL invocations.
    ///
    /// Every invocation (write, read, enumerate, revoke) passes through
    /// this. Checks:
    /// 1. Invocation signature
    /// 2. Proof binding (resolved delegations match signed prf CIDs)
    /// 3. Chain integrity via `from_chain()` (delegation signatures,
    ///    root issuer, subject consistency, area narrowing, principals)
    /// 4. Expiry / not-before
    ///
    /// Revocation is NOT checked here — it's stateful and checked
    /// explicitly at each security boundary (see `static_tokens.rs`,
    /// `capabilities.rs`, `auth.rs`).
    fn validate_common(&self) -> Result<UWillChain, InvocationError> {
        // 1. Invocation signature
        self.invocation
            .verify()
            .map_err(|e| InvocationError::Signature(format!("{e}")))?;

        // 2. Verify resolved proofs match the signed prf CIDs
        self.verify_proof_binding()?;

        // 3. Chain integrity
        let chain = self.to_capability_chain()?;

        // 4. Expiry / not-before
        Self::check_expiry(&chain)?;

        Ok(chain)
    }

    /// Run UCAN `syntatic_checks()` — additional validation for
    /// willow/* invocations (delegated authority model).
    ///
    /// Validates invocation-to-chain link, area predicates, and
    /// command hierarchy. NOT used for revocations (inherent authority).
    fn run_syntatic_checks(&self) -> Result<(), InvocationError> {
        self.invocation
            .payload()
            .syntatic_checks(self.resolved_proofs.iter())
            .map_err(|e| InvocationError::SyntaticCheck(format!("{e}")))?;
        Ok(())
    }

    /// The capability chain (from resolved proofs).
    pub fn capability(&self) -> UWillChain {
        self.to_capability_chain()
            .expect("resolved proofs should form a valid chain")
    }
}

// ---------------------------------------------------------------------------
// Write invocations
// ---------------------------------------------------------------------------

/// Build a write invocation for an entry.
///
/// Creates a UCAN Invocation with:
/// - `cmd`: `willow/write`
/// - `arg`: capability area fields (for `syntatic_checks()` predicate eval)
/// - `prf`: delegation CIDs from the proof chain
/// - Signed by the writer
///
/// The args describe the capability's area, NOT the specific entry.
/// Entry containment is validated separately via `area.includes_entry()`.
pub fn build_write_invocation(
    _entry: &Entry,
    chain: &UWillChain,
    user_secret: &UserSecretKey,
) -> Result<UWillInvocation, InvocationError> {
    let args = area_extract::area_to_args(chain.granted_area());
    build_invocation(chain, user_secret, super::command::WillowCommand::Write, args)
}

/// Build a read-proof invocation (proves read capability ownership).
pub fn build_read_invocation(
    challenge: &[u8; 32],
    chain: &UWillChain,
    user_secret: &UserSecretKey,
) -> Result<UWillInvocation, InvocationError> {
    let mut args = area_extract::area_to_args(chain.granted_area());
    args.insert(ARG_CHALLENGE.to_owned(), Promised::Bytes(challenge.to_vec()));
    build_invocation(chain, user_secret, super::command::WillowCommand::Read, args)
}

/// Build an enumerate-proof invocation (proves namespace membership).
pub fn build_enumerate_invocation(
    challenge: &[u8; 32],
    chain: &UWillChain,
    user_secret: &UserSecretKey,
) -> Result<UWillInvocation, InvocationError> {
    let mut args = area_extract::area_to_args(chain.granted_area());
    args.insert(ARG_CHALLENGE.to_owned(), Promised::Bytes(challenge.to_vec()));
    build_invocation(chain, user_secret, super::command::WillowCommand::Enumerate, args)
}

/// Argument key constants.
const ARG_CHALLENGE: &str = "challenge";
const ARG_REVOKE: &str = "revoke";

/// Revocation command segments.
const CMD_UCAN_REVOKE: &[&str] = &["ucan", "revoke"];

/// Shared builder for willow/* invocations.
fn build_invocation(
    chain: &UWillChain,
    user_secret: &UserSecretKey,
    command: super::command::WillowCommand,
    args: BTreeMap<String, Promised>,
) -> Result<UWillInvocation, InvocationError> {
    let issuer_key = ed25519_dalek::SigningKey::from_bytes(&user_secret.to_bytes());
    let issuer = Ed25519Signer::new(issuer_key);

    let issuer_did = user_id_to_ed25519_did(&chain.receiver())
        .map_err(|e| InvocationError::InvalidKey(e.to_string()))?;

    let namespace_did = namespace_id_to_ed25519_did(&chain.granted_namespace())
        .map_err(|e| InvocationError::InvalidKey(e.to_string()))?;

    let proof_cids: Vec<Cid> = chain.delegation_cids().to_vec();

    let invocation = Invocation::<Ed25519Did>::builder()
        .issuer(issuer)
        .audience(issuer_did)
        .subject(namespace_did)
        .command(command.to_ucan_command())
        .arguments(args)
        .proofs(proof_cids)
        .try_build()
        .map_err(|e| InvocationError::Build(format!("{e}")))?;

    Ok(UWillInvocation {
        invocation,
        resolved_proofs: chain.delegations().to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Revocation invocations
// ---------------------------------------------------------------------------

/// Build a revocation invocation.
///
/// Creates a UCAN Invocation with:
/// - `cmd`: `ucan/revoke`
/// - `arg`: `{ revoke: <CID bytes> }`
/// - `prf`: delegation CIDs proving the revoker's authority
/// - Signed by the revoker
pub fn build_revoke_invocation(
    revoked_cid: Cid,
    chain: &UWillChain,
    revoker_secret: &ed25519_dalek::SigningKey,
) -> Result<UWillInvocation, InvocationError> {
    let revoker = Ed25519Signer::new(revoker_secret.clone());
    let revoker_did = Ed25519Did::from(revoker_secret.verifying_key());

    let namespace_did = namespace_id_to_ed25519_did(&chain.granted_namespace())
        .map_err(|e| InvocationError::InvalidKey(e.to_string()))?;

    let proof_cids: Vec<Cid> = chain.delegation_cids().to_vec();

    let mut args = BTreeMap::new();
    args.insert(
        "revoke".to_owned(),
        Promised::Bytes(revoked_cid.to_bytes()),
    );

    let invocation = Invocation::<Ed25519Did>::builder()
        .issuer(revoker)
        .audience(revoker_did)
        .subject(namespace_did)
        .command(ucan::command::Command::new(CMD_UCAN_REVOKE.iter().map(|s| (*s).to_owned()).collect()))
        .arguments(args)
        .proofs(proof_cids)
        .try_build()
        .map_err(|e| InvocationError::Build(format!("{e}")))?;

    Ok(UWillInvocation {
        invocation,
        resolved_proofs: chain.delegations().to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Validation helpers for UWillInvocation
// ---------------------------------------------------------------------------

impl UWillInvocation {
    /// Validate this invocation as a write authorization for an entry.
    pub fn validate_write(&self, entry: &Entry) -> Result<(), InvocationError> {
        let chain = self.validate_common()?;
        self.run_syntatic_checks()?;

        if !chain.proves_write() {
            return Err(InvocationError::WrongCommand(
                "proof chain does not prove write".into(),
            ));
        }
        if chain.granted_namespace() != *entry.namespace_id() {
            return Err(InvocationError::NamespaceMismatch);
        }
        if !chain.granted_area().includes_entry(entry) {
            return Err(InvocationError::EntryOutsideArea);
        }

        Ok(())
    }

    /// Validate this invocation as a read capability proof.
    pub fn validate_read_proof(
        &self,
        expected_challenge: &[u8; 32],
    ) -> Result<UWillChain, InvocationError> {
        let chain = self.validate_common()?;
        self.run_syntatic_checks()?;
        self.check_challenge(expected_challenge)?;

        if !chain.proves_read() {
            return Err(InvocationError::WrongCommand(
                "proof chain does not prove read".into(),
            ));
        }

        Ok(chain)
    }

    /// Validate this invocation as an enumerate capability proof.
    pub fn validate_enumerate_proof(
        &self,
        expected_challenge: &[u8; 32],
    ) -> Result<UWillChain, InvocationError> {
        let chain = self.validate_common()?;
        self.run_syntatic_checks()?;
        self.check_challenge(expected_challenge)?;

        if !chain.proves_enumerate() {
            return Err(InvocationError::WrongCommand(
                "proof chain does not prove enumerate".into(),
            ));
        }

        Ok(chain)
    }

    /// Validate this invocation as a revocation (inherent authority).
    ///
    /// Per UCAN spec, inherent revocation authority comes from being an
    /// issuer in the delegation chain — NOT from a delegated command.
    ///
    /// `syntatic_checks()` is not used here: revocations use `ucan/revoke`
    /// which is outside the proof chain's `willow/*` command tree. The
    /// authority model is positional (issuer in chain), not command-based.
    /// Delegated revocation (`ucan/revoke` as a delegable command) is not
    /// yet implemented.
    pub fn validate_revoke(&self) -> Result<Cid, InvocationError> {
        let _chain = self.validate_common()?;

        // Command check (not via syntatic_checks — different authority model)
        let cmd = self.invocation.command();
        if cmd.segments().iter().map(|s| s.as_str()).collect::<Vec<_>>() != CMD_UCAN_REVOKE {
            return Err(InvocationError::WrongCommand(cmd.to_string()));
        }

        // Extract revoked CID from args
        let args = self.invocation.arguments();
        let revoke_bytes = match args.get(ARG_REVOKE) {
            Some(Promised::Bytes(b)) => b,
            _ => return Err(InvocationError::MissingArg("revoke")),
        };
        let cid = Cid::try_from(revoke_bytes.as_slice())
            .map_err(|e| InvocationError::InvalidArg(format!("invalid CID: {e}")))?;

        // Inherent authority: revoker must be an issuer at or above
        // the revoked delegation in the proof chain.
        let revoker_did = self.invocation.issuer();
        let mut found_authority = false;
        for d in &self.resolved_proofs {
            if d.issuer() == revoker_did {
                found_authority = true;
                break;
            }
            if d.to_cid() == cid {
                break;
            }
        }
        if !found_authority {
            return Err(InvocationError::Unauthorized);
        }

        Ok(cid)
    }

    fn check_challenge(&self, expected: &[u8; 32]) -> Result<(), InvocationError> {
        let args = self.invocation.arguments();
        match args.get(ARG_CHALLENGE) {
            Some(Promised::Bytes(b)) if b.as_slice() == expected => Ok(()),
            Some(Promised::Bytes(_)) => Err(InvocationError::ChallengeMismatch),
            _ => Err(InvocationError::MissingArg("challenge")),
        }
    }

    /// Verify that the resolved proof delegations match the CIDs in the
    /// signed `prf` field. Without this check, an attacker could bundle
    /// different delegations than what the invocation commits to.
    fn verify_proof_binding(&self) -> Result<(), InvocationError> {
        let prf_cids = self.invocation.proofs();
        if prf_cids.len() != self.resolved_proofs.len() {
            return Err(InvocationError::ProofBindingMismatch);
        }
        for (expected_cid, delegation) in prf_cids.iter().zip(self.resolved_proofs.iter()) {
            if *expected_cid != delegation.to_cid() {
                return Err(InvocationError::ProofBindingMismatch);
            }
        }
        Ok(())
    }

    fn check_expiry(chain: &UWillChain) -> Result<(), InvocationError> {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if chain.is_expired(now_secs) {
            return Err(InvocationError::Expired);
        }
        if chain.is_not_yet_valid(now_secs) {
            return Err(InvocationError::NotYetValid);
        }
        Ok(())
    }
}

impl willow_data_model::AuthorisationToken<
    { crate::proto::data_model::MAX_COMPONENT_LENGTH },
    { crate::proto::data_model::MAX_COMPONENT_COUNT },
    { crate::proto::data_model::MAX_PATH_LENGTH },
    crate::proto::data_model::NamespaceId,
    crate::proto::data_model::SubspaceId,
    crate::proto::data_model::PayloadDigest,
> for UWillInvocation
{
    fn is_authorised_write(&self, entry: &Entry) -> bool {
        // TODO: Fork willow-data-model to add a Context associated type
        // to AuthorisationToken, so is_authorised_write can accept the
        // revocation store. That would let AuthorisedEntry::new() do the
        // full check (including revocation) in one place, eliminating the
        // need for callers to check revocation separately.
        //
        // Current workaround: this method is defense-in-depth only (no
        // revocation check). The security boundary for untrusted entries
        // is static_tokens.rs (validate_write + new_unchecked) with
        // explicit revocation checks in data.rs / reconciler.rs / run.rs.
        self.validate_write(entry).is_ok()
    }
}

// Wire protocol: StaticToken = proof delegations (shared, bound once),
// DynamicToken = serialized Invocation (per entry).

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum InvocationError {
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("invocation build failed: {0}")]
    Build(String),
    #[error("signature verification failed: {0}")]
    Signature(String),
    #[error("syntatic_checks failed: {0}")]
    SyntaticCheck(String),
    #[error("wrong command: {0}")]
    WrongCommand(String),
    #[error("missing argument: {0}")]
    MissingArg(&'static str),
    #[error("invalid argument: {0}")]
    InvalidArg(String),
    #[error("challenge nonce mismatch")]
    ChallengeMismatch,
    #[error("revoker has no authority")]
    Unauthorized,
    #[error("invocation namespace does not match entry namespace")]
    NamespaceMismatch,
    #[error("entry outside capability area")]
    EntryOutsideArea,
    #[error("capability chain expired")]
    Expired,
    #[error("capability chain not yet valid")]
    NotYetValid,
    #[error("resolved proof delegations do not match signed prf CIDs")]
    ProofBindingMismatch,
    #[error("chain validation failed: {0}")]
    ChainValidation(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use rand_core::SeedableRng as _;

    use super::*;
    use crate::proto::{
        data_model::{Path, PathExt as _, PayloadDigest},
        keys::{NamespaceKind, NamespaceSecretKey},
        meadowcap::AccessMode,
    };
    use willow_data_model::grouping::{Area, AreaSubspace, Range, RangeEnd};

    #[test]
    fn build_and_validate_write_invocation() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(300);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();

        let chain =
            UWillChain::new_owned(ns_id, &ns_secret, alice_id, AccessMode::Write).unwrap();

        let entry = crate::proto::data_model::Entry::new(
            ns_id,
            alice_id,
            Path::from_bytes(&[b"test"]).unwrap(),
            1_700_000_000,
            0,
            PayloadDigest::default(),
        );

        let inv = build_write_invocation(&entry, &chain, &alice_secret).unwrap();

        assert!(inv.verify_signature());
        assert!(inv.validate_write(&entry).is_ok());
    }

    #[test]
    fn build_and_validate_revoke_invocation() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(301);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();

        let chain =
            UWillChain::new_owned(ns_id, &ns_secret, alice_id, AccessMode::Read).unwrap();

        let delegation_cid = chain.delegations()[0].to_cid();
        let ns_key = ed25519_dalek::SigningKey::from_bytes(&ns_secret.to_bytes());

        let inv = build_revoke_invocation(delegation_cid, &chain, &ns_key).unwrap();

        assert!(inv.verify_signature());
        let revoked_cid = inv.validate_revoke().unwrap();
        assert_eq!(revoked_cid, delegation_cid);
    }

    #[test]
    fn revoke_invocation_rejects_unauthorized() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(302);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();

        let chain =
            UWillChain::new_owned(ns_id, &ns_secret, alice_id, AccessMode::Read).unwrap();

        let delegation_cid = chain.delegations()[0].to_cid();

        // Outsider tries to revoke
        let outsider_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let inv = build_revoke_invocation(delegation_cid, &chain, &outsider_key).unwrap();

        assert!(inv.verify_signature()); // signature is valid
        let result = inv.validate_revoke();
        assert!(matches!(result, Err(InvocationError::Unauthorized)));
    }

    // -- read invocations ----------------------------------------------------

    #[test]
    fn build_and_validate_read_invocation() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(400);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();

        let chain =
            UWillChain::new_owned(ns_id, &ns_secret, alice_id, AccessMode::Read).unwrap();

        let challenge = [42u8; 32];
        let inv = build_read_invocation(&challenge, &chain, &alice_secret).unwrap();

        let result = inv.validate_read_proof(&challenge);
        assert!(result.is_ok(), "valid read proof: {result:?}");
        let validated_chain = result.unwrap();
        assert_eq!(validated_chain.granted_namespace(), ns_id);
        assert_eq!(validated_chain.receiver(), alice_id);
    }

    #[test]
    fn read_invocation_wrong_challenge_rejected() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(401);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();

        let chain =
            UWillChain::new_owned(ns_id, &ns_secret, alice_id, AccessMode::Read).unwrap();

        let challenge = [42u8; 32];
        let wrong_challenge = [99u8; 32];
        let inv = build_read_invocation(&challenge, &chain, &alice_secret).unwrap();

        let result = inv.validate_read_proof(&wrong_challenge);
        assert!(matches!(result, Err(InvocationError::ChallengeMismatch)));
    }

    #[test]
    fn read_invocation_wrong_signer_rejected() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(402);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();
        let mallory_secret = UserSecretKey::generate(&mut rng);

        let chain =
            UWillChain::new_owned(ns_id, &ns_secret, alice_id, AccessMode::Read).unwrap();

        let challenge = [42u8; 32];
        // Mallory signs with her key but Alice's chain
        let inv = build_read_invocation(&challenge, &chain, &mallory_secret).unwrap();

        let result = inv.validate_read_proof(&challenge);
        assert!(result.is_err(), "wrong signer should fail: {result:?}");
    }

    // -- enumerate invocations -----------------------------------------------

    #[test]
    fn build_and_validate_enumerate_invocation() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(410);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();

        let chain =
            UWillChain::new_enumerate(ns_id, &ns_secret, alice_id).unwrap();

        let challenge = [7u8; 32];
        let inv = build_enumerate_invocation(&challenge, &chain, &alice_secret).unwrap();

        let result = inv.validate_enumerate_proof(&challenge);
        assert!(result.is_ok(), "valid enumerate proof: {result:?}");
    }

    #[test]
    fn enumerate_invocation_not_accepted_as_read() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(411);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();

        let chain =
            UWillChain::new_enumerate(ns_id, &ns_secret, alice_id).unwrap();

        let challenge = [7u8; 32];
        let inv = build_enumerate_invocation(&challenge, &chain, &alice_secret).unwrap();

        // Enumerate proof should NOT validate as read proof
        let result = inv.validate_read_proof(&challenge);
        assert!(result.is_err());
    }

    // -- Full command chain tests --------------------------------------------

    #[test]
    fn full_command_chain_proves_read() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(420);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();

        // Full command chain (willow) should accept read invocation
        use super::super::command::WillowCommand;
        let chain = UWillChain::new_owned(ns_id, &ns_secret, alice_id, AccessMode::Write).unwrap();
        assert_eq!(chain.command(), WillowCommand::Write);

        // Write chain does NOT prove read
        let challenge = [1u8; 32];
        let inv = build_read_invocation(&challenge, &chain, &alice_secret).unwrap();
        let result = inv.validate_read_proof(&challenge);
        assert!(result.is_err(), "write chain should not prove read");

        // Now use a Full chain (build directly)
        let full_chain = super::super::chain::UWillChain::build_root_delegation_for_test(
            ns_id, &ns_secret, alice_id, WillowCommand::Full,
        ).unwrap();

        let inv = build_read_invocation(&challenge, &full_chain, &alice_secret).unwrap();
        let result = inv.validate_read_proof(&challenge);
        assert!(result.is_ok(), "Full chain should prove read: {result:?}");
    }

    #[test]
    fn full_command_chain_proves_enumerate() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(421);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();

        use super::super::command::WillowCommand;
        let full_chain = super::super::chain::UWillChain::build_root_delegation_for_test(
            ns_id, &ns_secret, alice_id, WillowCommand::Full,
        ).unwrap();

        let challenge = [2u8; 32];
        let inv = build_enumerate_invocation(&challenge, &full_chain, &alice_secret).unwrap();
        let result = inv.validate_enumerate_proof(&challenge);
        assert!(result.is_ok(), "Full chain should prove enumerate: {result:?}");
    }

    // -- write invocation with area validation -------------------------------

    #[test]
    fn write_invocation_entry_outside_area_rejected() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(430);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();
        let bob_secret = UserSecretKey::generate(&mut rng);
        let bob_id = bob_secret.public_key().id();

        let root = UWillChain::new_owned(ns_id, &ns_secret, alice_id, AccessMode::Write).unwrap();
        let restricted = root.delegate(
            &alice_secret, &alice_id,
            &Area::new(AreaSubspace::Id(alice_id), Path::from_bytes(&[b"data"]).unwrap(), Range::new(0, RangeEnd::Open)),
        ).unwrap();

        let good_entry = Entry::new(
            ns_id, alice_id,
            Path::from_bytes(&[b"data", b"file"]).unwrap(),
            0, 0, PayloadDigest::default(),
        );
        let bad_entry = Entry::new(
            ns_id, bob_id,
            Path::new_empty(), 0, 0, PayloadDigest::default(),
        );

        let good_inv = build_write_invocation(&good_entry, &restricted, &alice_secret).unwrap();
        assert!(good_inv.validate_write(&good_entry).is_ok());
        assert!(
            matches!(good_inv.validate_write(&bad_entry), Err(InvocationError::EntryOutsideArea)),
            "entry in wrong subspace should be rejected"
        );
    }

    // -- syntatic_checks integration -----------------------------------------

    #[test]
    fn syntatic_checks_passes_for_read_invocation() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(440);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();

        let root = UWillChain::new_owned(ns_id, &ns_secret, alice_id, AccessMode::Read).unwrap();
        let restricted = root.delegate(
            &alice_secret, &alice_id,
            &Area::new(AreaSubspace::Id(alice_id), Path::from_bytes(&[b"msgs"]).unwrap(), Range::new(0, RangeEnd::Open)),
        ).unwrap();

        let challenge = [5u8; 32];
        let inv = build_read_invocation(&challenge, &restricted, &alice_secret).unwrap();

        // syntatic_checks should pass (area predicates match)
        assert!(inv.run_syntatic_checks().is_ok());
        assert!(inv.validate_read_proof(&challenge).is_ok());
    }

    #[test]
    fn multi_level_path_narrowing_passes() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(450);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();
        let bob_secret = UserSecretKey::generate(&mut rng);
        let bob_id = bob_secret.public_key().id();

        // Root → alice (restricted to "data") → bob (restricted to "data/msgs")
        let root = UWillChain::new_owned(ns_id, &ns_secret, alice_id, AccessMode::Read).unwrap();
        let alice_chain = root.delegate(
            &alice_secret, &alice_id,
            &Area::new(AreaSubspace::Any, Path::from_bytes(&[b"data"]).unwrap(), Range::new(0, RangeEnd::Open)),
        ).unwrap();
        let bob_chain = alice_chain.delegate(
            &alice_secret, &bob_id,
            &Area::new(AreaSubspace::Any, Path::from_bytes(&[b"data", b"msgs"]).unwrap(), Range::new(0, RangeEnd::Open)),
        ).unwrap();

        let challenge = [3u8; 32];
        let inv = build_read_invocation(&challenge, &bob_chain, &bob_secret).unwrap();

        // syntatic_checks should pass — Or(Equal, Like) handles multi-level narrowing
        let result = inv.validate_read_proof(&challenge);
        assert!(result.is_ok(), "multi-level path narrowing: {result:?}");
    }

    // -- proof binding -------------------------------------------------------

    #[test]
    fn swapped_delegations_rejected() {
        // Build a valid invocation, then replace the resolved delegations
        // with a different chain. The signed prf CIDs won't match.
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(460);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();

        let chain =
            UWillChain::new_owned(ns_id, &ns_secret, alice_id, AccessMode::Write).unwrap();

        let entry = crate::proto::data_model::Entry::new(
            ns_id, alice_id,
            Path::from_bytes(&[b"test"]).unwrap(),
            0, 0, PayloadDigest::default(),
        );

        let inv = build_write_invocation(&entry, &chain, &alice_secret).unwrap();
        // Valid invocation works
        assert!(inv.validate_write(&entry).is_ok());

        // Now build a different chain and swap the delegations
        let other_ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let other_chain = UWillChain::new_owned(
            other_ns_secret.id(), &other_ns_secret, alice_id, AccessMode::Write,
        ).unwrap();

        let tampered = UWillInvocation::from_parts(
            inv.invocation().clone(),
            other_chain.delegations().to_vec(),
        );
        let result = tampered.validate_write(&entry);
        assert!(
            matches!(result, Err(InvocationError::ProofBindingMismatch)),
            "swapped delegations should be rejected: {result:?}"
        );
    }
}
