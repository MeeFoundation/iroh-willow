//! Revocation store for UWill.
//!
//! Each peer maintains a local set of revoked delegation CIDs.
//! When validating a chain, any delegation whose CID appears in
//! the revoked set invalidates the entire chain.
//!
//! Revocations are modeled as UCAN Invocations with `cmd: ucan/revoke`.
//! See `uwill/invocation.rs` for building and validating revocation
//! invocations.

use std::collections::HashSet;

use ipld_core::cid::Cid;

use super::chain::UWillChain;

/// CID-indexed set of revoked delegations.
#[derive(Debug, Clone, Default)]
pub struct RevocationStore {
    revoked: HashSet<Cid>,
}

impl RevocationStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a specific delegation CID is revoked.
    pub fn is_revoked(&self, cid: &Cid) -> bool {
        self.revoked.contains(cid)
    }

    pub(crate) fn revoke(&mut self, cid: Cid) {
        self.revoked.insert(cid);
    }

    /// Check if ANY delegation in a chain is revoked.
    pub fn chain_is_revoked(&self, chain: &UWillChain) -> bool {
        if self.revoked.is_empty() {
            return false;
        }
        chain.delegation_cids().iter().any(|cid| self.is_revoked(cid))
    }

    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use rand_core::SeedableRng;

    use super::*;
    use crate::proto::{
        keys::{NamespaceKind, NamespaceSecretKey, UserSecretKey},
        meadowcap::AccessMode,
    };
    use crate::uwill::invocation::build_revoke_invocation;

    fn rng() -> rand_chacha::ChaCha12Rng {
        rand_chacha::ChaCha12Rng::seed_from_u64(99)
    }

    fn setup() -> (UWillChain, NamespaceSecretKey, UserSecretKey) {
        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let user_secret = UserSecretKey::generate(&mut rng);
        let user_id = user_secret.public_key().id();

        let chain = UWillChain::new_owned(
            ns_id, &ns_secret, user_id, AccessMode::Read,
        ).unwrap();

        (chain, ns_secret, user_secret)
    }

    #[test]
    fn revoke_via_invocation() {
        let (chain, ns_secret, _) = setup();
        let mut store = RevocationStore::new();

        assert!(!store.chain_is_revoked(&chain));

        let delegation_cid = chain.delegations()[0].to_cid();
        let ns_key = ed25519_dalek::SigningKey::from_bytes(&ns_secret.to_bytes());
        let inv = build_revoke_invocation(delegation_cid, &chain, &ns_key).unwrap();

        let revoked_cid = inv.validate_revoke().unwrap();
        store.revoke(revoked_cid);

        assert!(store.chain_is_revoked(&chain));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn revoke_unrelated_chain() {
        let (chain, ns_secret, _) = setup();
        let mut store = RevocationStore::new();

        let mut rng = rng();
        let _ = UserSecretKey::generate(&mut rng);
        let other_secret = UserSecretKey::generate(&mut rng);
        let other_id = other_secret.public_key().id();
        let other_chain = UWillChain::new_owned(
            ns_secret.id(), &ns_secret, other_id, AccessMode::Read,
        ).unwrap();

        let cid = other_chain.delegations()[0].to_cid();
        let ns_key = ed25519_dalek::SigningKey::from_bytes(&ns_secret.to_bytes());
        let inv = build_revoke_invocation(cid, &other_chain, &ns_key).unwrap();

        let revoked_cid = inv.validate_revoke().unwrap();
        store.revoke(revoked_cid);

        assert!(!store.chain_is_revoked(&chain));
        assert!(store.chain_is_revoked(&other_chain));
    }

    #[test]
    fn revocation_authority_check() {
        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();

        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();
        let bob_secret = UserSecretKey::generate(&mut rng);
        let bob_id = bob_secret.public_key().id();

        let to_alice = UWillChain::new_owned(
            ns_id, &ns_secret, alice_id, AccessMode::Read,
        ).unwrap();
        let to_bob = to_alice.delegate(
            &alice_secret,
            &bob_id,
            &crate::proto::grouping::Area::new_full(),
        ).unwrap();

        let cid = to_bob.delegations()[1].to_cid();

        // Namespace owner can revoke
        let ns_key = ed25519_dalek::SigningKey::from_bytes(&ns_secret.to_bytes());
        let inv = build_revoke_invocation(cid, &to_bob, &ns_key).unwrap();
        assert!(inv.validate_revoke().is_ok());

        // Alice can revoke (she issued it)
        let alice_key = ed25519_dalek::SigningKey::from_bytes(&alice_secret.to_bytes());
        let inv = build_revoke_invocation(cid, &to_bob, &alice_key).unwrap();
        assert!(inv.validate_revoke().is_ok());

        // Bob cannot revoke (leaf, not an issuer above)
        let bob_key = ed25519_dalek::SigningKey::from_bytes(&bob_secret.to_bytes());
        let inv = build_revoke_invocation(cid, &to_bob, &bob_key).unwrap();
        assert!(inv.validate_revoke().is_err());
    }

    #[test]
    fn unauthorized_outsider_rejected() {
        let mut rng = rng();
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();

        let to_alice = UWillChain::new_owned(
            ns_id, &ns_secret, alice_id, AccessMode::Read,
        ).unwrap();

        let cid = to_alice.delegations()[0].to_cid();
        let outsider_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let inv = build_revoke_invocation(cid, &to_alice, &outsider_key).unwrap();

        // Signature valid but authority check fails
        assert!(inv.verify_signature());
        assert!(inv.validate_revoke().is_err());
    }
}
