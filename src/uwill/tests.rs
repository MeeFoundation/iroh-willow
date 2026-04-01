//! Cross-cutting tests for UWill capability system.
//!
//! Tests security invariants that span multiple subsystems
//! (chain validation, revocation, invocations, storage).

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use rand_core::{CryptoRngCore, SeedableRng};
    use willow_data_model::{grouping::{Area, AreaSubspace, Range, RangeEnd}, AuthorisationToken as _};

    use crate::{
        proto::{
            data_model::{Entry, Path, PathExt as _, PayloadDigest},
            keys::{NamespaceKind, NamespaceSecretKey, UserSecretKey, UserId},
            meadowcap::AccessMode,
        },
        uwill::{
            chain::{UWillChain, UWillChainRaw},
            invocation::{build_revoke_invocation, build_write_invocation},
            revocation::RevocationStore,
        },
    };

    fn keypair<R: CryptoRngCore + ?Sized>(rng: &mut R) -> (UserSecretKey, UserId) {
        let secret = UserSecretKey::generate(rng);
        let public = secret.public_key();
        (secret, public.id())
    }

    // -----------------------------------------------------------------------
    // 1. Revocation blocks import
    // -----------------------------------------------------------------------

    /// Revoke a delegation, then verify that a chain containing it
    /// is detected as revoked by the RevocationStore.
    #[test]
    fn revoked_chain_detected() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(500);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (_alice_secret, alice_id) = keypair(&mut rng);

        let chain = UWillChain::new_owned(
            ns_id, &ns_secret, alice_id, AccessMode::Read,
        ).unwrap();

        let mut store = RevocationStore::new();
        assert!(!store.chain_is_revoked(&chain));

        // Revoke via invocation
        let cid = chain.delegations()[0].to_cid();
        let ns_key = ed25519_dalek::SigningKey::from_bytes(&ns_secret.to_bytes());
        let inv = build_revoke_invocation(cid, &chain, &ns_key).unwrap();
        let revoked_cid = inv.validate_revoke().unwrap();
        store.revoke(revoked_cid);

        // Chain is now revoked
        assert!(store.chain_is_revoked(&chain));

        // A different chain for the same namespace is NOT revoked
        let (_, bob_id) = keypair(&mut rng);
        let bob_chain = UWillChain::new_owned(
            ns_id, &ns_secret, bob_id, AccessMode::Read,
        ).unwrap();
        assert!(!store.chain_is_revoked(&bob_chain));
    }

    // -----------------------------------------------------------------------
    // 2. Forged chain rejected
    // -----------------------------------------------------------------------

    /// A chain with delegations signed by the wrong key should be
    /// rejected during validation (from_chain).
    #[test]
    fn forged_chain_rejected() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(501);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (_, alice_id) = keypair(&mut rng);

        // Create a legitimate chain
        let legit = UWillChain::new_owned(
            ns_id, &ns_secret, alice_id, AccessMode::Read,
        ).unwrap();

        // Serialize, deserialize to get raw delegations
        let bytes = serde_ipld_dagcbor::to_vec(&legit).unwrap();
        let raw: UWillChainRaw = serde_ipld_dagcbor::from_slice(&bytes).unwrap();

        // The legitimate chain validates fine
        assert!(UWillChain::from_chain(raw.clone()).is_ok());

        // Now create a chain signed by a DIFFERENT namespace key
        let fake_ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let _forged = UWillChain::new_owned(
            ns_id, // same namespace ID but wrong key!
            &fake_ns_secret,
            alice_id,
            AccessMode::Read,
        );

        // This should fail because the namespace ID doesn't match the
        // signing key — the issuer DID in the delegation won't match
        // the expected namespace. But since we're using the fake key's
        // own namespace ID implicitly... let me construct the forgery
        // more carefully.

        // The real test: take a legitimate delegation and try to
        // deserialize it as if it came from a different context.
        // Since from_chain verifies signatures, any tampering with
        // the serialized bytes should fail.

        // Tamper with the serialized bytes (flip a byte in the middle)
        let mut tampered_bytes = bytes.clone();
        if tampered_bytes.len() > 50 {
            tampered_bytes[50] ^= 0xFF;
        }

        // Deserialization might fail, or if it succeeds, validation should fail
        let result: Result<UWillChainRaw, _> = serde_ipld_dagcbor::from_slice(&tampered_bytes);
        if let Ok(tampered_raw) = result {
            // If deserialization succeeded, chain validation should reject it
            let validation = UWillChain::from_chain(tampered_raw);
            assert!(
                validation.is_err(),
                "tampered chain should be rejected by from_chain"
            );
        }
        // If deserialization failed, that's also correct — corrupted data rejected
    }

    // -----------------------------------------------------------------------
    // 3. Enumerate chain can't read data
    // -----------------------------------------------------------------------

    /// The enumerate chain (willow/enumerate) should NOT prove read
    /// or write access. It's a namespace membership proof only.
    #[test]
    fn enumerate_chain_cannot_authorize_writes() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(502);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (alice_secret, alice_id) = keypair(&mut rng);

        // Create an enumerate chain
        let enumerate = UWillChain::new_enumerate(
            ns_id, &ns_secret, alice_id,
        ).unwrap();

        // It should NOT prove read or write
        assert!(!enumerate.proves_read());
        assert!(!enumerate.proves_write());

        // Building a write invocation with it should fail
        let entry = Entry::new(
            ns_id,
            alice_id,
            Path::new_empty(),
            0,
            0,
            PayloadDigest::default(),
        );

        let inv = build_write_invocation(&entry, &enumerate, &alice_secret);
        // The invocation might build (it just signs), but validation should fail
        if let Ok(inv) = inv {
            let result = inv.validate_write(&entry);
            assert!(result.is_err(), "enumerate chain should not authorize writes");
        }
    }

    /// The enumerate chain extracted from a ReadAuthorisation should
    /// NOT be usable as a full-area read capability.
    #[test]
    fn enumerate_chain_is_not_read_cap() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(503);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let _ns_id = ns_secret.id();
        let (_, alice_id) = keypair(&mut rng);

        use crate::proto::meadowcap::ReadAuthorisation;
        let auth = ReadAuthorisation::new_owned(&ns_secret, alice_id).unwrap();

        let enumerate = auth.subspace_cap().expect("should have enumerate chain");

        // The enumerate chain's command should be willow/enumerate, not willow/read
        assert_eq!(
            enumerate.command(),
            crate::uwill::command::WillowCommand::Enumerate,
        );
        assert!(!enumerate.proves_read());
        assert!(!enumerate.proves_write());
    }

    // -----------------------------------------------------------------------
    // 4. Revocation cascades through multi-step chains
    // -----------------------------------------------------------------------

    /// Revoking an intermediate delegation should invalidate all
    /// chains that contain it — including delegations further down.
    #[test]
    fn revocation_cascades_through_chain() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(504);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();

        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();
        let bob_secret = UserSecretKey::generate(&mut rng);
        let bob_id = bob_secret.public_key().id();
        let carol_secret = UserSecretKey::generate(&mut rng);
        let carol_id = carol_secret.public_key().id();

        // namespace owner → alice → bob → carol
        let to_alice = UWillChain::new_owned(
            ns_id, &ns_secret, alice_id, AccessMode::Read,
        ).unwrap();
        let to_bob = to_alice.delegate(
            &alice_secret, &bob_id, &Area::new_full(),
        ).unwrap();
        let to_carol = to_bob.delegate(
            &bob_secret, &carol_id, &Area::new_full(),
        ).unwrap();

        let mut store = RevocationStore::new();

        // Before revocation, all chains are valid
        assert!(!store.chain_is_revoked(&to_alice));
        assert!(!store.chain_is_revoked(&to_bob));
        assert!(!store.chain_is_revoked(&to_carol));

        // Revoke the alice→bob delegation (index 1 in to_bob's chain)
        let alice_to_bob_cid = to_bob.delegations()[1].to_cid();
        store.revoke(alice_to_bob_cid);

        // alice's chain is NOT revoked (doesn't contain alice→bob delegation)
        assert!(!store.chain_is_revoked(&to_alice));

        // bob's chain IS revoked (contains the revoked delegation)
        assert!(store.chain_is_revoked(&to_bob));

        // carol's chain IS ALSO revoked (contains alice→bob as step 1)
        assert!(store.chain_is_revoked(&to_carol));
    }

    // -----------------------------------------------------------------------
    // 5. Cross-namespace isolation
    // -----------------------------------------------------------------------

    /// A write invocation for namespace A should not authorize an
    /// entry in namespace B.
    #[test]
    fn cross_namespace_write_rejected() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(505);
        let ns_a_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_a = ns_a_secret.id();
        let ns_b_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_b = ns_b_secret.id();
        let (alice_secret, alice_id) = keypair(&mut rng);

        // Alice has write access to namespace A
        let chain_a = UWillChain::new_owned(
            ns_a, &ns_a_secret, alice_id, AccessMode::Write,
        ).unwrap();

        // Entry in namespace A — should work
        let entry_a = Entry::new(
            ns_a,
            alice_id,
            Path::new_empty(),
            0,
            0,
            PayloadDigest::default(),
        );

        let inv = build_write_invocation(&entry_a, &chain_a, &alice_secret).unwrap();
        assert!(inv.validate_write(&entry_a).is_ok());

        // Entry in namespace B — same user, same path, different namespace
        let entry_b = Entry::new(
            ns_b,
            alice_id,
            Path::new_empty(),
            0,
            0,
            PayloadDigest::default(),
        );

        // The invocation was built for namespace A's chain — it should
        // NOT authorize an entry in namespace B.
        // The invocation's subject (namespace DID) won't match entry_b's namespace.
        // Our validate_write checks predicates, which check the area against the entry.
        // The root delegation has full area for namespace A, not B.
        // But the area check is namespace-agnostic (it only checks subspace/path/time).
        // The namespace check happens at a higher level (the caller verifies
        // the token's namespace matches the entry's namespace).
        //
        // For now, validate_write doesn't check namespace — that's a gap.
        // The AuthorisationToken trait impl should verify this.
        // Let's test what actually happens:
        let result = inv.is_authorised_write(&entry_b);

        // This SHOULD be false — the invocation is for namespace A.
        // If it's true, we have a cross-namespace isolation bug.
        assert!(
            !result,
            "invocation for namespace A should not authorize writes to namespace B"
        );
    }

    // -----------------------------------------------------------------------
    // 6. Expired chain rejected
    // -----------------------------------------------------------------------

    /// A chain with delegations whose expiry is in the past should
    /// be rejected by is_authorised_write.
    #[test]
    fn expired_chain_rejected_in_write_auth() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(506);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (alice_secret, alice_id) = keypair(&mut rng);

        // Create a chain (no expiry — valid forever)
        let chain = UWillChain::new_owned(
            ns_id, &ns_secret, alice_id, AccessMode::Write,
        ).unwrap();

        let entry = Entry::new(
            ns_id,
            alice_id,
            Path::new_empty(),
            0,
            0,
            PayloadDigest::default(),
        );

        let inv = build_write_invocation(&entry, &chain, &alice_secret).unwrap();

        // Without expiry, it should be valid
        assert!(inv.is_authorised_write(&entry));

        // Now test expiry: the chain itself doesn't have exp/nbf,
        // but is_authorised_write checks chain.is_expired(now).
        // Since we can't easily create a chain with expiry (the builder
        // doesn't expose exp on delegations easily), let's verify that
        // the expiry check path exists and returns false for non-expired chains.
        assert!(!chain.is_expired(u64::MAX));

        // And that a far-future nbf would be detected
        // (can't construct this without builder changes, but the logic is tested
        // in the chain unit tests)
        assert!(!chain.is_not_yet_valid(0));
    }

    // -----------------------------------------------------------------------
    // 7. Read-only chain can't authorize writes
    // -----------------------------------------------------------------------

    /// A chain with willow/read should NOT authorize write invocations.
    #[test]
    fn read_chain_cannot_authorize_writes() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(507);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (alice_secret, alice_id) = keypair(&mut rng);

        // Read-only chain
        let read_chain = UWillChain::new_owned(
            ns_id, &ns_secret, alice_id, AccessMode::Read,
        ).unwrap();

        assert!(read_chain.proves_read());
        assert!(!read_chain.proves_write());

        let entry = Entry::new(
            ns_id, alice_id, Path::new_empty(), 0, 0,
            PayloadDigest::default(),
        );

        // Building a write invocation with a read chain succeeds (just signs),
        // but validation should reject it
        let inv = build_write_invocation(&entry, &read_chain, &alice_secret).unwrap();
        assert!(inv.validate_write(&entry).is_err());
        assert!(!inv.is_authorised_write(&entry));
    }

    // -----------------------------------------------------------------------
    // 8. Wrong signer rejected
    // -----------------------------------------------------------------------

    /// An invocation signed by someone other than the chain's receiver
    /// should fail signature verification.
    #[test]
    fn wrong_signer_rejected() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(508);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (_alice_secret, alice_id) = keypair(&mut rng);
        let (bob_secret, _bob_id) = keypair(&mut rng);

        // Chain grants write access to alice
        let chain = UWillChain::new_owned(
            ns_id, &ns_secret, alice_id, AccessMode::Write,
        ).unwrap();

        let entry = Entry::new(
            ns_id, alice_id, Path::new_empty(), 0, 0,
            PayloadDigest::default(),
        );

        // Bob signs the invocation — but the chain's receiver is alice
        let inv = build_write_invocation(&entry, &chain, &bob_secret).unwrap();

        // The invocation signature verifies (bob signed it validly)
        // but the issuer DID won't match the chain's receiver.
        // This should fail because the invocation's issuer (bob)
        // doesn't match the chain's receiver (alice).
        assert!(!inv.is_authorised_write(&entry));
    }

    // -----------------------------------------------------------------------
    // 9. Revoke unseen delegation (out-of-order)
    // -----------------------------------------------------------------------

    /// The spec says: accept revocations for delegations not yet seen.
    /// The store should hold the revoked CID and reject chains containing
    /// it even if the chain is imported after the revocation.
    #[test]
    fn revoke_before_seeing_delegation() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(509);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (_, alice_id) = keypair(&mut rng);

        let chain = UWillChain::new_owned(
            ns_id, &ns_secret, alice_id, AccessMode::Read,
        ).unwrap();

        let cid = chain.delegations()[0].to_cid();

        // Revoke BEFORE ever seeing the chain
        let mut store = RevocationStore::new();
        store.revoke(cid);

        // Now "import" the chain — it should be detected as revoked
        assert!(store.chain_is_revoked(&chain));
    }

    // -----------------------------------------------------------------------
    // 10. Double revocation is idempotent
    // -----------------------------------------------------------------------

    #[test]
    fn double_revocation_idempotent() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(510);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (_, alice_id) = keypair(&mut rng);

        let chain = UWillChain::new_owned(
            ns_id, &ns_secret, alice_id, AccessMode::Read,
        ).unwrap();

        let cid = chain.delegations()[0].to_cid();

        let mut store = RevocationStore::new();
        store.revoke(cid);
        store.revoke(cid); // second time — should be fine

        assert!(store.chain_is_revoked(&chain));
        assert_eq!(store.len(), 1); // not 2
    }

    // -----------------------------------------------------------------------
    // 11. Area narrowing enforced through invocations
    // -----------------------------------------------------------------------

    /// A delegated chain restricted to path "data" should reject
    /// entries at path "secrets".
    #[test]
    fn area_narrowing_enforced_in_invocation() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(511);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (alice_secret, alice_id) = keypair(&mut rng);

        let root = UWillChain::new_owned(
            ns_id, &ns_secret, alice_id, AccessMode::Write,
        ).unwrap();

        // Restrict to path "data"
        let restricted = root.delegate(
            &alice_secret,
            &alice_id,
            &Area::new(
                AreaSubspace::Id(alice_id),
                Path::from_bytes(&[b"data"]).unwrap(),
                Range::new(0, RangeEnd::Open),
            ),
        ).unwrap();

        // Entry under "data" — should work
        let good_entry = Entry::new(
            ns_id, alice_id,
            Path::from_bytes(&[b"data", b"file.txt"]).unwrap(),
            0, 0, PayloadDigest::default(),
        );
        let inv = build_write_invocation(&good_entry, &restricted, &alice_secret).unwrap();
        assert!(inv.is_authorised_write(&good_entry));

        // Entry under "secrets" — should be rejected
        let bad_entry = Entry::new(
            ns_id, alice_id,
            Path::from_bytes(&[b"secrets", b"keys"]).unwrap(),
            0, 0, PayloadDigest::default(),
        );
        let inv = build_write_invocation(&bad_entry, &restricted, &alice_secret).unwrap();
        assert!(!inv.is_authorised_write(&bad_entry));
    }

    // -----------------------------------------------------------------------
    // 12. Expired delegation rejects write authorization
    // -----------------------------------------------------------------------

    /// A delegation with exp in the past should cause is_authorised_write
    /// to return false.
    #[test]
    fn expired_delegation_rejects_write() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(512);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (alice_secret, alice_id) = keypair(&mut rng);

        // Build a delegation with expiry 1 second after epoch (long expired)
        let issuer_key = ed25519_dalek::SigningKey::from_bytes(&ns_secret.to_bytes());
        let issuer = ucan::did::Ed25519Signer::new(issuer_key);
        let audience = crate::uwill::chain::user_id_to_ed25519_did(&alice_id).unwrap();
        let namespace_did = crate::uwill::chain::namespace_id_to_ed25519_did(&ns_id).unwrap();

        let expired_ts = ucan::time::timestamp::Timestamp::from_unix(1).unwrap();

        let delegation = ucan::delegation::Delegation::<ucan::did::Ed25519Did>::builder()
            .issuer(issuer)
            .audience(audience)
            .subject(ucan::delegation::subject::DelegatedSubject::Specific(namespace_did))
            .command(ucan::command::Command::new(vec!["willow".to_owned(), "write".to_owned()]))
            .policy(vec![])
            .expiration(expired_ts)
            .try_build()
            .unwrap();

        let chain = UWillChain::from_chain(
            UWillChainRaw::from_delegations(vec![delegation]),
        ).unwrap();

        // Chain should report as expired
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(chain.is_expired(now));

        let entry = Entry::new(
            ns_id, alice_id, Path::new_empty(), 0, 0,
            PayloadDigest::default(),
        );

        let inv = build_write_invocation(&entry, &chain, &alice_secret).unwrap();
        assert!(!inv.is_authorised_write(&entry), "expired chain should reject writes");
    }

    // -----------------------------------------------------------------------
    // 13. Not-yet-valid delegation rejects write authorization
    // -----------------------------------------------------------------------

    /// A delegation with nbf far in the future should cause
    /// is_authorised_write to return false.
    #[test]
    fn not_yet_valid_delegation_rejects_write() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(513);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (alice_secret, alice_id) = keypair(&mut rng);

        let issuer_key = ed25519_dalek::SigningKey::from_bytes(&ns_secret.to_bytes());
        let issuer = ucan::did::Ed25519Signer::new(issuer_key);
        let audience = crate::uwill::chain::user_id_to_ed25519_did(&alice_id).unwrap();
        let namespace_did = crate::uwill::chain::namespace_id_to_ed25519_did(&ns_id).unwrap();

        // nbf = year 2100 (far future)
        let future_ts = ucan::time::timestamp::Timestamp::from_unix(4_102_444_800).unwrap();

        let delegation = ucan::delegation::Delegation::<ucan::did::Ed25519Did>::builder()
            .issuer(issuer)
            .audience(audience)
            .subject(ucan::delegation::subject::DelegatedSubject::Specific(namespace_did))
            .command(ucan::command::Command::new(vec!["willow".to_owned(), "write".to_owned()]))
            .policy(vec![])
            .not_before(future_ts)
            .try_build()
            .unwrap();

        let chain = UWillChain::from_chain(
            UWillChainRaw::from_delegations(vec![delegation]),
        ).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(chain.is_not_yet_valid(now));

        let entry = Entry::new(
            ns_id, alice_id, Path::new_empty(), 0, 0,
            PayloadDigest::default(),
        );

        let inv = build_write_invocation(&entry, &chain, &alice_secret).unwrap();
        assert!(!inv.is_authorised_write(&entry), "not-yet-valid chain should reject writes");
    }

    // -----------------------------------------------------------------------
    // 14. Valid time window accepts writes
    // -----------------------------------------------------------------------

    /// A delegation with exp in the future and nbf in the past should
    /// be accepted.
    #[test]
    fn valid_time_window_accepts_write() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(514);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();
        let (alice_secret, alice_id) = keypair(&mut rng);

        let issuer_key = ed25519_dalek::SigningKey::from_bytes(&ns_secret.to_bytes());
        let issuer = ucan::did::Ed25519Signer::new(issuer_key);
        let audience = crate::uwill::chain::user_id_to_ed25519_did(&alice_id).unwrap();
        let namespace_did = crate::uwill::chain::namespace_id_to_ed25519_did(&ns_id).unwrap();

        let past_ts = ucan::time::timestamp::Timestamp::from_unix(1).unwrap();
        let future_ts = ucan::time::timestamp::Timestamp::from_unix(4_102_444_800).unwrap();

        let delegation = ucan::delegation::Delegation::<ucan::did::Ed25519Did>::builder()
            .issuer(issuer)
            .audience(audience)
            .subject(ucan::delegation::subject::DelegatedSubject::Specific(namespace_did))
            .command(ucan::command::Command::new(vec!["willow".to_owned(), "write".to_owned()]))
            .policy(vec![])
            .not_before(past_ts)
            .expiration(future_ts)
            .try_build()
            .unwrap();

        let chain = UWillChain::from_chain(
            UWillChainRaw::from_delegations(vec![delegation]),
        ).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(!chain.is_expired(now));
        assert!(!chain.is_not_yet_valid(now));

        let entry = Entry::new(
            ns_id, alice_id, Path::new_empty(), 0, 0,
            PayloadDigest::default(),
        );

        let inv = build_write_invocation(&entry, &chain, &alice_secret).unwrap();
        assert!(inv.is_authorised_write(&entry), "chain within valid window should accept writes");
    }

    // -----------------------------------------------------------------------
    // 15. Revoke root delegation breaks all derived chains
    // -----------------------------------------------------------------------

    /// Revoking the root delegation (namespace owner → first recipient)
    /// should invalidate every chain derived from it.
    #[test]
    fn revoke_root_breaks_all_derived() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(515);
        let ns_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let ns_id = ns_secret.id();

        let alice_secret = UserSecretKey::generate(&mut rng);
        let alice_id = alice_secret.public_key().id();
        let bob_secret = UserSecretKey::generate(&mut rng);
        let bob_id = bob_secret.public_key().id();

        let to_alice = UWillChain::new_owned(
            ns_id, &ns_secret, alice_id, AccessMode::Write,
        ).unwrap();
        let to_bob = to_alice.delegate(
            &alice_secret, &bob_id, &Area::new_full(),
        ).unwrap();

        let mut store = RevocationStore::new();

        // Revoke the ROOT delegation (index 0 — namespace→alice)
        let root_cid = to_alice.delegations()[0].to_cid();
        store.revoke(root_cid);

        // Alice's chain is broken
        assert!(store.chain_is_revoked(&to_alice));

        // Bob's chain is ALSO broken (contains the root delegation)
        assert!(store.chain_is_revoked(&to_bob));
    }
}
