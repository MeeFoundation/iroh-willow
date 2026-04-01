use std::{
    cell::RefCell,
    future::poll_fn,
    rc::Rc,
    task::{ready, Poll, Waker},
};

use crate::{
    proto::{
        meadowcap::{serde_encoding::SerdeUWillInvocation, ReadCapability, SubspaceCapability},
        wgps::{
            AccessChallenge, CapabilityHandle, ChallengeHash, CommitmentReveal,
            IntersectionHandle, PaiReplySubspaceCapability, SetupBindReadCapability,
        },
    },
    session::{challenge::ChallengeState, resource::ResourceMap, Error, Role},
    store::traits::SecretStorage,
    uwill::{
        invocation::{build_enumerate_invocation, build_read_invocation},
        UWillInvocation,
    },
};

#[derive(Debug, Clone)]
pub struct Capabilities(Rc<RefCell<Inner>>);

#[derive(Debug)]
struct Inner {
    challenge: ChallengeState,
    ours: ResourceMap<CapabilityHandle, ReadCapability>,
    theirs: ResourceMap<CapabilityHandle, ReadCapability>,
    on_reveal_wakers: Vec<Waker>,
}

impl Capabilities {
    pub fn new(our_nonce: AccessChallenge, received_commitment: ChallengeHash) -> Self {
        let challenge = ChallengeState::Committed {
            our_nonce,
            received_commitment,
        };
        Self(Rc::new(RefCell::new(Inner {
            challenge,
            ours: Default::default(),
            theirs: Default::default(),
            on_reveal_wakers: Default::default(),
        })))
    }

    pub fn is_revealed(&self) -> bool {
        self.0.borrow().challenge.is_revealed()
    }

    pub fn find_ours(&self, cap: &ReadCapability) -> Option<CapabilityHandle> {
        self.0.borrow().ours.find(cap)
    }

    /// Build a read capability invocation for the sync session.
    ///
    /// The invocation carries the read cap chain as resolved proofs and
    /// embeds the session challenge nonce in its arguments.
    pub fn build_read_cap_invocation<S: SecretStorage>(
        &self,
        secret_store: &S,
        intersection_handle: IntersectionHandle,
        capability: ReadCapability,
    ) -> Result<SetupBindReadCapability, Error> {
        let inner = self.0.borrow();
        let challenge = inner.challenge.signable()?;
        let user_secret = secret_store
            .get_user(&capability.receiver())?
            .ok_or(Error::MissingSecret)?;
        let invocation = build_read_invocation(&challenge, &capability, &user_secret)
            .map_err(|e| Error::InvocationBuild(e.to_string()))?;
        Ok(SetupBindReadCapability {
            invocation: SerdeUWillInvocation(invocation),
            handle: intersection_handle,
        })
    }

    pub fn bind_ours(&self, capability: ReadCapability) -> (CapabilityHandle, bool) {
        self.0.borrow_mut().ours.bind_if_new(capability)
    }

    /// Validate a received read capability invocation and bind the cap.
    ///
    /// Caller must check revocation on the returned chain.
    pub fn validate_and_bind_read_invocation(
        &self,
        invocation: UWillInvocation,
    ) -> Result<ReadCapability, Error> {
        let inner = self.0.borrow();
        let their_challenge = inner.challenge.verifiable()?;
        let chain = invocation
            .validate_read_proof(&their_challenge)
            .map_err(|e| Error::InvocationValidation(e.to_string()))?;
        drop(inner);
        self.0.borrow_mut().theirs.bind(chain.clone());
        Ok(chain)
    }

    pub async fn get_theirs_eventually(&self, handle: CapabilityHandle) -> ReadCapability {
        poll_fn(|cx| {
            let mut inner = self.0.borrow_mut();
            let cap = ready!(inner.theirs.poll_get_eventually(handle, cx));
            Poll::Ready(cap.clone())
        })
        .await
    }

    /// Validate a received enumerate capability invocation.
    /// Caller must check revocation on the returned chain.
    pub fn validate_enumerate_cap_invocation(
        &self,
        invocation: &UWillInvocation,
    ) -> Result<SubspaceCapability, Error> {
        let inner = self.0.borrow();
        let their_challenge = inner.challenge.verifiable()?;
        let chain = invocation
            .validate_enumerate_proof(&their_challenge)
            .map_err(|e| Error::InvocationValidation(e.to_string()))?;
        Ok(chain)
    }

    pub fn reveal_commitment(&self) -> Result<CommitmentReveal, Error> {
        match self.0.borrow_mut().challenge {
            ChallengeState::Committed { our_nonce, .. } => {
                Ok(CommitmentReveal { nonce: our_nonce })
            }
            _ => Err(Error::InvalidMessageInCurrentState),
        }
    }

    pub fn received_commitment_reveal(
        &self,
        our_role: Role,
        their_nonce: AccessChallenge,
    ) -> Result<(), Error> {
        let mut inner = self.0.borrow_mut();
        inner.challenge.reveal(our_role, their_nonce)?;
        for waker in inner.on_reveal_wakers.drain(..) {
            waker.wake();
        }
        Ok(())
    }

    /// Build an enumerate capability invocation for PAI awkward pair.
    pub fn build_enumerate_cap_invocation<S: SecretStorage>(
        &self,
        secrets: &S,
        cap: SubspaceCapability,
        handle: IntersectionHandle,
    ) -> Result<PaiReplySubspaceCapability, Error> {
        let inner = self.0.borrow();
        let challenge = inner.challenge.signable()?;
        let user_secret = secrets
            .get_user(&cap.receiver())?
            .ok_or(Error::MissingSecret)?;
        let invocation = build_enumerate_invocation(&challenge, &cap, &user_secret)
            .map_err(|e| Error::InvocationBuild(e.to_string()))?;
        Ok(PaiReplySubspaceCapability {
            handle,
            invocation: SerdeUWillInvocation(invocation),
        })
    }
}
