//! Authentication backend for Willow.
//!
//! Manages capabilities. Rewritten for UWill.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use tracing::{debug, trace};

use crate::{
    interest::{
        AreaOfInterestSelector, CapSelector, CapabilityPack, DelegateTo, InterestMap, Interests,
        InvalidCapabilityPack, RestrictArea,
    },
    proto::{
        data_model::WriteCapability,
        grouping::AreaOfInterest,
        keys::{NamespaceId, UserId},
        meadowcap::{
            AccessMode, FailedDelegationError, McCapability, ReadAuthorisation,
        },
    },
    store::traits::{CapsStorage, RevocationStorage, SecretStorage, SecretStoreError, Storage},
    uwill::{
        chain::ChainError,
        UWillInvocation,
    },
};

#[derive(Debug, Clone)]
pub struct Auth<S: Storage> {
    secrets: S::Secrets,
    caps: S::Caps,
    revocations: S::Revocations,
}

impl<S: Storage> Auth<S> {
    pub fn new(
        secrets: S::Secrets,
        caps: S::Caps,
        revocations: S::Revocations,
    ) -> Self {
        Self { secrets, caps, revocations }
    }

    /// Apply a revocation invocation.
    ///
    /// Validates the invocation (signature, command, authority) then
    /// applies the revocation to the store.
    pub fn apply_revocation(&self, invocation: &UWillInvocation) -> Result<(), AuthError> {
        let revoked_cid = invocation.validate_revoke()
            .map_err(|e| AuthError::InvalidRevocation(e.to_string()))?;
        if self.is_chain_revoked(&invocation.capability()) {
            return Err(AuthError::Revoked);
        }
        self.revocations.apply_revoked_cid(revoked_cid);
        Ok(())
    }

    /// Check if a chain is revoked.
    pub fn is_chain_revoked(&self, chain: &crate::uwill::UWillChain) -> bool {
        self.revocations.chain_is_revoked(chain)
    }
    pub fn get_write_cap(
        &self,
        selector: &CapSelector,
    ) -> Result<Option<WriteCapability>, AuthError> {
        let cap = self.caps.get_write_cap(selector)?;
        Ok(cap)
    }

    pub fn del_caps(&self, selector: &CapSelector) -> Result<Vec<McCapability>, AuthError> {
        let cap = self.caps.del_caps(selector)?;
        Ok(cap)
    }

    pub fn get_read_cap(
        &self,
        selector: &CapSelector,
    ) -> Result<Option<ReadAuthorisation>, AuthError> {
        let cap = self.caps.get_read_cap(selector)?;
        Ok(cap)
    }

    pub fn list_read_caps(&self) -> Result<impl Iterator<Item = ReadAuthorisation> + '_> {
        self.caps.list_read_caps(None)
    }

    pub fn import_caps(
        &self,
        caps: impl IntoIterator<Item = CapabilityPack>,
    ) -> Result<(), AuthError> {
        for cap in caps.into_iter() {
            debug!(?cap, "import cap");
            cap.validate()?;

            // Check revocation
            let chain = match &cap {
                CapabilityPack::Read(auth) => auth.read_cap(),
                CapabilityPack::Write(chain) => chain,
            };
            if self.is_chain_revoked(chain) {
                return Err(AuthError::Revoked);
            }

            let user_id = cap.receiver();
            if !self.secrets.has_user(&user_id)? {
                return Err(AuthError::MissingUserSecret(user_id));
            }
            self.caps.insert(cap)?;
            trace!("imported");
        }
        Ok(())
    }

    pub fn insert_caps_unchecked(
        &self,
        caps: impl IntoIterator<Item = CapabilityPack>,
    ) -> Result<(), AuthError> {
        for cap in caps.into_iter() {
            debug!(?cap, "insert cap");
            self.caps.insert(cap)?;
        }
        Ok(())
    }

    pub fn resolve_interests(&self, interests: Interests) -> Result<InterestMap, AuthError> {
        match interests {
            Interests::All => {
                let out = self
                    .list_read_caps()?
                    .map(|auth| {
                        let area = auth.read_cap().granted_area().clone();
                        let aoi = AreaOfInterest::new(area, 0, 0);
                        (auth, HashSet::from_iter([aoi]))
                    })
                    .collect::<HashMap<_, _>>();
                Ok(out)
            }
            Interests::Select(interests) => {
                let mut out: InterestMap = HashMap::new();
                for (cap_selector, aoi_selector) in interests {
                    let cap = self.get_read_cap(&cap_selector)?;
                    if let Some(cap) = cap {
                        let entry = out.entry(cap.clone()).or_default();
                        match aoi_selector {
                            AreaOfInterestSelector::Widest => {
                                let area = cap.read_cap().granted_area().clone();
                                let aoi = AreaOfInterest::new(area, 0, 0);
                                entry.insert(aoi);
                            }
                            AreaOfInterestSelector::Exact(aois) => {
                                for aoi in aois {
                                    entry.insert(aoi);
                                }
                            }
                        }
                    }
                }
                Ok(out)
            }
        }
    }

    pub fn create_full_caps(
        &self,
        namespace_id: NamespaceId,
        user_id: UserId,
    ) -> Result<[CapabilityPack; 2], AuthError> {
        let read_cap = self.create_read_cap(namespace_id, user_id)?;
        let write_cap = self.create_write_cap(namespace_id, user_id)?;
        let pack = [read_cap, write_cap];
        self.insert_caps_unchecked(pack.clone())?;
        Ok(pack)
    }

    pub fn create_read_cap(
        &self,
        namespace_key: NamespaceId,
        user_key: UserId,
    ) -> Result<CapabilityPack, AuthError> {
        // UWill: all namespaces are owned. No communal support.
        let namespace_secret = self
            .secrets
            .get_namespace(&namespace_key)?
            .ok_or(AuthError::MissingNamespaceSecret(namespace_key))?;
        let auth = ReadAuthorisation::new_owned(&namespace_secret, user_key)
            .map_err(AuthError::Other)?;
        let pack = CapabilityPack::Read(auth);
        Ok(pack)
    }

    pub fn create_write_cap(
        &self,
        namespace_key: NamespaceId,
        user_key: UserId,
    ) -> Result<CapabilityPack, AuthError> {
        let namespace_secret = self
            .secrets
            .get_namespace(&namespace_key)?
            .ok_or(AuthError::MissingNamespaceSecret(namespace_key))?;
        let write_chain = McCapability::new_owned(
            namespace_key,
            &namespace_secret,
            user_key,
            AccessMode::Write,
        )?;
        let pack = CapabilityPack::Write(write_chain);
        Ok(pack)
    }

    pub fn delegate_full_caps(
        &self,
        from: CapSelector,
        access_mode: AccessMode,
        to: DelegateTo,
        store: bool,
    ) -> Result<Vec<CapabilityPack>, AuthError> {
        let mut out = Vec::with_capacity(2);
        let restrict_area = to.restrict_area;
        let read_cap = self.delegate_read_cap(&from, to.user, restrict_area.clone())?;
        out.push(read_cap);
        if access_mode == AccessMode::Write {
            let write_cap = self.delegate_write_cap(&from, to.user, restrict_area)?;
            out.push(write_cap);
        }
        if store {
            self.insert_caps_unchecked(out.clone())?;
        }
        Ok(out)
    }

    pub fn delegate_read_cap(
        &self,
        from: &CapSelector,
        to: UserId,
        restrict_area: RestrictArea,
    ) -> Result<CapabilityPack, AuthError> {
        let auth = self.get_read_cap(from)?.ok_or(AuthError::NoCapability)?;
        let read_cap = auth.read_cap();
        let user_id = read_cap.receiver();
        let user_secret = self
            .secrets
            .get_user(&user_id)?
            .ok_or(AuthError::MissingUserSecret(user_id))?;
        let area = restrict_area.or_default(read_cap.granted_area().clone());
        let new_read_cap = read_cap.delegate(&user_secret, &to, &area)?;

        // TODO(uwill): delegate enumerate chain if needed
        let pack = CapabilityPack::Read(ReadAuthorisation::from_read_chain(new_read_cap));
        Ok(pack)
    }

    pub fn delegate_write_cap(
        &self,
        from: &CapSelector,
        to: UserId,
        restrict_area: RestrictArea,
    ) -> Result<CapabilityPack, AuthError> {
        let cap = self.get_write_cap(from)?.ok_or(AuthError::NoCapability)?;
        let user_secret = self
            .secrets
            .get_user(&cap.receiver())?
            .ok_or(AuthError::MissingUserSecret(cap.receiver()))?;
        let area = restrict_area.or_default(cap.granted_area().clone());
        let new_cap = cap.delegate(&user_secret, &to, &area)?;
        Ok(CapabilityPack::Write(new_cap))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("missing user secret: {}", .0.fmt_short())]
    MissingUserSecret(UserId),
    #[error("missing namespace secret: {}", .0.fmt_short())]
    MissingNamespaceSecret(NamespaceId),
    #[error("secret store error: {0}")]
    SecretStore(#[from] SecretStoreError),
    #[error("no capability found")]
    NoCapability,
    #[error("{0}")]
    Other(#[from] anyhow::Error),
    #[error("Invalid capability pack")]
    InvalidPack(#[from] InvalidCapabilityPack),
    #[error("Failed to delegate capability: {0}")]
    DelegationFailed(#[from] FailedDelegationError),
    #[error("UWill chain error: {0}")]
    ChainError(#[from] ChainError),
    #[error("capability chain has been revoked")]
    Revoked,
    #[error("invalid revocation: {0}")]
    InvalidRevocation(String),
}
