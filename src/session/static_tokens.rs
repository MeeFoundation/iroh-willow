use std::{
    cell::RefCell,
    future::poll_fn,
    rc::Rc,
    task::{ready, Poll},
};

use crate::{
    proto::{
        data_model::{AuthorisedEntry, Entry},
        wgps::{DynamicToken, SetupBindStaticToken, StaticToken, StaticTokenHandle},
    },
    session::{channels::ChannelSenders, resource::ResourceMap, Error},
};

#[derive(Debug, Clone, Default)]
pub struct StaticTokens(Rc<RefCell<Inner>>);

#[derive(Debug, Default)]
struct Inner {
    ours: ResourceMap<StaticTokenHandle, StaticToken>,
    theirs: ResourceMap<StaticTokenHandle, StaticToken>,
}

impl StaticTokens {
    pub fn bind_theirs(&self, token: StaticToken) {
        self.0.borrow_mut().theirs.bind(token);
    }

    pub async fn bind_and_send_ours(
        &self,
        static_token: StaticToken,
        send: &ChannelSenders,
    ) -> Result<StaticTokenHandle, Error> {
        let (handle, is_new) = { self.0.borrow_mut().ours.bind_if_new(static_token.clone()) };
        if is_new {
            let msg = SetupBindStaticToken { static_token };
            send.send(msg).await?;
        }
        Ok(handle)
    }

    /// Validate and construct an `AuthorisedEntry` from wire data.
    ///
    /// This is the security boundary for untrusted entries from peers.
    /// `validate_write()` runs all stateless checks (signature, chain,
    /// expiry, syntatic_checks, entry containment). The caller must
    /// check revocation on the returned entry's token before ingesting.
    pub async fn authorise_entry_eventually(
        &self,
        entry: Entry,
        static_token_handle: StaticTokenHandle,
        dynamic_token: DynamicToken,
    ) -> Result<AuthorisedEntry, Error> {
        let inner = self.0.clone();
        let static_token = poll_fn(move |cx| {
            let mut inner = inner.borrow_mut();
            let token = ready!(inner.theirs.poll_get_eventually(static_token_handle, cx));
            Poll::Ready(token.clone())
        })
        .await;

        let chain = static_token.0;
        let invocation = dynamic_token.0;
        let token = crate::uwill::UWillInvocation::from_parts(invocation, chain.delegations().to_vec());
        token.validate_write(&entry)
            .map_err(|e| Error::InvocationValidation(e.to_string()))?;
        let authorised_entry = AuthorisedEntry::new_unchecked(entry, token);
        Ok(authorised_entry)
    }
}
