use std::time::Duration;

use webauthn_rs::prelude::WebauthnError;

pub type StoreError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("passkeys are misconfigured: {0}")]
	Config(String),
	#[error("too many passkey ceremonies from this address, retry in {}s", retry_after.as_secs())]
	TooMany { retry_after: Duration },
	#[error("too many passkey ceremonies are in flight")]
	Busy,
	#[error("the passkey ceremony is unknown, used or expired")]
	Ceremony,
	#[error("the passkey ceremony was started for something else")]
	Purpose,
	#[error("the passkey ceremony belongs to another session")]
	Binding,
	/// The browser's answer did not verify. `name` is the normalised name the sign-in was
	/// started for, so the app can count the failure against it.
	#[error("the passkey was not accepted")]
	Rejected { name: Option<String> },
	/// The passkey verified but its signature counter did not move forward: the key may have
	/// been cloned. `name` is as for `Rejected`.
	#[error("the passkey's signature counter went backwards")]
	Cloned { name: Option<String> },
	#[error("sign in again before adding a passkey")]
	StepUp,
	#[error("this passkey is already registered")]
	Duplicate,
	#[error("the last way to sign in cannot be removed")]
	LastCredential,
	#[error("no such passkey")]
	NotFound,
	#[error("credential store: {0}")]
	Store(StoreError),
	#[error("passkeys failed: {0}")]
	Internal(String),
	#[error("webauthn: {0}")]
	Webauthn(#[from] WebauthnError),
}

impl Error {
	pub(crate) fn store(error: impl Into<StoreError>) -> Self {
		Self::Store(error.into())
	}

	pub(crate) fn internal(error: impl std::fmt::Display) -> Self {
		Self::Internal(error.to_string())
	}
}
