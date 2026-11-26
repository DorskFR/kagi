use std::future::Future;

use sha2::{Digest, Sha256};
use webauthn_rs::prelude::{Passkey, Uuid};

use crate::StoreError;

/// A passkey row: the app's id for it, its owner and the webauthn-rs `Passkey`, stored in the
/// webauthn-rs serde format.
#[derive(Debug, Clone)]
pub struct StoredPasskey<U, P> {
	pub id: P,
	pub user: U,
	pub passkey: Passkey,
}

pub type Stored<C> = StoredPasskey<<C as CredentialStore>::User, <C as CredentialStore>::PasskeyId>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
	Removed { remaining: usize },
	NotFound,
	Last,
}

/// The app's passkey table.
pub trait CredentialStore: Send + Sync {
	type User: Clone + PartialEq + Send + Sync + 'static;
	type PasskeyId: Clone + PartialEq + Send + Sync + 'static;
	type Error: Into<StoreError> + Send;

	/// The WebAuthn user handle of a user: stable, 16 bytes and free of personal data. Keep
	/// the derivation the app registered its existing passkeys with.
	fn user_handle(&self, user: &Self::User) -> Uuid;

	fn passkeys(
		&self,
		user: &Self::User,
	) -> impl Future<Output = Result<Vec<Stored<Self>>, Self::Error>> + Send;

	fn find(
		&self,
		credential_id: &[u8],
	) -> impl Future<Output = Result<Option<Stored<Self>>, Self::Error>> + Send;

	fn add(
		&self,
		user: &Self::User,
		passkey: &Passkey,
		label: &str,
	) -> impl Future<Output = Result<Self::PasskeyId, Self::Error>> + Send;

	fn update(
		&self,
		id: &Self::PasskeyId,
		passkey: &Passkey,
	) -> impl Future<Output = Result<(), Self::Error>> + Send;

	/// Removes one of the user's passkeys. With `keep_last`, a passkey that is the user's only
	/// one stays and the answer is `Removal::Last`; checking and deleting must be one atomic
	/// step so two removals cannot both pass.
	fn remove(
		&self,
		user: &Self::User,
		id: &Self::PasskeyId,
		keep_last: bool,
	) -> impl Future<Output = Result<Removal, Self::Error>> + Send;
}

/// A user handle derived from a namespace and the app's user id.
pub fn derived_handle(namespace: &str, user_id: &[u8]) -> Uuid {
	let digest = Sha256::new()
		.chain_update(namespace)
		.chain_update([0])
		.chain_update(user_id)
		.finalize();
	let mut bytes = [0u8; 16];
	bytes.copy_from_slice(&digest[..16]);
	Uuid::from_bytes(bytes)
}
