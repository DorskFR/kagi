#![doc = include_str!("../README.md")]

mod ceremony;
mod credential;
mod decoy;
mod error;
mod kagi;
mod policy;
mod rp;
mod wire;

#[cfg(test)]
mod tests;

pub use ceremony::{
	Ceremony, CeremonyStore, Limits, MemoryCeremonies, Purpose, ceremony_id, ceremony_key, network,
};
pub use credential::{CredentialStore, Removal, Stored, StoredPasskey, derived_handle};
pub use decoy::{Decoys, normalize};
pub use error::{Error, StoreError};
pub use kagi::{
	Account, DEFAULT_STEP_UP, Enrolment, Kagi, Registered, Removed, ResidentKey, Settings, SignedIn,
};
pub use policy::{PasskeyRole, Proof};
pub use rp::relying_party;
pub use wire::{RegistrationChallenge, RegistrationFinish, SignInChallenge, SignInFinish};

pub use webauthn_rs;
pub use webauthn_rs::prelude::{
	CreationChallengeResponse, Passkey, PublicKeyCredential, RegisterPublicKeyCredential,
	RequestChallengeResponse, Url, Uuid, Webauthn,
};
