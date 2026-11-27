use std::marker::PhantomData;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use serde_json::json;
use webauthn_rs::Webauthn;
use webauthn_rs::prelude::{
	AuthenticationResult, CreationChallengeResponse, Passkey, PublicKeyCredential,
	RegisterPublicKeyCredential, Url, WebauthnError,
};

use crate::ceremony::{Step, digest};
use crate::{
	Ceremony, CeremonyStore, CredentialStore, Decoys, Error, MemoryCeremonies, PasskeyRole, Proof,
	Purpose, RegistrationChallenge, Removal, SignInChallenge, StoredPasskey, normalize,
	relying_party,
};

pub const DEFAULT_STEP_UP: Duration = Duration::from_secs(10 * 60);

/// Whether new passkeys are asked to be discoverable, which usernameless and autofill
/// sign-in need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidentKey {
	Required,
	Preferred,
	Discouraged,
}

impl ResidentKey {
	const fn as_str(self) -> &'static str {
		match self {
			Self::Required => "required",
			Self::Preferred => "preferred",
			Self::Discouraged => "discouraged",
		}
	}

	fn apply(self, options: &mut CreationChallengeResponse) -> Result<(), Error> {
		if let Some(selection) = options.public_key.authenticator_selection.as_mut() {
			selection.resident_key =
				Some(serde_json::from_value(json!(self.as_str())).map_err(Error::internal)?);
			selection.require_resident_key = self == Self::Required;
		}
		Ok(())
	}
}

#[derive(Debug, Clone, Copy)]
pub struct Settings<'a> {
	pub url: &'a Url,
	/// The RP id when it is not the URL's host: a parent domain of the host, so passkeys
	/// also work on its other subdomains.
	pub rp_id: Option<&'a str>,
	pub rp_name: &'a str,
	/// At least 32 bytes, kept across restarts.
	pub decoy_key: &'a [u8],
	pub step_up: Duration,
	pub resident_key: ResidentKey,
}

impl<'a> Settings<'a> {
	pub const fn new(url: &'a Url, rp_name: &'a str, decoy_key: &'a [u8]) -> Self {
		Self {
			url,
			rp_id: None,
			rp_name,
			decoy_key,
			step_up: DEFAULT_STEP_UP,
			resident_key: ResidentKey::Preferred,
		}
	}
}

/// The account a passkey is created for: `name` and `display_name` are what the
/// authenticator shows.
#[derive(Debug, Clone)]
pub struct Account<'a, U> {
	pub user: U,
	pub name: &'a str,
	pub display_name: &'a str,
}

#[derive(Debug, Clone)]
pub struct Registered<U, P> {
	pub user: U,
	pub passkey: P,
	/// The account had no passkey before. Under `PasskeyRole::ReplacesPassword` this is when
	/// password sign-in ends, together with the sessions it opened.
	pub first: bool,
	/// What the browser said through credProps, unsigned.
	pub discoverable: Option<bool>,
}

/// A verified passkey for a grant, not stored yet: the app stores it and consumes the grant in
/// one transaction.
#[derive(Debug, Clone)]
pub struct Enrolment<U> {
	pub user: U,
	pub grant: String,
	pub passkey: Passkey,
	pub discoverable: Option<bool>,
}

/// A verified sign-in. `at` is the assertion time the app keeps on the session it opens and
/// later hands back as `Proof::RecentSignIn`.
#[derive(Debug, Clone)]
pub struct SignedIn<U, P> {
	pub user: U,
	pub passkey: P,
	pub at: SystemTime,
	pub updated: bool,
}

/// A removed passkey: end the sessions it opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removed<P> {
	pub passkey: P,
	pub remaining: usize,
}

/// The relying party with its ceremonies and decoys.
pub struct Kagi<U, S = MemoryCeremonies<U>> {
	webauthn: Webauthn,
	decoys: Decoys,
	ceremonies: S,
	step_up: Duration,
	resident_key: ResidentKey,
	user: PhantomData<fn() -> U>,
}

impl<U, S> Kagi<U, S>
where
	U: Clone + PartialEq + Send + Sync + 'static,
	S: CeremonyStore<U>,
{
	pub fn new(settings: Settings<'_>, ceremonies: S) -> Result<Self, Error> {
		Ok(Self {
			webauthn: relying_party(settings.url, settings.rp_id, settings.rp_name)?,
			decoys: Decoys::new(settings.decoy_key)?,
			ceremonies,
			step_up: settings.step_up,
			resident_key: settings.resident_key,
			user: PhantomData,
		})
	}

	pub const fn webauthn(&self) -> &Webauthn {
		&self.webauthn
	}

	pub const fn ceremonies(&self) -> &S {
		&self.ceremonies
	}

	async fn take(&self, id: &str, purpose: Purpose) -> Result<Step<U>, Error> {
		let ceremony = self.ceremonies.take(id).await?.ok_or(Error::Ceremony)?;
		if ceremony.purpose() != purpose {
			return Err(Error::Purpose);
		}
		Ok(ceremony.step)
	}

	/// Starts adding a passkey to `account`. `binding` ties the ceremony to whatever must
	/// finish it, such as the session or the grant, and is checked again at the finish.
	pub async fn start_registration<C>(
		&self,
		store: &C,
		account: Account<'_, U>,
		proof: Proof,
		binding: &str,
		address: Option<IpAddr>,
	) -> Result<RegistrationChallenge, Error>
	where
		C: CredentialStore<User = U>,
	{
		proof.purpose(SystemTime::now(), self.step_up)?;
		let existing = store.passkeys(&account.user).await.map_err(Error::store)?;
		let exclude = existing
			.iter()
			.map(|stored| stored.passkey.cred_id().clone())
			.collect();
		let (mut options, state) = self.webauthn.start_passkey_registration(
			store.user_handle(&account.user),
			account.name,
			account.display_name,
			Some(exclude),
		)?;
		self.resident_key.apply(&mut options)?;
		let binding = digest(binding.as_bytes());
		let user = account.user;
		let step = match proof {
			Proof::Grant { grant } => Step::Enrol {
				user,
				grant,
				binding,
				state,
			},
			Proof::RecentSignIn { .. } => Step::Register {
				user,
				binding,
				state,
			},
		};
		let ceremony = self.ceremonies.begin(address, Ceremony { step }).await?;
		Ok(RegistrationChallenge { ceremony, options })
	}

	/// Finishes a registration started with `Proof::RecentSignIn` and stores the passkey.
	pub async fn finish_registration<C>(
		&self,
		store: &C,
		ceremony: &str,
		binding: &str,
		credential: &RegisterPublicKeyCredential,
		label: &str,
	) -> Result<Registered<U, C::PasskeyId>, Error>
	where
		C: CredentialStore<User = U>,
	{
		let Step::Register {
			user,
			binding: bound,
			state,
		} = self.take(ceremony, Purpose::Register).await?
		else {
			return Err(Error::Purpose);
		};
		if bound != digest(binding.as_bytes()) {
			return Err(Error::Binding);
		}
		let passkey = self
			.webauthn
			.finish_passkey_registration(credential, &state)
			.map_err(|_| Error::Rejected { name: None })?;
		if store
			.find(passkey.cred_id())
			.await
			.map_err(Error::store)?
			.is_some()
		{
			return Err(Error::Duplicate);
		}
		let first = store
			.passkeys(&user)
			.await
			.map_err(Error::store)?
			.is_empty();
		let id = store
			.add(&user, &passkey, label)
			.await
			.map_err(Error::store)?;
		Ok(Registered {
			user,
			passkey: id,
			first,
			discoverable: discoverable(credential),
		})
	}

	/// Finishes a registration started with `Proof::Grant`. Nothing is stored.
	pub async fn finish_enrolment<C>(
		&self,
		store: &C,
		ceremony: &str,
		binding: &str,
		credential: &RegisterPublicKeyCredential,
	) -> Result<Enrolment<U>, Error>
	where
		C: CredentialStore<User = U>,
	{
		let Step::Enrol {
			user,
			grant,
			binding: bound,
			state,
		} = self.take(ceremony, Purpose::Enrol).await?
		else {
			return Err(Error::Purpose);
		};
		if bound != digest(binding.as_bytes()) {
			return Err(Error::Binding);
		}
		let passkey = self
			.webauthn
			.finish_passkey_registration(credential, &state)
			.map_err(|_| Error::Rejected { name: None })?;
		if store
			.find(passkey.cred_id())
			.await
			.map_err(Error::store)?
			.is_some()
		{
			return Err(Error::Duplicate);
		}
		Ok(Enrolment {
			user,
			grant,
			passkey,
			discoverable: discoverable(credential),
		})
	}

	/// Starts a username-first sign-in. `user` is who `name` resolves to, if anyone: an
	/// unknown name and a user without passkeys both get the decoy for the name.
	pub async fn start_sign_in<C>(
		&self,
		store: &C,
		name: &str,
		user: Option<&U>,
		address: Option<IpAddr>,
	) -> Result<SignInChallenge, Error>
	where
		C: CredentialStore<User = U>,
	{
		let name = normalize(name);
		let passkeys: Vec<Passkey> = match user {
			Some(user) => store
				.passkeys(user)
				.await
				.map_err(Error::store)?
				.into_iter()
				.map(|stored| stored.passkey)
				.collect(),
			None => Vec::new(),
		};
		let (options, step) = if passkeys.is_empty() {
			let (options, _) = self
				.webauthn
				.start_passkey_authentication(&self.decoys.passkeys(&name)?)?;
			(
				options,
				Step::Named {
					name,
					user: None,
					state: None,
				},
			)
		} else {
			let (options, state) = self.webauthn.start_passkey_authentication(&passkeys)?;
			(
				options,
				Step::Named {
					name,
					user: user.cloned(),
					state: Some(state),
				},
			)
		};
		let ceremony = self.ceremonies.begin(address, Ceremony { step }).await?;
		Ok(SignInChallenge { ceremony, options })
	}

	/// Starts a usernameless sign-in: `conditional` for autofill on the name field, otherwise
	/// the browser's passkey picker.
	pub async fn start_discoverable(
		&self,
		address: Option<IpAddr>,
		conditional: bool,
	) -> Result<SignInChallenge, Error> {
		let (mut options, state) = self.webauthn.start_discoverable_authentication()?;
		if !conditional {
			options.mediation = None;
		}
		let step = Step::Discoverable { state };
		let ceremony = self.ceremonies.begin(address, Ceremony { step }).await?;
		Ok(SignInChallenge { ceremony, options })
	}

	/// Finishes either kind of sign-in and writes the counter and backup flags back.
	pub async fn finish_sign_in<C>(
		&self,
		store: &C,
		ceremony: &str,
		credential: &PublicKeyCredential,
	) -> Result<SignedIn<U, C::PasskeyId>, Error>
	where
		C: CredentialStore<User = U>,
	{
		match self.take(ceremony, Purpose::SignIn).await? {
			Step::Named {
				name,
				user: Some(user),
				state: Some(state),
			} => {
				let rejected = || Error::Rejected {
					name: Some(name.clone()),
				};
				let result = self
					.webauthn
					.finish_passkey_authentication(credential, &state)
					.map_err(|error| refused(&error, Some(name.clone())))?;
				let stored = store
					.passkeys(&user)
					.await
					.map_err(Error::store)?
					.into_iter()
					.find(|stored| stored.passkey.cred_id() == result.cred_id())
					.ok_or_else(rejected)?;
				write_back(store, stored, &result)
					.await
					.map_err(|error| match error {
						Error::Rejected { .. } => rejected(),
						other => other,
					})
			}
			Step::Named { name, .. } => Err(Error::Rejected { name: Some(name) }),
			Step::Discoverable { state } => {
				let rejected = || Error::Rejected { name: None };
				let (handle, id) = self
					.webauthn
					.identify_discoverable_authentication(credential)
					.map_err(|_| rejected())?;
				let stored = store
					.find(id)
					.await
					.map_err(Error::store)?
					.ok_or_else(rejected)?;
				if store.user_handle(&stored.user) != handle {
					return Err(rejected());
				}
				let result = self
					.webauthn
					.finish_discoverable_authentication_v2(credential, state, &stored.passkey)
					.map_err(|error| refused(&error, None))?;
				write_back(store, stored, &result).await
			}
			Step::Register { .. } | Step::Enrol { .. } => Err(Error::Purpose),
		}
	}

	/// Removes one of `user`'s passkeys unless it is the last way into the account.
	pub async fn remove<C>(
		&self,
		store: &C,
		user: &U,
		passkey: &C::PasskeyId,
		role: PasskeyRole,
		has_password: bool,
	) -> Result<Removed<C::PasskeyId>, Error>
	where
		C: CredentialStore<User = U>,
	{
		let keep_last = !role.may_remove_last(has_password);
		match store
			.remove(user, passkey, keep_last)
			.await
			.map_err(Error::store)?
		{
			Removal::Removed { remaining } => Ok(Removed {
				passkey: passkey.clone(),
				remaining,
			}),
			Removal::NotFound => Err(Error::NotFound),
			Removal::Last => Err(Error::LastCredential),
		}
	}
}

/// A signature counter at or below the stored one says two copies of the key exist.
pub(crate) fn refused(error: &WebauthnError, name: Option<String>) -> Error {
	match error {
		WebauthnError::CredentialPossibleCompromise => Error::Cloned { name },
		_ => Error::Rejected { name },
	}
}

fn discoverable(credential: &RegisterPublicKeyCredential) -> Option<bool> {
	credential
		.extensions
		.cred_props
		.as_ref()
		.and_then(|props| props.rk)
}

pub(crate) async fn write_back<C: CredentialStore>(
	store: &C,
	mut stored: StoredPasskey<C::User, C::PasskeyId>,
	result: &AuthenticationResult,
) -> Result<SignedIn<C::User, C::PasskeyId>, Error> {
	let updated = stored
		.passkey
		.update_credential(result)
		.ok_or(Error::Rejected { name: None })?;
	if updated {
		store
			.update(&stored.id, &stored.passkey)
			.await
			.map_err(Error::store)?;
	}
	Ok(SignedIn {
		user: stored.user,
		passkey: stored.id,
		at: SystemTime::now(),
		updated,
	})
}
