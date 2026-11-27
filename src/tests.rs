use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use webauthn_rs::prelude::AuthenticationResult;

use crate::decoy::fake_passkey;
use crate::kagi::{Verified, add, enrolment, write_back};
use crate::*;

const KEY: [u8; 32] = [7; 32];

type Row<'a> = (u64, u32, &'a [u8], Option<&'a [&'a str]>);

#[derive(Default)]
struct Credentials {
	rows: Mutex<Vec<StoredPasskey<u32, u64>>>,
	labels: Mutex<Vec<String>>,
	updates: AtomicUsize,
}

impl Credentials {
	fn with(rows: &[Row<'_>]) -> Self {
		let store = Self::default();
		for &(id, user, credential, transports) in rows {
			let passkey = fake_passkey(credential, transports).unwrap();
			store
				.rows
				.lock()
				.unwrap()
				.push(StoredPasskey { id, user, passkey });
		}
		store
	}

	fn counter(&self, id: u64) -> u64 {
		let rows = self.rows.lock().unwrap();
		let row = rows.iter().find(|row| row.id == id).unwrap();
		serde_json::to_value(&row.passkey).unwrap()["cred"]["counter"]
			.as_u64()
			.unwrap()
	}
}

impl CredentialStore for Credentials {
	type User = u32;
	type PasskeyId = u64;
	type Error = Infallible;

	fn user_handle(&self, user: &u32) -> Uuid {
		derived_handle("kagi-test", &user.to_be_bytes())
	}

	async fn passkeys(&self, user: &u32) -> Result<Vec<StoredPasskey<u32, u64>>, Infallible> {
		Ok(self
			.rows
			.lock()
			.unwrap()
			.iter()
			.filter(|row| row.user == *user)
			.cloned()
			.collect())
	}

	async fn find(&self, credential: &[u8]) -> Result<Option<StoredPasskey<u32, u64>>, Infallible> {
		let rows = self.rows.lock().unwrap();
		Ok(rows
			.iter()
			.find(|row| row.passkey.cred_id().as_slice() == credential)
			.cloned())
	}

	async fn add(&self, user: &u32, passkey: &Passkey, label: &str) -> Result<u64, Infallible> {
		self.labels.lock().unwrap().push(label.to_owned());
		let mut rows = self.rows.lock().unwrap();
		let id = rows.iter().map(|row| row.id).max().unwrap_or(0) + 1;
		rows.push(StoredPasskey {
			id,
			user: *user,
			passkey: passkey.clone(),
		});
		Ok(id)
	}

	async fn update(&self, id: &u64, passkey: &Passkey) -> Result<(), Infallible> {
		self.updates.fetch_add(1, Ordering::SeqCst);
		let mut rows = self.rows.lock().unwrap();
		if let Some(row) = rows.iter_mut().find(|row| row.id == *id) {
			row.passkey = passkey.clone();
		}
		Ok(())
	}

	async fn remove(&self, user: &u32, id: &u64, keep_last: bool) -> Result<Removal, Infallible> {
		let mut rows = self.rows.lock().unwrap();
		if !rows.iter().any(|row| row.user == *user && row.id == *id) {
			return Ok(Removal::NotFound);
		}
		let held = rows.iter().filter(|row| row.user == *user).count();
		if keep_last && held == 1 {
			return Ok(Removal::Last);
		}
		rows.retain(|row| row.id != *id);
		Ok(Removal::Removed {
			remaining: held - 1,
		})
	}
}

fn url() -> Url {
	Url::parse("https://kagi.example").unwrap()
}

fn kagi_with(key: &[u8], adjust: impl FnOnce(&mut Settings<'_>)) -> Kagi<u32> {
	let url = url();
	let mut settings = Settings::new(&url, "kagi", key);
	adjust(&mut settings);
	Kagi::new(settings, MemoryCeremonies::default()).unwrap()
}

fn kagi() -> Kagi<u32> {
	kagi_with(&KEY, |_| {})
}

fn home() -> Option<IpAddr> {
	"192.0.2.1".parse().ok()
}

fn fresh() -> Proof {
	Proof::RecentSignIn {
		at: SystemTime::now(),
		human: true,
	}
}

fn account(user: u32) -> Account<'static, u32> {
	Account {
		user,
		name: "jeanne",
		display_name: "Jeanne",
	}
}

fn b64(bytes: &[u8]) -> String {
	URL_SAFE_NO_PAD.encode(bytes)
}

fn assertion(credential: &[u8], user_handle: Option<Uuid>) -> PublicKeyCredential {
	serde_json::from_value(json!({
		"id": b64(credential),
		"rawId": b64(credential),
		"type": "public-key",
		"response": {
			"authenticatorData": b64(&[0; 37]),
			"clientDataJSON": b64(b"{}"),
			"signature": b64(&[0; 64]),
			"userHandle": user_handle.map(|handle| b64(handle.as_bytes())),
		},
		"clientExtensionResults": {},
	}))
	.unwrap()
}

fn attestation() -> RegisterPublicKeyCredential {
	serde_json::from_value(json!({
		"id": b64(&[9; 16]),
		"rawId": b64(&[9; 16]),
		"type": "public-key",
		"response": {
			"attestationObject": b64(&[0xa0]),
			"clientDataJSON": b64(b"{}"),
			"transports": ["internal"],
		},
		"clientExtensionResults": { "credProps": { "rk": true } },
	}))
	.unwrap()
}

fn options(challenge: &SignInChallenge) -> Value {
	serde_json::to_value(&challenge.options).unwrap()
}

fn allowed(challenge: &SignInChallenge) -> Value {
	options(challenge)["publicKey"]["allowCredentials"].clone()
}

#[tokio::test]
async fn a_ceremony_finishes_only_what_it_was_started_for_and_only_once() {
	let kagi = kagi();
	let att = attestation();
	let store = Credentials::with(&[(1, 1, &[1; 20], None)]);

	let sign_in = kagi
		.start_sign_in(&store, "jeanne", Some(&1), home())
		.await
		.unwrap();
	let wrong = kagi.finish_registration(&store, &sign_in.ceremony, "s", &att, "x");
	assert!(matches!(wrong.await, Err(Error::Purpose)));
	let again = kagi
		.finish_sign_in(&store, &sign_in.ceremony, &assertion(&[1; 20], None))
		.await;
	assert!(matches!(again, Err(Error::Ceremony)));

	let register = kagi
		.start_registration(&store, account(1), fresh(), "s", home())
		.await
		.unwrap();
	let answer = assertion(&[1; 20], None);
	let wrong = kagi.finish_sign_in(&store, &register.ceremony, &answer);
	assert!(matches!(wrong.await, Err(Error::Purpose)));
	let again = kagi.finish_registration(&store, &register.ceremony, "s", &att, "x");
	assert!(matches!(again.await, Err(Error::Ceremony)));

	let grant = Proof::Grant {
		grant: "invite-1".into(),
	};
	let enrol = kagi
		.start_registration(&store, account(2), grant, "g", home())
		.await
		.unwrap();
	let wrong = kagi.finish_registration(&store, &enrol.ceremony, "g", &att, "x");
	assert!(matches!(wrong.await, Err(Error::Purpose)));

	let register = kagi
		.start_registration(&store, account(1), fresh(), "s", home())
		.await
		.unwrap();
	let wrong = kagi.finish_enrolment(&store, &register.ceremony, "s", &att);
	assert!(matches!(wrong.await, Err(Error::Purpose)));

	let discoverable = kagi.start_discoverable(home(), true).await.unwrap();
	let wrong = kagi.finish_enrolment(&store, &discoverable.ceremony, "s", &att);
	assert!(matches!(wrong.await, Err(Error::Purpose)));

	let unknown = kagi
		.finish_sign_in(&store, "0123", &assertion(&[1; 20], None))
		.await;
	assert!(matches!(unknown, Err(Error::Ceremony)));
	assert!(kagi.ceremonies().keys().is_empty());
}

#[tokio::test]
async fn a_registration_is_bound_and_a_bad_attestation_is_rejected() {
	let kagi = kagi();
	let att = attestation();
	let store = Credentials::default();
	let register = kagi
		.start_registration(&store, account(1), fresh(), "session-a", home())
		.await
		.unwrap();
	let other = kagi.finish_registration(&store, &register.ceremony, "session-b", &att, "x");
	assert!(matches!(other.await, Err(Error::Binding)));
	assert!(!kagi.ceremonies().holds(&register.ceremony));

	let register = kagi
		.start_registration(&store, account(1), fresh(), "session-a", home())
		.await
		.unwrap();
	let bad = kagi.finish_registration(&store, &register.ceremony, "session-a", &att, "x");
	assert!(matches!(bad.await, Err(Error::Rejected { name: None })));
	assert!(store.rows.lock().unwrap().is_empty());
}

#[tokio::test]
async fn registration_needs_a_recent_human_sign_in_judged_from_its_assertion() {
	let store = Credentials::default();
	let kagi = kagi();
	let stale = Proof::RecentSignIn {
		at: SystemTime::now() - DEFAULT_STEP_UP - Duration::from_secs(1),
		human: true,
	};
	let refused = kagi
		.start_registration(&store, account(1), stale.clone(), "s", home())
		.await;
	assert!(matches!(refused, Err(Error::StepUp)));
	let robot = Proof::RecentSignIn {
		at: SystemTime::now(),
		human: false,
	};
	let refused = kagi
		.start_registration(&store, account(1), robot, "s", home())
		.await;
	assert!(matches!(refused, Err(Error::StepUp)));
	assert!(kagi.ceremonies().keys().is_empty());

	let recent = Proof::RecentSignIn {
		at: SystemTime::now() - DEFAULT_STEP_UP + Duration::from_secs(30),
		human: true,
	};
	assert!(
		kagi.start_registration(&store, account(1), recent, "s", home())
			.await
			.is_ok()
	);

	let patient = kagi_with(&KEY, |settings| {
		settings.step_up = Duration::from_secs(3600)
	});
	assert!(
		patient
			.start_registration(&store, account(1), stale, "s", home())
			.await
			.is_ok()
	);
}

#[tokio::test]
async fn a_grant_enrols_an_identifier_and_a_passkey_without_a_password() {
	let kagi = kagi_with(&KEY, |settings| {
		settings.resident_key = ResidentKey::Required
	});
	let att = attestation();
	let store = Credentials::default();
	let grant = Proof::Grant {
		grant: "invite-7".into(),
	};
	let account = Account {
		user: 9,
		name: "new@kagi.example",
		display_name: "New",
	};
	let enrol = kagi
		.start_registration(&store, account, grant, "invite-7", home())
		.await
		.unwrap();
	let options = serde_json::to_value(&enrol.options).unwrap();
	let public_key = &options["publicKey"];
	assert_eq!(public_key["user"]["name"], "new@kagi.example");
	assert_eq!(
		public_key["user"]["id"],
		b64(store.user_handle(&9).as_bytes())
	);
	assert_eq!(public_key["excludeCredentials"], json!([]));
	assert_eq!(
		public_key["authenticatorSelection"]["residentKey"],
		"required"
	);
	assert_eq!(
		public_key["authenticatorSelection"]["requireResidentKey"],
		true
	);
	assert_eq!(
		public_key["authenticatorSelection"]["userVerification"],
		"required"
	);
	assert_eq!(public_key["extensions"]["credProps"], true);
	assert_eq!(public_key["rp"]["id"], "kagi.example");

	let elsewhere = kagi.finish_enrolment(&store, &enrol.ceremony, "invite-8", &att);
	assert!(matches!(elsewhere.await, Err(Error::Binding)));

	let grant = Proof::Grant {
		grant: "invite-7".into(),
	};
	let account = Account {
		user: 9,
		name: "new@kagi.example",
		display_name: "New",
	};
	let enrol = kagi
		.start_registration(&store, account, grant, "invite-7", home())
		.await
		.unwrap();
	let bad = kagi.finish_enrolment(&store, &enrol.ceremony, "invite-7", &att);
	assert!(matches!(bad.await, Err(Error::Rejected { name: None })));
}

#[tokio::test]
async fn a_registration_carries_its_data_from_start_to_finish() {
	let kagi = kagi();
	let att = attestation();
	let store = Credentials::default();

	let plain = kagi
		.start_registration(&store, account(1), fresh(), "s", home())
		.await
		.unwrap();
	let unlabelled = kagi.finish_carried_registration(&store, &plain.ceremony, "s", &att);
	assert!(matches!(unlabelled.await, Err(Error::Purpose)));
	assert!(!kagi.ceremonies().holds(&plain.ceremony));

	let carried = kagi
		.start_registration_with(&store, account(1), fresh(), "s", home(), "Phone")
		.await
		.unwrap();
	let other = kagi.finish_carried_registration(&store, &carried.ceremony, "t", &att);
	assert!(matches!(other.await, Err(Error::Binding)));

	let carried = kagi
		.start_registration_with(&store, account(1), fresh(), "s", home(), "Phone")
		.await
		.unwrap();
	let bad = kagi.finish_carried_registration(&store, &carried.ceremony, "s", &att);
	assert!(matches!(bad.await, Err(Error::Rejected { name: None })));

	let grant = Proof::Grant {
		grant: "invite-3".into(),
	};
	let enrol = kagi
		.start_registration_with(&store, account(2), grant, "g", home(), "Laptop")
		.await
		.unwrap();
	let wrong = kagi.finish_carried_registration(&store, &enrol.ceremony, "g", &att);
	assert!(matches!(wrong.await, Err(Error::Purpose)));
	assert!(store.rows.lock().unwrap().is_empty());
	assert!(kagi.ceremonies().keys().is_empty());
}

#[tokio::test]
async fn a_verified_passkey_is_stored_under_its_label_with_its_data() {
	let store = Credentials::default();
	let verified = |data: Option<&str>| Verified {
		user: 1,
		passkey: fake_passkey(&[3; 16], None).unwrap(),
		discoverable: Some(true),
		data: data.map(str::to_owned),
	};

	let registered = add(&store, verified(Some("Phone")), "Phone").await.unwrap();
	assert_eq!(registered.data.as_deref(), Some("Phone"));
	assert!(registered.first);
	assert_eq!(registered.discoverable, Some(true));
	assert_eq!(*store.labels.lock().unwrap(), ["Phone"]);
	let again = add(&store, verified(None), "Other").await;
	assert!(matches!(again, Err(Error::Duplicate)));
	let enrolled = enrolment(&store, verified(None), "g".into()).await;
	assert!(matches!(enrolled, Err(Error::Duplicate)));

	let fresh_store = Credentials::default();
	let enrolled = enrolment(&fresh_store, verified(Some("Laptop")), "g".into())
		.await
		.unwrap();
	assert_eq!(enrolled.data.as_deref(), Some("Laptop"));
	assert_eq!(enrolled.grant, "g");
	assert!(fresh_store.rows.lock().unwrap().is_empty());
}

#[tokio::test]
async fn registration_excludes_the_accounts_passkeys_and_prefers_a_resident_key() {
	let kagi = kagi();
	let store = Credentials::with(&[
		(1, 1, &[1; 20], None),
		(2, 1, &[2; 64], Some(&["nfc", "usb"])),
	]);
	let register = kagi
		.start_registration(&store, account(1), fresh(), "s", home())
		.await
		.unwrap();
	let options = serde_json::to_value(&register.options).unwrap();
	let excluded: Vec<&str> = options["publicKey"]["excludeCredentials"]
		.as_array()
		.unwrap()
		.iter()
		.map(|entry| entry["id"].as_str().unwrap())
		.collect();
	assert_eq!(excluded, [b64(&[1; 20]), b64(&[2; 64])]);
	let selection = &options["publicKey"]["authenticatorSelection"];
	assert_eq!(selection["residentKey"], "preferred");
	assert_eq!(selection["requireResidentKey"], false);
}

#[tokio::test]
async fn unknown_names_and_names_without_passkeys_get_the_same_stable_decoy() {
	let store = Credentials::with(&[(1, 1, &[1; 20], None)]);
	let kagi = kagi();
	let unknown = kagi
		.start_sign_in(&store, "Paul", None, home())
		.await
		.unwrap();
	let empty = kagi
		.start_sign_in(&store, " paul ", Some(&2), home())
		.await
		.unwrap();
	assert!(!allowed(&unknown).as_array().unwrap().is_empty());
	assert_eq!(allowed(&unknown), allowed(&empty));
	assert_ne!(
		options(&unknown)["publicKey"]["challenge"],
		options(&empty)["publicKey"]["challenge"]
	);

	let restarted = kagi_with(&KEY, |_| {});
	let after = restarted
		.start_sign_in(&store, "paul", None, home())
		.await
		.unwrap();
	assert_eq!(allowed(&unknown), allowed(&after));

	let rekeyed = kagi_with(&[8; 32], |_| {});
	let other_key = rekeyed
		.start_sign_in(&store, "paul", None, home())
		.await
		.unwrap();
	assert_ne!(allowed(&unknown), allowed(&other_key));
	let other_name = kagi
		.start_sign_in(&store, "jeanne", None, home())
		.await
		.unwrap();
	assert_ne!(allowed(&unknown), allowed(&other_name));

	let real = kagi
		.start_sign_in(&store, "jeanne", Some(&1), home())
		.await
		.unwrap();
	let shape = |challenge: &SignInChallenge| {
		let mut value = options(challenge);
		value["publicKey"]["challenge"] = Value::Null;
		value["publicKey"]["allowCredentials"] = Value::Null;
		value
	};
	assert_eq!(shape(&real), shape(&unknown));
	assert_eq!(shape(&real), shape(&after));
	assert_eq!(
		serde_json::to_value(&real)
			.unwrap()
			.as_object()
			.unwrap()
			.len(),
		2
	);

	let decoy = kagi
		.finish_sign_in(&store, &unknown.ceremony, &assertion(&[1; 20], None))
		.await;
	assert!(matches!(decoy, Err(Error::Rejected { name: Some(name) }) if name == "paul"));
}

#[tokio::test]
async fn decoys_carry_the_transports_their_authenticator_would_have() {
	let kagi = kagi();
	let store = Credentials::with(&[(1, 1, &[3; 64], Some(&["nfc", "usb"]))]);
	let real = kagi
		.start_sign_in(&store, "jeanne", Some(&1), home())
		.await
		.unwrap();
	let real_entry = allowed(&real)[0].clone();
	assert_eq!(real_entry["transports"], json!(["nfc", "usb"]));

	let (mut keyed, mut bare) = (None, None);
	for n in 0..500 {
		let address = Some(IpAddr::from((0x0a00_0000u32 + n).to_be_bytes()));
		let decoy = kagi
			.start_sign_in(&store, &format!("user{n}"), None, address)
			.await
			.unwrap();
		let entries = allowed(&decoy);
		for entry in entries.as_array().unwrap() {
			let length = URL_SAFE_NO_PAD
				.decode(entry["id"].as_str().unwrap())
				.unwrap()
				.len();
			let keys: Vec<String> = entry.as_object().unwrap().keys().cloned().collect();
			if length == 64 || length == 128 {
				assert_eq!(entry["transports"], json!(["nfc", "usb"]));
				keyed.get_or_insert(keys);
			} else {
				assert!(entry.get("transports").is_none(), "{entry}");
				bare.get_or_insert(keys);
			}
		}
		if keyed.is_some() && bare.is_some() {
			break;
		}
	}
	let keyed = keyed.expect("some decoy is a security key");
	assert_eq!(
		keyed,
		real_entry
			.as_object()
			.unwrap()
			.keys()
			.cloned()
			.collect::<Vec<_>>()
	);
	assert_eq!(
		bare.expect("some decoy is a synced passkey"),
		["id", "type"]
	);
}

#[tokio::test]
async fn usernameless_sign_in_offers_conditional_and_modal_options() {
	let kagi = kagi();
	let conditional = kagi.start_discoverable(home(), true).await.unwrap();
	let value = options(&conditional);
	assert_eq!(value["mediation"], "conditional");
	assert_eq!(value["publicKey"]["allowCredentials"], json!([]));
	assert_eq!(value["publicKey"]["userVerification"], "required");
	let modal = kagi.start_discoverable(home(), false).await.unwrap();
	assert!(options(&modal).get("mediation").is_none());
}

#[tokio::test]
async fn a_discoverable_answer_must_name_the_owner_of_its_credential() {
	let kagi = kagi();
	let store = Credentials::with(&[(1, 1, &[1; 20], None), (2, 2, &[2; 20], None)]);
	let start = kagi.start_discoverable(home(), true).await.unwrap();
	let someone_else = assertion(&[1; 20], Some(store.user_handle(&2)));
	let refused = kagi
		.finish_sign_in(&store, &start.ceremony, &someone_else)
		.await;
	assert!(matches!(refused, Err(Error::Rejected { name: None })));
	assert!(!kagi.ceremonies().holds(&start.ceremony));

	let start = kagi.start_discoverable(home(), true).await.unwrap();
	let unknown = assertion(&[5; 20], Some(store.user_handle(&1)));
	let refused = kagi.finish_sign_in(&store, &start.ceremony, &unknown).await;
	assert!(matches!(refused, Err(Error::Rejected { name: None })));

	let start = kagi.start_discoverable(home(), true).await.unwrap();
	let forged = assertion(&[1; 20], Some(store.user_handle(&1)));
	let refused = kagi.finish_sign_in(&store, &start.ceremony, &forged).await;
	assert!(matches!(refused, Err(Error::Rejected { name: None })));
	assert_eq!(store.updates.load(Ordering::SeqCst), 0);
}

fn result(credential: &[u8], counter: u32, backup_state: bool) -> AuthenticationResult {
	serde_json::from_value(json!({
		"cred_id": b64(credential),
		"needs_update": true,
		"user_verified": true,
		"backup_state": backup_state,
		"backup_eligible": true,
		"counter": counter,
		"extensions": {},
	}))
	.unwrap()
}

#[tokio::test]
async fn a_sign_in_writes_the_counter_and_backup_flags_back() {
	let store = Credentials::with(&[(1, 1, &[1; 20], None)]);
	let stored = || store.rows.lock().unwrap()[0].clone();

	let signed_in = write_back(&store, stored(), &result(&[1; 20], 8, true))
		.await
		.unwrap();
	assert_eq!(
		(signed_in.user, signed_in.passkey, signed_in.updated),
		(1, 1, true)
	);
	assert_eq!(store.counter(1), 8);
	assert_eq!(store.updates.load(Ordering::SeqCst), 1);

	let same = write_back(&store, stored(), &result(&[1; 20], 8, true))
		.await
		.unwrap();
	assert!(!same.updated);
	assert_eq!(store.updates.load(Ordering::SeqCst), 1);

	let moved = write_back(&store, stored(), &result(&[1; 20], 8, false))
		.await
		.unwrap();
	assert!(moved.updated);
	let flags = serde_json::to_value(&stored().passkey).unwrap();
	assert_eq!(flags["cred"]["backup_state"], false);
	assert_eq!(store.updates.load(Ordering::SeqCst), 2);

	let stale = write_back(&store, stored(), &result(&[1; 20], 3, false))
		.await
		.unwrap();
	assert!(!stale.updated);
	assert_eq!(store.counter(1), 8);

	let other = write_back(&store, stored(), &result(&[2; 20], 9, true)).await;
	assert!(matches!(other, Err(Error::Rejected { .. })));
	assert_eq!(store.updates.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_last_passkey_stays_unless_a_password_remains() {
	let kagi = kagi();
	let one = || Credentials::with(&[(1, 1, &[1; 20], None), (2, 2, &[2; 20], None)]);
	for role in [PasskeyRole::Only, PasskeyRole::ReplacesPassword] {
		for has_password in [false, true] {
			let store = one();
			let refused = kagi.remove(&store, &1, &1, role, has_password).await;
			assert!(matches!(refused, Err(Error::LastCredential)), "{role:?}");
		}
	}
	let store = one();
	let refused = kagi
		.remove(&store, &1, &1, PasskeyRole::Alternative, false)
		.await;
	assert!(matches!(refused, Err(Error::LastCredential)));
	let removed = kagi
		.remove(&store, &1, &1, PasskeyRole::Alternative, true)
		.await
		.unwrap();
	assert_eq!(
		removed,
		Removed {
			passkey: 1,
			remaining: 0
		}
	);

	let store = Credentials::with(&[(1, 1, &[1; 20], None), (3, 1, &[3; 20], None)]);
	let removed = kagi
		.remove(&store, &1, &3, PasskeyRole::Only, false)
		.await
		.unwrap();
	assert_eq!(
		removed,
		Removed {
			passkey: 3,
			remaining: 1
		}
	);
	let theirs = kagi
		.remove(&one(), &1, &2, PasskeyRole::Alternative, true)
		.await;
	assert!(matches!(theirs, Err(Error::NotFound)));
}

#[test]
fn stored_passkeys_keep_the_webauthn_rs_format() {
	let row = r#"{"cred":{"cred_id":"AAECAwQFBgcICQoLDA0ODw","cred":{"type_":"ES256","key":{"EC_EC2":{"curve":"SECP256R1","x":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA","y":"ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0A"}}},"counter":7,"transports":["internal","hybrid"],"user_verified":true,"backup_eligible":true,"backup_state":true,"registration_policy":"required","extensions":{"cred_protect":"NotRequested","hmac_create_secret":"NotRequested","appid":"NotRequested","cred_props":"NotRequested"},"attestation":{"data":"None","metadata":"None"},"attestation_format":"none"}}"#;
	let passkey: Passkey = serde_json::from_str(row).unwrap();
	assert_eq!(passkey.cred_id().as_slice(), (0u8..16).collect::<Vec<_>>());
	let again: Value = serde_json::to_value(&passkey).unwrap();
	assert_eq!(again, serde_json::from_str::<Value>(row).unwrap());
}

#[test]
fn a_derived_handle_is_stable_and_separates_namespaces() {
	let a = derived_handle("app", b"42");
	assert_eq!(a, derived_handle("app", b"42"));
	assert_ne!(a, derived_handle("app", b"43"));
	assert_ne!(a, derived_handle("other", b"42"));
	assert_ne!(derived_handle("ab", b"c"), derived_handle("a", b"bc"));
}

#[test]
fn a_short_decoy_key_is_refused() {
	assert!(matches!(Decoys::new(&[1; 16]), Err(Error::Config(_))));
	let url = url();
	let settings = Settings::new(&url, "kagi", &[1; 31]);
	assert!(Kagi::<u32>::new(settings, MemoryCeremonies::default()).is_err());
}

#[test]
fn the_ceremony_futures_and_errors_cross_threads() {
	fn send<T: Send>(_: &T) {}
	fn shared<T: Send + Sync + 'static>() {}
	shared::<Error>();
	shared::<Kagi<u32>>();
	let (kagi, store) = (kagi(), Credentials::default());
	let answer = assertion(&[1; 20], None);
	let att = attestation();
	send(&kagi.start_sign_in(&store, "jeanne", None, home()));
	send(&kagi.start_discoverable(home(), true));
	send(&kagi.finish_sign_in(&store, "c", &answer));
	send(&kagi.start_registration(&store, account(1), fresh(), "s", home()));
	send(&kagi.finish_registration(&store, "c", "s", &att, "x"));
	send(&kagi.finish_enrolment(&store, "c", "s", &att));
	send(&kagi.remove(&store, &1, &1, PasskeyRole::Only, false));
}

#[test]
fn a_counter_that_goes_backwards_is_its_own_refusal() {
	use crate::kagi::refused;
	use webauthn_rs::prelude::WebauthnError;
	let cloned = refused(
		&WebauthnError::CredentialPossibleCompromise,
		Some("jeanne".into()),
	);
	assert!(matches!(cloned, Error::Cloned { name: Some(name) } if name == "jeanne"));
	let bad = refused(&WebauthnError::InvalidRPIDHash, None);
	assert!(matches!(bad, Error::Rejected { name: None }));
}

#[cfg(feature = "serde")]
mod shared_store {
	use std::collections::HashMap;

	use super::*;

	/// A store that keeps nothing but serialized ceremonies, like one shared between replicas.
	#[derive(Default)]
	struct Serialized {
		rows: Mutex<HashMap<[u8; 32], String>>,
	}

	impl CeremonyStore<u32> for Serialized {
		async fn begin(&self, _: Option<IpAddr>, ceremony: Ceremony<u32>) -> Result<String, Error> {
			let id = ceremony_id()?;
			let json = serde_json::to_string(&ceremony).map_err(Error::internal)?;
			self.rows.lock().unwrap().insert(ceremony_key(&id), json);
			Ok(id)
		}

		async fn take(&self, id: &str) -> Result<Option<Ceremony<u32>>, Error> {
			let row = self.rows.lock().unwrap().remove(&ceremony_key(id));
			row.map(|json| serde_json::from_str(&json).map_err(Error::internal))
				.transpose()
		}
	}

	fn shared() -> Kagi<u32, Serialized> {
		let url = url();
		Kagi::new(Settings::new(&url, "kagi", &KEY), Serialized::default()).unwrap()
	}

	#[tokio::test]
	async fn every_ceremony_survives_a_round_trip_through_its_serialized_form() {
		let (kagi, att) = (shared(), attestation());
		let store = Credentials::with(&[(1, 1, &[1; 20], None)]);

		let named = kagi
			.start_sign_in(&store, "jeanne", Some(&1), home())
			.await
			.unwrap();
		let decoy = kagi
			.start_sign_in(&store, "paul", None, home())
			.await
			.unwrap();
		let discoverable = kagi.start_discoverable(home(), true).await.unwrap();
		let register = kagi
			.start_registration(&store, account(1), fresh(), "s", home())
			.await
			.unwrap();
		let grant = Proof::Grant {
			grant: "invite-1".into(),
		};
		let enrol = kagi
			.start_registration(&store, account(2), grant, "g", home())
			.await
			.unwrap();

		let stored: Vec<String> = kagi
			.ceremonies()
			.rows
			.lock()
			.unwrap()
			.values()
			.cloned()
			.collect();
		assert_eq!(stored.len(), 5);
		for id in [&named.ceremony, &register.ceremony, &enrol.ceremony] {
			assert!(stored.iter().all(|json| !json.contains(id.as_str())));
		}
		for json in &stored {
			let ceremony: Ceremony<u32> = serde_json::from_str(json).unwrap();
			assert_eq!(&serde_json::to_string(&ceremony).unwrap(), json);
		}

		let answer = assertion(&[1; 20], None);
		let named = kagi.finish_sign_in(&store, &named.ceremony, &answer).await;
		assert!(matches!(named, Err(Error::Rejected { name: Some(name) }) if name == "jeanne"));
		let decoy = kagi.finish_sign_in(&store, &decoy.ceremony, &answer).await;
		assert!(matches!(decoy, Err(Error::Rejected { name: Some(name) }) if name == "paul"));
		let answer = assertion(&[1; 20], Some(store.user_handle(&1)));
		let discoverable = kagi
			.finish_sign_in(&store, &discoverable.ceremony, &answer)
			.await;
		assert!(matches!(discoverable, Err(Error::Rejected { name: None })));
		let other = kagi.finish_registration(&store, &register.ceremony, "t", &att, "x");
		assert!(matches!(other.await, Err(Error::Binding)));
		let bad = kagi.finish_enrolment(&store, &enrol.ceremony, "g", &att);
		assert!(matches!(bad.await, Err(Error::Rejected { name: None })));
		assert!(kagi.ceremonies().rows.lock().unwrap().is_empty());
	}

	#[tokio::test]
	async fn carried_data_survives_the_store_and_older_rows_still_load() {
		let (kagi, att) = (shared(), attestation());
		let store = Credentials::default();
		let plain = kagi
			.start_registration(&store, account(1), fresh(), "s", home())
			.await
			.unwrap();
		let carried = kagi
			.start_registration_with(&store, account(1), fresh(), "s", home(), "Phone")
			.await
			.unwrap();
		let rows = kagi.ceremonies().rows.lock().unwrap().clone();
		let plain_row = &rows[&ceremony_key(&plain.ceremony)];
		let carried_row = &rows[&ceremony_key(&carried.ceremony)];
		assert!(!plain_row.contains("\"data\""));
		let carried_json: Value = serde_json::from_str(carried_row).unwrap();
		assert_eq!(carried_json["step"]["Register"]["data"], "Phone");

		let mut older = carried_json.clone();
		older["step"]["Register"]
			.as_object_mut()
			.unwrap()
			.remove("data");
		let older: Ceremony<u32> = serde_json::from_value(older).unwrap();
		assert_eq!(older.purpose(), Purpose::Register);

		let bad = kagi.finish_carried_registration(&store, &carried.ceremony, "s", &att);
		assert!(matches!(bad.await, Err(Error::Rejected { name: None })));
	}

	#[test]
	fn a_purpose_has_a_stable_name() {
		for (purpose, name) in [
			(Purpose::Register, "register"),
			(Purpose::SignIn, "sign-in"),
			(Purpose::Enrol, "enrol"),
		] {
			assert_eq!(purpose.as_str(), name);
			assert_eq!(serde_json::to_value(purpose).unwrap(), name);
		}
	}
}
