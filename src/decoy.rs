use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use webauthn_rs::fake::{
	FakePasskeyDistribution, WebauthnFakeCredentialGenerator, YUBIKEY_CRED_LEN,
	YUBIKEY_EDDSA_CRED_LEN,
};
use webauthn_rs::prelude::Passkey;

use crate::Error;

const MIN_KEY: usize = 32;

/// The sign-in a name without passkeys gets: credential ids drawn from the distribution real
/// accounts have, stable for a name under one key. The key must be persisted, or every restart
/// changes the decoys while real credentials stay put.
pub struct Decoys {
	generator: WebauthnFakeCredentialGenerator<FakePasskeyDistribution>,
}

impl std::fmt::Debug for Decoys {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("Decoys")
	}
}

/// How sign-in names are compared and seeded.
pub fn normalize(name: &str) -> String {
	name.trim().to_lowercase()
}

impl Decoys {
	pub fn new(key: &[u8]) -> Result<Self, Error> {
		if key.len() < MIN_KEY {
			return Err(Error::Config(format!(
				"the decoy key needs at least {MIN_KEY} bytes"
			)));
		}
		Ok(Self {
			generator: WebauthnFakeCredentialGenerator::new(key)?,
		})
	}

	pub(crate) fn passkeys(&self, name: &str) -> Result<Vec<Passkey>, Error> {
		let name = normalize(name);
		let mut round = 0u32;
		let ids = loop {
			let seed = if round == 0 {
				name.clone()
			} else {
				format!("{name}\0{round}")
			};
			let ids = self.generator.generate(seed.as_bytes())?;
			if !ids.is_empty() {
				break ids;
			}
			round += 1;
		};
		ids.iter()
			.map(|id| fake_passkey(id, transports(id.len())))
			.collect()
	}
}

/// What webauthn-rs keeps for the authenticator a credential id length points to: security
/// keys keep their packed attestation and so their transports, platform and synced passkeys
/// come back with attestation `none` and none recorded.
fn transports(id_len: usize) -> Option<&'static [&'static str]> {
	match id_len {
		YUBIKEY_CRED_LEN | YUBIKEY_EDDSA_CRED_LEN => Some(&["nfc", "usb"]),
		_ => None,
	}
}

pub(crate) fn fake_passkey(id: &[u8], transports: Option<&[&str]>) -> Result<Passkey, Error> {
	let format = if transports.is_some() {
		"packed"
	} else {
		"none"
	};
	let credential = json!({
		"cred": {
			"cred_id": URL_SAFE_NO_PAD.encode(id),
			"cred": {
				"type_": "ES256",
				"key": { "EC_EC2": {
					"curve": "SECP256R1",
					"x": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
					"y": "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0A",
				}},
			},
			"counter": 0,
			"transports": transports.map_or(Value::Null, |list| json!(list)),
			"user_verified": true,
			"backup_eligible": transports.is_none(),
			"backup_state": transports.is_none(),
			"registration_policy": "required",
			"extensions": {
				"cred_protect": "NotRequested",
				"hmac_create_secret": "NotRequested",
				"appid": "NotRequested",
				"cred_props": "NotRequested",
			},
			"attestation": { "data": "None", "metadata": "None" },
			"attestation_format": format,
		}
	});
	serde_json::from_value(credential).map_err(Error::internal)
}
