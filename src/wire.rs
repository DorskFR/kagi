use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{
	CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
	RequestChallengeResponse,
};

/// What a registration start answers: the ceremony id and the options for
/// `navigator.credentials.create`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct RegistrationChallenge {
	pub ceremony: String,
	#[cfg_attr(test, ts(type = "import(\"../json\").CreationOptionsJSON"))]
	pub options: CreationChallengeResponse,
}

/// What a sign-in start answers: the ceremony id and the options for
/// `navigator.credentials.get`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct SignInChallenge {
	pub ceremony: String,
	#[cfg_attr(test, ts(type = "import(\"../json\").RequestOptionsJSON"))]
	pub options: RequestChallengeResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct RegistrationFinish {
	pub ceremony: String,
	#[cfg_attr(test, ts(type = "import(\"../json\").RegistrationResponseJSON"))]
	pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct SignInFinish {
	pub ceremony: String,
	#[cfg_attr(test, ts(type = "import(\"../json\").AuthenticationResponseJSON"))]
	pub credential: PublicKeyCredential,
}
