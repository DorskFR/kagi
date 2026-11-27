use webauthn_rs::prelude::Url;
use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::Error;

/// The relying party of a public URL: the URL is the only origin and its host the RP id, unless
/// `rp_id` names a parent domain of that host. Plain http is accepted for `localhost` only, the
/// one insecure context browsers allow.
pub fn relying_party(url: &Url, rp_id: Option<&str>, rp_name: &str) -> Result<Webauthn, Error> {
	let refuse = |why: &str| Err(Error::Config(format!("{url}: {why}")));
	if !matches!(url.scheme(), "https" | "http") {
		return refuse("the public URL must be http or https");
	}
	if !url.username().is_empty() || url.password().is_some() {
		return refuse("the public URL cannot carry credentials");
	}
	if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
		return refuse("the public URL must be an origin, without a path, query or fragment");
	}
	let Some(host) = url.domain() else {
		return refuse("the public URL must name a host, not an IP address");
	};
	let local = host == "localhost" || host.ends_with(".localhost");
	if url.scheme() == "http" && !local {
		return refuse("passkeys need https outside localhost");
	}
	let rp_id = rp_id.unwrap_or(host);
	let covered = rp_id == host
		|| host
			.strip_suffix(rp_id)
			.is_some_and(|sub| sub.ends_with('.') && !rp_id.starts_with('.'));
	if !covered || (!rp_id.contains('.') && rp_id != "localhost") {
		return Err(Error::Config(format!(
			"{rp_id}: the RP id must be the host of {url} or a parent domain of it"
		)));
	}
	Ok(WebauthnBuilder::new(rp_id, url)?.rp_name(rp_name).build()?)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_relying_party_is_the_origin_of_the_public_url() {
		for good in [
			"https://kira.example",
			"https://kira.example/",
			"https://kira.example:8443",
			"http://localhost:8080",
			"http://app.localhost:5173/",
		] {
			let webauthn = relying_party(&Url::parse(good).unwrap(), None, "kagi");
			assert!(webauthn.is_ok(), "{good}: {webauthn:?}");
		}
		for bad in [
			"https://kira.example/app",
			"https://kira.example/?next=1",
			"https://kira.example/#top",
			"https://user:pw@kira.example",
			"https://10.0.0.1",
			"https://[2001:db8::1]",
			"http://127.0.0.1:8080",
			"http://kira.example",
			"ftp://kira.example",
		] {
			assert!(
				relying_party(&Url::parse(bad).unwrap(), None, "kagi").is_err(),
				"{bad}"
			);
		}
	}

	#[test]
	fn an_rp_id_override_must_be_the_host_or_a_parent_domain() {
		let url = Url::parse("https://app.kira.example").unwrap();
		for good in ["kira.example", "app.kira.example"] {
			assert!(relying_party(&url, Some(good), "kagi").is_ok(), "{good}");
		}
		for bad in [
			"elsewhere.test",
			"pp.kira.example",
			"example",
			".kira.example",
			"",
		] {
			assert!(relying_party(&url, Some(bad), "kagi").is_err(), "{bad}");
		}
		let local = Url::parse("http://app.localhost:5173").unwrap();
		assert!(relying_party(&local, Some("localhost"), "kagi").is_ok());
	}
}
