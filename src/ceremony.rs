use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use webauthn_rs::prelude::{
	DiscoverableAuthentication, PasskeyAuthentication, PasskeyRegistration,
};

use crate::Error;

const ID_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum Purpose {
	Register,
	SignIn,
	Enrol,
}

impl Purpose {
	pub const fn as_str(self) -> &'static str {
		match self {
			Self::Register => "register",
			Self::SignIn => "sign-in",
			Self::Enrol => "enrol",
		}
	}
}

/// A ceremony between its start and finish requests. Its state stays server side: with the
/// `serde` feature a shared store can keep it serialized, which holds the webauthn-rs
/// challenge state and so must never reach the client.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ceremony<U> {
	pub(crate) step: Step<U>,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) enum Step<U> {
	Register {
		user: U,
		binding: [u8; 32],
		state: PasskeyRegistration,
		#[cfg_attr(
			feature = "serde",
			serde(default, skip_serializing_if = "Option::is_none")
		)]
		data: Option<String>,
	},
	Enrol {
		user: U,
		grant: String,
		binding: [u8; 32],
		state: PasskeyRegistration,
		#[cfg_attr(
			feature = "serde",
			serde(default, skip_serializing_if = "Option::is_none")
		)]
		data: Option<String>,
	},
	Named {
		name: String,
		user: Option<U>,
		state: Option<PasskeyAuthentication>,
	},
	Discoverable {
		state: DiscoverableAuthentication,
	},
}

impl<U> Ceremony<U> {
	pub const fn purpose(&self) -> Purpose {
		match self.step {
			Step::Register { .. } => Purpose::Register,
			Step::Enrol { .. } => Purpose::Enrol,
			Step::Named { .. } | Step::Discoverable { .. } => Purpose::SignIn,
		}
	}
}

/// Where ceremonies wait between start and finish.
///
/// An implementation hands out ids from [`ceremony_id`] and keeps only their
/// [`ceremony_key`], gives a ceremony back once and only within its lifetime (taking it removes
/// it even when it has expired), caps how many one client [`network`] holds without ever
/// dropping another address's ceremonies (`Error::TooMany`), and refuses new ceremonies when
/// full instead of evicting live ones (`Error::Busy`).
pub trait CeremonyStore<U>: Send + Sync {
	fn begin(
		&self,
		address: Option<IpAddr>,
		ceremony: Ceremony<U>,
	) -> impl Future<Output = Result<String, Error>> + Send;

	/// `Ok(None)` for an unknown, used or expired id.
	fn take(&self, id: &str) -> impl Future<Output = Result<Option<Ceremony<U>>, Error>> + Send;
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
	pub ttl: Duration,
	pub per_address: usize,
	pub global: usize,
}

impl Default for Limits {
	fn default() -> Self {
		Self {
			ttl: Duration::from_secs(5 * 60),
			per_address: 20,
			global: 10_000,
		}
	}
}

struct Entry<U> {
	at: Instant,
	address: Option<IpAddr>,
	ceremony: Ceremony<U>,
}

/// Ceremonies in process memory: lost on restart and not shared between replicas.
pub struct MemoryCeremonies<U> {
	limits: Limits,
	entries: Mutex<HashMap<[u8; 32], Entry<U>>>,
}

impl<U> Default for MemoryCeremonies<U> {
	fn default() -> Self {
		Self::new(Limits::default())
	}
}

/// The address a cap counts: an IPv6 client usually holds a whole /64.
pub fn network(ip: IpAddr) -> IpAddr {
	match ip.to_canonical() {
		IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !u128::from(u64::MAX)).into()),
		v4 => v4,
	}
}

pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
	Sha256::digest(bytes).into()
}

/// What a store keeps instead of a ceremony id.
pub fn ceremony_key(id: &str) -> [u8; 32] {
	digest(id.as_bytes())
}

/// A new ceremony id: 32 random bytes, hex encoded.
pub fn ceremony_id() -> Result<String, Error> {
	let mut bytes = [0u8; ID_BYTES];
	getrandom::fill(&mut bytes).map_err(Error::internal)?;
	Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

impl<U> MemoryCeremonies<U> {
	pub fn new(limits: Limits) -> Self {
		Self {
			limits,
			entries: Mutex::default(),
		}
	}

	fn entries(&self) -> MutexGuard<'_, HashMap<[u8; 32], Entry<U>>> {
		self.entries.lock().unwrap_or_else(PoisonError::into_inner)
	}

	pub(crate) fn begin_at(
		&self,
		now: Instant,
		address: Option<IpAddr>,
		ceremony: Ceremony<U>,
	) -> Result<String, Error> {
		let Limits {
			ttl,
			per_address,
			global,
		} = self.limits;
		let address = address.map(network);
		let mut entries = self.entries();
		entries.retain(|_, entry| now.saturating_duration_since(entry.at) < ttl);
		let held: Vec<Instant> = entries
			.values()
			.filter(|entry| entry.address == address)
			.map(|entry| entry.at)
			.collect();
		if held.len() >= per_address {
			let oldest = held.into_iter().min().unwrap_or(now);
			let retry_after = ttl.saturating_sub(now.saturating_duration_since(oldest));
			return Err(Error::TooMany {
				retry_after: retry_after.max(Duration::from_secs(1)),
			});
		}
		if entries.len() >= global {
			return Err(Error::Busy);
		}
		let id = ceremony_id()?;
		entries.insert(
			digest(id.as_bytes()),
			Entry {
				at: now,
				address,
				ceremony,
			},
		);
		Ok(id)
	}

	pub(crate) fn take_at(&self, now: Instant, id: &str) -> Option<Ceremony<U>> {
		let entry = self.entries().remove(&digest(id.as_bytes()))?;
		(now.saturating_duration_since(entry.at) < self.limits.ttl).then_some(entry.ceremony)
	}

	#[cfg(test)]
	pub(crate) fn holds(&self, id: &str) -> bool {
		self.entries().contains_key(&digest(id.as_bytes()))
	}

	#[cfg(test)]
	pub(crate) fn keys(&self) -> Vec<[u8; 32]> {
		self.entries().keys().copied().collect()
	}
}

impl<U: Send> CeremonyStore<U> for MemoryCeremonies<U> {
	async fn begin(&self, address: Option<IpAddr>, ceremony: Ceremony<U>) -> Result<String, Error> {
		self.begin_at(Instant::now(), address, ceremony)
	}

	async fn take(&self, id: &str) -> Result<Option<Ceremony<U>>, Error> {
		Ok(self.take_at(Instant::now(), id))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn ceremony(name: &str) -> Ceremony<u32> {
		Ceremony {
			step: Step::Named {
				name: name.into(),
				user: None,
				state: None,
			},
		}
	}

	fn address(n: u32) -> Option<IpAddr> {
		Some(IpAddr::from((0x0a00_0000 + n).to_be_bytes()))
	}

	fn small() -> MemoryCeremonies<u32> {
		MemoryCeremonies::new(Limits {
			ttl: Duration::from_secs(300),
			per_address: 3,
			global: 8,
		})
	}

	#[test]
	fn a_ceremony_is_taken_once_and_only_its_hash_is_kept() {
		let store = small();
		let now = Instant::now();
		let id = store.begin_at(now, address(1), ceremony("jeanne")).unwrap();
		assert_eq!(id.len(), ID_BYTES * 2);
		assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
		assert_eq!(store.keys(), vec![digest(id.as_bytes())]);
		assert!(
			!store
				.keys()
				.iter()
				.any(|key| key.as_slice() == id.as_bytes())
		);
		assert!(store.take_at(now, "not it").is_none());
		assert!(store.take_at(now, &id).is_some());
		assert!(store.take_at(now, &id).is_none());
		let other = store.begin_at(now, address(1), ceremony("jeanne")).unwrap();
		assert_ne!(id, other);
	}

	#[test]
	fn a_ceremony_expires_and_is_gone_even_when_taken_late() {
		let store = small();
		let now = Instant::now();
		let id = store.begin_at(now, address(1), ceremony("jeanne")).unwrap();
		let late = now + Duration::from_secs(300);
		assert!(store.take_at(late, &id).is_none());
		assert!(!store.holds(&id));
		let id = store.begin_at(now, address(1), ceremony("jeanne")).unwrap();
		assert!(store.take_at(now + Duration::from_secs(299), &id).is_some());
	}

	#[test]
	fn a_full_address_is_refused_and_never_evicts_another_address() {
		let store = small();
		let now = Instant::now();
		let mine: Vec<String> = (0..3)
			.map(|n| {
				let at = now + Duration::from_secs(n * 10);
				store.begin_at(at, address(1), ceremony("jeanne")).unwrap()
			})
			.collect();
		let later = now + Duration::from_secs(60);
		assert!(
			store
				.begin_at(later, address(2), ceremony("jeanne"))
				.is_ok()
		);
		for n in 0..2 {
			assert!(
				store
					.begin_at(later, address(2), ceremony(&format!("x{n}")))
					.is_ok()
			);
		}
		match store.begin_at(later, address(2), ceremony("jeanne")) {
			Err(Error::TooMany { .. }) => {}
			other => panic!("{other:?}"),
		}
		match store.begin_at(later, address(1), ceremony("paul")) {
			Err(Error::TooMany { retry_after }) => {
				assert_eq!(retry_after, Duration::from_secs(240))
			}
			other => panic!("{other:?}"),
		}
		for id in &mine {
			assert!(
				store.take_at(later, id).is_some(),
				"address 2 evicted a ceremony of address 1"
			);
		}
		assert!(store.begin_at(later, address(1), ceremony("paul")).is_ok());
	}

	#[test]
	fn an_ipv6_network_counts_as_one_address() {
		let store = small();
		let now = Instant::now();
		for host in 1..=3 {
			let ip: IpAddr = format!("2001:db8:1:2::{host:x}").parse().unwrap();
			store.begin_at(now, Some(ip), ceremony("jeanne")).unwrap();
		}
		let rotated: IpAddr = "2001:db8:1:2:ffff::1".parse().unwrap();
		assert!(matches!(
			store.begin_at(now, Some(rotated), ceremony("jeanne")),
			Err(Error::TooMany { .. })
		));
		let elsewhere: IpAddr = "2001:db8:1:3::1".parse().unwrap();
		assert!(
			store
				.begin_at(now, Some(elsewhere), ceremony("jeanne"))
				.is_ok()
		);
		let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
		assert_eq!(network(mapped), address(1).unwrap());
	}

	#[test]
	fn the_global_cap_refuses_instead_of_evicting() {
		let store = small();
		let now = Instant::now();
		let ids: Vec<String> = (0..8)
			.map(|n| store.begin_at(now, address(n), ceremony("jeanne")).unwrap())
			.collect();
		assert!(matches!(
			store.begin_at(now, address(100), ceremony("paul")),
			Err(Error::Busy)
		));
		for id in &ids {
			assert!(store.holds(id));
		}
		let later = now + Duration::from_secs(300);
		assert!(
			store
				.begin_at(later, address(100), ceremony("paul"))
				.is_ok()
		);
	}
}
